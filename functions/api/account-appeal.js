// POST /api/account-appeal  (JSON: { statement })
// Logged-in users whose account is rejected / deleted / flagged can send an appeal.
// The 3-request limit is enforced by a DB trigger (see milestone-b.sql), not only here.

const ALLOWED_HOSTS = ['avakri.com', 'www.avakri.com', 'avakri-dev.pages.dev', 'avakri-prod.pages.dev'];
const BLOCKED_STATUSES = ['rejected', 'deleted', 'flagged'];
const MAX_STATEMENT = 5000;
// Publishable key is public by design (it is already in the HTML pages); used only to verify the user's JWT.
const SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_RVEnnwWIzpXKXuwP1MUz_A_J5361pXZ';

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });

export async function onRequestPost({ request, env }) {
  try {
    if (!env.SUPABASE_URL || !env.SUPABASE_SECRET_KEY) {
      console.error('Missing environment variables: SUPABASE_URL, SUPABASE_SECRET_KEY');
      return json({ success: false, error: 'Server error' }, 500);
    }

    // Origin check
    const origin = request.headers.get('Origin') || '';
    let originHost = '';
    try { originHost = new URL(origin).hostname; } catch (e) {}
    if (!ALLOWED_HOSTS.includes(originHost) && !originHost.endsWith('.avakri-dev.pages.dev')) {
      return json({ success: false, error: 'Forbidden' }, 403);
    }

    // Who is calling? Verify the JWT with Supabase Auth.
    const auth = request.headers.get('Authorization') || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
    if (!token) return json({ success: false, error: 'Please sign in again.' }, 401);

    const userRes = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, {
      headers: { apikey: SUPABASE_PUBLISHABLE_KEY, Authorization: `Bearer ${token}` },
    });
    if (!userRes.ok) return json({ success: false, error: 'Please sign in again.' }, 401);
    const user = await userRes.json();
    if (!user || !user.id) return json({ success: false, error: 'Please sign in again.' }, 401);

    // Input
    let body;
    try { body = await request.json(); } catch (e) { return json({ success: false, error: 'Invalid request' }, 400); }
    const statement = typeof body.statement === 'string' ? body.statement.trim() : '';
    if (!statement) return json({ success: false, error: 'Please write your statement.' }, 400);
    if (statement.length > MAX_STATEMENT) {
      return json({ success: false, error: `Statement is too long (max ${MAX_STATEMENT} characters).` }, 400);
    }

    const sbHeaders = {
      apikey: env.SUPABASE_SECRET_KEY,
      'Content-Type': 'application/json',
    };

    // Only accounts with a blocked status may appeal
    const stRes = await fetch(
      `${env.SUPABASE_URL}/rest/v1/user_status?select=status&user_id=eq.${encodeURIComponent(user.id)}`,
      { headers: sbHeaders }
    );
    if (!stRes.ok) {
      console.error('Status lookup failed:', stRes.status, await stRes.text());
      return json({ success: false, error: 'Server error' }, 500);
    }
    const rows = await stRes.json();
    const status = rows[0]?.status || 'onboarding';
    if (!BLOCKED_STATUSES.includes(status)) {
      return json({ success: false, error: 'Forbidden' }, 403);
    }

    // Insert (the DB trigger enforces max 3 per user)
    const insRes = await fetch(`${env.SUPABASE_URL}/rest/v1/account_appeals`, {
      method: 'POST',
      headers: { ...sbHeaders, Prefer: 'return=minimal' },
      body: JSON.stringify({ user_id: user.id, statement }),
    });
    if (!insRes.ok) {
      const text = await insRes.text();
      if (text.includes('appeal_limit_reached')) {
        return json({ success: false, error: 'You have reached the maximum of 3 appeal requests.' }, 429);
      }
      console.error('Insert failed:', insRes.status, text);
      return json({ success: false, error: 'Server error' }, 500);
    }

    return json({ success: true });
  } catch (err) {
    console.error('Account appeal error:', err);
    return json({ success: false, error: 'Server error' }, 500);
  }
}
