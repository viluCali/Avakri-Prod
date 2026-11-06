// POST /api/checkout  (Authorization: Bearer <Supabase access token>)
// Creates a Stripe Checkout Session for the lifetime membership and returns { url }.
// The amount is read from public.prices on the server; the browser never sends a price.

const ALLOWED_HOSTS = ['avakri.com', 'www.avakri.com', 'avakri-dev.pages.dev', 'avakri-prod.pages.dev'];
const SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_RVEnnwWIzpXKXuwP1MUz_A_J5361pXZ';
const PRODUCT_NAME = 'One Membership to Avakri (never expires)';

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
const hostAllowed = (h) => ALLOWED_HOSTS.includes(h) || h.endsWith('.avakri-dev.pages.dev');

export async function onRequestPost({ request, env }) {
  try {
    const missing = ['SUPABASE_URL', 'SUPABASE_SECRET_KEY', 'STRIPE_SECRET_KEY'].filter((k) => !env[k]);
    if (missing.length) {
      console.error('Missing environment variables:', missing.join(', '));
      return json({ error: 'Server error' }, 500);
    }

    const origin = request.headers.get('Origin') || '';
    let originHost = '';
    try { originHost = new URL(origin).hostname; } catch (e) {}
    if (!hostAllowed(originHost)) return json({ error: 'Forbidden' }, 403);

    // Who is calling? Verify the JWT with Supabase Auth.
    const auth = request.headers.get('Authorization') || '';
    const jwt = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    if (!jwt) return json({ error: 'Please sign in.' }, 401);
    const uRes = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, {
      headers: { apikey: SUPABASE_PUBLISHABLE_KEY, Authorization: `Bearer ${jwt}` },
    });
    if (!uRes.ok) return json({ error: 'Please sign in.' }, 401);
    const user = await uRes.json();
    if (!user.id || !user.email) return json({ error: 'Please sign in.' }, 401);

    const sb = (path, init = {}) =>
      fetch(`${env.SUPABASE_URL}${path}`, {
        ...init,
        headers: { apikey: env.SUPABASE_SECRET_KEY, 'Content-Type': 'application/json', ...(init.headers || {}) },
      });

    // Already a member? Do not charge twice.
    const mRes = await sb(`/rest/v1/memberships?user_id=eq.${user.id}&status=eq.active&select=user_id`);
    const mRows = mRes.ok ? await mRes.json() : [];
    if (mRows.length) return json({ error: 'Your membership is already active.' }, 409);

    // Price comes from the database.
    const pRes = await sb('/rest/v1/prices?id=eq.lifetime&active=eq.true&select=amount_cents,currency');
    const pRows = pRes.ok ? await pRes.json() : [];
    if (!pRows.length) {
      console.error('Price not found');
      return json({ error: 'Server error' }, 500);
    }
    const { amount_cents, currency } = pRows[0];

    const form = new URLSearchParams({
      mode: 'payment',
      client_reference_id: user.id,
      customer_email: user.email,
      allow_promotion_codes: 'true',
      success_url: `${origin}/onboarding/?paid=1`,
      cancel_url: `${origin}/onboarding/`,
      'line_items[0][quantity]': '1',
      'line_items[0][price_data][currency]': currency,
      'line_items[0][price_data][unit_amount]': String(amount_cents),
      'metadata[user_id]': user.id,
    });
    // Coupons/promo codes in Stripe can be restricted to a product. If STRIPE_PRODUCT_ID (prod_...) is set,
    // charge against that existing product so such codes apply; otherwise use an ad-hoc product by name.
    if (env.STRIPE_PRODUCT_ID && /^prod_[A-Za-z0-9]+$/.test(env.STRIPE_PRODUCT_ID)) {
      form.set('line_items[0][price_data][product]', env.STRIPE_PRODUCT_ID);
    } else {
      form.set('line_items[0][price_data][product_data][name]', PRODUCT_NAME);
    }
    const sRes = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form,
    });
    const session = await sRes.json().catch(() => ({}));
    if (!sRes.ok || !session.url) {
      console.error('Stripe session failed:', sRes.status, JSON.stringify(session.error || session));
      return json({ error: 'Could not start checkout. Please try again.' }, 502);
    }
    return json({ url: session.url });
  } catch (err) {
    console.error('Checkout error:', err);
    return json({ error: 'Server error' }, 500);
  }
}
