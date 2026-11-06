// POST /api/signup  (JSON)
// { email, phone, password, link?, channels?: ['sms','whatsapp'], 'cf-turnstile-response', website }
// Creates the Supabase account (confirmation email via custom SMTP), records the lead / consents,
// and, when a valid prepaid link is supplied, redeems it once and creates the membership.

const ALLOWED_HOSTS = ['avakri.com', 'www.avakri.com', 'avakri-dev.pages.dev', 'avakri-prod.pages.dev'];
// Publishable key is public by design (it is already in the HTML pages).
const SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_RVEnnwWIzpXKXuwP1MUz_A_J5361pXZ';
const CHANNELS = ['sms', 'whatsapp'];

// Final wording from the client. Must stay identical to the checkbox labels in signup/index.html.
const CONSENT_TEXTS = {
  sms: 'I agree to receive updates from AVAKRI by text message. Message and data rates may apply. Reply STOP to opt out.',
  whatsapp: 'I agree to receive updates from AVAKRI on WhatsApp.',
};

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });

async function sha256hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function hostAllowed(host) {
  return ALLOWED_HOSTS.includes(host) || host.endsWith('.avakri-dev.pages.dev');
}

export async function onRequestPost({ request, env }) {
  let linkId = null;
  const sb = (path, init = {}) =>
    fetch(`${env.SUPABASE_URL}${path}`, {
      ...init,
      headers: { apikey: env.SUPABASE_SECRET_KEY, 'Content-Type': 'application/json', ...(init.headers || {}) },
    });
  const releaseLink = async () => {
    if (!linkId) return;
    try {
      await sb(`/rest/v1/prepaid_links?id=eq.${linkId}`, {
        method: 'PATCH',
        headers: { Prefer: 'return=minimal' },
        body: JSON.stringify({ redeemed_at: null, redeemed_by: null }),
      });
    } catch (e) { console.error('Release link failed:', e); }
    linkId = null;
  };

  try {
    const missing = ['SUPABASE_URL', 'SUPABASE_SECRET_KEY', 'TURNSTILE_SECRET_KEY'].filter((k) => !env[k]);
    if (missing.length) {
      console.error('Missing environment variables:', missing.join(', '));
      return json({ success: false, error: 'Server error' }, 500);
    }

    // Origin check
    const origin = request.headers.get('Origin') || '';
    let originHost = '';
    try { originHost = new URL(origin).hostname; } catch (e) {}
    if (!hostAllowed(originHost)) return json({ success: false, error: 'Forbidden' }, 403);

    let body;
    try { body = await request.json(); } catch (e) { return json({ success: false, error: 'Invalid request' }, 400); }

    // Honeypot: pretend success
    if (typeof body.website === 'string' && body.website.trim() !== '') return json({ success: true });

    // Validation
    const email = String(body.email || '').trim().toLowerCase();
    const phone = String(body.phone || '').trim();
    const password = String(body.password || '');
    const link = typeof body.link === 'string' ? body.link.trim() : '';
    const channels = Array.isArray(body.channels) ? [...new Set(body.channels.filter((c) => CHANNELS.includes(c)))] : [];

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
      return json({ success: false, error: 'Please enter a valid email address.' }, 400);
    }
    const phoneDigits = phone.replace(/\D/g, '');
    if (!/^[+\d\s().-]+$/.test(phone) || phoneDigits.length < 7 || phoneDigits.length > 15) {
      return json({ success: false, error: 'Please enter a valid phone number.' }, 400);
    }
    if (password.length < 8 || password.length > 72) {
      return json({ success: false, error: 'Password must be between 8 and 72 characters.' }, 400);
    }
    if (link && !/^[a-f0-9]{48}$/.test(link)) {
      return json({ success: false, error: 'This link is invalid, expired, or already used.' }, 400);
    }

    // Turnstile
    const token = body['cf-turnstile-response'];
    if (!token) return json({ success: false, error: 'Please complete the security check.' }, 400);
    const clientIp = request.headers.get('CF-Connecting-IP') || '';
    const tsRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret: env.TURNSTILE_SECRET_KEY, response: token, remoteip: clientIp }),
    });
    const ts = await tsRes.json();
    if (!ts.success || (ts.hostname && !hostAllowed(ts.hostname))) {
      console.error('Turnstile rejected:', ts['error-codes'], ts.hostname);
      return json({ success: false, error: 'Invalid captcha' }, 403);
    }
    const ipHash = await sha256hex(clientIp + env.TURNSTILE_SECRET_KEY);

    // Lead first (so people who fail or abandon signup are still in the marketing table)
    try {
      await sb('/rest/v1/marketing?on_conflict=email', {
        method: 'POST',
        headers: { Prefer: 'resolution=ignore-duplicates,return=minimal' },
        body: JSON.stringify({ email, phone, source: 'signup-page' }),
      });
    } catch (e) { console.error('Lead insert failed:', e); }

    // Claim the prepaid link atomically (works once; expired/used links match nothing)
    if (link) {
      const nowIso = new Date().toISOString();
      const hash = await sha256hex(link);
      const claim = await sb(
        `/rest/v1/prepaid_links?token_hash=eq.${hash}&redeemed_at=is.null&expires_at=gt.${encodeURIComponent(nowIso)}`,
        {
          method: 'PATCH',
          headers: { Prefer: 'return=representation' },
          body: JSON.stringify({ redeemed_at: nowIso, preferred_channels: channels }),
        }
      );
      const rows = claim.ok ? await claim.json() : [];
      if (!rows.length) return json({ success: false, error: 'This link is invalid, expired, or already used.' }, 400);
      linkId = rows[0].id;
    }

    // Create the account (sends the confirmation email through the custom SMTP)
    const sgRes = await fetch(
      `${env.SUPABASE_URL}/auth/v1/signup?redirect_to=${encodeURIComponent(origin + '/onboarding/')}`,
      {
        method: 'POST',
        headers: { apikey: SUPABASE_PUBLISHABLE_KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, data: { phone } }),
      }
    );
    const sg = await sgRes.json().catch(() => ({}));
    if (!sgRes.ok) {
      await releaseLink();
      console.error('Auth signup failed:', sgRes.status, JSON.stringify(sg));
      if (sgRes.status === 429) return json({ success: false, error: 'Too many attempts. Please try again later.' }, 429);
      const msg = String(sg.msg || sg.error_description || sg.message || '');
      if (/password/i.test(msg)) return json({ success: false, error: msg }, 400);
      return json({ success: false, error: 'Could not create the account. Please try again.' }, 400);
    }

    const user = sg.user || sg;
    // Existing email: Supabase hides it by returning a user with no identities. Do not burn the link.
    if (!user.id || (Array.isArray(user.identities) && user.identities.length === 0)) {
      await releaseLink();
      return json({ success: true, prepaid: false });
    }

    // Follow-up writes. Failures are logged and do not undo the account.
    const step = async (name, fn) => {
      try {
        const r = await fn();
        if (r && r.ok === false) console.error(`${name} failed:`, r.status, await r.text());
      } catch (e) { console.error(`${name} error:`, e); }
    };

    await step('lead update', () => sb(`/rest/v1/marketing?email=eq.${encodeURIComponent(email)}`, {
      method: 'PATCH', headers: { Prefer: 'return=minimal' }, body: JSON.stringify({ converted: true, phone }),
    }));
    await step('profile phone', () => sb('/rest/v1/users?on_conflict=id', {
      method: 'POST', headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify({ id: user.id, phone }),
    }));
    if (channels.length) {
      await step('consents', () => sb('/rest/v1/channel_consents', {
        method: 'POST', headers: { Prefer: 'return=minimal' },
        body: JSON.stringify(channels.map((channel) => ({
          user_id: user.id, email, phone, channel, context: 'signup', consent_text: CONSENT_TEXTS[channel], ip_hash: ipHash,
        }))),
      }));
    }
    if (linkId) {
      await step('membership', () => sb('/rest/v1/memberships', {
        method: 'POST', headers: { Prefer: 'return=minimal' },
        body: JSON.stringify({ user_id: user.id, source: 'prepaid_link' }),
      }));
      await step('link owner', () => sb(`/rest/v1/prepaid_links?id=eq.${linkId}`, {
        method: 'PATCH', headers: { Prefer: 'return=minimal' }, body: JSON.stringify({ redeemed_by: user.id }),
      }));
    }

    return json({ success: true, prepaid: Boolean(linkId) });
  } catch (err) {
    await releaseLink();
    console.error('Signup error:', err);
    return json({ success: false, error: 'Server error' }, 500);
  }
}
