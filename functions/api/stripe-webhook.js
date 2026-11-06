// POST /api/stripe-webhook  - Stripe -> us.
// Verifies the signature, then activates the membership for paid Checkout Sessions.
// Stripe dashboard: endpoint https://avakri.com/api/stripe-webhook,
// events: checkout.session.completed, checkout.session.async_payment_succeeded.

const TOLERANCE_SECONDS = 300;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const text = (body, status) => new Response(body, { status });

async function hmacHex(secret, message) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// Returns '' when the signature is valid, otherwise a short reason (safe to log, contains no secrets).
async function verifyStripeSignature(rawBody, header, secret, now = Date.now()) {
  if (!header) return 'no Stripe-Signature header';
  const parts = header.split(',').map((p) => p.trim().split('='));
  const t = (parts.find((p) => p[0] === 't') || [])[1];
  const sigs = parts.filter((p) => p[0] === 'v1').map((p) => p[1]);
  if (!t || !sigs.length || !/^\d+$/.test(t)) return 'malformed Stripe-Signature header';
  const age = Math.round(now / 1000 - Number(t));
  if (Math.abs(age) > TOLERANCE_SECONDS) return `timestamp outside tolerance (${age}s)`;
  const expected = await hmacHex(secret, `${t}.${rawBody}`);
  return sigs.some((s) => safeEqual(s, expected)) ? '' : 'signature mismatch (wrong or differently-formatted STRIPE_WEBHOOK_SECRET?)';
}

export async function onRequestPost({ request, env }) {
  try {
    const missing = ['SUPABASE_URL', 'SUPABASE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET'].filter((k) => !env[k]);
    if (missing.length) {
      console.error('Missing environment variables:', missing.join(', '));
      return text('Server error', 500);
    }
    const raw = await request.text();
    const failure = await verifyStripeSignature(raw, request.headers.get('Stripe-Signature'), String(env.STRIPE_WEBHOOK_SECRET).trim());
    if (failure) {
      console.error('Webhook rejected:', failure, '| secret prefix:', String(env.STRIPE_WEBHOOK_SECRET).trim().slice(0, 6));
      return text('Invalid signature', 400);
    }

    let event;
    try { event = JSON.parse(raw); } catch (e) { return text('Bad payload', 400); }

    const sb = (path, init = {}) =>
      fetch(`${env.SUPABASE_URL}${path}`, {
        ...init,
        headers: { apikey: env.SUPABASE_SECRET_KEY, 'Content-Type': 'application/json', ...(init.headers || {}) },
      });

    const handled = ['checkout.session.completed', 'checkout.session.async_payment_succeeded'];
    if (handled.includes(event.type)) {
      const s = event.data && event.data.object ? event.data.object : {};
      const userId = s.client_reference_id;
      // 'paid', or a 100%-discounted session (promo code): Stripe may report it as no_payment_required with amount 0.
      const isPaid = s.payment_status === 'paid' || (s.payment_status === 'no_payment_required' && s.amount_total === 0);
      if (isPaid && typeof userId === 'string' && UUID.test(userId)) {
        // Idempotent: user_id is the primary key, an existing membership (e.g. prepaid) is left alone.
        const r = await sb('/rest/v1/memberships?on_conflict=user_id', {
          method: 'POST',
          headers: { Prefer: 'resolution=ignore-duplicates,return=minimal' },
          body: JSON.stringify({
            user_id: userId, status: 'active', source: 'stripe',
            stripe_session_id: s.id, amount_cents: s.amount_total ?? null,
          }),
        });
        if (!r.ok) {
          // Non-2xx makes Stripe retry later.
          console.error('Membership insert failed:', r.status, await r.text());
          return text('Database error', 500);
        }
      } else if (!isPaid) {
        console.log('Session not paid yet, ignored:', s.id, s.payment_status);
      } else {
        console.error('Paid session without a valid client_reference_id:', s.id);
      }
    }

    // Audit trail of processed events (best effort; processing above is already idempotent).
    try {
      await sb('/rest/v1/stripe_events?on_conflict=event_id', {
        method: 'POST',
        headers: { Prefer: 'resolution=ignore-duplicates,return=minimal' },
        body: JSON.stringify({ event_id: event.id, type: event.type }),
      });
    } catch (e) { console.error('Event log failed:', e); }

    return text('ok', 200);
  } catch (err) {
    console.error('Webhook error:', err);
    return text('Server error', 500);
  }
}
