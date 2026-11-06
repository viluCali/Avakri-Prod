const ALLOWED_HOSTS = ['avakri.com', 'www.avakri.com', 'avakri-dev.pages.dev', 'avakri-prod.pages.dev'];
const VIOLATION_TYPES = ['impersonation', 'harassment', 'inappropriate_content',
'commercial_solicitation', 'safety_concern', 'copyright_dmca', 'other'];
const SWORN_REQUIRED = ['impersonation', 'copyright_dmca'];
const MAX_PER_HOUR = 5;

const json = (obj, status) => new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json' }
});

async function sha256Hex(text) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function onRequestPost({ request, env }) {
    try {
        const missing = ['TURNSTILE_SECRET_KEY', 'SUPABASE_URL', 'SUPABASE_SECRET_KEY'].filter(k => !env[k]);
        if (missing.length) {
            console.error('Missing environment variables:', missing.join(', '));
            return json({ success: false, error: 'Server error' }, 500);
        }

        // Origin check (browsers always send Origin on fetch POST)
        const origin = request.headers.get('Origin');
        if (origin) {
            let host = '';
            try { host = new URL(origin).hostname; } catch (e) {}
            if (!ALLOWED_HOSTS.includes(host)) return json({ success: false, error: 'Forbidden' }, 403);
        }

        const formData = await request.formData();
        const field = (k) => String(formData.get(k) ?? '').trim();

        // Honeypot: real users never fill this hidden field; pretend success to bots
        if (field('website')) return json({ success: true }, 200);

        const reporterName = field('reporter_name');
        const reporterEmail = field('reporter_email');
        const subjectDetails = field('subject_details');
        const violationType = field('violation_type');
        const description = field('description');
        const sworn = formData.get('sworn_confirmation') === 'on';
        const token = field('cf-turnstile-response');

        if (!token) return json({ success: false, error: 'Please complete the security check' }, 400);

        const invalid =
        !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(reporterEmail) || reporterEmail.length > 254 ||
        reporterName.length > 200 ||
        !subjectDetails || subjectDetails.length > 2000 ||
        !VIOLATION_TYPES.includes(violationType) ||
        !description || description.length > 5000 ||
        (SWORN_REQUIRED.includes(violationType) && !sworn);
        if (invalid) return json({ success: false, error: 'Please check the form fields and try again' }, 400);

        // Turnstile verification
        const clientIp = request.headers.get('CF-Connecting-IP') || '';
        const verifyData = new URLSearchParams({ secret: env.TURNSTILE_SECRET_KEY, response: token });
        if (clientIp) verifyData.append('remoteip', clientIp);
        const tRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST', body: verifyData
        });
        const outcome = await tRes.json();
        if (!outcome.success || !ALLOWED_HOSTS.includes(outcome.hostname)) {
            console.error('Turnstile rejected:', outcome['error-codes'], outcome.hostname);
            return json({ success: false, error: 'Invalid captcha' }, 403);
        }

        // Supabase headers (new sb_secret keys go in apikey only; legacy JWT keys need Authorization too)
        const key = env.SUPABASE_SECRET_KEY;
        const sbHeaders = { apikey: key, 'Content-Type': 'application/json' };
        if (key.startsWith('eyJ')) sbHeaders.Authorization = `Bearer ${key}`;

        // DB-backed rate limit per IP (hashed)
        const ipHash = await sha256Hex(clientIp + env.TURNSTILE_SECRET_KEY);
        const since = encodeURIComponent(new Date(Date.now() - 3600 * 1000).toISOString());
        const cRes = await fetch(
            `${env.SUPABASE_URL}/rest/v1/reports?select=id&ip_hash=eq.${ipHash}&created_at=gte.${since}`,
            { method: 'HEAD', headers: { ...sbHeaders, Prefer: 'count=exact' } }
        );
        const recent = parseInt((cRes.headers.get('content-range') || '').split('/')[1] || '0', 10);
        if (recent >= MAX_PER_HOUR) {
            return json({ success: false, error: 'Too many submissions. Please try again later.' }, 429);
        }

        const ins = await fetch(`${env.SUPABASE_URL}/rest/v1/reports`, {
            method: 'POST',
            headers: { ...sbHeaders, Prefer: 'return=minimal' },
            body: JSON.stringify({
                reporter_name: reporterName || null,
                reporter_email: reporterEmail,
                subject_details: subjectDetails,
                violation_type: violationType,
                description,
                sworn_confirmation: sworn,
                ip_hash: ipHash
            })
        });
        if (!ins.ok) {
            console.error('Supabase insert failed:', ins.status, await ins.text());
            return json({ success: false, error: 'Could not save, please try again' }, 502);
        }
        return json({ success: true }, 200);
    } catch (err) {
        console.error('Report error:', err);
        return json({ success: false, error: 'Server error' }, 500);
    }
}
