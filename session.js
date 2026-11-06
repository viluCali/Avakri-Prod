/* AVAKRI shared session helpers.
   Needs the supabase-js CDN script loaded before this file. */
(function () {
    var SUPABASE_URL = "https://vhrmnnxwwvpmckforzci.supabase.co";
    var SUPABASE_KEY = "sb_publishable_RVEnnwWIzpXKXuwP1MUz_A_J5361pXZ";
    var ROUTES = {
        approved: '/dashboard/',
        onboarding: '/onboarding/',
        rejected: '/dashboard-error/',
        deleted: '/dashboard-error/',
        flagged: '/dashboard-error/'
    };
    // Staff roles go straight to their own page (no onboarding needed).
    var ROLE_ROUTES = { mm: '/mm-dashboard/', support: '/support/', admin: '/admin/' };
    var LABELS = { approved: 'Dashboard', onboarding: 'Continue onboarding' };

    function client() {
        if (!window.supabaseClient && window.supabase && window.supabase.createClient) {
            window.supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);
        }
        return window.supabaseClient;
    }

    // Returns { status, type, url, label } or null if the account row could not be loaded.
    // type = user_type from user_status ('user' | 'mm' | 'support' | 'admin').
    async function route(sb, session) {
        var res = await sb.from('user_status').select('status,user_type').eq('user_id', session.user.id).maybeSingle();
        if (res.error) {
            // user_type column not there yet: fall back to status only
            res = await sb.from('user_status').select('status').eq('user_id', session.user.id).maybeSingle();
            if (res.error) return null;
        }
        var status = (res.data && res.data.status) || 'onboarding'; // missing row = still onboarding
        var type = (res.data && res.data.user_type) || 'user';
        if (ROLE_ROUTES[type]) return { status: status, type: type, url: ROLE_ROUTES[type], label: 'My dashboard' };
        return { status: status, type: type, url: ROUTES[status] || '/dashboard-error/', label: LABELS[status] || 'My account' };
    }

    // For role pages (/mm-dashboard, /support, /admin, /dashboard).
    // Needs a session whose user_type equals `role`; anyone else is sent to their own page.
    // Reveals the page (body.ready) when allowed. Resolves true if allowed.
    // For role 'user' the account must also be approved.
    async function requireRole(role) {
        try {
            var sb = client();
            var s = await sb.auth.getSession();
            var session = s && s.data && s.data.session;
            if (!session) { location.replace('/login/'); return false; }
            var r = await route(sb, session);
            if (!r) { location.replace('/login/'); return false; }
            if (r.type !== role || (role === 'user' && r.status !== 'approved')) { location.replace(r.url); return false; }
            window.AvakriUser = { id: session.user.id, email: session.user.email, type: r.type, status: r.status };
            document.body.classList.add('ready');
            return true;
        } catch (e) {
            location.replace('/login/');
            return false;
        }
    }

    // For /login and /signup: send an already signed-in user to the right page.
    // Resolves true if a redirect was started, false if the page should be shown.
    async function redirectIfSignedIn(sb) {
        try {
            sb = sb || client();
            if (!sb) return false;
            var s = await sb.auth.getSession();
            var session = s && s.data && s.data.session;
            if (!session) return false;
            var r = await route(sb, session);
            if (!r) return false; // expired/invalid session or lookup error: show the form
            location.replace(r.url);
            return true;
        } catch (e) {
            return false;
        }
    }

    // Header: logged out = Login + YouTube; logged in = logo + Log out.
    // The logo links to the member's own page (dashboard / onboarding) when signed in.
    async function setupNav() {
        try {
            var header = document.getElementById('av-header');
            var sb = client();
            if (!header || !sb) return;
            var out = document.getElementById('nav-logout');
            if (out && !out.__bound) {
                out.__bound = true;
                out.addEventListener('click', async function (e) {
                    e.preventDefault();
                    try { await sb.auth.signOut(); } catch (err) { /* ignore */ }
                    location.reload();
                });
            }
            var s = await sb.auth.getSession();
            var session = s && s.data && s.data.session;
            if (!session) { header.setAttribute('data-state', 'out'); return; }
            header.setAttribute('data-state', 'in');
            var r = await route(sb, session);
            var logo = document.getElementById('av-logo');
            if (r && logo) logo.setAttribute('href', r.url);
        } catch (e) { /* leave the header as rendered */ }
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', setupNav);
    else setupNav();

    window.AvakriSession = { client: client, route: route, requireRole: requireRole, redirectIfSignedIn: redirectIfSignedIn, setupNav: setupNav };
})();
