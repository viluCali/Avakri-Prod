export async function onRequestPost(context) {
    const json = (obj, status) => new Response(JSON.stringify(obj), {
        status,
        headers: { 'Content-Type': 'application/json' }
    });

    // Разрешаем только боевые домены, дев-ссылку и example.com (для тестовых ключей)
    const ALLOWED_HOSTS = ['avakri.com', 'www.avakri.com', 'avakri-dev.pages.dev', 'avakri-prod.pages.dev'];

    try {
        const { request, env } = context;
        const formData = await request.formData();

        const email = formData.get('email');
        const token = formData.get('cf-turnstile-response');
        const clientIp = request.headers.get('CF-Connecting-IP');

        // 1. Проверка наличия ключа на сервере
        if (!env.TURNSTILE_SECRET_KEY) {
            console.error('TURNSTILE_SECRET_KEY is not set in environment variables');
            return json({ success: false, error: 'Server error' }, 500);
        }

        // 2. Валидация email (наличие, длина, базовый формат) и наличия токена
        if (!email || email.length > 254 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || !token) {
            return json({ success: false, error: 'Missing or invalid email or captcha' }, 400);
        }

        // 3. Отправка запроса к Turnstile
        const verifyData = new URLSearchParams();
        verifyData.append('secret', env.TURNSTILE_SECRET_KEY);
        verifyData.append('response', token);
        if (clientIp) {
            verifyData.append('remoteip', clientIp);
        }

        const turnstileRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: verifyData.toString()
        });

        const outcome = await turnstileRes.json();

        // 4. Проверка результата капчи и принадлежности хоста (защита от кражи токена с Fabjump)
        if (!outcome.success || !ALLOWED_HOSTS.includes(outcome.hostname)) {
            console.error('Turnstile rejected. Error codes:', outcome['error-codes'], 'Hostname:', outcome.hostname);
            return json({ success: false, error: 'Invalid captcha' }, 403);
        }

        // 5. Отправка данных в Google Form
        const googleFormUrl = 'https://docs.google.com/forms/d/1LM3IdY5Xy3w8C_EWnBxsVx7_4b_GraL1WW9aIUxQvYI/formResponse';
        const googleFormData = new URLSearchParams();
        // Убедись, что 'emailAddress' — это правильный параметр для твоей формы. Иногда это 'entry.123456789'
        googleFormData.append('emailAddress', email);

        const gRes = await fetch(googleFormUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: googleFormData.toString()
        });

        // 6. Проверка, что Google Форма действительно приняла ответ
        if (!gRes.ok) {
            console.error('Google form rejected the submission. Status:', gRes.status);
            return json({ success: false, error: 'Could not save, please try again' }, 502);
        }

        // 7. Сохраняем лид в Supabase (таблица marketing). Ошибка здесь не ломает ответ пользователю.
        if (env.SUPABASE_URL && env.SUPABASE_SECRET_KEY) {
            try {
                const lead = await fetch(`${env.SUPABASE_URL}/rest/v1/marketing?on_conflict=email`, {
                    method: 'POST',
                    headers: {
                        apikey: env.SUPABASE_SECRET_KEY,
                        'Content-Type': 'application/json',
                        Prefer: 'resolution=ignore-duplicates,return=minimal'
                    },
                    body: JSON.stringify({ email: String(email).trim().toLowerCase(), source: 'notify-me' })
                });
                if (!lead.ok) console.error('Marketing insert failed:', lead.status, await lead.text());
            } catch (e) {
                console.error('Marketing insert error:', e);
            }
        }

        return json({ success: true }, 200);

    } catch (err) {
        // 8. Скрываем детали ошибки от пользователя, пишем их только в консоль сервера
        console.error('Form submission error:', err);
        return json({ success: false, error: 'Server error' }, 500);
    }
}
