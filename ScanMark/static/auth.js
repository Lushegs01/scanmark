/* Keep credentials only in this page's memory. Only retry a response that
 * explicitly says password processing never started, never a lost response. */
'use strict';

function authSleep(ms, signal) {
    return new Promise((resolve, reject) => {
        if (signal.aborted) { reject(new Error('Aborted')); return; }
        const abort = () => {
            clearTimeout(timer);
            reject(new Error('Aborted'));
        };
        const timer = setTimeout(() => {
            signal.removeEventListener('abort', abort);
            resolve();
        }, ms);
        signal.addEventListener('abort', abort, { once: true });
    });
}

async function authenticate(url, body, {
    signal, onWait = () => {}, fetchImpl = fetch, sleep = authSleep,
    now = Date.now, random = Math.random
}) {
    const deadline = now() + 120000;
    for (let attempt = 0; attempt < 12; attempt++) {
        if (signal.aborted) throw new Error('Aborted');
        const response = await fetchImpl(url, {
            method: 'POST', body, signal, credentials: 'same-origin',
            headers: { Accept: 'application/json' }
        });
        const data = await response.json().catch(() => ({
            message: 'Unable to complete this request. Please reload the page and try again.'
        }));
        if (response.status !== 503 || data.outcome !== 'auth_overloaded') {
            if (response.status === 429) {
                const seconds = Math.max(1, Number(response.headers.get('Retry-After')) || 1);
                data.message = `Please wait ${seconds} seconds before trying again. ${data.message || ''}`;
            }
            return data;
        }
        const minimum = Math.max(1, Number(response.headers.get('Retry-After')) || 3);
        // Never shorten Retry-After. Jitter spreads a cohort's next attempt.
        const delay = (Math.max(minimum, Math.min(20, 3 * 2 ** attempt)) + random() * 5) * 1000;
        if (attempt === 11 || now() + delay >= deadline) break;
        onWait(Math.ceil(delay / 1000));
        await sleep(delay, signal);
    }
    return { message: 'The service is still busy. Your details are still in the form; please try again shortly.' };
}

if (typeof document !== 'undefined') {
    document.querySelectorAll('[data-auth-form]').forEach(form => {
        let pending = false;
        form.addEventListener('submit', async event => {
            event.preventDefault();
            if (pending) return;
            pending = true;
            const body = new FormData(form);
            const controls = Array.from(form.elements).map(element => [element, element.disabled]);
            controls.forEach(([element]) => { element.disabled = true; });
            const status = form.querySelector('[data-auth-status]');
            const show = message => { status.hidden = false; status.textContent = message; };
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 120000);
            const leave = () => controller.abort();
            window.addEventListener('pagehide', leave, { once: true });
            form.setAttribute('aria-busy', 'true');
            show('Submitting…');
            try {
                const data = await authenticate(form.action, body, {
                    signal: controller.signal,
                    onWait: seconds => show(`The service is busy. Retrying in ${seconds} seconds; please keep this page open.`)
                });
                if (data.outcome === 'success' && data.redirect) {
                    const target = new URL(data.redirect, window.location.href);
                    if (target.origin !== window.location.origin) throw new Error('Invalid redirect');
                    window.location.assign(target.href);
                    return;
                }
                show(data.messages?.join(' ') || data.message || 'Please check your details and try again.');
                const verification = document.querySelector('[data-auth-verification]');
                if (verification) {
                    verification.hidden = !data.unverified_email;
                    verification.querySelector('[name=email]').value = data.unverified_email || '';
                }
            } catch (_error) {
                // The server might already have committed a signup. Replaying
                // an ambiguous network failure would risk duplicate side effects.
                show('We could not confirm the result. If you were creating an account, try signing in. Otherwise, please try again.');
            } finally {
                clearTimeout(timeout);
                window.removeEventListener('pagehide', leave);
                controls.forEach(([element, disabled]) => { element.disabled = disabled; });
                form.removeAttribute('aria-busy');
                pending = false;
            }
        });
    });
}

if (typeof module !== 'undefined') module.exports = { authenticate };
