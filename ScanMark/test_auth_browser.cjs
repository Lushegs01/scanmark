const { test } = require('node:test');
const assert = require('node:assert/strict');
const { authenticate } = require('./static/auth.js');

const reply = (status, data, retry = '3') => ({
    status, json: async () => data, headers: { get: () => retry }
});

test('capacity retries honor Retry-After and retain the same form', async () => {
    let count = 0;
    const waits = [];
    const body = { password: 'only-in-memory' };
    const result = await authenticate('/login', body, {
        signal: new AbortController().signal, random: () => 0.5,
        sleep: async delay => waits.push(delay),
        fetchImpl: async (_url, options) => {
            assert.equal(options.body, body);
            assert.equal(options.headers.Accept, 'application/json');
            return ++count === 1
                ? reply(503, { outcome: 'auth_overloaded' }, '8')
                : reply(200, { outcome: 'success', redirect: '/dashboard' });
        }
    });
    assert.equal(result.outcome, 'success');
    assert.deepEqual(waits, [10500]);
});

test('retries stop at the deadline even if capacity remains exhausted', async () => {
    let clock = 0, calls = 0;
    const result = await authenticate('/signup', {}, {
        signal: new AbortController().signal, now: () => clock, random: () => 0,
        sleep: async delay => { clock += delay; },
        fetchImpl: async () => { calls++; return reply(503, { outcome: 'auth_overloaded' }); }
    });
    assert.ok(calls > 1 && calls <= 12);
    assert.ok(clock < 120000);
    assert.match(result.message, /still busy/);
});

for (const [status, data] of [
    [429, { outcome: 'rate_limited', message: 'Email limit reached.' }],
    [503, { outcome: 'database_busy' }],
    [200, { outcome: 'form_error', messages: ['Invalid email or password.'] }],
    [400, { outcome: 'csrf_expired' }]
]) {
    test(`does not replay ${data.outcome}`, async () => {
        let calls = 0;
        const result = await authenticate('/login', {}, {
            signal: new AbortController().signal,
            fetchImpl: async () => { calls++; return reply(status, { ...data }, '3600'); }
        });
        assert.equal(calls, 1);
        if (status === 429) assert.match(result.message, /3600 seconds/);
    });
}

test('an ambiguous network failure is never retried', async () => {
    let calls = 0;
    await assert.rejects(authenticate('/signup', {}, {
        signal: new AbortController().signal,
        fetchImpl: async () => { calls++; throw new Error('Network lost'); }
    }));
    assert.equal(calls, 1);
});

test('leaving the page stops the next attempt', async () => {
    const controller = new AbortController();
    let calls = 0;
    await assert.rejects(authenticate('/login', {}, {
        signal: controller.signal, random: () => 0,
        sleep: async () => controller.abort(),
        fetchImpl: async () => { calls++; return reply(503, { outcome: 'auth_overloaded' }); }
    }));
    assert.equal(calls, 1);
});
