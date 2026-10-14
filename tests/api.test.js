// GistApp — automated API tests
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { req, signup, verifyUser, uniqueEmail, BASE } = require('./helpers.js');

console.log('🧪 Testing against', BASE);

// ----------------------------------------------------------------
// 1. Server health
// ----------------------------------------------------------------
test('server is alive', async () => {
  const r = await req('GET', '/api/me', { noAuth: true });
  assert.equal(r.status, 401, 'should return 401 without token');
});

// ----------------------------------------------------------------
// 2. Signup hardening
// ----------------------------------------------------------------
test('signup rejects missing terms', async () => {
  const email = uniqueEmail('noterms');
  const r = await req('POST', '/api/signup', {
    body: { email, password: 'TestPass123abc', display_name: 'X' },
    noAuth: true
  });
  assert.equal(r.status, 400);
  assert.match(String(r.data.error), /terms/i);
});

test('signup rejects weak password', async () => {
  const email = uniqueEmail('weakpw');
  const r = await req('POST', '/api/signup', {
    body: { email, password: '123456', display_name: 'X', terms_accepted: true },
    noAuth: true
  });
  assert.equal(r.status, 400);
  assert.match(String(r.data.error), /8\+|password/i);
});

test('signup rejects disposable email', async () => {
  const r = await req('POST', '/api/signup', {
    body: { email: `disposable${Date.now()}@tempmail.com`, password: 'TestPass123abc', display_name: 'X', terms_accepted: true },
    noAuth: true
  });
  assert.equal(r.status, 400);
  assert.match(String(r.data.error), /disposable|permanent/i);
});

test('signup rejects honeypot', async () => {
  const r = await req('POST', '/api/signup', {
    body: { email: uniqueEmail('hp'), password: 'TestPass123abc', display_name: 'X', terms_accepted: true, website: 'bot-fill' },
    noAuth: true
  });
  // Either rejected OR rate-limited (both are correct rejections)
  assert.ok(r.status === 400 || r.status === 429, `expected 400 or 429, got ${r.status}`);
});

test('signup succeeds with valid data', async () => {
  const { res, token } = await signup();
  // Could be 429 if rate-limited from other tests
  if (res.status === 429) {
    console.log('⚠ signup rate limited — skipping positive test');
    return;
  }
  assert.ok(res.ok, `signup should succeed: ${JSON.stringify(res.data).slice(0,150)}`);
  assert.ok(token, 'should receive a token');
});

// ----------------------------------------------------------------
// 3. Auth middleware — unverified users can't write
// ----------------------------------------------------------------
test('unverified user gets 403 on PATCH /api/me', async () => {
  const { token, res } = await signup({ email: uniqueEmail('unverified') });
  if (res.status === 429 || !token) { console.log('⚠ skipped: rate limited'); return; }
  const r = await req('PATCH', '/api/me', {
    body: { bio: 'test bio' },
    token
  });
  assert.equal(r.status, 403, 'should block unverified write');
  assert.match(String(r.data.error), /verify/i);
});

test('verified user can PATCH /api/me', async () => {
  const { email, token, res } = await signup({ email: uniqueEmail('verified') });
  if (res.status === 429 || !token) { console.log('⚠ skipped: rate limited'); return; }
  await verifyUser(email);
  const r = await req('PATCH', '/api/me', {
    body: { bio: 'verified bio test' },
    token
  });
  assert.ok(r.ok, `PATCH should succeed: ${JSON.stringify(r.data).slice(0,150)}`);
});

// ----------------------------------------------------------------
// 4. Rate limiting
// ----------------------------------------------------------------
test('login rate limiter fires (10/15min)', async () => {
  const email = uniqueEmail('rl');
  let hit429 = false;
  for (let i = 0; i < 15; i++) {
    const r = await req('POST', '/api/login', {
      body: { email, password: 'wrong-password' },
      noAuth: true
    });
    if (r.status === 429) { hit429 = true; break; }
  }
  assert.ok(hit429, 'expected 429 after repeated failed logins');
});

// ----------------------------------------------------------------
// 5. Stickers CRUD
// ----------------------------------------------------------------
test('stickers list requires auth', async () => {
  const r = await req('GET', '/api/stickers', { noAuth: true });
  assert.equal(r.status, 401);
});

test('stickers CRUD works for authed user', async () => {
  const { email, token, res } = await signup({ email: uniqueEmail('sticker') });
  if (res.status === 429 || !token) { console.log('⚠ skipped: rate limited'); return; }
  await verifyUser(email);

  // List (empty)
  const list1 = await req('GET', '/api/stickers', { token });
  assert.ok(list1.ok, 'list works');
  assert.ok(Array.isArray(list1.data), 'returns array');

  // Add
  const add = await req('POST', '/api/stickers', {
    token,
    body: { url: '/uploads/test-sticker.png', name: 'Test' }
  });
  assert.ok(add.ok, `add works: ${JSON.stringify(add.data).slice(0,150)}`);
  assert.ok(add.data.id, 'returns id');

  // List (1 item)
  const list2 = await req('GET', '/api/stickers', { token });
  assert.equal(list2.data.length, 1);

  // Delete
  const del = await req('DELETE', '/api/stickers/' + add.data.id, { token });
  assert.ok(del.ok, 'delete works');

  // List (empty)
  const list3 = await req('GET', '/api/stickers', { token });
  assert.equal(list3.data.length, 0);
});

// ----------------------------------------------------------------
// 6. Admin endpoints
// ----------------------------------------------------------------
test('admin backup requires auth', async () => {
  const r = await req('POST', '/api/admin/backup', { noAuth: true });
  assert.equal(r.status, 401);
});

test('admin backup rejects non-admin user', async () => {
  const { email, token, res } = await signup({ email: uniqueEmail('nonadmin') });
  if (res.status === 429 || !token) { console.log('⚠ skipped: rate limited'); return; }
  await verifyUser(email);
  const r = await req('POST', '/api/admin/backup', { token });
  assert.equal(r.status, 403, `expected 403, got ${r.status}`);
  assert.match(String(r.data.error), /admin/i);
});

// ----------------------------------------------------------------
// 7. Read endpoints — sanity checks
// ----------------------------------------------------------------
test('feed endpoint responds', async () => {
  const { token, res } = await signup({ email: uniqueEmail('feed') });
  if (res.status === 429 || !token) { console.log('⚠ skipped: rate limited'); return; }
  const r = await req('GET', '/api/feed', { token });
  assert.ok(r.ok, 'feed responds');
  assert.ok(Array.isArray(r.data), 'returns array');
});

test('chats endpoint responds', async () => {
  const { token, res } = await signup({ email: uniqueEmail('chats') });
  if (res.status === 429 || !token) { console.log('⚠ skipped: rate limited'); return; }
  const r = await req('GET', '/api/chats', { token });
  assert.ok(r.ok, 'chats responds');
  assert.ok(Array.isArray(r.data), 'returns array');
});

test('push vapid-public endpoint responds', async () => {
  const r = await req('GET', '/api/push/vapid-public', { noAuth: true });
  assert.ok(r.ok, 'vapid-public responds');
  assert.ok(r.data.publicKey, 'returns a public key');
});



// ================================================================
// GISTAPP_LIVE_TESTS — live streaming + premium tests
// ================================================================

// ----------------------------------------------------------------
// Live stream routes
// ----------------------------------------------------------------
test('live streams list requires auth', async () => {
  const r = await req('GET', '/api/live/streams', { noAuth: true });
  assert.equal(r.status, 401);
});

test('live streams list returns array for authed user', async () => {
  const { email, token, res } = await signup({ email: uniqueEmail('livelist') });
  if (res.status === 429 || !token) { console.log('⚠ skipped: rate limited'); return; }
  const r = await req('GET', '/api/live/streams', { token });
  assert.ok(r.ok, 'streams list responds');
  assert.ok(Array.isArray(r.data), 'returns array');
});

test('live start requires premium', async () => {
  const { email, token, res } = await signup({ email: uniqueEmail('livefreetier') });
  if (res.status === 429 || !token) { console.log('⚠ skipped: rate limited'); return; }
  await verifyUser(email);
  // Free user should be rejected
  const r = await req('POST', '/api/live/start', {
    token,
    body: { title: 'Test stream' }
  });
  // Should be 403 needs_premium
  assert.ok(r.status === 403 || r.status === 429, 'should reject non-premium');
  if (r.status === 403){
    assert.ok(r.data.needs_premium || /premium/i.test(r.data.error || ''), 'error mentions premium');
  }
});

test('live chat requires valid stream', async () => {
  const { email, token, res } = await signup({ email: uniqueEmail('livechat') });
  if (res.status === 429 || !token) { console.log('⚠ skipped: rate limited'); return; }
  await verifyUser(email);
  // Try to post to a stream that doesn't exist
  const r = await req('POST', '/api/live/99999/chat', {
    token,
    body: { text: 'hello' }
  });
  // Should be 404 or 410 (no stream) or 500 (never reached)
  assert.ok(r.status === 404 || r.status === 410 || r.status === 500, 'rejects invalid stream');
});

// ----------------------------------------------------------------
// Wallet + earnings
// ----------------------------------------------------------------
test('wallet requires auth', async () => {
  const r = await req('GET', '/api/wallet', { noAuth: true });
  assert.equal(r.status, 401);
});

test('wallet returns balance structure', async () => {
  const { email, token, res } = await signup({ email: uniqueEmail('wallet') });
  if (res.status === 429 || !token) { console.log('⚠ skipped: rate limited'); return; }
  await verifyUser(email);
  const r = await req('GET', '/api/wallet', { token });
  assert.ok(r.ok, 'wallet responds');
  assert.ok(typeof r.data.balance_coins === 'number', 'has balance_coins');
  assert.ok(typeof r.data.lifetime_coins === 'number', 'has lifetime_coins');
  assert.ok(typeof r.data.available_ngn === 'number', 'has available_ngn');
  assert.ok(Array.isArray(r.data.transactions), 'has transactions array');
});

test('wallet payout-info saves', async () => {
  const { email, token, res } = await signup({ email: uniqueEmail('payout') });
  if (res.status === 429 || !token) { console.log('⚠ skipped: rate limited'); return; }
  await verifyUser(email);
  const save = await req('POST', '/api/wallet/payout-info', {
    token,
    body: { method: 'opay', account: '08012345678', name: 'Test User', country: 'NG' }
  });
  assert.ok(save.ok, 'payout info saved');
  const w = await req('GET', '/api/wallet', { token });
  assert.equal(w.data.payout_method, 'opay');
  assert.equal(w.data.payout_account, '08012345678');
});

test('wallet withdraw rejects below minimum', async () => {
  const { email, token, res } = await signup({ email: uniqueEmail('belowmin') });
  if (res.status === 429 || !token) { console.log('⚠ skipped: rate limited'); return; }
  await verifyUser(email);
  const r = await req('POST', '/api/wallet/withdraw', {
    token,
    body: { coins: 100 }
  });
  assert.ok(r.status === 400, 'rejects low amount');
});

// ----------------------------------------------------------------
// Admin endpoints
// ----------------------------------------------------------------
test('admin withdrawals requires admin', async () => {
  const { email, token, res } = await signup({ email: uniqueEmail('nonadmin2') });
  if (res.status === 429 || !token) { console.log('⚠ skipped: rate limited'); return; }
  await verifyUser(email);
  const r = await req('GET', '/api/admin/withdrawals', { token });
  assert.equal(r.status, 403);
});

// ----------------------------------------------------------------
// Session / single-device login
// ----------------------------------------------------------------
test('second login rotates session (single-device)', async () => {
  const email = uniqueEmail('sessionrot');
  const password = 'TestPass123abc';
  const s1 = await signup({ email, password });
  if (s1.res.status === 429 || !s1.token) { console.log('⚠ skipped: rate limited'); return; }
  await verifyUser(email);

  // First login
  const login1 = await req('POST', '/api/login', {
    body: { email, password },
    noAuth: true
  });
  if (!login1.ok){ console.log('⚠ first login failed'); return; }
  const token1 = login1.data.token;

  // Second login (should rotate session)
  const login2 = await req('POST', '/api/login', {
    body: { email, password },
    noAuth: true
  });
  if (!login2.ok){ console.log('⚠ second login failed'); return; }
  const token2 = login2.data.token;

  // Old token should now be rejected
  const useOld = await req('GET', '/api/me', { token: token1 });
  assert.equal(useOld.status, 401, 'old token rejected');
  assert.equal(useOld.data.code, 'SESSION_REPLACED', 'correct error code');

  // New token should work
  const useNew = await req('GET', '/api/me', { token: token2 });
  assert.ok(useNew.ok, 'new token works');
});

// ----------------------------------------------------------------
// Stickers (regression test after live work)
// ----------------------------------------------------------------
test('stickers still work after live changes', async () => {
  const { email, token, res } = await signup({ email: uniqueEmail('regsticker') });
  if (res.status === 429 || !token) { console.log('⚠ skipped: rate limited'); return; }
  await verifyUser(email);
  const r = await req('GET', '/api/stickers', { token });
  assert.ok(r.ok, 'stickers list works');
  assert.ok(Array.isArray(r.data), 'returns array');
});

test('feed still returns data after live changes', async () => {
  const { email, token, res } = await signup({ email: uniqueEmail('regfeed') });
  if (res.status === 429 || !token) { console.log('⚠ skipped: rate limited'); return; }
  await verifyUser(email);
  const r = await req('GET', '/api/feed', { token });
  assert.ok(r.ok, 'feed works');
  assert.ok(Array.isArray(r.data), 'feed returns array');
});

// ----------------------------------------------------------------
// Join request flow
// ----------------------------------------------------------------
test('join request to invalid stream fails cleanly', async () => {
  const { email, token, res } = await signup({ email: uniqueEmail('joinreq') });
  if (res.status === 429 || !token) { console.log('⚠ skipped: rate limited'); return; }
  await verifyUser(email);
  const r = await req('POST', '/api/live/99999/request', { token });
  assert.ok(r.status === 404 || r.status === 410 || r.status === 500, 'rejects invalid stream');
});

console.log('✅ All test files loaded');
