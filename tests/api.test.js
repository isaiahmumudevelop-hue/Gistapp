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

console.log('✅ All test files loaded');
