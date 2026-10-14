// Shared test helpers
const BASE = process.env.TEST_BASE || 'http://localhost:4000';

let _counter = 0;
function uniqueEmail(prefix = 'test') {
  _counter++;
  return `${prefix}${Date.now()}-${_counter}@gmail.com`;
}

async function req(method, path, { body, token, noAuth = false } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token && !noAuth) headers.Authorization = 'Bearer ' + token;
  try {
    const r = await fetch(BASE + path, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined
    });
    const text = await r.text();
    let data = null;
    try { data = JSON.parse(text); } catch (_) { data = text.slice(0, 200); }
    return { ok: r.ok, status: r.status, data };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

async function signup(overrides = {}) {
  const email = overrides.email || uniqueEmail('auto');
  const payload = {
    email,
    password: 'TestPass123abc',
    display_name: 'Auto Test',
    terms_accepted: true,
    ...overrides
  };
  const r = await req('POST', '/api/signup', { body: payload, noAuth: true });
  return { email, res: r, token: r.data && r.data.token, userId: r.data && r.data.user && r.data.user.id };
}

// Directly mark a user as verified in the DB (test-only helper)
async function verifyUser(email) {
  const pool = require('../db.js');
  await pool.query('UPDATE users SET verified=true WHERE LOWER(email)=$1', [email.toLowerCase()]);
  return true;
}

module.exports = { BASE, req, signup, verifyUser, uniqueEmail };
