/**
 * /api/auth
 * GET  → validate session, return { ok, email, name, role, mustChangePassword }
 * POST { email, password } → validate credentials, issue 24hr session cookie
 *
 * Env vars: SESSION_SECRET, BLOB_READ_WRITE_TOKEN
 */

const crypto = require('crypto');
const { get } = require('@vercel/blob');

const COOKIE_NAME = 'ops_session';
const TTL_MS      = 24 * 60 * 60 * 1000;
const USERS_KEY   = 'users/users.json';

function hashPw(pw, salt) {
  return crypto.pbkdf2Sync(pw, salt, 100000, 64, 'sha512').toString('hex');
}

function sign(payload, secret) {
  const b64 = Buffer.from(JSON.stringify(payload)).toString('base64');
  const sig  = crypto.createHmac('sha256', secret).update(b64).digest('hex');
  return `${b64}.${sig}`;
}

function verify(token, secret) {
  try {
    const [b64, sig] = token.split('.');
    const expected   = crypto.createHmac('sha256', secret).update(b64).digest('hex');
    const a = Buffer.from(sig, 'hex'), b = Buffer.from(expected, 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const p = JSON.parse(Buffer.from(b64, 'base64').toString());
    return Date.now() <= p.exp ? p : null;
  } catch { return null; }
}

function parseCookies(h = '') {
  return Object.fromEntries(
    h.split(';').map(c => c.trim().split('=')).filter(p => p.length >= 2)
     .map(([k, ...v]) => [k.trim(), v.join('=').trim()])
  );
}

async function getUsers(blobToken) {
  try {
    const result = await get(USERS_KEY, { access: 'private', token: blobToken });
    if (!result || result.statusCode !== 200 || !result.stream) return null;
    const chunks = [];
    const reader = result.stream.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    const text = Buffer.concat(chunks.map(c => Buffer.from(c))).toString('utf8');
    return JSON.parse(text);
  } catch { return null; }
}

module.exports = async function handler(req, res) {
  const secret    = process.env.SESSION_SECRET;
  const blobToken = process.env.BLOB_READ_WRITE_TOKEN;
  res.setHeader('Content-Type', 'application/json');

  if (!secret || !blobToken) return res.status(500).json({ error: 'Server misconfigured.' });

  // GET — validate session
  if (req.method === 'GET') {
    const token = parseCookies(req.headers.cookie || '')[COOKIE_NAME];
    if (token) {
      const p = verify(token, secret);
      if (p) return res.status(200).json({
        ok: true,
        email: p.email,
        name:  p.name,
        role:  p.role,
        mustChangePassword: p.mustChangePassword || false,
      });
    }
    return res.status(401).json({ ok: false });
  }

  // POST — login
  if (req.method === 'POST') {
    const body     = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const { email, password } = body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });

    const data = await getUsers(blobToken);
    if (!data) return res.status(503).json({ error: 'User store not initialised. Run /api/setup first.' });

    const user    = (data.users || []).find(u => u.email.toLowerCase() === email.trim().toLowerCase());
    const salt    = user ? user.salt : 'dummy-salt-prevents-timing-attack-x';
    const testHash = hashPw(password, salt);
    if (!user || testHash !== (user.hash || '')) {
      return res.status(401).json({ error: 'Incorrect email or password.' });
    }

    const token = sign({
      email: user.email,
      name:  user.name,
      role:  user.role,
      mustChangePassword: user.mustChangePassword || false,
      iat: Date.now(),
      exp: Date.now() + TTL_MS,
    }, secret);

    res.setHeader('Set-Cookie', [
      `${COOKIE_NAME}=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Strict',
      `Max-Age=${TTL_MS / 1000}`, 'Secure',
    ].join('; '));

    return res.status(200).json({
      ok: true,
      email: user.email,
      name:  user.name,
      role:  user.role,
      mustChangePassword: user.mustChangePassword || false,
    });
  }

  return res.status(405).json({ error: 'Method not allowed.' });
};
