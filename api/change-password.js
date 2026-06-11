/**
 * /api/change-password
 * POST { newPassword } → updates password for authenticated user, clears mustChangePassword
 *
 * Env vars: SESSION_SECRET, BLOB_READ_WRITE_TOKEN
 */

const crypto = require('crypto');
const { put, get } = require('@vercel/blob');

const COOKIE_NAME = 'ops_session';
const USERS_KEY   = 'users/users.json';
const TTL_MS      = 24 * 60 * 60 * 1000;

function hashPw(pw, salt) {
  return crypto.pbkdf2Sync(pw, salt, 100000, 64, 'sha512').toString('hex');
}
function generateSalt() { return crypto.randomBytes(32).toString('hex'); }

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

async function readUsers(blobToken) {
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
async function writeUsers(data, blobToken) {
  await put(USERS_KEY, JSON.stringify({ ...data, updatedAt: new Date().toISOString() }), {
    access: 'private', allowOverwrite: true, contentType: 'application/json', token: blobToken,
  });
}

module.exports = async function handler(req, res) {
  const secret    = process.env.SESSION_SECRET;
  const blobToken = process.env.BLOB_READ_WRITE_TOKEN;
  res.setHeader('Content-Type', 'application/json');

  if (!secret || !blobToken) return res.status(500).json({ error: 'Server misconfigured.' });
  if (req.method !== 'POST')  return res.status(405).json({ error: 'Method not allowed.' });

  const token   = parseCookies(req.headers.cookie || '')[COOKIE_NAME];
  const session = token ? verify(token, secret) : null;
  if (!session) return res.status(401).json({ error: 'Unauthorized.' });

  const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
  const { newPassword } = body;
  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  const data = await readUsers(blobToken);
  if (!data) return res.status(503).json({ error: 'User store unavailable.' });

  const idx = (data.users || []).findIndex(u => u.email.toLowerCase() === session.email.toLowerCase());
  if (idx === -1) return res.status(404).json({ error: 'User not found.' });

  const salt = generateSalt();
  data.users[idx] = { ...data.users[idx], salt, hash: hashPw(newPassword, salt), mustChangePassword: false };
  await writeUsers(data, blobToken);

  // Re-issue session cookie without mustChangePassword flag
  const newToken = sign({
    email: session.email,
    name:  session.name,
    role:  session.role,
    mustChangePassword: false,
    iat: Date.now(),
    exp: Date.now() + TTL_MS,
  }, secret);

  res.setHeader('Set-Cookie', [
    `${COOKIE_NAME}=${newToken}`, 'Path=/', 'HttpOnly', 'SameSite=Strict',
    `Max-Age=${TTL_MS / 1000}`, 'Secure',
  ].join('; '));

  return res.status(200).json({ ok: true });
};
