/**
 * /api/users
 * GET              → list all users (admin only)
 * POST { email, name, role } → add user, returns tempPassword (admin only)
 * DELETE ?email=…  → remove user (admin only, can't remove self or last admin)
 *
 * Env vars: SESSION_SECRET, BLOB_READ_WRITE_TOKEN
 */

const crypto = require('crypto');
const { list, put } = require('@vercel/blob');

const COOKIE_NAME = 'ops_session';
const USERS_KEY   = 'users/users.json';

function hashPw(pw, salt) {
  return crypto.pbkdf2Sync(pw, salt, 100000, 64, 'sha512').toString('hex');
}
function generateSalt() { return crypto.randomBytes(32).toString('hex'); }
function generateTempPassword() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  return 'GM-' + Array.from({ length: 6 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
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
function getSession(req, secret) {
  const token = parseCookies(req.headers.cookie || '')[COOKIE_NAME];
  return token ? verify(token, secret) : null;
}

async function readUsers(blobToken) {
  try {
    const { blobs } = await list({ prefix: USERS_KEY, token: blobToken });
    const blob = blobs.find(b => b.pathname === USERS_KEY);
    if (!blob) return null;
    const r = await fetch(blob.url);
    if (!r.ok) return null;
    return r.json();
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
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (!secret || !blobToken) return res.status(500).json({ error: 'Server misconfigured.' });

  const session = getSession(req, secret);
  if (!session)               return res.status(401).json({ error: 'Unauthorized.' });
  if (session.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' });

  const data = await readUsers(blobToken);
  if (!data) return res.status(503).json({ error: 'User store unavailable.' });

  // GET — list users
  if (req.method === 'GET') {
    const users = (data.users || []).map(({ email, name, role, mustChangePassword, createdAt }) => ({
      email, name, role, mustChangePassword, createdAt,
    }));
    return res.status(200).json({ users });
  }

  // POST — add user
  if (req.method === 'POST') {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const { email, name, role } = body;
    if (!email || !role)                           return res.status(400).json({ error: 'Email and role required.' });
    if (!['admin', 'user'].includes(role))         return res.status(400).json({ error: 'Role must be admin or user.' });
    if ((data.users || []).find(u => u.email.toLowerCase() === email.trim().toLowerCase())) {
      return res.status(409).json({ error: 'A user with that email already exists.' });
    }

    const tempPassword = generateTempPassword();
    const salt         = generateSalt();
    data.users = [...(data.users || []), {
      email: email.trim().toLowerCase(),
      name:  (name || email).trim(),
      role,
      salt,
      hash: hashPw(tempPassword, salt),
      mustChangePassword: true,
      createdAt: new Date().toISOString(),
    }];
    await writeUsers(data, blobToken);
    return res.status(201).json({ ok: true, tempPassword });
  }

  // DELETE — remove user
  if (req.method === 'DELETE') {
    const emailToRemove = (req.query || {}).email;
    if (!emailToRemove) return res.status(400).json({ error: 'email query param required.' });

    if (emailToRemove.toLowerCase() === session.email.toLowerCase()) {
      return res.status(400).json({ error: 'You cannot remove your own account.' });
    }
    const users  = data.users || [];
    const target = users.find(u => u.email.toLowerCase() === emailToRemove.toLowerCase());
    if (!target) return res.status(404).json({ error: 'User not found.' });

    const adminCount = users.filter(u => u.role === 'admin').length;
    if (target.role === 'admin' && adminCount <= 1) {
      return res.status(400).json({ error: 'Cannot remove the last admin.' });
    }

    data.users = users.filter(u => u.email.toLowerCase() !== emailToRemove.toLowerCase());
    await writeUsers(data, blobToken);
    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: 'Method not allowed.' });
};
