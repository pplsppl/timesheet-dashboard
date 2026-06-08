/**
 * Vercel Serverless Function: /api/auth
 *
 * POST { password } → sets a signed session cookie valid for 24 hours
 * GET              → validates the current session cookie
 *
 * Env vars required (set in Vercel dashboard):
 *   DASHBOARD_PASSWORD  — the shared password managers enter
 *   SESSION_SECRET      — random string to sign tokens (openssl rand -hex 32)
 */

const crypto = require('crypto');

const COOKIE_NAME = 'ops_session';
const TTL_MS      = 24 * 60 * 60 * 1000;

function sign(payload, secret) {
  const b64 = Buffer.from(JSON.stringify(payload)).toString('base64');
  const sig  = crypto.createHmac('sha256', secret).update(b64).digest('hex');
  return `${b64}.${sig}`;
}

function verify(token, secret) {
  try {
    const [b64, sig] = token.split('.');
    const expected   = crypto.createHmac('sha256', secret).update(b64).digest('hex');
    const sigBuf      = Buffer.from(sig,      'hex');
    const expBuf      = Buffer.from(expected, 'hex');
    if (sigBuf.length !== expBuf.length) return null;
    if (!crypto.timingSafeEqual(sigBuf, expBuf)) return null;
    const payload = JSON.parse(Buffer.from(b64, 'base64').toString());
    return Date.now() <= payload.exp ? payload : null;
  } catch {
    return null;
  }
}

function parseCookies(header = '') {
  return Object.fromEntries(
    header.split(';')
      .map(c => c.trim().split('='))
      .filter(p => p.length >= 2)
      .map(([k, ...v]) => [k.trim(), v.join('=').trim()])
  );
}

module.exports = async function handler(req, res) {
  const secret   = process.env.SESSION_SECRET;
  const password = process.env.DASHBOARD_PASSWORD;

  if (!secret || !password) {
    return res.status(500).json({ error: 'Server misconfigured: missing SESSION_SECRET or DASHBOARD_PASSWORD.' });
  }

  // GET — validate session
  if (req.method === 'GET') {
    const cookies = parseCookies(req.headers.cookie || '');
    const token   = cookies[COOKIE_NAME];
    if (token && verify(token, secret)) {
      return res.status(200).json({ ok: true });
    }
    return res.status(401).json({ ok: false });
  }

  // POST — login
  if (req.method === 'POST') {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});

    if (!body.password || body.password !== password) {
      return res.status(401).json({ error: 'Incorrect password.' });
    }

    const token = sign({ iat: Date.now(), exp: Date.now() + TTL_MS }, secret);
    res.setHeader('Set-Cookie', [
      `${COOKIE_NAME}=${token}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      `Max-Age=${TTL_MS / 1000}`,
      'Secure',
    ].join('; '));

    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: 'Method not allowed.' });
};
