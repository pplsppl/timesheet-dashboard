/**
 * Vercel Serverless Function: /api/approve
 *
 * POST { entryId, workerId } → PATCHes Rippling time entry status to APPROVED
 * Requires valid session cookie.
 *
 * Env vars required:
 *   RIPPLING_API_KEY  — needs time_tracking:read-write scope
 *   SESSION_SECRET    — must match auth.js
 */

const crypto = require('crypto');

const BASE        = 'https://rest.ripplingapis.com';
const COOKIE_NAME = 'ops_session';

function parseCookies(header = '') {
  return Object.fromEntries(
    header.split(';')
      .map(c => c.trim().split('='))
      .filter(p => p.length >= 2)
      .map(([k, ...v]) => [k.trim(), v.join('=').trim()])
  );
}

function verifySession(cookieHeader, secret) {
  try {
    const token = parseCookies(cookieHeader || '')[COOKIE_NAME];
    if (!token) return false;
    const [b64, sig] = token.split('.');
    const expected   = crypto.createHmac('sha256', secret).update(b64).digest('hex');
    const sigBuf     = Buffer.from(sig,      'hex');
    const expBuf     = Buffer.from(expected, 'hex');
    if (sigBuf.length !== expBuf.length) return false;
    if (!crypto.timingSafeEqual(sigBuf, expBuf)) return false;
    const payload = JSON.parse(Buffer.from(b64, 'base64').toString());
    return Date.now() <= payload.exp;
  } catch { return false; }
}

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  const secret = process.env.SESSION_SECRET;
  const apiKey = process.env.RIPPLING_API_KEY;
  if (!secret || !apiKey) return res.status(500).json({ error: 'Server misconfigured.' });
  if (!verifySession(req.headers.cookie, secret)) return res.status(401).json({ error: 'Unauthorized.' });

  const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
  const { entryId, workerId } = body;

  if (!entryId || !workerId) {
    return res.status(400).json({ error: 'entryId and workerId are required.' });
  }

  try {
    const r = await fetch(`${BASE}/time-entries/${entryId}`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        worker_id: workerId,
        status: 'APPROVED',
      }),
    });

    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      return res.status(r.status).json({ error: err.detail || err.message || `Rippling ${r.status}` });
    }

    const data = await r.json();
    return res.status(200).json({ ok: true, status: data.status });

  } catch (err) {
    console.error('[approve]', err.message);
    return res.status(502).json({ error: err.message });
  }
};
