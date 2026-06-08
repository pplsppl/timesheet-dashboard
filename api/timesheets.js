/**
 * Vercel Serverless Function: /api/timesheets
 *
 * Validates session cookie, then proxies Rippling REST API.
 * Strictly filters to the four Operations sub-departments.
 *
 * Env vars required:
 *   RIPPLING_API_KEY   — Rippling REST API key
 *   SESSION_SECRET     — must match auth.js
 */

const crypto = require('crypto');

const BASE        = 'https://rest.ripplingapis.com';
const COOKIE_NAME = 'ops_session';
const OPS_SUBDEPTS = ['Care Coordinators', 'Licensing', 'Billing & RCM', 'Credentialing'];

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
    const sigBuf      = Buffer.from(sig,      'hex');
    const expBuf      = Buffer.from(expected, 'hex');
    if (sigBuf.length !== expBuf.length) return false;
    if (!crypto.timingSafeEqual(sigBuf, expBuf)) return false;
    const payload = JSON.parse(Buffer.from(b64, 'base64').toString());
    return Date.now() <= payload.exp;
  } catch {
    return false;
  }
}

async function fetchAllPages(url, apiKey) {
  const results = [];
  let next = url;
  while (next) {
    const r = await fetch(next, {
      headers: { Authorization: `Bearer ${apiKey}`, Accept: 'application/json' },
    });
    if (!r.ok) {
      const body = await r.text().catch(() => '');
      throw new Error(`Rippling ${r.status}: ${body.slice(0, 300)}`);
    }
    const data = await r.json();
    results.push(...(Array.isArray(data) ? data : (data.results || [])));
    next = data.next_link || null;
  }
  return results;
}

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const secret = process.env.SESSION_SECRET;
  const apiKey = process.env.RIPPLING_API_KEY;

  if (!secret || !apiKey) {
    return res.status(500).json({ error: 'Server misconfigured.' });
  }

  if (!verifySession(req.headers.cookie, secret)) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }

  const { endpoint, startDate, endDate } = req.query || {};

  try {
    if (endpoint === 'workers') {
      const all = await fetchAllPages(`${BASE}/workers?expand=user,department`, apiKey);
      const ops = all.filter(w =>
        w.status === 'ACTIVE' && OPS_SUBDEPTS.includes(w.department?.name || '')
      );
      return res.status(200).json({ results: ops });

    } else {
      if (!startDate || !endDate) {
        return res.status(400).json({ error: 'startDate and endDate are required.' });
      }
      const filter = encodeURIComponent(
        `start_time ge ${startDate}T00:00:00 and start_time le ${endDate}T23:59:59`
      );
      const all = await fetchAllPages(`${BASE}/time-entries?filter=${filter}`, apiKey);
      return res.status(200).json({ results: all });
    }
  } catch (err) {
    console.error('[timesheets]', err.message);
    return res.status(502).json({ error: err.message });
  }
};
