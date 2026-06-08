/**
 * Vercel Serverless Function: /api/timesheets
 *
 * Validates session cookie, then proxies Rippling REST API.
 * Strictly filters to Care Coordinators sub-department only.
 * Fetches workers, managers, time entries, AND time off entries.
 *
 * Env vars required:
 *   RIPPLING_API_KEY   — Rippling REST API key
 *   SESSION_SECRET     — must match auth.js
 */

const crypto = require('crypto');

const BASE        = 'https://rest.ripplingapis.com';
const COOKIE_NAME = 'ops_session';
const TARGET_DEPT = 'Care Coordinators';

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

async function fetchAllPages(url, apiKey) {
  const results = [];
  let next = url;
  while (next) {
    const r = await fetch(next, {
      headers: { Authorization: `Bearer ${apiKey}`, Accept: 'application/json' },
    });
    if (!r.ok) {
      const body = await r.text().catch(() => '');
      throw new Error(`Rippling ${r.status} (${url}): ${body.slice(0, 200)}`);
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
  if (!secret || !apiKey) return res.status(500).json({ error: 'Server misconfigured.' });
  if (!verifySession(req.headers.cookie, secret)) return res.status(401).json({ error: 'Unauthorized.' });

  const { endpoint, startDate, endDate } = req.query || {};

  try {
    if (endpoint === 'workers') {
      // Fetch all active workers with user + department expanded
      const all = await fetchAllPages(`${BASE}/workers?expand=user,department`, apiKey);

      // Filter to Care Coordinators only
      const careCoords = all.filter(w =>
        w.status === 'ACTIVE' && (w.department?.name || '') === TARGET_DEPT
      );

      // Collect unique manager IDs from Care Coordinator workers
      const managerIds = [...new Set(careCoords.map(w => w.manager_id).filter(Boolean))];

      // Fetch manager details (name) for each manager ID
      // Managers may not be in Care Coordinators themselves, so fetch individually
      const managerMap = {};
      await Promise.all(managerIds.map(async (mid) => {
        try {
          const r = await fetch(`${BASE}/workers/${mid}?expand=user`, {
            headers: { Authorization: `Bearer ${apiKey}`, Accept: 'application/json' },
          });
          if (r.ok) {
            const m = await r.json();
            const u = m.user || {};
            const name = [u.first_name || '', u.last_name || ''].filter(Boolean).join(' ')
              || m.work_email || mid;
            managerMap[mid] = { id: mid, name };
          }
        } catch { /* skip if individual fetch fails */ }
      }));

      return res.status(200).json({ results: careCoords, managers: managerMap });

    } else if (endpoint === 'timeoff') {
      // Time off entries — separate endpoint from time entries
      if (!startDate || !endDate) return res.status(400).json({ error: 'startDate and endDate required.' });

      const filter = encodeURIComponent(
        `start_time ge ${startDate}T00:00:00 and start_time le ${endDate}T23:59:59`
      );

      // Try known time-off endpoint variants
      let results = [];
      const endpoints = [
        `${BASE}/time-off-entries?filter=${filter}`,
        `${BASE}/time-off-requests?filter=${filter}`,
        `${BASE}/leave-requests?filter=${filter}`,
      ];

      for (const url of endpoints) {
        try {
          const r = await fetch(url, {
            headers: { Authorization: `Bearer ${apiKey}`, Accept: 'application/json' },
          });
          if (r.ok) {
            const data = await r.json();
            const page = Array.isArray(data) ? data : (data.results || []);
            if (page.length >= 0) { // endpoint exists even if empty
              results = page;
              // paginate if needed
              let next = data.next_link || null;
              while (next) {
                const nr = await fetch(next, { headers: { Authorization: `Bearer ${apiKey}` } });
                if (!nr.ok) break;
                const nd = await nr.json();
                results.push(...(Array.isArray(nd) ? nd : (nd.results || [])));
                next = nd.next_link || null;
              }
              break; // found working endpoint
            }
          }
        } catch { continue; }
      }

      return res.status(200).json({ results });

    } else {
      // Time entries
      if (!startDate || !endDate) return res.status(400).json({ error: 'startDate and endDate required.' });
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
