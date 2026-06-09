/**
 * Vercel Serverless Function: /api/timesheets
 *
 * Reads from Vercel Blob cache (written by /api/cron).
 * Falls back to live Rippling fetch if cache is missing.
 * All requests require a valid session cookie.
 *
 * Env vars required:
 *   SESSION_SECRET        — must match auth.js
 *   RIPPLING_API_KEY      — used only for cache-miss fallback
 *   BLOB_READ_WRITE_TOKEN — Vercel Blob token
 */

const crypto   = require('crypto');
const { list, put, get } = require('@vercel/blob');

const BASE        = 'https://rest.ripplingapis.com';
const COOKIE_NAME = 'ops_session';
const TARGET_DEPT = 'Care Coordinators';

// If cache is older than this, we still serve it but trigger a background refresh
const STALE_MS = 5 * 60 * 1000; // 5 minutes

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

async function readBlob(filename) {
  try {
    const response = await get(filename, {
      access: 'private',
      token: process.env.BLOB_READ_WRITE_TOKEN,
    });
    if (!response || !response.stream) return null;
    const chunks = [];
    const reader = response.stream.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    const text = Buffer.concat(chunks.map(c => Buffer.from(c))).toString('utf8');
    return JSON.parse(text);
  } catch { return null; }
}

async function fetchAllPages(url, apiKey) {
  const results = [];
  let next = url;
  while (next) {
    const r = await fetch(next, {
      headers: { Authorization: `Bearer ${apiKey}`, Accept: 'application/json' },
    });
    if (!r.ok) throw new Error(`Rippling ${r.status}`);
    const data = await r.json();
    results.push(...(Array.isArray(data) ? data : (data.results || [])));
    next = data.next_link || null;
  }
  return results;
}

function getWeekStart(startDate, endDate, apiKey) {
  // Live fallback for a single week
  return Promise.all([
    fetchAllPages(
      `${BASE}/time-entries?filter=${encodeURIComponent(`start_time ge ${startDate}T00:00:00 and start_time le ${endDate}T23:59:59`)}`,
      apiKey
    ),
    fetchAllPages(`${BASE}/leave-requests`, apiKey),
    fetchAllPages(`${BASE}/leave-types`, apiKey),
  ]);
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
      // Try cache first
      const cached = await readBlob('cache/workers.json');
      if (cached) {
        const age = cached.cachedAt ? Date.now() - new Date(cached.cachedAt).getTime() : Infinity;
        // Return cache immediately — always fast
        return res.status(200).json({
          results:  cached.results,
          managers: cached.managers,
          cachedAt: cached.cachedAt,
          fromCache: true,
          stale: age > STALE_MS,
        });
      }

      // Cache miss — fetch live
      const allWorkers = await fetchAllPages(`${BASE}/workers?expand=user,department`, apiKey);
      const careCoords = allWorkers.filter(w =>
        w.status === 'ACTIVE' && (w.department?.name || '') === TARGET_DEPT
      );
      const managerIds = [...new Set(careCoords.map(w => w.manager_id).filter(Boolean))];
      const managerMap = {};
      await Promise.all(managerIds.map(async (mid) => {
        try {
          const r = await fetch(`${BASE}/workers/${mid}?expand=user`, {
            headers: { Authorization: `Bearer ${apiKey}`, Accept: 'application/json' },
          });
          if (r.ok) {
            const m = await r.json();
            const u = m.user || {};
            managerMap[mid] = { id: mid, name: [u.first_name||'', u.last_name||''].filter(Boolean).join(' ') || m.work_email || mid };
          }
        } catch { /* skip */ }
      }));

      return res.status(200).json({ results: careCoords, managers: managerMap, fromCache: false });

    } else if (endpoint === 'week') {
      if (!startDate || !endDate) return res.status(400).json({ error: 'startDate and endDate required.' });

      // Try cache first
      const cached = await readBlob(`cache/week-${startDate}.json`);
      if (cached) {
        const age = cached.cachedAt ? Date.now() - new Date(cached.cachedAt).getTime() : Infinity;
        return res.status(200).json({
          timeEntries:   cached.timeEntries   || [],
          leaveRequests: cached.leaveRequests || [],
          cachedAt:      cached.cachedAt,
          fromCache:     true,
          stale:         age > STALE_MS,
        });
      }

      // Cache miss — fetch live and write to cache for next time
      const filter = encodeURIComponent(
        `start_time ge ${startDate}T00:00:00 and start_time le ${endDate}T23:59:59`
      );
      const [timeEntries, allLeave, leaveTypes] = await Promise.all([
        fetchAllPages(`${BASE}/time-entries?filter=${filter}`, apiKey),
        fetchAllPages(`${BASE}/leave-requests`, apiKey),
        fetchAllPages(`${BASE}/leave-types`, apiKey),
      ]);

      const leaveTypeMap = {};
      leaveTypes.forEach(lt => { leaveTypeMap[lt.id] = { name: lt.name, isPaid: lt.is_paid === true }; });

      const leaveRequests = [];
      allLeave.forEach(req => {
        if (req.status !== 'APPROVED') return;
        const lt = leaveTypeMap[req.leave_type_id] || { name: 'Time off', isPaid: true };
        (req.days_take_off || []).forEach(day => {
          if (day.date < startDate || day.date > endDate) return;
          const hrs = (day.number_of_minutes_taken_off || 0) / 60;
          if (hrs <= 0) return;
          leaveRequests.push({
            worker_id:  req.worker_id,
            date:       day.date,
            hours:      hrs,
            leave_type: lt.name,
            is_paid:    lt.isPaid,
            start_time: hrs < 8 && req.start_time ? req.start_time : null,
            reason:     req.reason_for_leave || null,
          });
        });
      });

      // Write to cache in background (don't await — return to client immediately)
      const payload = JSON.stringify({ timeEntries, leaveRequests, cachedAt: new Date().toISOString() });
      put(`cache/week-${startDate}.json`, payload, { allowOverwrite: true, contentType: 'application/json',
        token: process.env.BLOB_READ_WRITE_TOKEN,
      }).catch(err => console.error('[cache write]', err.message));

      return res.status(200).json({ timeEntries, leaveRequests, fromCache: false });

    } else {
      return res.status(400).json({ error: 'Unknown endpoint.' });
    }
  } catch (err) {
    console.error('[timesheets]', err.message);
    return res.status(502).json({ error: err.message });
  }
};
