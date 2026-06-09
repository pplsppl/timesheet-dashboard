/**
 * Vercel Serverless Function: /api/timesheets
 *
 * Validates session cookie, then proxies Rippling REST API.
 * Strictly filters to Care Coordinators sub-department only.
 *
 * Env vars required:
 *   RIPPLING_API_KEY   — Rippling REST API key
 *   SESSION_SECRET     — must match auth.js
 *
 * Endpoints (via ?endpoint=):
 *   workers            → active Care Coordinator workers + their managers
 *   timeoff            → approved leave requests filtered to date range, enriched with leave type
 *   (default)          → time entries filtered by startDate/endDate
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
      const all = await fetchAllPages(`${BASE}/workers?expand=user,department`, apiKey);

      const careCoords = all.filter(w =>
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
            const name = [u.first_name || '', u.last_name || ''].filter(Boolean).join(' ')
              || m.work_email || mid;
            managerMap[mid] = { id: mid, name };
          }
        } catch { /* skip */ }
      }));

      return res.status(200).json({ results: careCoords, managers: managerMap });

    } else if (endpoint === 'timeoff') {
      if (!startDate || !endDate) return res.status(400).json({ error: 'startDate and endDate required.' });

      // Fetch leave types and leave requests in parallel
      const [leaveTypes, allRequests] = await Promise.all([
        fetchAllPages(`${BASE}/leave-types`, apiKey),
        fetchAllPages(`${BASE}/leave-requests`, apiKey),
      ]);

      // Build leave type lookup: id → { name, is_paid }
      const leaveTypeMap = {};
      leaveTypes.forEach(lt => {
        leaveTypeMap[lt.id] = { name: lt.name, isPaid: lt.is_paid === true };
      });

      // Filter to APPROVED requests with days in the target week
      const results = [];
      allRequests.forEach(req => {
        if (req.status !== 'APPROVED') return;
        const wid       = req.worker_id;
        const leaveType = leaveTypeMap[req.leave_type_id] || { name: 'Time off', isPaid: true };

        (req.days_take_off || []).forEach(day => {
          if (day.date < startDate || day.date > endDate) return;
          const hrs = (day.number_of_minutes_taken_off || 0) / 60;
          if (hrs <= 0) return;

          // Partial-day: use start_time from the request if present and this is a single-day request
          const isPartialDay = hrs < 8;
          const startTime = isPartialDay && req.start_time ? req.start_time : null;

          results.push({
            worker_id:    wid,
            date:         day.date,
            hours:        hrs,
            leave_type:   leaveType.name,
            is_paid:      leaveType.isPaid,
            start_time:   startTime,
            reason:       req.reason_for_leave || null,
          });
        });
      });

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
