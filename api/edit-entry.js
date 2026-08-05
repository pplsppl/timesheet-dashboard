/**
 * Vercel Serverless Function: /api/edit-entry
 *
 * POST { entryId, workerId, clockInUtc, clockOutUtc, weekStart }
 *   → updates a Rippling time entry's clock-in / clock-out.
 *
 * clockInUtc / clockOutUtc are full UTC ISO timestamps. The client (index.html)
 * has already converted the manager's typed wall-clock time — in whichever zone the
 * dashboard was displaying — into a UTC instant, so this function just writes it.
 *
 * Behaviour:
 *   - Fetches the entry, sets the first work segment's start_time and the last work
 *     segment's end_time (and the top-level start_time/end_time), preserving breaks,
 *     job codes, and everything else.
 *   - If the entry is APPROVED / PAID / FINALIZED, reverts it to DRAFT so the edit
 *     is accepted, and leaves it DRAFT.
 *   - Invalidates the cached week blob so the dashboard shows fresh data on reload.
 *
 * Any valid session may call this (no role restriction), matching /api/approve.
 *
 * Env vars:
 *   RIPPLING_API_KEY       — needs time_tracking:read-write scope
 *   SESSION_SECRET         — must match auth.js
 *   BLOB_READ_WRITE_TOKEN  — Vercel Blob token (for cache invalidation)
 */

const crypto = require('crypto');
const { list, del } = require('@vercel/blob');

const BASE        = 'https://rest.ripplingapis.com';
const COOKIE_NAME = 'ops_session';
const LOCKED      = ['APPROVED', 'PAID', 'FINALIZED'];

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

// Delete the cached week blob so the next dashboard load re-reads/re-fetches it.
async function invalidateWeek(weekStart, blobToken) {
  if (!blobToken || !weekStart) return;
  try {
    const key = `cache/week-${weekStart}.json`;
    const { blobs } = await list({ prefix: key, token: blobToken });
    const blob = blobs.find(b => b.pathname === key);
    if (blob) await del(blob.url, { token: blobToken });
  } catch (err) {
    console.error('[edit-entry] cache invalidation failed:', err.message);
  }
}

// Pull the most useful message out of a Rippling error response (JSON shapes vary,
// and some errors aren't JSON at all), so the UI shows the real reason for a failure.
async function ripplingError(resp, phase) {
  const raw = await resp.text().catch(() => '');
  let msg = raw;
  try {
    const j = JSON.parse(raw);
    msg = j.detail || j.message || j.error
      || (Array.isArray(j.errors) ? j.errors.map(e => e.detail || e.message || JSON.stringify(e)).join('; ') : '')
      || raw;
  } catch { /* not JSON — keep raw text */ }
  return `Rippling ${resp.status} on ${phase}: ${String(msg).slice(0, 400) || '(no body)'}`;
}

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed.' });

  const secret    = process.env.SESSION_SECRET;
  const apiKey    = process.env.RIPPLING_API_KEY;
  const blobToken = process.env.BLOB_READ_WRITE_TOKEN;
  if (!secret || !apiKey) return res.status(500).json({ error: 'Server misconfigured.' });
  if (!verifySession(req.headers.cookie, secret)) return res.status(401).json({ error: 'Unauthorized.' });

  const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
  const { entryId, workerId, clockInUtc, clockOutUtc, weekStart } = body;
  // clockOutUtc is optional: an open/in-progress shift (e.g. fixing a forgotten
  // clock-in mid-shift) has no clock-out yet.
  if (!entryId || !workerId || !clockInUtc) {
    return res.status(400).json({ error: 'entryId, workerId and clockInUtc are required.' });
  }

  const authHeaders = {
    Authorization: `Bearer ${apiKey}`,
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };

  try {
    // 1. Fetch the current entry (Rippling's documented GET-then-PATCH flow).
    const getRes = await fetch(`${BASE}/time-entries/${entryId}`, { headers: authHeaders });
    if (!getRes.ok) return res.status(getRes.status).json({ error: await ripplingError(getRes, 'fetch') });
    const entry = await getRes.json();

    // 2. Split the read-side `segments` into work shifts vs. breaks, then apply the edit.
    //    clockOutUtc may be null — e.g. a manager fixing a forgotten clock-in mid-shift,
    //    where the shift is still open. In that case we only move the start.
    const segments = Array.isArray(entry.segments) ? entry.segments : [];
    const workSegs  = segments.filter(s => !s.break_type_id);
    const breakSegs = segments.filter(s =>  s.break_type_id);
    if (!workSegs.length) {
      return res.status(422).json({ error: 'This entry has no editable work shift.' });
    }
    workSegs[0].start_time = clockInUtc;
    if (clockOutUtc) workSegs[workSegs.length - 1].end_time = clockOutUtc;

    // 3. Auto-revert a locked entry to DRAFT so the edit is accepted.
    let status = entry.status;
    if (LOCKED.includes(status)) status = 'DRAFT';

    // 4. PATCH using Rippling's WRITE shape: job_shifts + breaks (the read-side
    //    `segments` field is not writable). Rippling recomputes hours from these.
    const job_shifts = workSegs.map(s => ({
      start_time:          s.start_time,
      end_time:            s.end_time != null ? s.end_time : null,   // null == still-open shift
      original_start_time: s.original_start_time != null ? s.original_start_time : null,
      original_end_time:   s.original_end_time   != null ? s.original_end_time   : null,
      job_codes_id:        Array.isArray(s.job_codes_id) ? s.job_codes_id : [],
      is_hours_only_input: s.is_hours_only_input === true,
    }));
    const breaks = breakSegs.map(s => ({
      start_time:    s.start_time,
      end_time:      s.end_time != null ? s.end_time : null,
      break_type_id: s.break_type_id,
    }));

    const patchRes = await fetch(`${BASE}/time-entries/${entryId}`, {
      method: 'PATCH',
      headers: authHeaders,
      body: JSON.stringify({ worker_id: workerId, job_shifts, breaks, status }),
    });

    if (!patchRes.ok) return res.status(patchRes.status).json({ error: await ripplingError(patchRes, 'update') });

    const data = await patchRes.json().catch(() => ({}));
    await invalidateWeek(weekStart, blobToken);
    return res.status(200).json({ ok: true, status: data.status || status });

  } catch (err) {
    console.error('[edit-entry]', err.message);
    return res.status(502).json({ error: err.message });
  }
};
