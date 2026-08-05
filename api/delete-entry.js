/**
 * Vercel Serverless Function: /api/delete-entry
 *
 * POST { entryId, workerId, weekStart } → deletes a Rippling time entry.
 *
 * Behaviour:
 *   - If the entry is APPROVED / PAID / FINALIZED, reverts it to DRAFT first
 *     (locked entries can't be deleted directly), then deletes it.
 *   - Invalidates the cached week blob so the dashboard drops the row on reload.
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

async function invalidateWeek(weekStart, blobToken) {
  if (!blobToken || !weekStart) return;
  try {
    const key = `cache/week-${weekStart}.json`;
    const { blobs } = await list({ prefix: key, token: blobToken });
    const blob = blobs.find(b => b.pathname === key);
    if (blob) await del(blob.url, { token: blobToken });
  } catch (err) {
    console.error('[delete-entry] cache invalidation failed:', err.message);
  }
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
  const { entryId, workerId, weekStart } = body;
  if (!entryId || !workerId) {
    return res.status(400).json({ error: 'entryId and workerId are required.' });
  }

  const authHeaders = {
    Authorization: `Bearer ${apiKey}`,
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };

  try {
    // 1. Read current status to decide whether we must unlock first.
    const getRes = await fetch(`${BASE}/time-entries/${entryId}`, { headers: authHeaders });
    if (!getRes.ok) {
      const err = await getRes.json().catch(() => ({}));
      return res.status(getRes.status).json({ error: err.detail || err.message || `Rippling ${getRes.status} on fetch` });
    }
    const entry = await getRes.json();

    // 2. If locked, revert to DRAFT so the delete is permitted.
    if (LOCKED.includes(entry.status)) {
      const patchRes = await fetch(`${BASE}/time-entries/${entryId}`, {
        method: 'PATCH',
        headers: authHeaders,
        body: JSON.stringify({ worker_id: workerId, status: 'DRAFT' }),
      });
      if (!patchRes.ok) {
        const err = await patchRes.json().catch(() => ({}));
        return res.status(patchRes.status).json({ error: err.detail || err.message || `Rippling ${patchRes.status} on unlock` });
      }
    }

    // 3. Delete.
    const delRes = await fetch(`${BASE}/time-entries/${entryId}`, {
      method: 'DELETE',
      headers: authHeaders,
    });
    if (!delRes.ok) {
      const err = await delRes.json().catch(() => ({}));
      return res.status(delRes.status).json({ error: err.detail || err.message || `Rippling ${delRes.status} on delete` });
    }

    await invalidateWeek(weekStart, blobToken);
    return res.status(200).json({ ok: true });

  } catch (err) {
    console.error('[delete-entry]', err.message);
    return res.status(502).json({ error: err.message });
  }
};
