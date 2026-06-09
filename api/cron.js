/**
 * Vercel Cron Function: /api/cron
 * Schedule: every 5 minutes (defined in vercel.json)
 *
 * Fetches all data from Rippling and writes to Vercel Blob cache.
 * The timesheets function reads from this cache instead of hitting Rippling directly.
 *
 * Env vars required:
 *   RIPPLING_API_KEY      — Rippling REST API key
 *   BLOB_READ_WRITE_TOKEN — Vercel Blob token (auto-added when you connected the store)
 *   CRON_SECRET           — optional secret to prevent unauthorized manual triggers
 */

const { put } = require('@vercel/blob');

const BASE        = 'https://rest.ripplingapis.com';
const TARGET_DEPT = 'Care Coordinators';

// How many weeks back to cache (current week + N prior)
const WEEKS_BACK = 8;

async function fetchAllPages(url, apiKey) {
  const results = [];
  let next = url;
  while (next) {
    const r = await fetch(next, {
      headers: { Authorization: `Bearer ${apiKey}`, Accept: 'application/json' },
    });
    if (!r.ok) {
      const body = await r.text().catch(() => '');
      throw new Error(`Rippling ${r.status}: ${body.slice(0, 200)}`);
    }
    const data = await r.json();
    results.push(...(Array.isArray(data) ? data : (data.results || [])));
    next = data.next_link || null;
  }
  return results;
}

function getWeekBounds(offsetFromNow = 0) {
  const now   = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const sunDate = today.getDate() - today.getDay() + (offsetFromNow * 7);
  const sun   = new Date(today.getFullYear(), today.getMonth(), sunDate, 0, 0, 0, 0);
  const sat   = new Date(today.getFullYear(), today.getMonth(), sunDate + 6, 23, 59, 59, 999);
  return {
    start: sun.toISOString().split('T')[0],
    end:   sat.toISOString().split('T')[0],
  };
}

module.exports = async function handler(req, res) {
  // Optional: protect manual triggers
  const cronSecret = process.env.CRON_SECRET;
  if (cronSecret) {
    const auth = req.headers.authorization || '';
    if (auth !== `Bearer ${cronSecret}`) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
  }

  const apiKey = process.env.RIPPLING_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'RIPPLING_API_KEY not set' });

  const startTime = Date.now();
  const results   = { weeks: [], errors: [] };

  try {
    // ── 1. Fetch workers (Care Coordinators only) ──
    const allWorkers = await fetchAllPages(`${BASE}/workers?expand=user,department`, apiKey);
    const careCoords = allWorkers.filter(w =>
      w.status === 'ACTIVE' && (w.department?.name || '') === TARGET_DEPT
    );

    // Build manager map from the same workers list — no extra API calls
    const managerIds = [...new Set(careCoords.map(w => w.manager_id).filter(Boolean))];
    const managerMap = {};
    // Managers may be outside Care Coordinators, so fetch them individually
    // but do it in parallel this time
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

    // ── 2. Fetch leave types ──
    const leaveTypes    = await fetchAllPages(`${BASE}/leave-types`, apiKey);
    const leaveTypeMap  = {};
    leaveTypes.forEach(lt => {
      leaveTypeMap[lt.id] = { name: lt.name, isPaid: lt.is_paid === true };
    });

    // ── 3. Fetch ALL leave requests once (no date filter available) ──
    const allLeaveRequests = await fetchAllPages(`${BASE}/leave-requests`, apiKey);

    // ── 4. Write workers + managers to blob (rarely changes) ──
    const workersPayload = JSON.stringify({
      results:  careCoords,
      managers: managerMap,
      cachedAt: new Date().toISOString(),
    });
    await put('cache/workers.json', workersPayload, {
      access: 'private',
      allowOverwrite: true,
      contentType: 'application/json',
      token: process.env.BLOB_READ_WRITE_TOKEN,
    });

    // ── 5. For each week, fetch time entries + filter leave requests ──
    for (let offset = 0; offset >= -WEEKS_BACK; offset--) {
      const { start, end } = getWeekBounds(offset);
      try {
        // Time entries — supports date filter, fast
        const filter = encodeURIComponent(
          `start_time ge ${start}T00:00:00 and start_time le ${end}T23:59:59`
        );
        const timeEntries = await fetchAllPages(
          `${BASE}/time-entries?filter=${filter}`, apiKey
        );

        // Leave — filter from already-fetched full list
        const leaveForWeek = [];
        allLeaveRequests.forEach(req => {
          if (req.status !== 'APPROVED') return;
          const leaveType = leaveTypeMap[req.leave_type_id] || { name: 'Time off', isPaid: true };
          (req.days_take_off || []).forEach(day => {
            if (day.date < start || day.date > end) return;
            const hrs = (day.number_of_minutes_taken_off || 0) / 60;
            if (hrs <= 0) return;
            const isPartialDay = hrs < 8;
            leaveForWeek.push({
              worker_id:   req.worker_id,
              date:        day.date,
              hours:       hrs,
              leave_type:  leaveType.name,
              is_paid:     leaveType.isPaid,
              start_time:  isPartialDay && req.start_time ? req.start_time : null,
              reason:      req.reason_for_leave || null,
            });
          });
        });

        const weekPayload = JSON.stringify({
          timeEntries,
          leaveRequests: leaveForWeek,
          cachedAt: new Date().toISOString(),
        });

        await put(`cache/week-${start}.json`, weekPayload, {
          access: 'private',
          allowOverwrite: true,
          contentType: 'application/json',
          token: process.env.BLOB_READ_WRITE_TOKEN,
        });

        results.weeks.push({ week: start, timeEntries: timeEntries.length, leave: leaveForWeek.length });
      } catch (weekErr) {
        results.errors.push({ week: start, error: weekErr.message });
      }
    }

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`[cron] completed in ${elapsed}s`, results);
    return res.status(200).json({ ok: true, elapsed, ...results });

  } catch (err) {
    console.error('[cron] fatal error:', err.message);
    return res.status(500).json({ error: err.message });
  }
};
