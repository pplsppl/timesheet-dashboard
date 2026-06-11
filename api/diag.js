/**
 * /api/diag — TEMPORARY diagnostic. DELETE THIS FILE after debugging.
 *
 * POST (Authorization: Bearer <SESSION_SECRET>) → reports how the private
 * users blob read is behaving. Read-only — never writes or mutates anything.
 * Does not leak password hashes or the session secret.
 */

const blob = require('@vercel/blob');

let blobVersion = 'unknown';
try { blobVersion = require('@vercel/blob/package.json').version; } catch { /* noop */ }

const USERS_KEY = 'users/users.json';

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  const secret    = process.env.SESSION_SECRET;
  const blobToken = process.env.BLOB_READ_WRITE_TOKEN;
  if (!secret) return res.status(500).json({ error: 'SESSION_SECRET not set' });

  const auth = req.headers.authorization || '';
  if (auth !== `Bearer ${secret}`) return res.status(401).json({ error: 'Unauthorized.' });

  const out = {
    blobVersion,
    hasBlobToken: !!blobToken,
    exports: {
      get:  typeof blob.get,
      put:  typeof blob.put,
      list: typeof blob.list,
      head: typeof blob.head,
    },
  };

  // 1. What does list() see?
  try {
    const { blobs } = await blob.list({ prefix: USERS_KEY, token: blobToken });
    out.list = { ok: true, count: blobs.length, pathnames: blobs.map(b => b.pathname) };
  } catch (e) {
    out.list = { ok: false, error: e.message };
  }

  // 2. What does get() return?
  try {
    if (typeof blob.get !== 'function') {
      out.getPrivate = { ok: false, error: 'get() does not exist in this @vercel/blob version' };
    } else {
      const r = await blob.get(USERS_KEY, { access: 'private', token: blobToken });
      if (!r) {
        out.getPrivate = { ok: false, result: 'null (blob not found)' };
      } else {
        out.getPrivate = {
          ok: true,
          statusCode: r.statusCode,
          hasStream: !!r.stream,
          size: r.blob && r.blob.size,
        };
        if (r.stream) {
          const chunks = [];
          const reader = r.stream.getReader();
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value);
          }
          const text = Buffer.concat(chunks.map(c => Buffer.from(c))).toString('utf8');
          try {
            const data = JSON.parse(text);
            out.getPrivate.parsedUserCount = (data.users || []).length;
          } catch (pe) {
            out.getPrivate.parseError = pe.message;
            out.getPrivate.sample = text.slice(0, 80);
          }
        }
      }
    }
  } catch (e) {
    out.getPrivate = { ok: false, error: e.message };
  }

  return res.status(200).json(out);
};
