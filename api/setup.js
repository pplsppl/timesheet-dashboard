/**
 * /api/setup
 * POST (Authorization: Bearer <SESSION_SECRET>) → one-time initialisation of users.json
 * Returns plaintext temp passwords to distribute to users.
 * Errors with 409 if already initialised.
 *
 * Env vars: SESSION_SECRET, BLOB_READ_WRITE_TOKEN
 */

const crypto = require('crypto');
const { list, put } = require('@vercel/blob');

const USERS_KEY = 'users/users.json';

const INITIAL_USERS = [
  { email: 'andrew@generalmedicine.co',  name: 'Andrew Beeks',       role: 'admin' },
  { email: 'steph@generalmedicine.co',   name: 'Stephanie Croteau',  role: 'admin' },
  { email: 'taylor@generalmedicine.co',  name: 'Taylor Robb',        role: 'user'  },
  { email: 'heather@generalmedicine.co', name: 'Heather Hawley',     role: 'user'  },
  { email: 'sharrie@generalmedicine.co', name: 'Sharrie Lower',      role: 'user'  },
  { email: 'john@generalmedicine.co',    name: 'John Coakley',       role: 'user'  },
];

function hashPw(pw, salt) {
  return crypto.pbkdf2Sync(pw, salt, 100000, 64, 'sha512').toString('hex');
}
function generateSalt()    { return crypto.randomBytes(32).toString('hex'); }
function generateTempPw()  {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  return 'GM-' + Array.from({ length: 6 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

module.exports = async function handler(req, res) {
  const secret    = process.env.SESSION_SECRET;
  const blobToken = process.env.BLOB_READ_WRITE_TOKEN;
  res.setHeader('Content-Type', 'application/json');

  if (!secret || !blobToken) return res.status(500).json({ error: 'Server misconfigured.' });
  if (req.method !== 'POST')  return res.status(405).json({ error: 'Method not allowed.' });

  // Protect with SESSION_SECRET passed as Bearer token
  const auth = req.headers.authorization || '';
  if (auth !== `Bearer ${secret}`) return res.status(401).json({ error: 'Unauthorized.' });

  // Check if already initialised
  try {
    const { blobs } = await list({ prefix: USERS_KEY, token: blobToken });
    if (blobs.find(b => b.pathname === USERS_KEY)) {
      return res.status(409).json({ error: 'Already initialised. Delete users/users.json from Blob store to re-run.' });
    }
  } catch { /* first run — store doesn't exist yet */ }

  // Generate users with temp passwords
  const tempPasswords = [];
  const users = INITIAL_USERS.map(u => {
    const tempPassword = generateTempPw();
    const salt         = generateSalt();
    tempPasswords.push({ email: u.email, name: u.name, tempPassword });
    return {
      email: u.email,
      name:  u.name,
      role:  u.role,
      salt,
      hash: hashPw(tempPassword, salt),
      mustChangePassword: true,
      createdAt: new Date().toISOString(),
    };
  });

  await put(USERS_KEY, JSON.stringify({ users, createdAt: new Date().toISOString() }), {
    access: 'private', allowOverwrite: false, contentType: 'application/json', token: blobToken,
  });

  return res.status(200).json({
    ok: true,
    message: 'Users initialised. Distribute the temp passwords below — each user must change theirs on first login.',
    users: tempPasswords,
  });
};
