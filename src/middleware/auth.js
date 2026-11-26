/* Diptera Authentication, Session Management & RBAC User Store.
 *
 * Uses Node.js built-in crypto (scryptSync + timingSafeEqual + SHA-256 session tokens).
 * Supports PostgreSQL persistence via pgBackend, with an in-memory fallback for isolated unit tests.
 */
'use strict';

const crypto = require('node:crypto');

const SESSION_COOKIE_NAME = 'diptera_session';
const DEFAULT_SESSION_TTL_HOURS = 168; // 7 days
const RATE_LIMIT_WINDOW_MS = 5 * 60 * 1000;
const RATE_LIMIT_MAX_ATTEMPTS = 10;

function hashPassword(password) {
  if (typeof password !== 'string' || !password) {
    throw Object.assign(new Error('Password wajib diisi'), { status: 400 });
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

function verifyPassword(password, storedHash) {
  if (typeof password !== 'string' || typeof storedHash !== 'string') return false;
  const parts = storedHash.split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  const [, salt, expectedHex] = parts;
  if (!salt || !expectedHex) return false;
  try {
    const derived = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
    const expectedBuf = Buffer.from(expectedHex, 'hex');
    if (derived.length !== expectedBuf.length) return false;
    return crypto.timingSafeEqual(derived, expectedBuf);
  } catch {
    return false;
  }
}

function isValidPasswordHash(val) {
  return typeof val === 'string' && /^scrypt\$[0-9a-f]{32}\$[0-9a-f]{128}$/i.test(val.trim());
}

function hashApiSecret(secret) {
  if (typeof secret !== 'string' || !secret.trim()) {
    throw Object.assign(new Error('Secret wajib diisi'), { status: 400 });
  }
  const digest = crypto.createHash('sha256').update(secret.trim(), 'utf8').digest('hex');
  return `sha256$${digest}`;
}

function verifyApiSecretHash(provided, storedHash) {
  if (typeof provided !== 'string' || !provided || typeof storedHash !== 'string' || !storedHash.trim()) {
    return false;
  }
  const rawHash = storedHash.trim();
  if (rawHash.startsWith('scrypt$')) {
    return verifyPassword(provided, rawHash);
  }
  const expectedHex = rawHash.startsWith('sha256$') ? rawHash.slice('sha256$'.length) : rawHash;
  if (!/^[0-9a-f]{64}$/i.test(expectedHex)) return false;
  try {
    const actualBuf = crypto.createHash('sha256').update(provided, 'utf8').digest();
    const expectedBuf = Buffer.from(expectedHex, 'hex');
    if (actualBuf.length !== expectedBuf.length) return false;
    return crypto.timingSafeEqual(actualBuf, expectedBuf);
  } catch {
    return false;
  }
}

function hashSessionToken(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}

function parseCookies(cookieHeader) {
  const out = {};
  const raw = String(cookieHeader || '');
  if (!raw) return out;
  for (const chunk of raw.split(';')) {
    const eq = chunk.indexOf('=');
    if (eq <= 0) continue;
    const key = chunk.slice(0, eq).trim();
    const val = chunk.slice(eq + 1).trim();
    if (!key) continue;
    try {
      out[key] = decodeURIComponent(val);
    } catch {
      out[key] = val;
    }
  }
  return out;
}

function extractSessionToken(req) {
  if (!req || !req.headers) return null;
  const cookies = parseCookies(req.headers.cookie);
  if (cookies[SESSION_COOKIE_NAME]) return cookies[SESSION_COOKIE_NAME];
  const authHeader = String(req.headers.authorization || '').trim();
  if (/^bearer\s+/i.test(authHeader)) {
    return authHeader.replace(/^bearer\s+/i, '').trim() || null;
  }
  return null;
}

function buildSessionCookie(token, opts = {}) {
  const maxAgeSec = Math.max(60, Math.floor(Number(opts.maxAgeSec) || DEFAULT_SESSION_TTL_HOURS * 3600));
  const parts = [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(String(token))}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSec}`,
  ];
  if (opts.secure) parts.push('Secure');
  return parts.join('; ');
}

function buildClearSessionCookie(opts = {}) {
  const parts = [
    `${SESSION_COOKIE_NAME}=`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0',
  ];
  if (opts.secure) parts.push('Secure');
  return parts.join('; ');
}

function validateUsername(raw) {
  const username = String(raw || '').trim();
  if (username.length < 3 || username.length > 40) {
    throw Object.assign(new Error('Username harus 3 sampai 40 karakter'), { status: 400 });
  }
  if (!/^[a-zA-Z0-9._-]+$/.test(username)) {
    throw Object.assign(new Error('Username hanya boleh huruf, angka, titik (.), garis bawah (_), atau tanda hubung (-)'), { status: 400 });
  }
  return username;
}

function validatePassword(raw) {
  if (typeof raw !== 'string') {
    throw Object.assign(new Error('Password harus berupa teks'), { status: 400 });
  }
  if (raw.length < 6 || raw.length > 128) {
    throw Object.assign(new Error('Password harus 6 sampai 128 karakter'), { status: 400 });
  }
  return raw;
}

function validateDisplayName(raw, fallback = '') {
  const name = String(raw ?? fallback ?? '').trim().slice(0, 80);
  if (!name) {
    throw Object.assign(new Error('Nama tampilan wajib diisi'), { status: 400 });
  }
  return name;
}

function validateRole(raw) {
  const r = String(raw || 'analyst').trim().toLowerCase();
  if (r !== 'admin' && r !== 'analyst') {
    throw Object.assign(new Error('Role harus "admin" atau "analyst"'), { status: 400 });
  }
  return r;
}

function sanitizeUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name ?? row.displayName ?? row.username,
    role: row.role === 'admin' ? 'admin' : 'analyst',
    isActive: row.is_active !== undefined ? Boolean(row.is_active) : Boolean(row.isActive ?? true),
    createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : (row.created_at || row.createdAt || null),
    updatedAt: row.updated_at instanceof Date ? row.updated_at.toISOString() : (row.updated_at || row.updatedAt || null),
  };
}

function createAuthStore(options = {}) {
  const pgBackend = options.pgBackend || null;
  const env = options.env || process.env;
  const sessionTtlHours = Math.max(1, Number(env.SESSION_TTL_HOURS) || DEFAULT_SESSION_TTL_HOURS);
  const maxAgeSec = sessionTtlHours * 3600;

  // In-memory store fallback when pgBackend is null (unit tests without PG)
  const memUsers = new Map(); // id -> user row
  const memSessions = new Map(); // tokenHash -> session row
  const failedAttempts = new Map(); // key -> { count, resetAt }

  function rateLimitKey(clientIp, username) {
    return `${String(clientIp || 'unknown')}|${String(username || '').trim().toLowerCase()}`;
  }

  function checkRateLimit(clientIp, username) {
    const key = rateLimitKey(clientIp, username);
    const entry = failedAttempts.get(key);
    if (!entry) return;
    if (Date.now() > entry.resetAt) {
      failedAttempts.delete(key);
      return;
    }
    if (entry.count >= RATE_LIMIT_MAX_ATTEMPTS) {
      throw Object.assign(
        new Error('Terlalu banyak percobaan login gagal. Coba lagi beberapa menit lagi.'),
        { status: 429 },
      );
    }
  }

  function recordFailedAttempt(clientIp, username) {
    const key = rateLimitKey(clientIp, username);
    const now = Date.now();
    const cur = failedAttempts.get(key);
    if (!cur || now > cur.resetAt) {
      failedAttempts.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    } else {
      cur.count += 1;
    }
  }

  function clearFailedAttempts(clientIp, username) {
    failedAttempts.delete(rateLimitKey(clientIp, username));
  }

  async function countUsers() {
    if (pgBackend) {
      const res = await pgBackend.query('SELECT COUNT(*)::int AS cnt FROM users');
      return Number(res.rows?.[0]?.cnt || 0);
    }
    return memUsers.size;
  }

  async function findUserByUsername(username) {
    const target = String(username || '').trim();
    if (!target) return null;
    if (pgBackend) {
      const res = await pgBackend.query(
        `SELECT id, username, display_name, role, password_hash, is_active, created_at, updated_at
         FROM users WHERE LOWER(username) = LOWER($1) LIMIT 1`,
        [target],
      );
      return res.rows?.[0] || null;
    }
    const lower = target.toLowerCase();
    for (const u of memUsers.values()) {
      if (u.username.toLowerCase() === lower) return u;
    }
    return null;
  }

  async function findUserById(id) {
    if (!id) return null;
    if (pgBackend) {
      const res = await pgBackend.query(
        `SELECT id, username, display_name, role, password_hash, is_active, created_at, updated_at
         FROM users WHERE id = $1 LIMIT 1`,
        [id],
      );
      return res.rows?.[0] || null;
    }
    return memUsers.get(id) || null;
  }

  async function countOtherActiveAdmins(excludeId) {
    if (pgBackend) {
      const res = await pgBackend.query(
        `SELECT COUNT(*)::int AS cnt FROM users WHERE role = 'admin' AND is_active = TRUE AND id <> $1`,
        [excludeId],
      );
      return Number(res.rows?.[0]?.cnt || 0);
    }
    let cnt = 0;
    for (const u of memUsers.values()) {
      if (u.id !== excludeId && u.role === 'admin' && u.is_active) cnt++;
    }
    return cnt;
  }

  async function insertUserRecord({ id, username, displayName, role, passwordHash, isActive = true }) {
    const now = new Date().toISOString();
    if (pgBackend) {
      const res = await pgBackend.query(
        `INSERT INTO users (id, username, display_name, role, password_hash, is_active, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz, $8::timestamptz)
         RETURNING id, username, display_name, role, password_hash, is_active, created_at, updated_at`,
        [id, username, displayName, role, passwordHash, Boolean(isActive), now, now],
      );
      return res.rows[0];
    }
    const rec = {
      id,
      username,
      display_name: displayName,
      role,
      password_hash: passwordHash,
      is_active: Boolean(isActive),
      created_at: now,
      updated_at: now,
    };
    memUsers.set(id, rec);
    return rec;
  }

  async function ensureDefaultAdmin() {
    const existingCount = await countUsers();
    if (existingCount > 0) {
      return { seeded: false, username: null, usingDefaultPassword: false };
    }
    const rawUser = String(env.ADMIN_USERNAME || 'admin').trim() || 'admin';
    const rawDisplay = String(env.ADMIN_DISPLAY_NAME || 'Administrator').trim() || 'Administrator';
    const preHashed = String(env.ADMIN_PASSWORD_HASH || '').trim();
    let passwordHash;
    let usingDefaultPassword = false;
    if (preHashed) {
      if (!isValidPasswordHash(preHashed)) {
        throw Object.assign(
          new Error('ADMIN_PASSWORD_HASH tidak valid (gunakan format scrypt$<salt>$<hash> dari: node src/middleware/auth.js hash <password>)'),
          { status: 400 },
        );
      }
      passwordHash = preHashed;
    } else {
      const rawPw = typeof env.ADMIN_PASSWORD === 'string' && env.ADMIN_PASSWORD.length >= 6
        ? env.ADMIN_PASSWORD
        : 'admin123';
      usingDefaultPassword = rawPw === 'admin123';
      passwordHash = hashPassword(rawPw);
    }
    const id = 'usr_' + crypto.randomBytes(6).toString('hex');
    try {
      await insertUserRecord({
        id,
        username: rawUser,
        displayName: rawDisplay,
        role: 'admin',
        passwordHash,
        isActive: true,
      });
      return { seeded: true, username: rawUser, usingDefaultPassword };
    } catch (err) {
      // Handle race on concurrent startup
      if (err && err.code === '23505') {
        return { seeded: false, username: rawUser, usingDefaultPassword: false };
      }
      throw err;
    }
  }

  async function login({ username, password, userAgent = '', clientIp = '' }) {
    const cleanUser = String(username || '').trim();
    const rawPw = typeof password === 'string' ? password : '';
    if (!cleanUser || !rawPw) {
      throw Object.assign(new Error('Username dan password wajib diisi'), { status: 400 });
    }

    checkRateLimit(clientIp, cleanUser);

    const row = await findUserByUsername(cleanUser);
    if (!row || !row.is_active || !verifyPassword(rawPw, row.password_hash)) {
      recordFailedAttempt(clientIp, cleanUser);
      throw Object.assign(new Error('Username atau password salah'), { status: 401 });
    }

    clearFailedAttempts(clientIp, cleanUser);

    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = hashSessionToken(token);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + maxAgeSec * 1000).toISOString();
    const nowIso = now.toISOString();
    const ua = String(userAgent || '').slice(0, 300) || null;

    if (pgBackend) {
      await pgBackend.query('DELETE FROM sessions WHERE expires_at <= NOW()');
      await pgBackend.query(
        `INSERT INTO sessions (token_hash, user_id, expires_at, created_at, last_seen_at, user_agent)
         VALUES ($1, $2, $3::timestamptz, $4::timestamptz, $5::timestamptz, $6)`,
        [tokenHash, row.id, expiresAt, nowIso, nowIso, ua],
      );
    } else {
      for (const [k, s] of memSessions.entries()) {
        if (Date.parse(s.expires_at) <= Date.now()) memSessions.delete(k);
      }
      memSessions.set(tokenHash, {
        token_hash: tokenHash,
        user_id: row.id,
        expires_at: expiresAt,
        created_at: nowIso,
        last_seen_at: nowIso,
        user_agent: ua,
      });
    }

    return {
      token,
      user: sanitizeUser(row),
      maxAgeSec,
    };
  }

  async function authenticateRequest(req) {
    const token = extractSessionToken(req);
    if (!token) return null;
    const tokenHash = hashSessionToken(token);

    if (pgBackend) {
      const res = await pgBackend.query(
        `SELECT u.id, u.username, u.display_name, u.role, u.is_active, u.created_at, u.updated_at, s.expires_at
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = $1 AND s.expires_at > NOW() AND u.is_active = TRUE
         LIMIT 1`,
        [tokenHash],
      );
      const row = res.rows?.[0];
      if (!row) return null;
      return sanitizeUser(row);
    }

    const sess = memSessions.get(tokenHash);
    if (!sess) return null;
    if (Date.parse(sess.expires_at) <= Date.now()) {
      memSessions.delete(tokenHash);
      return null;
    }
    const user = memUsers.get(sess.user_id);
    if (!user || !user.is_active) return null;
    return sanitizeUser(user);
  }

  async function logout(token) {
    if (!token) return;
    const tokenHash = hashSessionToken(token);
    if (pgBackend) {
      await pgBackend.query('DELETE FROM sessions WHERE token_hash = $1', [tokenHash]);
    } else {
      memSessions.delete(tokenHash);
    }
  }

  async function revokeUserSessions(userId, exceptToken = null) {
    const exceptHash = exceptToken ? hashSessionToken(exceptToken) : null;
    if (pgBackend) {
      if (exceptHash) {
        await pgBackend.query('DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2', [userId, exceptHash]);
      } else {
        await pgBackend.query('DELETE FROM sessions WHERE user_id = $1', [userId]);
      }
      return;
    }
    for (const [k, s] of memSessions.entries()) {
      if (s.user_id === userId && (!exceptHash || k !== exceptHash)) {
        memSessions.delete(k);
      }
    }
  }

  async function changeOwnPassword(userId, { currentPassword, newPassword, currentToken = null }) {
    const user = await findUserById(userId);
    if (!user || !user.is_active) {
      throw Object.assign(new Error('User tidak ditemukan'), { status: 404 });
    }
    if (!verifyPassword(String(currentPassword || ''), user.password_hash)) {
      throw Object.assign(new Error('Password saat ini salah'), { status: 401 });
    }
    const cleanNew = validatePassword(newPassword);
    const nextHash = hashPassword(cleanNew);
    const now = new Date().toISOString();

    if (pgBackend) {
      await pgBackend.query(
        'UPDATE users SET password_hash = $1, updated_at = $2::timestamptz WHERE id = $3',
        [nextHash, now, userId],
      );
    } else {
      user.password_hash = nextHash;
      user.updated_at = now;
    }

    await revokeUserSessions(userId, currentToken);
    return { ok: true };
  }

  async function listUsers() {
    if (pgBackend) {
      const res = await pgBackend.query(
        `SELECT id, username, display_name, role, is_active, created_at, updated_at
         FROM users
         ORDER BY CASE WHEN role = 'admin' THEN 0 ELSE 1 END, created_at ASC`,
      );
      return (res.rows || []).map(sanitizeUser);
    }
    return Array.from(memUsers.values())
      .slice()
      .sort((a, b) => {
        const ra = a.role === 'admin' ? 0 : 1;
        const rb = b.role === 'admin' ? 0 : 1;
        if (ra !== rb) return ra - rb;
        return String(a.created_at).localeCompare(String(b.created_at));
      })
      .map(sanitizeUser);
  }

  async function createUser({ username, displayName, password, role }) {
    const cleanUsername = validateUsername(username);
    const cleanRole = validateRole(role);
    const cleanPassword = validatePassword(password);
    const cleanDisplayName = validateDisplayName(displayName, cleanUsername);

    const existing = await findUserByUsername(cleanUsername);
    if (existing) {
      throw Object.assign(new Error(`Username "${cleanUsername}" sudah digunakan`), { status: 409 });
    }

    const id = 'usr_' + crypto.randomBytes(6).toString('hex');
    const passwordHash = hashPassword(cleanPassword);
    try {
      const inserted = await insertUserRecord({
        id,
        username: cleanUsername,
        displayName: cleanDisplayName,
        role: cleanRole,
        passwordHash,
        isActive: true,
      });
      return sanitizeUser(inserted);
    } catch (err) {
      if (err && err.code === '23505') {
        throw Object.assign(new Error(`Username "${cleanUsername}" sudah digunakan`), { status: 409 });
      }
      throw err;
    }
  }

  async function updateUser(targetId, payload = {}, actorUser = null, currentToken = null) {
    const target = await findUserById(targetId);
    if (!target) {
      throw Object.assign(new Error('User tidak ditemukan'), { status: 404 });
    }

    const nextDisplayName = payload.displayName !== undefined
      ? validateDisplayName(payload.displayName, target.username)
      : target.display_name;
    const nextRole = payload.role !== undefined ? validateRole(payload.role) : target.role;
    const nextIsActive = payload.isActive !== undefined ? Boolean(payload.isActive) : Boolean(target.is_active);
    const hasPasswordChange = payload.password !== undefined && payload.password !== null && payload.password !== '';
    const nextPasswordHash = hasPasswordChange ? hashPassword(validatePassword(payload.password)) : target.password_hash;

    if (actorUser && targetId === actorUser.id && !nextIsActive) {
      throw Object.assign(new Error('Tidak dapat menonaktifkan akun Anda sendiri'), { status: 400 });
    }

    const wasActiveAdmin = target.role === 'admin' && Boolean(target.is_active);
    const remainsActiveAdmin = nextRole === 'admin' && nextIsActive;
    if (wasActiveAdmin && !remainsActiveAdmin) {
      const otherAdmins = await countOtherActiveAdmins(targetId);
      if (otherAdmins < 1) {
        throw Object.assign(new Error('Harus ada minimal satu akun admin yang aktif'), { status: 400 });
      }
    }

    const now = new Date().toISOString();
    let updatedRow;
    if (pgBackend) {
      const res = await pgBackend.query(
        `UPDATE users
         SET display_name = $1, role = $2, is_active = $3, password_hash = $4, updated_at = $5::timestamptz
         WHERE id = $6
         RETURNING id, username, display_name, role, is_active, created_at, updated_at`,
        [nextDisplayName, nextRole, nextIsActive, nextPasswordHash, now, targetId],
      );
      updatedRow = res.rows[0];
    } else {
      target.display_name = nextDisplayName;
      target.role = nextRole;
      target.is_active = nextIsActive;
      target.password_hash = nextPasswordHash;
      target.updated_at = now;
      updatedRow = target;
    }

    if (!nextIsActive) {
      await revokeUserSessions(targetId, null);
    } else if (hasPasswordChange) {
      await revokeUserSessions(targetId, actorUser && actorUser.id === targetId ? currentToken : null);
    }

    return sanitizeUser(updatedRow);
  }

  async function deleteUser(targetId, actorUser = null) {
    if (actorUser && targetId === actorUser.id) {
      throw Object.assign(new Error('Tidak dapat menghapus akun Anda sendiri yang sedang login'), { status: 400 });
    }
    const target = await findUserById(targetId);
    if (!target) {
      throw Object.assign(new Error('User tidak ditemukan'), { status: 404 });
    }
    if (target.role === 'admin' && target.is_active) {
      const otherAdmins = await countOtherActiveAdmins(targetId);
      if (otherAdmins < 1) {
        throw Object.assign(new Error('Tidak dapat menghapus satu-satunya admin yang aktif'), { status: 400 });
      }
    }

    await revokeUserSessions(targetId, null);
    if (pgBackend) {
      await pgBackend.query('DELETE FROM users WHERE id = $1', [targetId]);
    } else {
      memUsers.delete(targetId);
    }
    return { ok: true };
  }

  return {
    ensureDefaultAdmin,
    login,
    authenticateRequest,
    logout,
    changeOwnPassword,
    listUsers,
    createUser,
    updateUser,
    deleteUser,
  };
}

module.exports = {
  SESSION_COOKIE_NAME,
  hashPassword,
  verifyPassword,
  isValidPasswordHash,
  hashApiSecret,
  verifyApiSecretHash,
  hashSessionToken,
  parseCookies,
  extractSessionToken,
  buildSessionCookie,
  buildClearSessionCookie,
  validateUsername,
  validatePassword,
  validateDisplayName,
  validateRole,
  sanitizeUser,
  createAuthStore,
};

if (require.main === module) {
  const [, , cmd, ...args] = process.argv;
  const val = args.join(' ');
  try {
    if (cmd === 'hash') {
      validatePassword(val);
      console.log(hashPassword(val));
      process.exit(0);
    }
    if (cmd === 'hash-secret') {
      console.log(hashApiSecret(val));
      process.exit(0);
    }
    console.error('Penggunaan:');
    console.error('  node src/middleware/auth.js hash <password-min-6-karakter>   -> ADMIN_PASSWORD_HASH (scrypt)');
    console.error('  node src/middleware/auth.js hash-secret <api-secret>          -> APPROVAL_API_SECRET_HASH (sha256)');
    process.exit(1);
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
}

