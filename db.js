/* Diptera PostgreSQL Backend — Schema initialization & persistent domain storage.
 *
 * Activated automatically when DATABASE_URL or PGHOST is configured.
 * Handles idempotent DDL setup, retryable startup connection, and JSONB-backed
 * persistence for users, sessions, workspace_counters, history_entries, approvals, and rejections.
 */
'use strict';

const SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin', 'analyst')),
    password_hash TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower ON users (LOWER(username))`,
  `CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_agent TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at)`,
  `CREATE TABLE IF NOT EXISTS workspace_counters (
    workspace TEXT PRIMARY KEY,
    last_iris_case_id TEXT,
    tickets_by_tenant JSONB NOT NULL DEFAULT '{}'::jsonb,
    tenants JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by TEXT
  )`,
  `CREATE TABLE IF NOT EXISTS history_entries (
    id TEXT PRIMARY KEY,
    workspace TEXT NOT NULL DEFAULT 'asoc',
    mode TEXT NOT NULL DEFAULT 'reporting',
    tenant TEXT,
    ticket_number TEXT,
    iris_case_id TEXT,
    case_name TEXT,
    severity TEXT,
    status TEXT,
    created_by_user_id TEXT,
    created_by_name TEXT,
    reviewed_by_user_id TEXT,
    reviewed_by_name TEXT,
    reviewed_at TIMESTAMPTZ,
    approval_id TEXT,
    approval_status TEXT,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_history_ws_created ON history_entries (workspace, created_at DESC)`,
  `CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    workspace TEXT NOT NULL DEFAULT 'asoc',
    status TEXT NOT NULL DEFAULT 'pending',
    job_id TEXT,
    exec_id TEXT,
    iris_case_id TEXT,
    case_name TEXT,
    tenant TEXT,
    severity TEXT,
    resume_url TEXT,
    created_by_user_id TEXT,
    created_by_name TEXT,
    decided_by_user_id TEXT,
    decided_by TEXT,
    decided_at TIMESTAMPTZ,
    decision TEXT,
    reason TEXT,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_approvals_status_created ON approvals (status, created_at DESC)`,
  `CREATE TABLE IF NOT EXISTS rejections (
    id TEXT PRIMARY KEY,
    workspace TEXT NOT NULL DEFAULT 'asoc',
    status TEXT NOT NULL DEFAULT 'open',
    approval_id TEXT,
    job_id TEXT,
    exec_id TEXT,
    iris_case_id TEXT,
    case_name TEXT,
    tenant TEXT,
    decided_by_user_id TEXT,
    decided_by TEXT,
    completed_by_user_id TEXT,
    completed_by TEXT,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_rejections_status_created ON rejections (status, created_at DESC)`,
];

function hasPostgresConfig(env = process.env) {
  return Boolean(
    String(env.DATABASE_URL || '').trim() ||
    String(env.PGHOST || '').trim()
  );
}

function buildPoolConfig(env = process.env) {
  const connStr = String(env.DATABASE_URL || '').trim();
  const cfg = connStr
    ? { connectionString: connStr }
    : {
        host: String(env.PGHOST || '127.0.0.1').trim(),
        port: Number(env.PGPORT) || 5432,
        database: String(env.PGDATABASE || env.POSTGRES_DB || 'diptera').trim(),
        user: String(env.PGUSER || env.POSTGRES_USER || 'diptera').trim(),
        password: String(env.PGPASSWORD || env.POSTGRES_PASSWORD || ''),
      };

  const sslRaw = String(env.PGSSL || '').trim().toLowerCase();
  if (sslRaw === 'true' || sslRaw === '1' || sslRaw === 'yes') {
    cfg.ssl = { rejectUnauthorized: false };
  }

  cfg.max = Number(env.PGPOOL_MAX) || 10;
  cfg.idleTimeoutMillis = 30000;
  cfg.connectionTimeoutMillis = 5000;
  return cfg;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function asIso(val, fallback) {
  if (!val) return fallback || new Date().toISOString();
  if (val instanceof Date) return val.toISOString();
  const s = String(val).trim();
  return s || fallback || new Date().toISOString();
}

function parseJsonValue(val, fallback) {
  if (val == null) return fallback;
  if (typeof val === 'object') return val;
  try {
    return JSON.parse(String(val));
  } catch {
    return fallback;
  }
}

function createPostgresBackend(options = {}) {
  const env = options.env || process.env;
  let pool = options.pool || null;
  const ownsPool = !pool;
  let closed = false;

  function getPool() {
    if (!pool) {
      const { Pool } = require('pg');
      pool = new Pool(buildPoolConfig(env));
    }
    return pool;
  }

  async function query(sql, params = []) {
    return getPool().query(sql, params);
  }

  async function connectWithRetry(maxAttempts = 15, delayMs = 1000) {
    let lastErr = null;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        await query('SELECT 1');
        return true;
      } catch (err) {
        lastErr = err;
        if (attempt < maxAttempts) await sleep(delayMs);
      }
    }
    throw lastErr || new Error('Gagal terhubung ke PostgreSQL');
  }

  async function initSchema() {
    for (const stmt of SCHEMA_STATEMENTS) {
      await query(stmt);
    }
  }

  async function loadAllDomainData() {
    const [wsRes, histRes, apprRes, rejRes] = await Promise.all([
      query('SELECT workspace, last_iris_case_id, tickets_by_tenant, tenants, updated_at, updated_by FROM workspace_counters'),
      query('SELECT data FROM history_entries ORDER BY created_at DESC LIMIT 1000'),
      query('SELECT data FROM approvals ORDER BY created_at DESC LIMIT 1000'),
      query('SELECT data FROM rejections ORDER BY created_at DESC LIMIT 500'),
    ]);

    const countersByWs = {};
    for (const row of wsRes.rows || []) {
      const ws = String(row.workspace || '').trim().toLowerCase();
      if (!ws) continue;
      countersByWs[ws] = {
        lastIrisCaseId: row.last_iris_case_id || null,
        ticketsByTenant: parseJsonValue(row.tickets_by_tenant, {}),
        tenants: Array.isArray(parseJsonValue(row.tenants, [])) ? parseJsonValue(row.tenants, []) : [],
        updatedAt: asIso(row.updated_at),
        updatedBy: row.updated_by || 'postgres',
      };
    }

    const history = (histRes.rows || [])
      .map((r) => parseJsonValue(r.data, null))
      .filter((x) => x && typeof x === 'object');

    const approvals = (apprRes.rows || [])
      .map((r) => parseJsonValue(r.data, null))
      .filter((x) => x && typeof x === 'object');

    const rejections = (rejRes.rows || [])
      .map((r) => parseJsonValue(r.data, null))
      .filter((x) => x && typeof x === 'object');

    return { countersByWs, history, approvals, rejections };
  }

  async function upsertWorkspaceCounter(ws, bucket) {
    await query(
      `INSERT INTO workspace_counters (workspace, last_iris_case_id, tickets_by_tenant, tenants, updated_at, updated_by)
       VALUES ($1, $2, $3::jsonb, $4::jsonb, $5::timestamptz, $6)
       ON CONFLICT (workspace) DO UPDATE SET
         last_iris_case_id = EXCLUDED.last_iris_case_id,
         tickets_by_tenant = EXCLUDED.tickets_by_tenant,
         tenants = EXCLUDED.tenants,
         updated_at = EXCLUDED.updated_at,
         updated_by = EXCLUDED.updated_by`,
      [
        String(ws),
        bucket.lastIrisCaseId || null,
        JSON.stringify(bucket.ticketsByTenant || {}),
        JSON.stringify(Array.isArray(bucket.tenants) ? bucket.tenants : []),
        asIso(bucket.updatedAt),
        bucket.updatedBy || 'api',
      ],
    );
  }

  async function upsertHistory(entry) {
    const now = new Date().toISOString();
    await query(
      `INSERT INTO history_entries (
         id, workspace, mode, tenant, ticket_number, iris_case_id, case_name, severity, status,
         created_by_user_id, created_by_name, reviewed_by_user_id, reviewed_by_name, reviewed_at,
         approval_id, approval_status, data, created_at, updated_at
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::timestamptz, $15, $16, $17::jsonb, $18::timestamptz, $19::timestamptz)
       ON CONFLICT (id) DO UPDATE SET
         workspace = EXCLUDED.workspace,
         mode = EXCLUDED.mode,
         tenant = EXCLUDED.tenant,
         ticket_number = EXCLUDED.ticket_number,
         iris_case_id = EXCLUDED.iris_case_id,
         case_name = EXCLUDED.case_name,
         severity = EXCLUDED.severity,
         status = EXCLUDED.status,
         created_by_user_id = EXCLUDED.created_by_user_id,
         created_by_name = EXCLUDED.created_by_name,
         reviewed_by_user_id = EXCLUDED.reviewed_by_user_id,
         reviewed_by_name = EXCLUDED.reviewed_by_name,
         reviewed_at = EXCLUDED.reviewed_at,
         approval_id = EXCLUDED.approval_id,
         approval_status = EXCLUDED.approval_status,
         data = EXCLUDED.data,
         updated_at = EXCLUDED.updated_at`,
      [
        entry.id,
        entry.workspace || 'asoc',
        entry.mode || 'reporting',
        entry.tenant || null,
        entry.ticketNumber || null,
        entry.irisCaseId || null,
        entry.caseName || null,
        entry.severity || null,
        entry.status || 'running',
        entry.createdByUserId || null,
        entry.createdByName || null,
        entry.reviewedByUserId || null,
        entry.reviewedByName || null,
        entry.reviewedAt || null,
        entry.approvalId || null,
        entry.approvalStatus || null,
        JSON.stringify(entry),
        asIso(entry.createdAt, now),
        asIso(entry.updatedAt, now),
      ],
    );
  }

  async function deleteHistory(id) {
    await query('DELETE FROM history_entries WHERE id = $1', [id]);
  }

  async function upsertApproval(entry) {
    const now = new Date().toISOString();
    await query(
      `INSERT INTO approvals (
         id, workspace, status, job_id, exec_id, iris_case_id, case_name, tenant, severity, resume_url,
         created_by_user_id, created_by_name, decided_by_user_id, decided_by, decided_at, decision, reason,
         data, created_at, updated_at
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15::timestamptz, $16, $17, $18::jsonb, $19::timestamptz, $20::timestamptz)
       ON CONFLICT (id) DO UPDATE SET
         workspace = EXCLUDED.workspace,
         status = EXCLUDED.status,
         job_id = EXCLUDED.job_id,
         exec_id = EXCLUDED.exec_id,
         iris_case_id = EXCLUDED.iris_case_id,
         case_name = EXCLUDED.case_name,
         tenant = EXCLUDED.tenant,
         severity = EXCLUDED.severity,
         resume_url = EXCLUDED.resume_url,
         created_by_user_id = EXCLUDED.created_by_user_id,
         created_by_name = EXCLUDED.created_by_name,
         decided_by_user_id = EXCLUDED.decided_by_user_id,
         decided_by = EXCLUDED.decided_by,
         decided_at = EXCLUDED.decided_at,
         decision = EXCLUDED.decision,
         reason = EXCLUDED.reason,
         data = EXCLUDED.data,
         updated_at = EXCLUDED.updated_at`,
      [
        entry.id,
        entry.workspace || 'asoc',
        entry.status || 'pending',
        entry.jobId || null,
        entry.execId || null,
        entry.irisCaseId || null,
        entry.caseName || null,
        entry.tenant || null,
        entry.severity || null,
        entry.resumeUrl || null,
        entry.createdByUserId || null,
        entry.createdByName || null,
        entry.decidedByUserId || null,
        entry.decidedBy || null,
        entry.decidedAt || null,
        entry.decision || null,
        entry.reason || null,
        JSON.stringify(entry),
        asIso(entry.createdAt, now),
        asIso(entry.updatedAt, now),
      ],
    );
  }

  async function deleteApproval(id) {
    await query('DELETE FROM approvals WHERE id = $1', [id]);
  }

  async function upsertRejection(entry) {
    const now = new Date().toISOString();
    await query(
      `INSERT INTO rejections (
         id, workspace, status, approval_id, job_id, exec_id, iris_case_id, case_name, tenant,
         decided_by_user_id, decided_by, completed_by_user_id, completed_by, data, created_at, updated_at
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb, $15::timestamptz, $16::timestamptz)
       ON CONFLICT (id) DO UPDATE SET
         workspace = EXCLUDED.workspace,
         status = EXCLUDED.status,
         approval_id = EXCLUDED.approval_id,
         job_id = EXCLUDED.job_id,
         exec_id = EXCLUDED.exec_id,
         iris_case_id = EXCLUDED.iris_case_id,
         case_name = EXCLUDED.case_name,
         tenant = EXCLUDED.tenant,
         decided_by_user_id = EXCLUDED.decided_by_user_id,
         decided_by = EXCLUDED.decided_by,
         completed_by_user_id = EXCLUDED.completed_by_user_id,
         completed_by = EXCLUDED.completed_by,
         data = EXCLUDED.data,
         updated_at = EXCLUDED.updated_at`,
      [
        entry.id,
        entry.workspace || 'asoc',
        entry.status || 'open',
        entry.approvalId || null,
        entry.jobId || null,
        entry.execId || null,
        entry.irisCaseId || null,
        entry.caseName || null,
        entry.tenant || null,
        entry.decidedByUserId || null,
        entry.decidedBy || null,
        entry.completedByUserId || null,
        entry.completedBy || null,
        JSON.stringify(entry),
        asIso(entry.createdAt, now),
        asIso(entry.updatedAt, now),
      ],
    );
  }

  async function deleteRejection(id) {
    await query('DELETE FROM rejections WHERE id = $1', [id]);
  }

  async function close() {
    if (closed) return;
    closed = true;
    if (ownsPool && pool && typeof pool.end === 'function') {
      await pool.end();
    }
  }

  return {
    query,
    connectWithRetry,
    initSchema,
    loadAllDomainData,
    upsertWorkspaceCounter,
    upsertHistory,
    deleteHistory,
    upsertApproval,
    deleteApproval,
    upsertRejection,
    deleteRejection,
    close,
  };
}

module.exports = {
  SCHEMA_STATEMENTS,
  hasPostgresConfig,
  buildPoolConfig,
  createPostgresBackend,
};

