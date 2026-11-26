'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { execFileSync } = require('node:child_process');

const db = require('../src/config/db.js');
const auth = require('../src/middleware/auth.js');
const { createServer, createStore } = require('../src/server.js');

function req(port, method, urlPath, body, cookie = '', extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const payload = body !== undefined ? JSON.stringify(body) : null;
    const headers = { ...extraHeaders };
    if (cookie) headers.cookie = cookie;
    if (payload) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = Buffer.byteLength(payload);
    }
    const r = http.request({ hostname: '127.0.0.1', port, path: urlPath, method, headers }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch {}
        const setCookie = res.headers['set-cookie'];
        const firstCookie = Array.isArray(setCookie) ? setCookie[0] : setCookie;
        const parsedCookie = firstCookie ? firstCookie.split(';')[0] : null;
        resolve({ status: res.statusCode, headers: res.headers, cookie: parsedCookie, text: data, json });
      });
    });
    r.on('error', reject);
    if (payload) r.write(payload);
    r.end();
  });
}

// Lightweight in-memory mock pg Pool supporting db.js & auth.js queries
function createMockPgPool() {
  const tables = {
    users: new Map(),
    sessions: new Map(),
    workspace_counters: new Map(),
    history_entries: new Map(),
    approvals: new Map(),
    rejections: new Map(),
  };

  return {
    tables,
    async query(sql, params = []) {
      const s = String(sql).replace(/\s+/g, ' ').trim();
      if (s === 'SELECT 1') return { rows: [{ '?column?': 1 }] };
      if (/^CREATE (TABLE|UNIQUE INDEX|INDEX) IF NOT EXISTS/i.test(s)) return { rows: [] };

      if (s.startsWith('SELECT COUNT(*)::int AS cnt FROM users WHERE role')) {
        let cnt = 0;
        for (const u of tables.users.values()) {
          if (u.role === 'admin' && u.is_active && u.id !== params[0]) cnt++;
        }
        return { rows: [{ cnt }] };
      }
      if (s.startsWith('SELECT COUNT(*)::int AS cnt FROM users')) {
        return { rows: [{ cnt: tables.users.size }] };
      }
      if (s.includes('FROM users WHERE LOWER(username) = LOWER($1)')) {
        const target = String(params[0] || '').toLowerCase();
        for (const u of tables.users.values()) {
          if (u.username.toLowerCase() === target) return { rows: [u] };
        }
        return { rows: [] };
      }
      if (s.includes('FROM users WHERE id = $1')) {
        const u = tables.users.get(params[0]);
        return { rows: u ? [u] : [] };
      }
      if (s.includes('FROM users ORDER BY')) {
        const rows = Array.from(tables.users.values()).sort((a, b) => {
          const ra = a.role === 'admin' ? 0 : 1;
          const rb = b.role === 'admin' ? 0 : 1;
          if (ra !== rb) return ra - rb;
          return String(a.created_at).localeCompare(String(b.created_at));
        });
        return { rows };
      }
      if (s.startsWith('INSERT INTO users')) {
        const [id, username, display_name, role, password_hash, is_active, created_at, updated_at] = params;
        for (const u of tables.users.values()) {
          if (u.username.toLowerCase() === String(username).toLowerCase()) {
            const err = new Error('duplicate key');
            err.code = '23505';
            throw err;
          }
        }
        const row = { id, username, display_name, role, password_hash, is_active, created_at, updated_at };
        tables.users.set(id, row);
        return { rows: [row] };
      }
      if (s.startsWith('UPDATE users SET display_name')) {
        const [display_name, role, is_active, password_hash, updated_at, id] = params;
        const row = tables.users.get(id);
        if (!row) return { rows: [] };
        Object.assign(row, { display_name, role, is_active, password_hash, updated_at });
        return { rows: [row] };
      }
      if (s.startsWith('UPDATE users SET password_hash')) {
        const [password_hash, updated_at, id] = params;
        const row = tables.users.get(id);
        if (row) Object.assign(row, { password_hash, updated_at });
        return { rows: [] };
      }
      if (s.startsWith('DELETE FROM users WHERE id = $1')) {
        tables.users.delete(params[0]);
        for (const [th, sess] of tables.sessions.entries()) {
          if (sess.user_id === params[0]) tables.sessions.delete(th);
        }
        return { rows: [] };
      }

      if (s === 'DELETE FROM sessions WHERE expires_at <= NOW()') {
        for (const [th, sess] of tables.sessions.entries()) {
          if (Date.parse(sess.expires_at) <= Date.now()) tables.sessions.delete(th);
        }
        return { rows: [] };
      }
      if (s.startsWith('INSERT INTO sessions')) {
        const [token_hash, user_id, expires_at, created_at, last_seen_at, user_agent] = params;
        tables.sessions.set(token_hash, { token_hash, user_id, expires_at, created_at, last_seen_at, user_agent });
        return { rows: [] };
      }
      if (s.includes('FROM sessions s JOIN users u')) {
        const sess = tables.sessions.get(params[0]);
        if (!sess || Date.parse(sess.expires_at) <= Date.now()) return { rows: [] };
        const user = tables.users.get(sess.user_id);
        if (!user || !user.is_active) return { rows: [] };
        return { rows: [{ ...user, expires_at: sess.expires_at }] };
      }
      if (s.startsWith('DELETE FROM sessions WHERE token_hash = $1')) {
        tables.sessions.delete(params[0]);
        return { rows: [] };
      }
      if (s.startsWith('DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2')) {
        for (const [th, sess] of tables.sessions.entries()) {
          if (sess.user_id === params[0] && th !== params[1]) tables.sessions.delete(th);
        }
        return { rows: [] };
      }
      if (s.startsWith('DELETE FROM sessions WHERE user_id = $1')) {
        for (const [th, sess] of tables.sessions.entries()) {
          if (sess.user_id === params[0]) tables.sessions.delete(th);
        }
        return { rows: [] };
      }

      if (s.startsWith('SELECT workspace, last_iris_case_id')) {
        return { rows: Array.from(tables.workspace_counters.values()) };
      }
      if (s.startsWith('INSERT INTO workspace_counters')) {
        const [workspace, last_iris_case_id, tickets_by_tenant, tenants, updated_at, updated_by] = params;
        tables.workspace_counters.set(workspace, {
          workspace,
          last_iris_case_id,
          tickets_by_tenant: JSON.parse(tickets_by_tenant),
          tenants: JSON.parse(tenants),
          updated_at,
          updated_by,
        });
        return { rows: [] };
      }
      if (s.startsWith('SELECT data FROM history_entries')) {
        return { rows: Array.from(tables.history_entries.values()).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).map((r) => ({ data: r.data })) };
      }
      if (s.startsWith('INSERT INTO history_entries')) {
        const [id, workspace, mode, tenant, ticket_number, iris_case_id, case_name, severity, status, created_by_user_id, created_by_name, reviewed_by_user_id, reviewed_by_name, reviewed_at, approval_id, approval_status, data, created_at, updated_at] = params;
        tables.history_entries.set(id, { id, workspace, mode, tenant, ticket_number, iris_case_id, case_name, severity, status, created_by_user_id, created_by_name, reviewed_by_user_id, reviewed_by_name, reviewed_at, approval_id, approval_status, data: JSON.parse(data), created_at, updated_at });
        return { rows: [] };
      }
      if (s.startsWith('DELETE FROM history_entries')) {
        tables.history_entries.delete(params[0]);
        return { rows: [] };
      }
      if (s.startsWith('SELECT data FROM approvals')) {
        return { rows: Array.from(tables.approvals.values()).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).map((r) => ({ data: r.data })) };
      }
      if (s.startsWith('INSERT INTO approvals')) {
        const [id, workspace, status, job_id, exec_id, iris_case_id, case_name, tenant, severity, resume_url, created_by_user_id, created_by_name, decided_by_user_id, decided_by, decided_at, decision, reason, data, created_at, updated_at] = params;
        tables.approvals.set(id, { id, workspace, status, job_id, exec_id, iris_case_id, case_name, tenant, severity, resume_url, created_by_user_id, created_by_name, decided_by_user_id, decided_by, decided_at, decision, reason, data: JSON.parse(data), created_at, updated_at });
        return { rows: [] };
      }
      if (s.startsWith('DELETE FROM approvals')) {
        tables.approvals.delete(params[0]);
        return { rows: [] };
      }
      if (s.startsWith('SELECT data FROM rejections')) {
        return { rows: Array.from(tables.rejections.values()).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).map((r) => ({ data: r.data })) };
      }
      if (s.startsWith('INSERT INTO rejections')) {
        const [id, workspace, status, approval_id, job_id, exec_id, iris_case_id, case_name, tenant, decided_by_user_id, decided_by, completed_by_user_id, completed_by, data, created_at, updated_at] = params;
        tables.rejections.set(id, { id, workspace, status, approval_id, job_id, exec_id, iris_case_id, case_name, tenant, decided_by_user_id, decided_by, completed_by_user_id, completed_by, data: JSON.parse(data), created_at, updated_at });
        return { rows: [] };
      }
      if (s.startsWith('DELETE FROM rejections')) {
        tables.rejections.delete(params[0]);
        return { rows: [] };
      }

      throw new Error('Unhandled mock SQL: ' + s);
    },
    async end() {},
  };
}

(async () => {
  // 1. Password crypto & validation
  const h1 = auth.hashPassword('rahasia123');
  assert.ok(h1.startsWith('scrypt$'));
  assert.equal(auth.verifyPassword('rahasia123', h1), true);
  assert.equal(auth.verifyPassword('salah', h1), false);
  assert.equal(db.hasPostgresConfig({ DATABASE_URL: 'postgres://u:p@h:5432/db' }), true);
  assert.equal(db.hasPostgresConfig({ PGHOST: 'postgres' }), true);
  assert.equal(db.hasPostgresConfig({}), false);

  // 2. JSON-to-PostgreSQL auto-migration + persistence via mock PG pool
  const migDir = fs.mkdtempSync(path.join(os.tmpdir(), 'diptera-pg-mig-'));
  fs.writeFileSync(path.join(migDir, 'counters.json'), JSON.stringify({
    version: 2,
    asoc: { lastIrisCaseId: '#700', ticketsByTenant: { petra: '30200' }, tenants: ['petra'] },
    soc: { lastIrisCaseId: '#100', ticketsByTenant: { petra: '10100' }, tenants: ['petra'] },
  }));
  fs.writeFileSync(path.join(migDir, 'history.json'), JSON.stringify([
    { id: 'job_mig_1', workspace: 'asoc', tenant: 'petra', irisCaseId: '#700', status: 'done', caseName: 'Migrated Case', createdAt: '2026-11-24T00:00:00.000Z' },
  ]));

  const mockPool = createMockPgPool();
  const migBackend = db.createPostgresBackend({ pool: mockPool });
  const migStore = createStore(migDir, {}, { pgBackend: migBackend });
  await migStore.ready;
  assert.equal(mockPool.tables.workspace_counters.get('asoc').last_iris_case_id, '#700');
  assert.equal(mockPool.tables.history_entries.get('job_mig_1').case_name, 'Migrated Case');

  // 3. Full HTTP + Auth + RBAC + Case Attribution + PG Persistence test
  const mockWebhookCalls = [];
  const mockN8n = http.createServer((mReq, mRes) => {
    const chunks = [];
    mReq.on('data', (c) => chunks.push(c));
    mReq.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      mockWebhookCalls.push({ path: mReq.url, body: raw ? JSON.parse(raw) : null });
      mRes.writeHead(200, { 'content-type': 'application/json' });
      mRes.end('{"ok":true}');
    });
  });
  await new Promise((r) => mockN8n.listen(0, '127.0.0.1', r));
  const mockPort = mockN8n.address().port;

  const pgPool = createMockPgPool();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'diptera-auth-test-'));
  const server = createServer({
    dataDir,
    pool: pgPool,
    env: {
      AUTH_ENABLED: 'true',
      ADMIN_USERNAME: 'superadmin',
      ADMIN_PASSWORD: 'AdminPassword!1',
      ADMIN_DISPLAY_NAME: 'SOC Lead Admin',
      ASOC_N8N_BASE_URL: `http://127.0.0.1:${mockPort}`,
    },
  });
  await server.ready;
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  try {
    // 3a. /config.js exposes authEnabled: true
    const cfgRes = await req(port, 'GET', '/config.js');
    assert.equal(cfgRes.status, 200);
    assert.ok(cfgRes.text.includes('"authEnabled":true'));

    // 3b. Unauthenticated /api/auth/me & protected routes return 401 AUTH_REQUIRED
    const meAnon = await req(port, 'GET', '/api/auth/me');
    assert.equal(meAnon.status, 200);
    assert.equal(meAnon.json.authEnabled, true);
    assert.equal(meAnon.json.authenticated, false);

    for (const p of ['/api/state', '/api/history', '/api/approvals', '/api/users']) {
      const unauth = await req(port, 'GET', p);
      assert.equal(unauth.status, 401, `${p} must require auth`);
      assert.equal(unauth.json.code, 'AUTH_REQUIRED');
    }

    // 3c. Failed login returns 401 & rate limits on 10th attempt
    const badLogin = await req(port, 'POST', '/api/auth/login', { username: 'superadmin', password: 'wrong' });
    assert.equal(badLogin.status, 401);

    for (let i = 0; i < 10; i++) {
      await req(port, 'POST', '/api/auth/login', { username: 'ratelimit_user', password: 'bad' });
    }
    const rateLimited = await req(port, 'POST', '/api/auth/login', { username: 'ratelimit_user', password: 'bad' });
    assert.equal(rateLimited.status, 429);

    // 3d. Admin login sets HttpOnly cookie
    const adminLogin = await req(port, 'POST', '/api/auth/login', {
      username: 'superadmin',
      password: 'AdminPassword!1',
    });
    assert.equal(adminLogin.status, 200);
    assert.equal(adminLogin.json.user.role, 'admin');
    assert.equal(adminLogin.json.user.displayName, 'SOC Lead Admin');
    assert.ok(adminLogin.headers['set-cookie'][0].includes('HttpOnly'));
    const adminCookie = adminLogin.cookie;

    // 3e. Admin creates Analyst user; duplicate username rejected (409)
    const createdAnalyst = await req(port, 'POST', '/api/users', {
      username: 'budi.soc',
      displayName: 'Budi Analis',
      role: 'analyst',
      password: 'AnalystPass123',
    }, adminCookie);
    assert.equal(createdAnalyst.status, 201);
    const analystId = createdAnalyst.json.user.id;

    const dupUser = await req(port, 'POST', '/api/users', {
      username: 'BUDI.SOC',
      displayName: 'Dup',
      role: 'analyst',
      password: 'AnalystPass123',
    }, adminCookie);
    assert.equal(dupUser.status, 409);

    // 3f. Analyst logs in & cannot access /api/users (403)
    const analystLogin = await req(port, 'POST', '/api/auth/login', {
      username: 'budi.soc',
      password: 'AnalystPass123',
    });
    assert.equal(analystLogin.status, 200);
    const analystCookie = analystLogin.cookie;

    const analystUsersBlocked = await req(port, 'GET', '/api/users', undefined, analystCookie);
    assert.equal(analystUsersBlocked.status, 403);

    // 3g. Analyst creates case -> createdBy stamped & saved to PostgreSQL
    const jobRes = await req(port, 'POST', '/api/history', {
      id: 'job_attr_1',
      workspace: 'asoc',
      mode: 'reporting',
      tenant: 'petra',
      ticketNumber: '30500',
      irisCaseId: '#801',
      caseName: '[HIGH] Suspicious Login',
      severity: 'HIGH',
      status: 'running',
    }, analystCookie);
    assert.equal(jobRes.status, 201);
    assert.equal(jobRes.json.record.createdByName, 'Budi Analis');
    assert.equal(jobRes.json.record.createdByUsername, 'budi.soc');
    assert.equal(jobRes.json.record.createdByUserId, analystId);
    assert.equal(pgPool.tables.history_entries.get('job_attr_1').created_by_name, 'Budi Analis');

    // 3h. Machine-to-machine n8n callbacks work WITHOUT session cookie & preserve createdBy
    const cbRes = await req(port, 'POST', '/api/n8n-callback', {
      jobId: 'job_attr_1',
      event: 'report_ready',
      workspace: 'asoc',
      caseId: 801,
      caseName: '[HIGH] Suspicious Login Final',
      severity: 'HIGH',
      markdown: '## Report',
    });
    assert.equal(cbRes.status, 200);
    assert.equal(cbRes.json.record.createdByName, 'Budi Analis');

    // n8n creates approval without browser cookie -> inherits createdByName from history
    const apprRes = await req(port, 'POST', '/api/approvals', {
      resumeUrl: `http://127.0.0.1:${mockPort}/webhook-waiting/exec-801`,
      workspace: 'asoc',
      jobId: 'job_attr_1',
      caseId: 801,
      caseName: '[HIGH] Suspicious Login Final',
      tenant: 'petra',
      severity: 'HIGH',
    });
    assert.equal(apprRes.status, 201);
    assert.equal(apprRes.json.approval.createdByName, 'Budi Analis');
    const aprId = apprRes.json.approval.id;

    // 3i. Admin approves (even if client sends spoofed decidedBy) -> server stamps logged-in Admin
    const decideRes = await req(port, 'POST', `/api/approvals/${aprId}/decide`, {
      decision: 'approve',
      reason: 'Valid incident',
      decidedBy: 'Spoofed Name',
    }, adminCookie);
    assert.equal(decideRes.status, 200);
    assert.equal(decideRes.json.approval.decidedBy, 'SOC Lead Admin');
    assert.equal(decideRes.json.approval.decidedByUsername, 'superadmin');
    assert.equal(mockWebhookCalls[0].body.decidedBy, 'SOC Lead Admin');

    // History row now has BOTH creator and reviewer & is searchable by creator or reviewer name
    const histAfterApprove = await req(port, 'GET', '/api/history/job_attr_1', undefined, analystCookie);
    assert.equal(histAfterApprove.json.record.createdByName, 'Budi Analis');
    assert.equal(histAfterApprove.json.record.reviewedByName, 'SOC Lead Admin');
    assert.equal(histAfterApprove.json.record.approvalStatus, 'approved');
    assert.equal(pgPool.tables.history_entries.get('job_attr_1').reviewed_by_name, 'SOC Lead Admin');

    const histSearchReviewer = await req(port, 'GET', '/api/history?workspace=asoc&q=SOC%20Lead%20Admin', undefined, analystCookie);
    assert.equal(histSearchReviewer.json.items.length, 1);

    // 3j. Rejection & completion by analyst stamps completedBy from session
    const rejCreate = await req(port, 'POST', '/api/rejections', {
      resumeUrl: `http://127.0.0.1:${mockPort}/webhook-waiting/rev-802`,
      workspace: 'asoc',
      jobId: 'job_attr_1',
      caseId: 801,
      caseName: '[HIGH] Suspicious Login Final',
      reason: 'Need more IOCs',
    });
    assert.equal(rejCreate.status, 201);
    assert.equal(rejCreate.json.rejection.createdByName, 'Budi Analis');
    const rejComplete = await req(port, 'POST', `/api/rejections/${rejCreate.json.rejection.id}/complete`, {
      completedBy: 'Fake',
    }, analystCookie);
    assert.equal(rejComplete.status, 200);
    assert.equal(rejComplete.json.rejection.completedBy, 'Budi Analis');

    // 3k. Analyst changes own password & old password fails
    const pwChange = await req(port, 'POST', '/api/auth/password', {
      currentPassword: 'AnalystPass123',
      newPassword: 'AnalystNewPass!9',
    }, analystCookie);
    assert.equal(pwChange.status, 200);

    const oldPwFail = await req(port, 'POST', '/api/auth/login', { username: 'budi.soc', password: 'AnalystPass123' });
    assert.equal(oldPwFail.status, 401);
    const newPwOk = await req(port, 'POST', '/api/auth/login', { username: 'budi.soc', password: 'AnalystNewPass!9' });
    assert.equal(newPwOk.status, 200);
    const analystCookie2 = newPwOk.cookie;

    // 3l. Admin resets analyst password -> revokes analyst's existing sessions
    const adminReset = await req(port, 'PATCH', `/api/users/${analystId}`, {
      password: 'ResetByAdmin!2',
    }, adminCookie);
    assert.equal(adminReset.status, 200);
    const revokedCheck = await req(port, 'GET', '/api/state', undefined, analystCookie2);
    assert.equal(revokedCheck.status, 401);

    // 3m. Admin safety rules: cannot self-delete, cannot demote last active admin
    const adminRow = (await req(port, 'GET', '/api/users', undefined, adminCookie)).json.users.find((u) => u.username === 'superadmin');
    const selfDel = await req(port, 'DELETE', `/api/users/${adminRow.id}`, undefined, adminCookie);
    assert.equal(selfDel.status, 400);
    const demoteLast = await req(port, 'PATCH', `/api/users/${adminRow.id}`, { role: 'analyst' }, adminCookie);
    assert.equal(demoteLast.status, 400);

    // 3n. Admin deletes analyst -> history record retains createdByName audit trail
    const delAnalyst = await req(port, 'DELETE', `/api/users/${analystId}`, undefined, adminCookie);
    assert.equal(delAnalyst.status, 200);
    const histPreserved = await req(port, 'GET', '/api/history/job_attr_1', undefined, adminCookie);
    assert.equal(histPreserved.json.record.createdByName, 'Budi Analis');

    // 3o. Logout invalidates cookie
    const logoutRes = await req(port, 'POST', '/api/auth/logout', {}, adminCookie);
    assert.equal(logoutRes.status, 200);
    const afterLogout = await req(port, 'GET', '/api/state', undefined, adminCookie);
    assert.equal(afterLogout.status, 401);

    // 3p. Verify UI HTML/CSS/JS contain login, user management, attribution & scroll-preservation hooks
    const html = (await req(port, 'GET', '/')).text;
    assert.ok(html.includes('id="auth-screen"'));
    assert.ok(html.includes('id="user-modal"'));
    assert.ok(html.includes('Analis / Reviewer'));
    const js = (await req(port, 'GET', '/js/app.js')).text;
    assert.ok(js.includes('handleLoginSubmit'));
    assert.ok(js.includes('handleCreateUser'));
    assert.ok(js.includes('createdByName'));
    assert.ok(js.includes('updateApprovalCountdownsInPlace'));
    assert.ok(js.includes('data-pre-kind'));
    assert.ok(js.includes('domAlreadyRendered'));
    assert.ok(js.includes('replaceChildren'));
    const css = (await req(port, 'GET', '/css/styles.css')).text;
    assert.ok(css.includes('.auth-screen'));
    assert.ok(css.includes('.modal-card'));
    assert.ok(css.includes('overscroll-behavior: contain'));

    // 4. Hash-only bootstrap (ADMIN_PASSWORD_HASH) & hashed API secret (APPROVAL_API_SECRET_HASH) + CLI helper
    const cliAdminHash = execFileSync('node', [path.join(__dirname, '..', 'src', 'middleware', 'auth.js'), 'hash', 'PreHashedAdmin!9'], { encoding: 'utf8' }).trim();
    const cliSecretHash = execFileSync('node', [path.join(__dirname, '..', 'src', 'middleware', 'auth.js'), 'hash-secret', 'hashed-n8n-secret'], { encoding: 'utf8' }).trim();
    assert.equal(auth.isValidPasswordHash(cliAdminHash), true);
    assert.ok(cliSecretHash.startsWith('sha256$'));
    assert.equal(auth.verifyApiSecretHash('hashed-n8n-secret', cliSecretHash), true);

    const hashPool = createMockPgPool();
    const hashDir = fs.mkdtempSync(path.join(os.tmpdir(), 'diptera-hash-env-'));
    const hashServer = createServer({
      dataDir: hashDir,
      pool: hashPool,
      env: {
        AUTH_ENABLED: 'true',
        ADMIN_USERNAME: 'hashadmin',
        ADMIN_PASSWORD_HASH: cliAdminHash,
        APPROVAL_API_SECRET_HASH: cliSecretHash,
      },
    });
    await hashServer.ready;
    await new Promise((r) => hashServer.listen(0, '127.0.0.1', r));
    const hashPort = hashServer.address().port;
    try {
      const hashLogin = await req(hashPort, 'POST', '/api/auth/login', {
        username: 'hashadmin',
        password: 'PreHashedAdmin!9',
      });
      assert.equal(hashLogin.status, 200);
      assert.equal(hashLogin.json.user.role, 'admin');

      const badSec = await req(hashPort, 'POST', '/api/approvals', { resumeUrl: 'http://127.0.0.1/hook' });
      assert.equal(badSec.status, 401);
      const okSec = await req(
        hashPort,
        'POST',
        '/api/approvals',
        { resumeUrl: 'http://127.0.0.1/hook', caseName: 'Hashed Secret Case' },
        '',
        { 'X-Diptera-Secret': 'hashed-n8n-secret' },
      );
      assert.equal(okSec.status, 201);
    } finally {
      await new Promise((r) => hashServer.close(r));
      fs.rmSync(hashDir, { recursive: true, force: true });
    }

    // 5. Verify .gitignore covers sensitive/local files while keeping .env.example unignored
    const repoRoot = path.join(__dirname, '..');
    const checkIgnored = (relPath) => {
      try {
        execFileSync('git', ['check-ignore', '-q', relPath], { cwd: repoRoot });
        return true;
      } catch {
        return false;
      }
    };
    for (const sensitive of [
      '.env',
      '.env.local',
      'backup.sql',
      'secret.key',
      'credentials.json',
      'server-config.json',
      'data/server-config.json',
      'docker-compose.override.yml',
      'Alpha Reporter v2 (1).json',
      'workflows/Alpha Reporter v2 (1).json',
      'finding.md',
      'docs/finding.md',
      'update.md',
      'docs/update.md',
      'Dokumentasi Diptera.md',
      'docs/Dokumentasi Diptera.md'
    ]) {
      assert.equal(checkIgnored(sensitive), true, `${sensitive} must be ignored by .gitignore`);
    }
    assert.equal(checkIgnored('.env.example'), false, '.env.example must stay tracked');

    console.log('ALL_AUTH_AND_ATTRIBUTION_TESTS_PASSED');
  } finally {
    await new Promise((r) => server.close(r));
    await new Promise((r) => mockN8n.close(r));
    fs.rmSync(migDir, { recursive: true, force: true });
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
})();

