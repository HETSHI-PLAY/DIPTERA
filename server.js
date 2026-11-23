/* Unified Diptera Server — Static assets + dual-workspace (ASOC & SOC) counters & history API.
 *
 * Fitur backend ringan:
 *   - Whitelist file aplikasi statis + /healthz + /config.js dinamis dari env
 *   - Counter bersama lintas user terpisah per workspace (asoc & soc) di data/counters.json (auto-migrate v1 -> v2)
 *   - Riwayat bersama lintas user terpisah per workspace (metadata + markdown, TANPA raw alert) di data/history.json
 *   - Webhook callback /api/n8n-callback untuk Alpha Reporter v2 (update otomatis walau browser tutup)
 */
'use strict';

const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const numbering = require('./numbering.js');

const ROOT = __dirname;

function loadEnvFallback(filePath) {
  if (typeof process.loadEnvFile === 'function') {
    try {
      process.loadEnvFile(filePath);
      return;
    } catch {
      return;
    }
  }
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eq = trimmed.indexOf('=');
      if (eq <= 0) continue;
      const key = trimmed.slice(0, eq).trim();
      let val = trimmed.slice(eq + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      if (process.env[key] === undefined) process.env[key] = val;
    }
  } catch {
    // .env opsional
  }
}

loadEnvFallback(path.join(ROOT, '.env'));

const HOST = process.env.HOST || '0.0.0.0';
const PORT = Number(process.env.PORT) || 8787;
const DEFAULT_DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
const MAX_HISTORY = 1000;
const MAX_APPROVALS = 1000;
const MAX_REJECTIONS = 500;
const MAX_BODY_BYTES = 2 * 1024 * 1024;
const DEFAULT_APPROVAL_RESUME_TIMEOUT_MS = 15000;
const WORKSPACES = ['asoc', 'soc'];

const APP_FILES = {
  '/': 'index.html',
  '/index.html': 'index.html',
  '/styles.css': 'styles.css',
  '/tenants.css': 'tenants.css',
  '/app.js': 'app.js',
  '/extract.js': 'extract.js',
  '/numbering.js': 'numbering.js',
  '/config.js': 'config.js',
};

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function normalizeWorkspace(val, fallback = 'asoc') {
  const s = String(val || '').trim().toLowerCase();
  if (s === 'soc' || s === 'charlie') return 'soc';
  if (s === 'asoc' || s === 'alpha') return 'asoc';
  return fallback;
}

function isLocalHostname(hostname) {
  const h = String(hostname || '').toLowerCase();
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '[::1]' || h === '0.0.0.0';
}

function isVirtualInterface(name) {
  return /^(lo|docker|br-|veth|virbr|vmnet|vboxnet|tun|tap)/i.test(String(name || ''));
}

function lanUrls(port, interfaces) {
  const candidates = [];
  for (const [name, addrs] of Object.entries(interfaces || os.networkInterfaces())) {
    if (isVirtualInterface(name)) continue;
    for (const addr of addrs || []) {
      const family = typeof addr.family === 'string' ? addr.family : addr.family === 4 ? 'IPv4' : 'IPv6';
      if (family !== 'IPv4' || addr.internal) continue;
      candidates.push({ name, url: 'http://' + addr.address + ':' + port });
    }
  }
  candidates.sort((a, b) => Number(!/^(wl|en|eth)/i.test(a.name)) - Number(!/^(wl|en|eth)/i.test(b.name)));
  return candidates.map((c) => c.url);
}

function inContainer() {
  return process.env.IRIS_IN_CONTAINER === '1' || fs.existsSync('/.dockerenv');
}

function parseJsonArray(raw, fallback = []) {
  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(String(raw).trim());
    if (Array.isArray(parsed)) return parsed.map((t) => String(t).trim()).filter(Boolean);
  } catch {}
  return fallback;
}

function parseJsonObject(raw, fallback = {}) {
  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(String(raw).trim());
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
  } catch {}
  return fallback;
}

function parseBoolEnv(val) {
  const s = String(val || '').trim().toLowerCase();
  return s === 'true' || s === '1' || s === 'yes';
}

function parseHttpUrl(raw) {
  const s = String(raw || '').trim();
  if (!s) return null;
  try {
    const u = new URL(s);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return u;
  } catch {
    return null;
  }
}

function execIdFromResumeUrl(rawUrl) {
  const m = String(rawUrl || '').match(/\/(?:webhook-waiting|form-waiting)\/([^/?#]+)/);
  return m ? m[1] : null;
}

function isHostAllowed(urlObj, allowedHosts) {
  if (!Array.isArray(allowedHosts) || !allowedHosts.length) return true;
  const host = String(urlObj.host || '').toLowerCase();
  const hostname = String(urlObj.hostname || '').toLowerCase();
  return allowedHosts.includes(host) || allowedHosts.includes(hostname);
}

function resolveResumeUrl(rawUrl, wsBaseUrl, rewriteLocalhost) {
  const u = parseHttpUrl(rawUrl);
  if (!u) return null;
  if (rewriteLocalhost && isLocalHostname(u.hostname)) {
    const b = parseHttpUrl(wsBaseUrl);
    if (b && !isLocalHostname(b.hostname)) {
      u.protocol = b.protocol;
      u.host = b.host;
    }
  }
  return u.toString();
}

function sendWebhookResume({ url, method = 'POST', payload = {}, timeoutMs = DEFAULT_APPROVAL_RESUME_TIMEOUT_MS, allowInsecureTls = false }) {
  return new Promise((resolve, reject) => {
    const target = parseHttpUrl(url);
    if (!target) {
      return reject(Object.assign(new Error('resumeUrl tidak valid'), { status: 400 }));
    }
    const httpMethod = String(method || 'POST').toUpperCase() === 'GET' ? 'GET' : 'POST';
    let bodyBuf = null;
    const headers = {
      'user-agent': 'diptera-approval-proxy',
    };

    if (httpMethod === 'GET') {
      const queryKeys = [
        'approvalId',
        'decision',
        'approved',
        'status',
        'approvalStatus',
        'reason',
        'decidedBy',
        'decidedAt',
        'workspace',
        'caseId',
        'jobId',
      ];
      for (const k of queryKeys) {
        if (payload[k] !== undefined && payload[k] !== null && payload[k] !== '') {
          target.searchParams.set(k, String(payload[k]));
        }
      }
    } else {
      bodyBuf = Buffer.from(JSON.stringify(payload), 'utf8');
      headers['content-type'] = 'application/json';
      headers['content-length'] = bodyBuf.length;
    }

    const lib = target.protocol === 'https:' ? https : http;
    const reqOpts = {
      method: httpMethod,
      headers,
      timeout: timeoutMs,
    };
    if (target.protocol === 'https:') {
      reqOpts.rejectUnauthorized = !allowInsecureTls;
    }

    const req = lib.request(target, reqOpts, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => {
        if (size < 65536) {
          chunks.push(chunk);
          size += chunk.length;
        }
      });
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8').slice(0, 2000);
        resolve({ statusCode: res.statusCode || 0, body: text });
      });
    });

    req.on('timeout', () => {
      req.destroy(Object.assign(new Error('Timeout menghubungi webhook n8n (' + timeoutMs + ' ms)'), { status: 504 }));
    });
    req.on('error', (err) => {
      reject(Object.assign(new Error('Gagal menghubungi webhook n8n: ' + err.message), { status: err.status || 502 }));
    });

    if (bodyBuf) req.write(bodyBuf);
    req.end();
  });
}

function checkApprovalSecret(req, secret) {
  if (!secret) return true;
  const provided = String(req.headers['x-diptera-secret'] || '').trim();
  if (!provided || provided.length !== secret.length) return false;
  return crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(secret));
}

function parseEnvConfig(env = process.env) {
  const defaultWorkspace = normalizeWorkspace(env.DEFAULT_WORKSPACE, 'asoc');

  const asocTenantsDefault = ['wicida', 'instikibali', 'petra', 'praditauniversity', 'sgu', 'ikmicirebon'];
  const socTenantsDefault = ['petra', 'praditauniversity', 'wicida', 'instikibali', 'ikmicirebon', 'sgu'];

  const asocTenants = parseJsonArray(env.ASOC_TENANT_OPTIONS || env.TENANT_OPTIONS, asocTenantsDefault);
  const asocTickets = parseJsonObject(env.ASOC_INITIAL_TICKETS || env.INITIAL_TICKETS, {});
  const asocInitMap = parseJsonObject(env.ASOC_INITIAL_TENANTS || env.INITIAL_TENANTS, null);

  const socTenants = parseJsonArray(env.SOC_TENANT_OPTIONS, socTenantsDefault);
  const socTickets = parseJsonObject(env.SOC_INITIAL_TICKETS, {});
  const socInitMap = parseJsonObject(env.SOC_INITIAL_TENANTS, null);

  const asoc = {
    baseUrl: String(env.ASOC_N8N_BASE_URL || env.N8N_BASE_URL || 'http://10.20.100.65:5678').trim().replace(/\/+$/, ''),
    formPath: String(env.ASOC_FORM_PATH || env.DIPTERA_FORM_PATH || 'alpha-form').trim(),
    irisBaseUrl: String(env.ASOC_IRIS_BASE_URL || env.IRIS_BASE_URL || 'https://10.20.100.66').trim().replace(/\/+$/, ''),
    callbackUrl: String(env.ASOC_CALLBACK_URL || env.DIPTERA_CALLBACK_URL || '').trim(),
    caseIdMode: String(env.ASOC_CASE_ID_MODE || env.CASE_ID_MODE || 'auto_iris').trim() === 'manual' ? 'manual' : 'auto_iris',
    initialCaseId: String(env.ASOC_INITIAL_CASE_ID || env.INITIAL_CASE_ID || '').trim() || null,
    tenantOptions: asocInitMap ? Object.keys(asocInitMap).map((t) => String(t).trim()).filter(Boolean) : asocTenants,
    initialTickets: asocInitMap || asocTickets,
  };

  const soc = {
    baseUrl: String(env.SOC_N8N_BASE_URL || 'http://10.20.100.134:5678').trim().replace(/\/+$/, ''),
    formPath: String(env.SOC_FORM_PATH || 'Job-Creator').trim(),
    irisBaseUrl: String(env.SOC_IRIS_BASE_URL || '').trim().replace(/\/+$/, ''),
    callbackUrl: '',
    caseIdMode: 'manual',
    initialCaseId: String(env.SOC_INITIAL_CASE_ID || '').trim() || null,
    tenantOptions: socInitMap ? Object.keys(socInitMap).map((t) => String(t).trim()).filter(Boolean) : socTenants,
    initialTickets: socInitMap || socTickets,
  };

  const approvalAllowedHosts = String(env.APPROVAL_ALLOWED_HOSTS || '')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);

  return {
    defaultWorkspace,
    publicUrl: String(env.DIPTERA_PUBLIC_URL || '').trim().replace(/\/+$/, ''),
    approvalSecret: String(env.APPROVAL_API_SECRET || '').trim(),
    approvalAllowedHosts,
    approvalRewriteResumeHost: parseBoolEnv(env.APPROVAL_REWRITE_RESUME_HOST),
    approvalAllowInsecureTls: parseBoolEnv(env.APPROVAL_ALLOW_INSECURE_TLS),
    approvalResumeTimeoutMs: Math.max(2000, Number(env.APPROVAL_RESUME_TIMEOUT_MS) || DEFAULT_APPROVAL_RESUME_TIMEOUT_MS),
    workspaces: { asoc, soc },
  };
}

function normalizeCaseIdValue(val) {
  if (val == null) return null;
  const s = String(val).trim();
  if (!s || /^auto$/i.test(s) || /^n\/a$/i.test(s)) return null;
  return s.startsWith('#') ? s : (/^\d+$/.test(s) ? '#' + s : s);
}

function numericTail(val) {
  const n = numbering.lastNumber(val);
  return n ? n.value : null;
}

function shouldAdvance(currentVal, candidateVal, force) {
  if (!candidateVal) return false;
  if (force) return true;
  if (!currentVal) return true;
  const curNum = numericTail(currentVal);
  const nextNum = numericTail(candidateVal);
  if (curNum == null || nextNum == null) return true;
  return nextNum >= curNum;
}

function atomicWriteJson(filePath, data) {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = filePath + '.' + process.pid + '.' + Date.now() + '.' + Math.random().toString(36).slice(2, 7) + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', 'utf8');
  fs.renameSync(tmp, filePath);
}

function createStore(dataDir = DEFAULT_DATA_DIR, env = process.env) {
  const countersPath = path.join(dataDir, 'counters.json');
  const historyPath = path.join(dataDir, 'history.json');
  const approvalsPath = path.join(dataDir, 'approvals.json');
  const rejectionsPath = path.join(dataDir, 'rejections.json');
  const envCfg = parseEnvConfig(env);

  fs.mkdirSync(dataDir, { recursive: true });

  function defaultWorkspaceCounters(ws) {
    const cfg = envCfg.workspaces[ws];
    const tickets = {};
    for (const [k, v] of Object.entries(cfg.initialTickets || {})) {
      const key = String(k).trim();
      const val = String(v ?? '').trim();
      if (key && val) tickets[key] = val;
    }
    return {
      lastIrisCaseId: normalizeCaseIdValue(cfg.initialCaseId),
      ticketsByTenant: tickets,
      tenants: Array.from(new Set([...(cfg.tenantOptions || []), ...Object.keys(tickets)])),
      updatedAt: new Date().toISOString(),
      updatedBy: 'seed',
    };
  }

  function mergeWorkspaceCounters(ws, rawBucket) {
    const base = defaultWorkspaceCounters(ws);
    if (!rawBucket || typeof rawBucket !== 'object') return base;
    const mergedTickets = { ...base.ticketsByTenant, ...(rawBucket.ticketsByTenant || {}) };
    const mergedTenants = Array.isArray(rawBucket.tenants) && rawBucket.tenants.length
      ? rawBucket.tenants.map((t) => String(t).trim()).filter(Boolean)
      : base.tenants;
    return {
      lastIrisCaseId: rawBucket.lastIrisCaseId !== undefined ? normalizeCaseIdValue(rawBucket.lastIrisCaseId) : base.lastIrisCaseId,
      ticketsByTenant: mergedTickets,
      tenants: Array.from(new Set([...mergedTenants, ...Object.keys(mergedTickets)])),
      updatedAt: rawBucket.updatedAt || base.updatedAt,
      updatedBy: rawBucket.updatedBy || 'persisted',
    };
  }

  function loadCounters() {
    try {
      const raw = fs.readFileSync(countersPath, 'utf8');
      const parsed = JSON.parse(raw);
      // v2 format
      if (parsed && parsed.version === 2 && (parsed.asoc || parsed.soc)) {
        return {
          version: 2,
          asoc: mergeWorkspaceCounters('asoc', parsed.asoc),
          soc: mergeWorkspaceCounters('soc', parsed.soc),
        };
      }
      // v1 migration -> v2 (preserve all existing ASOC counters)
      const migrated = {
        version: 2,
        asoc: mergeWorkspaceCounters('asoc', parsed),
        soc: defaultWorkspaceCounters('soc'),
      };
      migrated.asoc.updatedBy = 'migrated-v1';
      atomicWriteJson(countersPath, migrated);
      return migrated;
    } catch {
      const seeded = {
        version: 2,
        asoc: defaultWorkspaceCounters('asoc'),
        soc: defaultWorkspaceCounters('soc'),
      };
      atomicWriteJson(countersPath, seeded);
      return seeded;
    }
  }

  function loadHistory() {
    try {
      const raw = fs.readFileSync(historyPath, 'utf8');
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      return parsed.map((item) => ({
        ...item,
        workspace: normalizeWorkspace(item.workspace, 'asoc'),
      }));
    } catch {
      return [];
    }
  }

  function loadApprovals() {
    try {
      const raw = fs.readFileSync(approvalsPath, 'utf8');
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      const allowedStatus = new Set(['pending', 'approved', 'denied', 'expired']);
      return parsed.map((item) => ({
        ...item,
        workspace: normalizeWorkspace(item.workspace, 'asoc'),
        status: allowedStatus.has(item.status) ? item.status : 'pending',
      }));
    } catch {
      return [];
    }
  }

  function loadRejections() {
    try {
      const raw = fs.readFileSync(rejectionsPath, 'utf8');
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      const allowedStatus = new Set(['open', 'acknowledged', 'resolved']);
      return parsed.map((item) => ({
        ...item,
        workspace: normalizeWorkspace(item.workspace, 'asoc'),
        status: allowedStatus.has(item.status) ? item.status : 'open',
      }));
    } catch {
      return [];
    }
  }

  let counters = loadCounters();
  let history = loadHistory();
  let approvals = loadApprovals();
  let rejections = loadRejections();
  const inFlightDecisions = new Set();
  let lock = Promise.resolve();

  function withLock(fn) {
    const run = lock.then(() => fn());
    lock = run.catch(() => {});
    return run;
  }

  function sanitizeHistoryPatch(input) {
    // Sengaja hanya menerima field metadata + markdown; raw alert TIDAK pernah disimpan.
    const out = {};
    const str = (v, max = 500) => (v == null ? null : String(v).trim().slice(0, max) || null);
    if (input.workspace !== undefined) out.workspace = normalizeWorkspace(input.workspace, 'asoc');
    if (input.mode !== undefined) out.mode = input.mode === 'repeating' ? 'repeating' : 'reporting';
    if (input.repeatOptions !== undefined && input.repeatOptions && typeof input.repeatOptions === 'object') {
      out.repeatOptions = {
        caseIdMode: String(input.repeatOptions.caseIdMode || 'auto_iris'),
        createIrisCase: Boolean(input.repeatOptions.createIrisCase),
        updateIrisSummary: Boolean(input.repeatOptions.updateIrisSummary),
        requireApproval: Boolean(input.repeatOptions.requireApproval),
        sendEmailPdf: Boolean(input.repeatOptions.sendEmailPdf),
        uploadGdoc: Boolean(input.repeatOptions.uploadGdoc),
        appendSheet: Boolean(input.repeatOptions.appendSheet),
        returnMarkdown: input.repeatOptions.returnMarkdown !== false,
      };
    }
    if (input.tenant !== undefined) out.tenant = str(input.tenant, 120);
    if (input.ticketNumber !== undefined) out.ticketNumber = str(input.ticketNumber, 120);
    if (input.irisCaseId !== undefined) out.irisCaseId = normalizeCaseIdValue(input.irisCaseId);
    if (input.caseName !== undefined) out.caseName = str(input.caseName, 300);
    if (input.severity !== undefined) out.severity = str(input.severity, 32)?.toUpperCase() || null;
    if (input.classification !== undefined) out.classification = str(input.classification, 64);
    if (input.status !== undefined) {
      const allowed = new Set(['queued', 'running', 'awaiting_approval', 'done', 'error']);
      out.status = allowed.has(input.status) ? input.status : 'running';
    }
    if (input.execId !== undefined) out.execId = str(input.execId, 120);
    if (input.waitingUrl !== undefined) out.waitingUrl = str(input.waitingUrl, 600);
    if (input.errorMsg !== undefined) out.errorMsg = str(input.errorMsg, 500);
    if (input.markdown !== undefined) {
      out.markdown = input.markdown == null ? null : String(input.markdown).slice(0, 300000);
    }
    if (input.source !== undefined) out.source = str(input.source, 64);
    if (input.approvalId !== undefined) out.approvalId = str(input.approvalId, 120);
    if (input.approvalStatus !== undefined) {
      const allowedAppr = new Set(['pending', 'approved', 'denied', 'expired']);
      out.approvalStatus = allowedAppr.has(input.approvalStatus) ? input.approvalStatus : null;
    }
    if (input.rejectionId !== undefined) out.rejectionId = str(input.rejectionId, 120);
    if (input.rejectionReason !== undefined) out.rejectionReason = str(input.rejectionReason, 2000);
    return out;
  }

  function sanitizeAlertData(raw) {
    if (raw === undefined || raw === null || raw === '') return null;
    if (typeof raw === 'string') {
      const trimmed = raw.trim();
      if (!trimmed) return null;
      try {
        const parsed = JSON.parse(trimmed);
        const serialized = JSON.stringify(parsed);
        if (serialized.length <= 50000) return parsed;
        return serialized.slice(0, 50000) + '… [truncated]';
      } catch {
        return trimmed.slice(0, 50000);
      }
    }
    if (typeof raw === 'object') {
      try {
        const serialized = JSON.stringify(raw);
        if (serialized.length <= 50000) return JSON.parse(serialized);
        return serialized.slice(0, 50000) + '… [truncated]';
      } catch {
        return null;
      }
    }
    return String(raw).slice(0, 50000);
  }

  function sanitizeMetadataMap(raw) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
    const out = {};
    let count = 0;
    for (const [k, v] of Object.entries(raw)) {
      if (count >= 30) break;
      const key = String(k || '').trim().slice(0, 80);
      if (!key) continue;
      const val = v == null ? '' : (typeof v === 'object' ? JSON.stringify(v) : String(v));
      out[key] = val.slice(0, 500);
      count++;
    }
    return count ? out : null;
  }

  function saveCounters(ws, updatedBy) {
    if (ws && counters[ws]) {
      counters[ws].updatedAt = new Date().toISOString();
      counters[ws].updatedBy = updatedBy || 'api';
    }
    atomicWriteJson(countersPath, counters);
  }

  function saveHistory() {
    if (history.length > MAX_HISTORY) history = history.slice(0, MAX_HISTORY);
    atomicWriteJson(historyPath, history);
  }

  function saveApprovals() {
    if (approvals.length > MAX_APPROVALS) approvals = approvals.slice(0, MAX_APPROVALS);
    atomicWriteJson(approvalsPath, approvals);
  }

  function saveRejections() {
    if (rejections.length > MAX_REJECTIONS) rejections = rejections.slice(0, MAX_REJECTIONS);
    atomicWriteJson(rejectionsPath, rejections);
  }

  function rejectionCounts() {
    let open = 0;
    let acknowledged = 0;
    let resolved = 0;
    const openItems = [];
    for (const item of rejections) {
      if (item.status === 'open') {
        open++;
        if (openItems.length < 10) {
          openItems.push({
            id: item.id,
            workspace: normalizeWorkspace(item.workspace, 'asoc'),
            approvalId: item.approvalId || null,
            jobId: item.jobId || null,
            execId: item.execId || null,
            irisCaseId: item.irisCaseId || null,
            caseUrl: item.caseUrl || null,
            caseName: item.caseName || null,
            tenant: item.tenant || null,
            clientName: item.clientName || null,
            ticketNumber: item.ticketNumber || null,
            severity: item.severity || null,
            classification: item.classification || null,
            reason: item.reason || null,
            decidedBy: item.decidedBy || null,
            retryInMinutes: item.retryInMinutes ?? null,
            nextRetryAt: item.nextRetryAt || null,
            deadlineAt: item.deadlineAt || null,
            createdAt: item.createdAt,
          });
        }
      } else if (item.status === 'acknowledged') {
        acknowledged++;
      } else if (item.status === 'resolved') {
        resolved++;
      }
    }
    return {
      open,
      acknowledged,
      resolved,
      total: rejections.length,
      openItems,
    };
  }

  function resolveOpenRejectionsFor({ execId, jobId, irisCaseId, workspace, resolvedReason }) {
    const ws = normalizeWorkspace(workspace, 'asoc');
    const nowIso = new Date().toISOString();
    let rejChanged = false;
    let apprChanged = false;
    for (const item of rejections) {
      if (item.status !== 'open') continue;
      const match = (execId && item.execId && item.execId === execId) ||
        (jobId && item.jobId && item.jobId === jobId) ||
        (irisCaseId && item.irisCaseId && item.workspace === ws && item.irisCaseId === irisCaseId);
      if (!match) continue;
      item.status = 'resolved';
      item.resolvedAt = nowIso;
      item.resolvedReason = resolvedReason || 'resolved';
      item.updatedAt = nowIso;
      rejChanged = true;
      if (item.approvalId) {
        const appr = approvals.find((a) => a.id === item.approvalId);
        if (appr && appr.rejectionStatus !== 'resolved') {
          appr.rejectionStatus = 'resolved';
          appr.updatedAt = nowIso;
          apprChanged = true;
        }
      }
    }
    if (rejChanged) saveRejections();
    if (apprChanged) saveApprovals();
    return rejChanged;
  }

  function recordRejectionInternal(payload = {}) {
    const str = (v, max = 500) => (v == null ? null : String(v).trim().slice(0, max) || null);
    const ws = normalizeWorkspace(payload.workspace, 'asoc');
    const approvalId = str(payload.approvalId, 120);
    const jobId = str(payload.jobId || payload.dipteraJobId, 120);
    const execId = str(payload.execId || payload.executionId, 120);
    const rawCaseInput = payload.caseId ?? payload.irisCaseId ?? payload.case_id;
    const irisCaseId = normalizeCaseIdValue(rawCaseInput);
    const rawCaseId = rawCaseInput == null
      ? null
      : (String(rawCaseInput).trim().replace(/^#+/, '').trim() || null);
    const rawCaseUrl = payload.caseUrl || payload.case_url || payload.linkUrl || payload.link_url || '';
    const parsedCaseUrl = parseHttpUrl(rawCaseUrl);
    const caseUrl = parsedCaseUrl ? parsedCaseUrl.toString() : null;
    const caseName = str(payload.caseName || payload.title, 300) || (irisCaseId ? 'Case ' + irisCaseId : 'Case Ditolak');
    const tenant = str(payload.tenant || payload.organization, 120);
    const clientName = str(payload.clientName || payload.customer_name || payload.client, 200);
    const ticketNumber = str(payload.ticketNumber || payload.reportNumber || payload.ticket, 120);
    const severity = str(payload.severity || payload.level, 32)?.toUpperCase() || null;
    const classification = str(payload.classification || payload.outcome, 120);
    const openDate = str(payload.openDate || payload.open_date, 64);
    const reason = str(payload.reason ?? payload.Reason, 2000) || 'Tidak ada alasan yang diberikan.';
    const decidedBy = str(payload.decidedBy ?? payload.reviewer, 120);
    const parsedRetryMin = Number(payload.retryInMinutes);
    const retryInMinutes = Number.isFinite(parsedRetryMin) ? Math.max(0, Math.round(parsedRetryMin)) : 10;

    let nextRetryAt = null;
    if (payload.nextRetryAt) {
      const ms = Date.parse(String(payload.nextRetryAt));
      if (!Number.isNaN(ms)) nextRetryAt = new Date(ms).toISOString();
    } else if (retryInMinutes > 0) {
      nextRetryAt = new Date(Date.now() + retryInMinutes * 60000).toISOString();
    }

    let deadlineAt = null;
    const rawDeadline = payload.deadlineAt || payload.approvalDeadline || null;
    if (rawDeadline) {
      const ms = Date.parse(String(rawDeadline));
      if (!Number.isNaN(ms)) deadlineAt = new Date(ms).toISOString();
    }

    const now = new Date().toISOString();
    const id = String(payload.id || '').trim() || ('rej_' + crypto.randomBytes(6).toString('hex'));
    const record = {
      id,
      workspace: ws,
      status: 'open',
      approvalId,
      jobId,
      execId,
      irisCaseId,
      caseUrl,
      caseName,
      tenant,
      clientName,
      ticketNumber,
      severity,
      classification,
      openDate,
      reason,
      decidedBy,
      retryInMinutes,
      nextRetryAt,
      deadlineAt,
      source: str(payload.source, 64) || 'n8n-rejection',
      acknowledgedBy: null,
      acknowledgedAt: null,
      resolvedAt: null,
      resolvedReason: null,
      createdAt: now,
      updatedAt: now,
    };

    rejections.unshift(record);
    saveRejections();

    // Link ke approval terkait (by approvalId, atau latest denied matching execId/jobId/irisCaseId)
    let linkedAppr = approvalId ? approvals.find((a) => a.id === approvalId) : null;
    if (!linkedAppr) {
      linkedAppr = approvals.find((a) => a.status === 'denied' && (
        (execId && a.execId === execId) ||
        (jobId && a.jobId === jobId) ||
        (irisCaseId && a.irisCaseId === irisCaseId && a.workspace === ws)
      ));
    }
    if (linkedAppr) {
      linkedAppr.rejectionId = record.id;
      linkedAppr.rejectionNotifiedAt = now;
      linkedAppr.nextRetryAt = nextRetryAt;
      linkedAppr.rejectionStatus = 'open';
      linkedAppr.updatedAt = now;
      saveApprovals();
    }

    // Link ke history terkait
    let linkedHist = jobId ? history.find((h) => h.id === jobId) : null;
    if (!linkedHist && irisCaseId) {
      linkedHist = history.find((h) => h.workspace === ws && h.irisCaseId === irisCaseId);
    }
    if (linkedHist) {
      linkedHist.rejectionId = record.id;
      linkedHist.rejectionReason = reason;
      linkedHist.approvalStatus = 'denied';
      linkedHist.updatedAt = now;
      saveHistory();
    }

    return {
      ok: true,
      rejection: record,
      case_id: rawCaseId,
      counts: rejectionCounts(),
    };
  }

  function refreshExpiredApprovals() {
    const nowMs = Date.now();
    const nowIso = new Date(nowMs).toISOString();
    let changed = false;
    let histChanged = false;
    for (const item of approvals) {
      if (item.status !== 'pending' || !item.deadlineAt) continue;
      const dlMs = Date.parse(item.deadlineAt);
      if (!Number.isNaN(dlMs) && nowMs >= dlMs) {
        item.status = 'expired';
        item.updatedAt = nowIso;
        changed = true;
        if (item.jobId) {
          const h = history.find((x) => x.id === item.jobId);
          if (h && h.approvalStatus !== 'expired') {
            h.approvalId = item.id;
            h.approvalStatus = 'expired';
            h.updatedAt = nowIso;
            histChanged = true;
          }
        }
      }
    }
    if (changed) saveApprovals();
    if (histChanged) saveHistory();
    return changed;
  }

  function approvalCounts() {
    const counts = {
      pending: 0,
      approved: 0,
      denied: 0,
      expired: 0,
      total: approvals.length,
      byWorkspace: {
        asoc: { pending: 0, total: 0 },
        soc: { pending: 0, total: 0 },
      },
    };
    for (const item of approvals) {
      const ws = normalizeWorkspace(item.workspace, 'asoc');
      counts.byWorkspace[ws].total++;
      if (item.status === 'pending') {
        counts.pending++;
        counts.byWorkspace[ws].pending++;
      } else if (item.status === 'approved') {
        counts.approved++;
      } else if (item.status === 'denied') {
        counts.denied++;
      } else if (item.status === 'expired') {
        counts.expired++;
      }
    }
    return counts;
  }

  function syncHistoryApprovalStatus(item) {
    if (!item || !item.jobId) return false;
    const h = history.find((x) => x.id === item.jobId);
    if (!h) return false;
    h.approvalId = item.id;
    h.approvalStatus = item.status;
    h.updatedAt = new Date().toISOString();
    saveHistory();
    return true;
  }

  function countHistoryByWs(ws) {
    return history.filter((item) => normalizeWorkspace(item.workspace, 'asoc') === ws).length;
  }

  return {
    getState() {
      refreshExpiredApprovals();
      const asocCounters = JSON.parse(JSON.stringify(counters.asoc));
      const socCounters = JSON.parse(JSON.stringify(counters.soc));
      const asocCount = countHistoryByWs('asoc');
      const socCount = countHistoryByWs('soc');
      return {
        defaultWorkspace: envCfg.defaultWorkspace,
        workspaces: {
          asoc: { counters: asocCounters, historyCount: asocCount },
          soc: { counters: socCounters, historyCount: socCount },
        },
        approvals: approvalCounts(),
        rejections: rejectionCounts(),
        // Backward-compatible aliases pointing to ASOC
        counters: asocCounters,
        historyCount: asocCount,
        serverTime: new Date().toISOString(),
      };
    },

    syncCounters(payload = {}) {
      return withLock(() => {
        const ws = normalizeWorkspace(payload.workspace, 'asoc');
        const bucket = counters[ws];
        const force = Boolean(payload.force);
        const replace = Boolean(payload.replace);
        let changed = false;

        if (payload.lastIrisCaseId !== undefined) {
          const norm = normalizeCaseIdValue(payload.lastIrisCaseId);
          if (force && norm === null) {
            bucket.lastIrisCaseId = null;
            changed = true;
          } else if (norm && shouldAdvance(bucket.lastIrisCaseId, norm, force)) {
            bucket.lastIrisCaseId = norm;
            changed = true;
          }
        }

        if (Array.isArray(payload.tenants)) {
          const clean = Array.from(new Set(payload.tenants.map((t) => String(t).trim()).filter(Boolean)));
          bucket.tenants = clean;
          changed = true;
        }

        if (payload.ticketsByTenant && typeof payload.ticketsByTenant === 'object') {
          const nextMap = replace ? {} : { ...bucket.ticketsByTenant };
          for (const [rawT, rawNum] of Object.entries(payload.ticketsByTenant)) {
            const tenant = String(rawT).trim();
            const val = String(rawNum ?? '').trim();
            if (!tenant) continue;
            if (!val) {
              if (force || replace) {
                delete nextMap[tenant];
                changed = true;
              }
              continue;
            }
            if (shouldAdvance(nextMap[tenant], val, force || replace)) {
              nextMap[tenant] = val;
              if (!bucket.tenants.includes(tenant)) bucket.tenants.push(tenant);
              changed = true;
            }
          }
          bucket.ticketsByTenant = nextMap;
        }

        if (changed) saveCounters(ws, payload.updatedBy || 'sync');
        return { workspace: ws, counters: JSON.parse(JSON.stringify(bucket)) };
      });
    },

    reserveNext(payload = {}) {
      return withLock(() => {
        const ws = normalizeWorkspace(payload.workspace, 'asoc');
        const bucket = counters[ws];
        const tenant = String(payload.tenant || '').trim();
        const wantTicket = payload.reserveTicket !== false && Boolean(tenant);
        const wantCaseId = Boolean(payload.reserveCaseId);
        let reservedTicket = null;
        let reservedCaseId = null;
        let changed = false;

        if (wantTicket && bucket.ticketsByTenant[tenant]) {
          const next = numbering.nextValue(bucket.ticketsByTenant[tenant]);
          if (next) {
            bucket.ticketsByTenant[tenant] = next;
            reservedTicket = next;
            changed = true;
          }
        }

        if (wantCaseId && bucket.lastIrisCaseId) {
          const next = numbering.nextValue(bucket.lastIrisCaseId);
          if (next) {
            bucket.lastIrisCaseId = next;
            reservedCaseId = next;
            changed = true;
          }
        }

        if (changed) saveCounters(ws, 'reserve');
        return {
          workspace: ws,
          ticketNumber: reservedTicket,
          irisCaseId: reservedCaseId,
          counters: JSON.parse(JSON.stringify(bucket)),
        };
      });
    },

    listHistory(filters = {}) {
      const limit = Math.min(Math.max(Number(filters.limit) || 150, 1), MAX_HISTORY);
      const wsRaw = String(filters.workspace || 'asoc').trim().toLowerCase();
      const wsFilter = wsRaw === 'all' ? null : normalizeWorkspace(wsRaw, 'asoc');
      const tenant = String(filters.tenant || '').trim().toLowerCase();
      const mode = String(filters.mode || '').trim().toLowerCase();
      const status = String(filters.status || '').trim().toLowerCase();
      const q = String(filters.q || '').trim().toLowerCase();

      const filtered = history.filter((item) => {
        const itemWs = normalizeWorkspace(item.workspace, 'asoc');
        if (wsFilter && itemWs !== wsFilter) return false;
        if (tenant && String(item.tenant || '').toLowerCase() !== tenant) return false;
        if (mode && String(item.mode || '').toLowerCase() !== mode) return false;
        if (status && String(item.status || '').toLowerCase() !== status) return false;
        if (q) {
          const hay = [item.caseName, item.irisCaseId, item.ticketNumber, item.tenant, item.severity, item.classification]
            .filter(Boolean)
            .join(' ')
            .toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      });

      const activeWs = wsFilter || 'asoc';
      return {
        workspace: activeWs,
        items: filtered.slice(0, limit),
        total: filtered.length,
        counts: {
          asoc: countHistoryByWs('asoc'),
          soc: countHistoryByWs('soc'),
        },
        counters: JSON.parse(JSON.stringify(counters[activeWs])),
      };
    },

    getHistoryById(id) {
      return history.find((x) => x.id === id) || null;
    },

    createHistory(payload = {}) {
      return withLock(() => {
        const ws = normalizeWorkspace(payload.workspace, 'asoc');
        const bucket = counters[ws];
        const clean = sanitizeHistoryPatch({ ...payload, workspace: ws });
        const now = new Date().toISOString();
        const id = String(payload.id || '').trim() || ('job_' + crypto.randomBytes(6).toString('hex'));
        const existingIdx = history.findIndex((x) => x.id === id);

        const entry = {
          id,
          workspace: ws,
          createdAt: now,
          updatedAt: now,
          mode: clean.mode || 'reporting',
          repeatOptions: clean.repeatOptions || null,
          tenant: clean.tenant || null,
          ticketNumber: clean.ticketNumber || null,
          irisCaseId: clean.irisCaseId || null,
          caseName: clean.caseName || null,
          severity: clean.severity || null,
          classification: clean.classification || null,
          status: clean.status || 'running',
          execId: clean.execId || null,
          waitingUrl: clean.waitingUrl || null,
          errorMsg: clean.errorMsg || null,
          markdown: clean.markdown || null,
          source: clean.source || ('diptera-' + ws),
        };

        if (existingIdx >= 0) {
          history[existingIdx] = { ...history[existingIdx], ...clean, workspace: ws, updatedAt: now };
        } else {
          history.unshift(entry);
        }

        let countersChanged = false;
        if (entry.mode === 'reporting') {
          if (entry.tenant && entry.ticketNumber && shouldAdvance(bucket.ticketsByTenant[entry.tenant], entry.ticketNumber, false)) {
            bucket.ticketsByTenant[entry.tenant] = entry.ticketNumber;
            if (!bucket.tenants.includes(entry.tenant)) bucket.tenants.push(entry.tenant);
            countersChanged = true;
          }
          if (entry.irisCaseId && shouldAdvance(bucket.lastIrisCaseId, entry.irisCaseId, false)) {
            bucket.lastIrisCaseId = entry.irisCaseId;
            countersChanged = true;
          }
        }
        if (countersChanged) saveCounters(ws, 'history-create');
        saveHistory();
        return history.find((x) => x.id === id);
      });
    },

    updateHistory(id, payload = {}) {
      return withLock(() => {
        const idx = history.findIndex((x) => x.id === id);
        if (idx === -1) return null;
        const ws = normalizeWorkspace(payload.workspace || history[idx].workspace, 'asoc');
        const bucket = counters[ws];
        const clean = sanitizeHistoryPatch(payload);
        const updated = {
          ...history[idx],
          ...clean,
          workspace: ws,
          updatedAt: new Date().toISOString(),
        };
        history[idx] = updated;

        let countersChanged = false;
        const allowCounterUpdate = updated.mode === 'reporting' || Boolean(updated.repeatOptions?.createIrisCase);
        if (allowCounterUpdate) {
          if (updated.irisCaseId && shouldAdvance(bucket.lastIrisCaseId, updated.irisCaseId, false)) {
            bucket.lastIrisCaseId = updated.irisCaseId;
            countersChanged = true;
          }
          if (updated.mode === 'reporting' && updated.tenant && updated.ticketNumber && shouldAdvance(bucket.ticketsByTenant[updated.tenant], updated.ticketNumber, false)) {
            bucket.ticketsByTenant[updated.tenant] = updated.ticketNumber;
            if (!bucket.tenants.includes(updated.tenant)) bucket.tenants.push(updated.tenant);
            countersChanged = true;
          }
        }
        if (countersChanged) saveCounters(ws, 'history-update');
        saveHistory();
        return updated;
      });
    },

    deleteHistory(id) {
      return withLock(() => {
        const before = history.length;
        history = history.filter((x) => x.id !== id);
        if (history.length !== before) {
          saveHistory();
          return true;
        }
        return false;
      });
    },

    handleN8nCallback(payload = {}) {
      return withLock(() => {
        const event = String(payload.event || 'report_ready').trim();
        const jobId = String(payload.jobId || '').trim();
        const existingIdx = jobId ? history.findIndex((x) => x.id === jobId) : -1;
        const ws = normalizeWorkspace(
          payload.workspace || (existingIdx >= 0 ? history[existingIdx].workspace : null),
          'asoc',
        );
        const bucket = counters[ws];

        if (event === 'approval_expired') {
          const approvalId = String(payload.approvalId || '').trim();
          const execId = String(payload.execId || payload.executionId || '').trim();
          const nowIso = new Date().toISOString();
          let expiredCount = 0;
          for (const item of approvals) {
            if (item.status !== 'pending') continue;
            const match = (approvalId && item.id === approvalId) ||
              (jobId && item.jobId === jobId) ||
              (execId && item.execId === execId);
            if (match) {
              item.status = 'expired';
              item.updatedAt = nowIso;
              expiredCount++;
              syncHistoryApprovalStatus(item);
            }
          }
          if (expiredCount > 0) saveApprovals();
          return {
            ok: true,
            workspace: ws,
            event,
            expiredCount,
            approvals: approvalCounts(),
          };
        }

        if (event === 'approval_rejected') {
          return recordRejectionInternal({ ...payload, workspace: ws });
        }

        const caseId = normalizeCaseIdValue(payload.caseId);
        const tenant = payload.tenant ? String(payload.tenant).trim() : null;
        const ticketNumber = payload.reportNumber ? String(payload.reportNumber).trim() : null;
        const runMode = payload.runMode === 'repeating' ? 'repeating' : 'reporting';
        const now = new Date().toISOString();

        const patch = sanitizeHistoryPatch({
          workspace: ws,
          mode: runMode,
          repeatOptions: payload.runOptions,
          tenant: tenant || undefined,
          ticketNumber: ticketNumber || undefined,
          irisCaseId: caseId || undefined,
          caseName: payload.caseName || undefined,
          severity: payload.severity || undefined,
          classification: payload.classification || undefined,
          markdown: payload.markdown || undefined,
          status: event === 'case_created' ? 'running' : (payload.status || 'done'),
          source: 'n8n-callback',
        });

        let record = null;
        if (existingIdx >= 0) {
          record = { ...history[existingIdx], ...patch, workspace: ws, updatedAt: now };
          history[existingIdx] = record;
        } else {
          const id = jobId || ('n8n_' + crypto.randomBytes(6).toString('hex'));
          record = {
            id,
            workspace: ws,
            createdAt: now,
            updatedAt: now,
            mode: runMode,
            repeatOptions: patch.repeatOptions || null,
            tenant: patch.tenant || null,
            ticketNumber: patch.ticketNumber || null,
            irisCaseId: patch.irisCaseId || null,
            caseName: patch.caseName || null,
            severity: patch.severity || null,
            classification: patch.classification || null,
            status: patch.status || (event === 'case_created' ? 'running' : 'done'),
            execId: null,
            waitingUrl: null,
            errorMsg: null,
            markdown: patch.markdown || null,
            source: 'n8n-callback',
          };
          history.unshift(record);
        }

        let countersChanged = false;
        const createdNewCase = runMode === 'reporting' || Boolean(payload.irisCaseCreated) || Boolean(payload.runOptions?.createIrisCase);
        if (createdNewCase && caseId && shouldAdvance(bucket.lastIrisCaseId, caseId, false)) {
          bucket.lastIrisCaseId = caseId;
          countersChanged = true;
        }
        if (runMode === 'reporting' && tenant && ticketNumber && shouldAdvance(bucket.ticketsByTenant[tenant], ticketNumber, false)) {
          bucket.ticketsByTenant[tenant] = ticketNumber;
          if (!bucket.tenants.includes(tenant)) bucket.tenants.push(tenant);
          countersChanged = true;
        }

        if (countersChanged) saveCounters(ws, 'n8n-callback:' + event);
        saveHistory();
        return {
          ok: true,
          workspace: ws,
          event,
          record,
          counters: JSON.parse(JSON.stringify(bucket)),
        };
      });
    },

    listApprovals(filters = {}) {
      refreshExpiredApprovals();
      const limit = Math.min(Math.max(Number(filters.limit) || 200, 1), MAX_APPROVALS);
      const wsRaw = String(filters.workspace || 'all').trim().toLowerCase();
      const wsFilter = wsRaw === 'all' ? null : normalizeWorkspace(wsRaw, 'asoc');
      const statusRaw = String(filters.status || 'all').trim().toLowerCase();
      const statusFilter = statusRaw === 'all' ? null : statusRaw;
      const tenant = String(filters.tenant || '').trim().toLowerCase();
      const severity = String(filters.severity || '').trim().toUpperCase();
      const q = String(filters.q || '').trim().toLowerCase();

      const filtered = approvals.filter((item) => {
        const itemWs = normalizeWorkspace(item.workspace, 'asoc');
        if (wsFilter && itemWs !== wsFilter) return false;
        if (statusFilter && String(item.status || '').toLowerCase() !== statusFilter) return false;
        if (tenant && String(item.tenant || '').toLowerCase() !== tenant) return false;
        if (severity && String(item.severity || '').toUpperCase() !== severity) return false;
        if (q) {
          const hay = [
            item.id,
            item.caseName,
            item.irisCaseId,
            item.ticketNumber,
            item.tenant,
            item.clientName,
            item.workflowName,
            item.classification,
            item.summary,
            item.reason,
            item.decidedBy,
            item.execId,
          ]
            .filter(Boolean)
            .join(' ')
            .toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      });

      const sorted = filtered.slice().sort((a, b) => {
        if (!statusFilter) {
          const aPend = a.status === 'pending' ? 0 : 1;
          const bPend = b.status === 'pending' ? 0 : 1;
          if (aPend !== bPend) return aPend - bPend;
        }
        return String(b.createdAt || '').localeCompare(String(a.createdAt || ''));
      });

      return {
        items: sorted.slice(0, limit),
        total: sorted.length,
        counts: approvalCounts(),
      };
    },

    getApprovalById(id) {
      refreshExpiredApprovals();
      return approvals.find((x) => x.id === id) || null;
    },

    createApproval(payload = {}) {
      return withLock(() => {
        refreshExpiredApprovals();
        const str = (v, max = 500) => (v == null ? null : String(v).trim().slice(0, max) || null);
        const rawResumeUrl = payload.resumeUrl || payload.resume_url || payload.webhookUrl || payload.resumeURL || '';
        const parsedResume = parseHttpUrl(rawResumeUrl);
        if (!parsedResume) {
          throw Object.assign(new Error('resumeUrl tidak valid atau kosong (harus http/https)'), { status: 400 });
        }
        if (!isHostAllowed(parsedResume, envCfg.approvalAllowedHosts)) {
          throw Object.assign(new Error('Host resumeUrl tidak diizinkan oleh APPROVAL_ALLOWED_HOSTS'), { status: 403 });
        }

        const resumeUrl = parsedResume.toString();
        const resumeMethod = String(payload.resumeMethod || payload.resume_method || 'POST').trim().toUpperCase() === 'GET' ? 'GET' : 'POST';
        const ws = normalizeWorkspace(payload.workspace, 'asoc');
        const workflowName = str(payload.workflowName || payload.workflow, 160) || 'n8n Workflow';
        const source = str(payload.source, 64) || 'n8n';
        const execId = str(payload.execId || payload.executionId || execIdFromResumeUrl(resumeUrl), 120);
        const jobId = str(payload.jobId || payload.dipteraJobId, 120);
        const irisCaseId = normalizeCaseIdValue(payload.caseId ?? payload.irisCaseId ?? payload.case_id);
        const rawCaseUrl = payload.caseUrl || payload.case_url || payload.linkUrl || payload.link_url || '';
        const parsedCaseUrl = parseHttpUrl(rawCaseUrl);
        const caseUrl = parsedCaseUrl ? parsedCaseUrl.toString() : null;
        const caseName = str(payload.caseName || payload.title || payload.alertTitle || payload.subject, 300)
          || (irisCaseId ? 'Case ' + irisCaseId : 'Permintaan Approval');
        const tenant = str(payload.tenant || payload.organization, 120);
        const clientName = str(payload.clientName || payload.customer_name || payload.client, 200);
        const ticketNumber = str(payload.ticketNumber || payload.reportNumber || payload.ticket, 120);
        const severity = str(payload.severity || payload.level, 32)?.toUpperCase() || null;
        const classification = str(payload.classification || payload.outcome || payload.verdict, 120);
        const openDate = str(payload.openDate || payload.open_date, 64);
        const summary = str(payload.summary || payload.message || payload.description, 4000);
        const rawMd = payload.markdown ?? payload.case_description ?? payload.reportMarkdown ?? payload.report ?? null;
        const markdown = rawMd == null ? null : (String(rawMd).slice(0, 300000) || null);
        const alertData = sanitizeAlertData(payload.alertData ?? payload.alert ?? payload.payload ?? null);
        const metadata = sanitizeMetadataMap(payload.metadata);

        const rawDeadline = payload.deadlineAt || payload.approvalDeadline || payload.expiresAt || null;
        let deadlineAt = null;
        if (rawDeadline) {
          const ms = Date.parse(String(rawDeadline));
          if (!Number.isNaN(ms)) deadlineAt = new Date(ms).toISOString();
        }

        const now = new Date().toISOString();
        const existingPending = approvals.find((x) => x.status === 'pending' && x.resumeUrl === resumeUrl);
        if (existingPending) {
          if (caseName) existingPending.caseName = caseName;
          if (summary !== null) existingPending.summary = summary;
          if (markdown !== null) existingPending.markdown = markdown;
          if (classification !== null) existingPending.classification = classification;
          if (severity !== null) existingPending.severity = severity;
          if (deadlineAt !== null) existingPending.deadlineAt = deadlineAt;
          if (tenant !== null) existingPending.tenant = tenant;
          if (clientName !== null) existingPending.clientName = clientName;
          if (ticketNumber !== null) existingPending.ticketNumber = ticketNumber;
          if (irisCaseId !== null) existingPending.irisCaseId = irisCaseId;
          if (caseUrl !== null) existingPending.caseUrl = caseUrl;
          if (alertData !== null) existingPending.alertData = alertData;
          if (metadata !== null) existingPending.metadata = metadata;
          existingPending.resumeMethod = resumeMethod;
          existingPending.updatedAt = now;
          saveApprovals();
          syncHistoryApprovalStatus(existingPending);
          return {
            ok: true,
            approval: existingPending,
            deduplicated: true,
            counts: approvalCounts(),
          };
        }

        const explicitAttempt = Number(payload.attempt);
        let attempt = Number.isFinite(explicitAttempt) && explicitAttempt >= 1 ? Math.floor(explicitAttempt) : 0;
        if (!attempt) {
          const prevMatches = approvals.filter((x) => {
            if (execId && x.execId && x.execId === execId) return true;
            if (jobId && x.jobId && x.jobId === jobId) return true;
            if (irisCaseId && x.irisCaseId && x.workspace === ws && x.irisCaseId === irisCaseId && x.resumeUrl === resumeUrl) return true;
            return false;
          });
          attempt = prevMatches.length + 1;
        }

        const id = String(payload.id || '').trim() || ('apr_' + crypto.randomBytes(6).toString('hex'));
        const record = {
          id,
          workspace: ws,
          status: 'pending',
          workflowName,
          source,
          execId,
          jobId,
          irisCaseId,
          caseUrl,
          caseName,
          tenant,
          clientName,
          ticketNumber,
          severity,
          classification,
          openDate,
          summary,
          markdown,
          alertData,
          metadata,
          resumeUrl,
          resumeMethod,
          deadlineAt,
          attempt,
          decision: null,
          reason: null,
          decidedBy: null,
          decidedAt: null,
          resumeHttpStatus: null,
          resumeResponse: null,
          lastError: null,
          createdAt: now,
          updatedAt: now,
        };

        approvals.unshift(record);
        saveApprovals();
        syncHistoryApprovalStatus(record);
        resolveOpenRejectionsFor({
          execId,
          jobId,
          irisCaseId,
          workspace: ws,
          resolvedReason: 'reapproval_requested',
        });

        return {
          ok: true,
          approval: record,
          deduplicated: false,
          counts: approvalCounts(),
        };
      });
    },

    async decideApproval(id, payload = {}) {
      const rawDecision = String(payload.decision ?? payload.action ?? payload.approvalStatus ?? '').trim().toLowerCase();
      let decision = null;
      if (['approve', 'approved', 'yes', 'true', '✅ approve'].includes(rawDecision)) {
        decision = 'approve';
      } else if (['deny', 'denied', 'decline', 'declined', 'reject', 'rejected', 'false', '❌ decline'].includes(rawDecision)) {
        decision = 'deny';
      }
      if (!decision) {
        throw Object.assign(new Error('Decision harus "approve" atau "deny"'), { status: 400 });
      }

      const reason = String(payload.reason ?? payload.notes ?? '').trim().slice(0, 2000) || null;
      const decidedBy = String(payload.decidedBy ?? payload.analyst ?? '').trim().slice(0, 120) || null;

      const prep = await withLock(() => {
        refreshExpiredApprovals();
        const record = approvals.find((x) => x.id === id);
        if (!record) {
          throw Object.assign(new Error('Approval tidak ditemukan'), { status: 404 });
        }
        if (record.status !== 'pending') {
          throw Object.assign(new Error(`Approval sudah berstatus ${record.status}`), {
            status: 409,
            body: { ok: false, error: `Approval sudah berstatus ${record.status}`, approval: record, counts: approvalCounts() },
          });
        }
        if (inFlightDecisions.has(id)) {
          throw Object.assign(new Error('Approval sedang diproses oleh permintaan lain'), {
            status: 409,
            body: { ok: false, error: 'Approval sedang diproses oleh permintaan lain', approval: record, counts: approvalCounts() },
          });
        }
        const wsBase = envCfg.workspaces[normalizeWorkspace(record.workspace, 'asoc')]?.baseUrl;
        const targetUrl = resolveResumeUrl(record.resumeUrl, wsBase, envCfg.approvalRewriteResumeHost);
        const parsedTarget = parseHttpUrl(targetUrl);
        if (!parsedTarget) {
          throw Object.assign(new Error('resumeUrl approval tidak valid'), { status: 400 });
        }
        if (!isHostAllowed(parsedTarget, envCfg.approvalAllowedHosts)) {
          throw Object.assign(new Error('Host resumeUrl tidak diizinkan oleh APPROVAL_ALLOWED_HOSTS'), { status: 403 });
        }
        inFlightDecisions.add(id);
        return {
          snapshot: { ...record },
          targetUrl: parsedTarget.toString(),
        };
      });

      const decidedAt = new Date().toISOString();
      const rec = prep.snapshot;
      const webhookPayload = {
        approvalId: rec.id,
        decision,
        approved: decision === 'approve',
        status: decision === 'approve' ? 'approved' : 'denied',
        approvalStatus: decision === 'approve' ? '✅ Approve' : '❌ Decline',
        'Approval Status': decision === 'approve' ? '✅ Approve' : '❌ Decline',
        reason: reason || '',
        Reason: reason || '',
        decidedBy: decidedBy || '',
        decidedAt,
        workspace: rec.workspace,
        caseId: rec.irisCaseId || null,
        ticketNumber: rec.ticketNumber || null,
        tenant: rec.tenant || null,
        jobId: rec.jobId || null,
      };

      let resp = null;
      let netErr = null;
      try {
        resp = await sendWebhookResume({
          url: prep.targetUrl,
          method: rec.resumeMethod,
          payload: webhookPayload,
          timeoutMs: envCfg.approvalResumeTimeoutMs,
          allowInsecureTls: envCfg.approvalAllowInsecureTls,
        });
      } catch (err) {
        netErr = err;
      } finally {
        inFlightDecisions.delete(id);
      }

      if (!netErr && resp && resp.statusCode >= 200 && resp.statusCode < 300) {
        return withLock(() => {
          const target = approvals.find((x) => x.id === id);
          if (!target) throw Object.assign(new Error('Approval tidak ditemukan'), { status: 404 });
          target.status = decision === 'approve' ? 'approved' : 'denied';
          target.decision = decision;
          target.reason = reason;
          target.decidedBy = decidedBy;
          target.decidedAt = decidedAt;
          target.resumeHttpStatus = resp.statusCode;
          target.resumeResponse = String(resp.body || '').slice(0, 500) || null;
          target.lastError = null;
          target.updatedAt = decidedAt;
          saveApprovals();
          syncHistoryApprovalStatus(target);
          if (decision === 'approve') {
            resolveOpenRejectionsFor({
              execId: target.execId,
              jobId: target.jobId,
              irisCaseId: target.irisCaseId,
              workspace: target.workspace,
              resolvedReason: 'approved',
            });
          }
          return {
            ok: true,
            approval: target,
            n8nStatus: resp.statusCode,
            counts: approvalCounts(),
          };
        });
      }

      const n8nStatus = resp?.statusCode ?? null;
      const errMsg = netErr
        ? netErr.message
        : `Webhook n8n membalas HTTP ${n8nStatus}`;
      const expiredHint = [404, 409, 410].includes(n8nStatus);

      const updatedRecord = await withLock(() => {
        const target = approvals.find((x) => x.id === id);
        if (target) {
          target.resumeHttpStatus = n8nStatus;
          target.resumeResponse = resp?.body ? String(resp.body).slice(0, 500) : null;
          target.lastError = errMsg;
          target.updatedAt = new Date().toISOString();
          saveApprovals();
        }
        return target || rec;
      });

      throw Object.assign(new Error(errMsg), {
        status: 502,
        body: {
          ok: false,
          error: errMsg,
          n8nStatus,
          expiredHint,
          approval: updatedRecord,
          counts: approvalCounts(),
        },
      });
    },

    updateApproval(id, payload = {}) {
      return withLock(() => {
        refreshExpiredApprovals();
        const target = approvals.find((x) => x.id === id);
        if (!target) return null;
        const allowed = new Set(['pending', 'approved', 'denied', 'expired']);
        if (payload.status !== undefined && allowed.has(payload.status)) {
          target.status = payload.status;
        }
        if (payload.lastError !== undefined) {
          target.lastError = payload.lastError == null ? null : String(payload.lastError).slice(0, 500);
        }
        if (payload.reason !== undefined) {
          target.reason = payload.reason == null ? null : String(payload.reason).slice(0, 2000);
        }
        target.updatedAt = new Date().toISOString();
        saveApprovals();
        syncHistoryApprovalStatus(target);
        return {
          ok: true,
          approval: target,
          counts: approvalCounts(),
        };
      });
    },

    deleteApproval(id) {
      return withLock(() => {
        const before = approvals.length;
        approvals = approvals.filter((x) => x.id !== id);
        if (approvals.length === before) return null;
        saveApprovals();
        return {
          ok: true,
          counts: approvalCounts(),
        };
      });
    },

    listRejections(filters = {}) {
      const limit = Math.min(Math.max(Number(filters.limit) || 100, 1), MAX_REJECTIONS);
      const wsRaw = String(filters.workspace || 'all').trim().toLowerCase();
      const wsFilter = wsRaw === 'all' ? null : normalizeWorkspace(wsRaw, 'asoc');
      const statusRaw = String(filters.status || 'all').trim().toLowerCase();
      const statusFilter = statusRaw === 'all' ? null : statusRaw;
      const q = String(filters.q || '').trim().toLowerCase();

      const filtered = rejections.filter((item) => {
        const itemWs = normalizeWorkspace(item.workspace, 'asoc');
        if (wsFilter && itemWs !== wsFilter) return false;
        if (statusFilter && String(item.status || '').toLowerCase() !== statusFilter) return false;
        if (q) {
          const hay = [
            item.id,
            item.caseName,
            item.irisCaseId,
            item.ticketNumber,
            item.tenant,
            item.clientName,
            item.classification,
            item.reason,
            item.decidedBy,
            item.execId,
          ]
            .filter(Boolean)
            .join(' ')
            .toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      });

      const sorted = filtered.slice().sort((a, b) => {
        if (!statusFilter) {
          const aOpen = a.status === 'open' ? 0 : 1;
          const bOpen = b.status === 'open' ? 0 : 1;
          if (aOpen !== bOpen) return aOpen - bOpen;
        }
        return String(b.createdAt || '').localeCompare(String(a.createdAt || ''));
      });

      return {
        items: sorted.slice(0, limit),
        total: sorted.length,
        counts: rejectionCounts(),
      };
    },

    getRejectionById(id) {
      return rejections.find((x) => x.id === id) || null;
    },

    createRejection(payload = {}) {
      return withLock(() => recordRejectionInternal(payload));
    },

    updateRejection(id, payload = {}) {
      return withLock(() => {
        const target = rejections.find((x) => x.id === id);
        if (!target) return null;
        const nowIso = new Date().toISOString();
        const allowed = new Set(['open', 'acknowledged', 'resolved']);
        let nextStatus = null;
        if (payload.status !== undefined && allowed.has(payload.status)) {
          nextStatus = payload.status;
        } else if (payload.acknowledged === true) {
          nextStatus = 'acknowledged';
        }
        if (nextStatus) {
          target.status = nextStatus;
          if (nextStatus === 'acknowledged') {
            target.acknowledgedAt = nowIso;
            const ackBy = payload.acknowledgedBy != null ? String(payload.acknowledgedBy).trim().slice(0, 120) : '';
            if (ackBy) target.acknowledgedBy = ackBy;
          } else if (nextStatus === 'resolved') {
            target.resolvedAt = nowIso;
          }
        }
        target.updatedAt = nowIso;
        saveRejections();

        if (target.approvalId) {
          const appr = approvals.find((a) => a.id === target.approvalId);
          if (appr) {
            appr.rejectionStatus = target.status;
            appr.updatedAt = nowIso;
            saveApprovals();
          }
        }

        return {
          ok: true,
          rejection: target,
          counts: rejectionCounts(),
        };
      });
    },

    deleteRejection(id) {
      return withLock(() => {
        const before = rejections.length;
        rejections = rejections.filter((x) => x.id !== id);
        if (rejections.length === before) return null;
        saveRejections();
        return {
          ok: true,
          counts: rejectionCounts(),
        };
      });
    },
  };
}

function configScript(store, env = process.env) {
  const cfg = parseEnvConfig(env);
  const st = store.getState();

  const buildWsClient = (ws) => {
    const c = cfg.workspaces[ws];
    const sc = st.workspaces[ws].counters;
    return {
      baseUrl: c.baseUrl || undefined,
      formPath: c.formPath,
      irisBaseUrl: c.irisBaseUrl || undefined,
      callbackUrl: c.callbackUrl || undefined,
      caseIdMode: c.caseIdMode,
      tenantOptions: sc.tenants.length ? sc.tenants : c.tenantOptions,
      initialCaseId: sc.lastIrisCaseId || c.initialCaseId || undefined,
      initialTickets: Object.keys(sc.ticketsByTenant || {}).length ? sc.ticketsByTenant : c.initialTickets,
    };
  };

  const clientCfg = {
    defaultWorkspace: cfg.defaultWorkspace,
    publicUrl: cfg.publicUrl || undefined,
    workspaces: {
      asoc: buildWsClient('asoc'),
      soc: buildWsClient('soc'),
    },
  };
  return 'window.DIPTERA_CONFIG = ' + JSON.stringify(clientCfg) + ';\n';
}

function send(res, method, status, type, body, extraHeaders = {}) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
  res.writeHead(status, {
    'content-type': type,
    'content-length': buf.length,
    'cache-control': 'no-cache',
    'x-content-type-options': 'nosniff',
    ...extraHeaders,
  });
  if (method === 'HEAD') res.end();
  else res.end(buf);
}

function sendJson(res, method, status, obj) {
  send(res, method, status, MIME['.json'], JSON.stringify(obj), {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'access-control-allow-headers': 'Content-Type, X-Diptera-Secret',
  });
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(Object.assign(new Error('Payload terlalu besar (maks 2 MB)'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8').trim();
      if (!text) return resolve({});
      try {
        resolve(JSON.parse(text));
      } catch {
        reject(Object.assign(new Error('Body JSON tidak valid'), { status: 400 }));
      }
    });
    req.on('error', reject);
  });
}

function createServer(options = {}) {
  const dataDir = options.dataDir || DEFAULT_DATA_DIR;
  const env = options.env || process.env;
  const store = options.store || createStore(dataDir, env);

  return http.createServer(async (req, res) => {
    const method = req.method === 'HEAD' ? 'HEAD' : req.method;

    let urlObj;
    let pathname;
    try {
      urlObj = new URL(req.url, 'http://localhost');
      pathname = decodeURIComponent(urlObj.pathname);
    } catch {
      return send(res, method, 400, 'text/plain; charset=utf-8', 'Bad Request\n');
    }

    if (pathname.startsWith('/api/')) {
      if (method === 'OPTIONS') {
        return sendJson(res, 'GET', 200, { ok: true });
      }
      try {
        if (method === 'GET' && pathname === '/api/state') {
          return sendJson(res, method, 200, store.getState());
        }
        if (method === 'POST' && pathname === '/api/counters/sync') {
          const body = await readJsonBody(req);
          const result = await store.syncCounters(body);
          return sendJson(res, method, 200, { ok: true, ...result });
        }
        if (method === 'POST' && pathname === '/api/counters/reserve') {
          const body = await readJsonBody(req);
          const reserved = await store.reserveNext(body);
          return sendJson(res, method, 200, { ok: true, ...reserved });
        }
        if (method === 'GET' && pathname === '/api/history') {
          const data = store.listHistory({
            workspace: urlObj.searchParams.get('workspace') || 'asoc',
            limit: urlObj.searchParams.get('limit'),
            tenant: urlObj.searchParams.get('tenant'),
            mode: urlObj.searchParams.get('mode'),
            status: urlObj.searchParams.get('status'),
            q: urlObj.searchParams.get('q'),
          });
          return sendJson(res, method, 200, data);
        }
        if (method === 'POST' && pathname === '/api/history') {
          const body = await readJsonBody(req);
          const record = await store.createHistory(body);
          const ws = normalizeWorkspace(record.workspace, 'asoc');
          return sendJson(res, method, 201, {
            ok: true,
            record,
            counters: store.getState().workspaces[ws].counters,
          });
        }
        if (pathname.startsWith('/api/history/')) {
          const id = pathname.slice('/api/history/'.length);
          if (!id || id.includes('/')) return sendJson(res, method, 400, { error: 'Invalid history ID' });
          if (method === 'GET') {
            const record = store.getHistoryById(id);
            if (!record) return sendJson(res, method, 404, { error: 'Not found' });
            return sendJson(res, method, 200, { ok: true, record });
          }
          if (method === 'PATCH') {
            const body = await readJsonBody(req);
            const record = await store.updateHistory(id, body);
            if (!record) return sendJson(res, method, 404, { error: 'Not found' });
            const ws = normalizeWorkspace(record.workspace, 'asoc');
            return sendJson(res, method, 200, {
              ok: true,
              record,
              counters: store.getState().workspaces[ws].counters,
            });
          }
          if (method === 'DELETE') {
            const deleted = await store.deleteHistory(id);
            if (!deleted) return sendJson(res, method, 404, { error: 'Not found' });
            return sendJson(res, method, 200, { ok: true });
          }
        }
        if (method === 'POST' && pathname === '/api/n8n-callback') {
          const body = await readJsonBody(req);
          const result = await store.handleN8nCallback(body);
          return sendJson(res, method, 200, result);
        }
        if (method === 'GET' && pathname === '/api/approvals') {
          const data = store.listApprovals({
            workspace: urlObj.searchParams.get('workspace') || 'all',
            status: urlObj.searchParams.get('status') || 'all',
            tenant: urlObj.searchParams.get('tenant'),
            severity: urlObj.searchParams.get('severity'),
            q: urlObj.searchParams.get('q'),
            limit: urlObj.searchParams.get('limit'),
          });
          return sendJson(res, method, 200, data);
        }
        if (method === 'POST' && pathname === '/api/approvals') {
          const reqEnvCfg = parseEnvConfig(env);
          if (!checkApprovalSecret(req, reqEnvCfg.approvalSecret)) {
            return sendJson(res, method, 401, { error: 'Unauthorized: invalid X-Diptera-Secret' });
          }
          const body = await readJsonBody(req);
          const result = await store.createApproval(body);
          return sendJson(res, method, result.deduplicated ? 200 : 201, result);
        }
        if (pathname.startsWith('/api/approvals/')) {
          const rest = pathname.slice('/api/approvals/'.length);
          const parts = rest.split('/').filter(Boolean);
          if (parts.length === 2 && parts[1] === 'decide' && method === 'POST') {
            const body = await readJsonBody(req);
            const result = await store.decideApproval(parts[0], body);
            return sendJson(res, method, 200, result);
          }
          if (parts.length === 1) {
            const id = parts[0];
            if (method === 'GET') {
              const record = store.getApprovalById(id);
              if (!record) return sendJson(res, method, 404, { error: 'Approval not found' });
              return sendJson(res, method, 200, { ok: true, approval: record });
            }
            if (method === 'PATCH') {
              const body = await readJsonBody(req);
              const result = await store.updateApproval(id, body);
              if (!result) return sendJson(res, method, 404, { error: 'Approval not found' });
              return sendJson(res, method, 200, result);
            }
            if (method === 'DELETE') {
              const result = await store.deleteApproval(id);
              if (!result) return sendJson(res, method, 404, { error: 'Approval not found' });
              return sendJson(res, method, 200, result);
            }
          }
          return sendJson(res, method, 400, { error: 'Invalid approval endpoint' });
        }
        if (method === 'GET' && pathname === '/api/rejections') {
          const data = store.listRejections({
            workspace: urlObj.searchParams.get('workspace') || 'all',
            status: urlObj.searchParams.get('status') || 'all',
            q: urlObj.searchParams.get('q'),
            limit: urlObj.searchParams.get('limit'),
          });
          return sendJson(res, method, 200, data);
        }
        if (method === 'POST' && pathname === '/api/rejections') {
          const reqEnvCfg = parseEnvConfig(env);
          if (!checkApprovalSecret(req, reqEnvCfg.approvalSecret)) {
            return sendJson(res, method, 401, { error: 'Unauthorized: invalid X-Diptera-Secret' });
          }
          const body = await readJsonBody(req);
          const result = await store.createRejection(body);
          return sendJson(res, method, 201, result);
        }
        if (pathname.startsWith('/api/rejections/')) {
          const id = pathname.slice('/api/rejections/'.length);
          if (!id || id.includes('/')) return sendJson(res, method, 400, { error: 'Invalid rejection ID' });
          if (method === 'GET') {
            const record = store.getRejectionById(id);
            if (!record) return sendJson(res, method, 404, { error: 'Rejection not found' });
            return sendJson(res, method, 200, { ok: true, rejection: record });
          }
          if (method === 'PATCH') {
            const body = await readJsonBody(req);
            const result = await store.updateRejection(id, body);
            if (!result) return sendJson(res, method, 404, { error: 'Rejection not found' });
            return sendJson(res, method, 200, result);
          }
          if (method === 'DELETE') {
            const result = await store.deleteRejection(id);
            if (!result) return sendJson(res, method, 404, { error: 'Rejection not found' });
            return sendJson(res, method, 200, result);
          }
        }
        return sendJson(res, method, 404, { error: 'API endpoint not found' });
      } catch (err) {
        return sendJson(res, method, err.status || 500, err.body || { error: err.message || 'Internal Server Error' });
      }
    }

    if (method !== 'GET' && method !== 'HEAD') {
      res.setHeader('allow', 'GET, HEAD');
      return send(res, method, 405, 'text/plain; charset=utf-8', 'Method Not Allowed\n');
    }

    if (pathname === '/healthz') {
      return send(res, method, 200, 'text/plain; charset=utf-8', 'ok\n');
    }

    if (pathname === '/config.js') {
      return send(res, method, 200, MIME['.js'], configScript(store, env));
    }

    const rel = APP_FILES[pathname];
    if (!rel) {
      return send(
        res,
        method,
        404,
        'text/plain; charset=utf-8',
        '404 — hanya file aplikasi yang dilayani. Buka / untuk halaman utama.\n',
      );
    }

    const full = path.join(ROOT, rel);
    fs.readFile(full, (err, buf) => {
      if (err) {
        return send(res, method, 500, 'text/plain; charset=utf-8', 'Gagal membaca ' + rel + '\n');
      }
      send(res, method, 200, MIME[path.extname(full).toLowerCase()] || 'application/octet-stream', buf);
    });
  });
}

function printBanner(port, host) {
  const local = 'http://localhost:' + port;
  const container = inContainer();
  const lans = container ? [] : lanUrls(port);
  console.log('');
  console.log('  Diptera Unified (ASOC + SOC)');
  console.log('  ' + '-'.repeat(48));
  console.log('  Lokal     : ' + local);
  if (container) {
    console.log('  Jaringan  : http://<IP-PC>:' + port + ' (port host yang dipetakan)');
  } else if (lans.length) {
    for (const url of lans) console.log('  Jaringan  : ' + url);
  }
  console.log('  Data dir  : ' + DEFAULT_DATA_DIR);
  console.log('  ' + '-'.repeat(48));
  console.log('');
}

if (require.main === module) {
  const server = createServer();
  server.listen(PORT, HOST, () => printBanner(PORT, HOST));
  server.on('error', (err) => {
    console.error('\n  Gagal menjalankan Diptera:', err.message, '\n');
    process.exit(1);
  });
  const stop = () => server.close(() => process.exit(0));
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

module.exports = { createServer, createStore, parseEnvConfig, normalizeWorkspace, lanUrls, isLocalHostname, isVirtualInterface, inContainer };
