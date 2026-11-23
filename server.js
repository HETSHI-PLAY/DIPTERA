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
const MAX_BODY_BYTES = 2 * 1024 * 1024;
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

  return { defaultWorkspace, workspaces: { asoc, soc } };
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

  let counters = loadCounters();
  let history = loadHistory();
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
    return out;
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

  function countHistoryByWs(ws) {
    return history.filter((item) => normalizeWorkspace(item.workspace, 'asoc') === ws).length;
  }

  return {
    getState() {
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
        return sendJson(res, method, 404, { error: 'API endpoint not found' });
      } catch (err) {
        return sendJson(res, method, err.status || 500, { error: err.message || 'Internal Server Error' });
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
