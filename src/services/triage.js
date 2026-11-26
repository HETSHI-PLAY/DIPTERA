/* Diptera Autonomous Wazuh Indexer Polling, Realtime Live Feed (1:1 Parity),
 * Tenant-Isolated 2-Stage Semantic Grouping, Ollama Pre-Triage & Case Audit History.
 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');

const MAX_ACTIVE_GROUPS = 500;
const MAX_CASE_HISTORY = 2000;
const MAX_SEEN_IDS = 20000;
const MAX_ALERTS_PER_CASE = 1000;
const OLLAMA_MICRO_BATCH_SIZE = 15;
const VALID_VERDICTS = ['TRUE_POSITIVE', 'NEEDS_REVIEW', 'FALSE_POSITIVE'];
const TRIAGE_RESPONSE_SCHEMA = {
  type: 'object',
  properties: {
    results: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          candidate_id: { type: 'string' },
          verdict: { type: 'string', enum: VALID_VERDICTS },
          group_key: { type: 'string' },
          incident_title: { type: 'string' },
          ai_reasoning: { type: 'string' },
        },
        required: ['candidate_id', 'verdict', 'group_key', 'incident_title', 'ai_reasoning'],
        additionalProperties: false,
      },
    },
  },
  required: ['results'],
  additionalProperties: false,
};

const DEFAULT_SYSTEM_PROMPT = [
  'Anda adalah Analis SOC L1 senior yang bertugas melakukan pre-triage alert Wazuh (severity Medium hingga Critical, level >= 7) secara micro-batch untuk SATU tenant tertentu.',
  'Analisis konteks log secara mendalam (URL/URI, payload, HTTP status, User-Agent, source IP, dan sampel full_log) — JANGAN hanya bergantung pada rule.id atau rule.description.',
  '',
  'Aturan Klasifikasi:',
  '1. TRUE_POSITIVE: Indikasi kuat eksploitasi CVE, serangan aktif, brute-force berhasil, web scanning ke file sensitif (/.env, /.git, /phpmyadmin, shell), SQLi, XSS, atau C2.',
  '2. NEEDS_REVIEW: Aktivitas anomali mencurigakan yang butuh verifikasi konteks (misal: vulnerability scanner tanpa eksploitasi berhasil, perubahan konfigurasi sistem, atau lonjakan error 500 tidak wajar).',
  '3. FALSE_POSITIVE: Trafik pengguna normal/legit yang memicu rule sensitif (misal: error 400/404 pada endpoint aplikasi valid seperti /login.php, /mhs/nim, kesalahan input user biasa, atau crawler/healthcheck internal).',
  '',
  'Aturan Pengelompokan:',
  '- Pisahkan pengelompokan (group_key) antara trafik legit dan aktivitas serangan meskipun memiliki rule.id Wazuh yang sama.',
  '- Gabungkan kandidat yang merupakan kampanye serangan yang sama ke dalam satu insiden walaupun menyasar beberapa agent berbeda di dalam tenant ini.',
  'Keluarkan output HANYA dalam format JSON valid sesuai skema yang diminta.',
].join('\n');

const DEFAULT_EXCLUSION_RULES = [
  { id: 'ex-path-login', target: 'path', mode: 'contains', pattern: '/login.php', enabled: true, note: 'Login page aplikasi' },
  { id: 'ex-path-mhs', target: 'path', mode: 'contains', pattern: '/mhs/nim', enabled: true, note: 'Endpoint akademik kampus' },
  { id: 'ex-path-favicon', target: 'path', mode: 'contains', pattern: '/favicon.ico', enabled: true, note: 'Favicon browser' },
  { id: 'ex-path-assets', target: 'path', mode: 'starts_with', pattern: '/assets/', enabled: true, note: 'Static assets' },
  { id: 'ex-log-healthcheck', target: 'full_log', mode: 'contains', pattern: 'HealthCheck', enabled: true, note: 'Health check internal' },
  { id: 'ex-log-wordfence', target: 'full_log', mode: 'contains', pattern: 'Wordfence', enabled: true, note: 'Plugin security noise' },
  { id: 'ex-log-loopback', target: 'full_log', mode: 'contains', pattern: '127.0.0.1', enabled: true, note: 'Loopback noise' },
];

function cloneJson(v) {
  return JSON.parse(JSON.stringify(v));
}

function defaultConfig() {
  return {
    workerEnabled: false,
    wazuh: {
      url: '',
      indexPattern: 'wazuh-alerts-*',
      username: '',
      password: '',
      allowSelfSigned: true,
      severityPreset: 'medium_critical',
      minRuleLevel: 7,
      maxRuleLevel: 15,
      pollIntervalMin: 3,
      liveRefreshSec: 10,
      tenantMapping: {},
    },
    ollama: {
      baseUrl: 'http://localhost:11434',
      model: 'hf.co/Triago/NVIDIA-Nemotron-Nano-12B-v2-Q8_0-GGUF:Q8_0',
      temperature: 0.1,
      systemPrompt: DEFAULT_SYSTEM_PROMPT,
    },
    exclusionRules: cloneJson(DEFAULT_EXCLUSION_RULES),
    updatedAt: null,
  };
}

function defaultTriageState() {
  return {
    watermarkTimestamp: null,
    groups: [],
    processedAlertIds: [],
    dismissedAlertIds: [],
    caseCreatedAlertIds: [],
    excludedAlertMap: {},
    workerStatus: {
      running: false,
      lastPollAt: null,
      lastSuccessAt: null,
      lastError: null,
      lastBatchCount: 0,
      lastExcludedCount: 0,
      lastAnalyzedCount: 0,
    },
  };
}

function readJsonSafe(filePath, fallback) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return typeof fallback === 'function' ? fallback() : cloneJson(fallback);
  }
}

function writeJsonAtomic(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = filePath + '.' + process.pid + '.' + Date.now() + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', 'utf8');
  fs.renameSync(tmp, filePath);
}

function trimArray(arr, max) {
  if (!Array.isArray(arr)) return [];
  if (arr.length <= max) return arr;
  return arr.slice(arr.length - max);
}

function severityLabel(level) {
  const n = Number(level) || 0;
  if (n >= 15) return 'Critical';
  if (n >= 12) return 'High';
  if (n >= 7) return 'Medium';
  return 'Low';
}

function extractAlertTimestamp(rawAlert) {
  return rawAlert?.['@timestamp'] || rawAlert?.timestamp || rawAlert?.ts || null;
}

function extractSrcIp(rawAlert) {
  return String(
    rawAlert?.data?.srcip ||
    rawAlert?.data?.src_ip ||
    rawAlert?.data?.win?.eventdata?.ipAddress ||
    rawAlert?.srcip ||
    ''
  ).trim();
}

function extractUserAgent(rawAlert) {
  return String(
    rawAlert?.data?.http_user_agent ||
    rawAlert?.data?.user_agent ||
    rawAlert?.data?.http?.user_agent ||
    rawAlert?.user_agent ||
    ''
  ).trim();
}

function extractPathCandidates(rawAlert) {
  const candidates = [];
  const push = (v) => {
    const s = String(v ?? '').trim();
    if (s && !candidates.includes(s)) candidates.push(s);
  };
  push(rawAlert?.data?.url);
  push(rawAlert?.data?.uri);
  push(rawAlert?.data?.http?.url);
  push(rawAlert?.data?.http?.path);
  push(rawAlert?.data?.win?.eventdata?.targetFilename);

  const fullLog = String(rawAlert?.full_log || '');
  const httpMatch = fullLog.match(/(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s"']+)/i);
  if (httpMatch && httpMatch[1]) push(httpMatch[1]);
  return candidates;
}

function extractHttpStatus(rawAlert) {
  const candidates = [
    rawAlert?.data?.http_status,
    rawAlert?.data?.status,
    rawAlert?.data?.http?.status_code,
    rawAlert?.data?.id,
  ];
  for (const c of candidates) {
    const s = String(c ?? '').trim();
    if (/^[1-5]\d{2}$/.test(s)) return s;
  }
  const fullLog = String(rawAlert?.full_log || '');
  const m = fullLog.match(/HTTP\/[12](?:\.\d)?"\s+([1-5]\d\d)\b/);
  return m ? m[1] : '';
}

function normalizePath(rawPath) {
  const s = String(rawPath || '').trim();
  if (!s) return '';
  const noQuery = s.split('?')[0];
  return noQuery
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '/:uuid')
    .replace(/\/[0-9a-f]{24,}/gi, '/:hex')
    .replace(/\/\d+(?=\/|$)/g, '/:id')
    .slice(0, 140);
}

function sanitizeExclusionRule(raw, idx = 0) {
  const target = raw?.target === 'full_log' ? 'full_log' : 'path';
  const mode = raw?.mode === 'starts_with' || raw?.mode === 'regex' ? raw.mode : 'contains';
  const pattern = String(raw?.pattern ?? '').trim();
  if (!pattern) return null;
  return {
    id: String(raw?.id || ('ex_' + idx + '_' + crypto.randomBytes(3).toString('hex'))),
    target,
    mode,
    pattern,
    enabled: raw?.enabled !== false,
    note: String(raw?.note ?? '').trim().slice(0, 120),
  };
}

function matchesRule(candidates, rule) {
  if (!rule || !rule.enabled || !rule.pattern) return false;
  const needle = String(rule.pattern);
  const needleLower = needle.toLowerCase();

  let compiledRe = null;
  if (rule.mode === 'regex') {
    try {
      compiledRe = new RegExp(needle, 'i');
    } catch {
      return false;
    }
  }

  for (const val of candidates) {
    const str = String(val || '');
    if (!str) continue;
    if (rule.mode === 'regex') {
      if (compiledRe && compiledRe.test(str)) return true;
    } else if (rule.mode === 'starts_with') {
      if (str.toLowerCase().startsWith(needleLower)) return true;
    } else {
      if (str.toLowerCase().includes(needleLower)) return true;
    }
  }
  return false;
}

function evaluateExclusions(rawAlert, rules) {
  const activeRules = Array.isArray(rules) ? rules.filter((r) => r && r.enabled && r.pattern) : [];
  if (!activeRules.length) return { excluded: false };

  const pathCandidates = extractPathCandidates(rawAlert);
  const logCandidates = [
    rawAlert?.full_log,
    rawAlert?.rule?.description,
    rawAlert?.data?.http_user_agent,
    rawAlert?.data?.url,
  ].filter(Boolean);

  for (const rule of activeRules) {
    const targets = rule.target === 'full_log' ? logCandidates : pathCandidates;
    if (matchesRule(targets, rule)) {
      return {
        excluded: true,
        ruleId: rule.id,
        ruleLabel: rule.pattern,
      };
    }
  }
  return { excluded: false };
}

function wildcardToRegex(pattern) {
  const escaped = String(pattern || '')
    .trim()
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*');
  return new RegExp('^' + escaped + '$', 'i');
}

function resolveTenant(rawAlert, tenantMapping = {}, knownTenants = []) {
  const directTenant = String(rawAlert?.agent?.labels?.tenant || '').trim();
  const groupLabel = String(rawAlert?.agent?.labels?.group || '').trim();
  const agentName = String(rawAlert?.agent?.name || '').trim();
  const candidates = [directTenant, groupLabel, agentName].filter(Boolean);

  if (tenantMapping && typeof tenantMapping === 'object') {
    for (const [pattern, mappedTenant] of Object.entries(tenantMapping)) {
      const target = String(mappedTenant || '').trim();
      const pat = String(pattern || '').trim();
      if (!pat || !target) continue;
      if (pat.includes('*')) {
        const re = wildcardToRegex(pat);
        if (candidates.some((c) => re.test(c))) return target;
      } else {
        const patLow = pat.toLowerCase();
        if (candidates.some((c) => c.toLowerCase() === patLow || c.toLowerCase().includes(patLow))) {
          return target;
        }
      }
    }
  }

  if (directTenant) return directTenant.toLowerCase();

  const known = Array.isArray(knownTenants) ? knownTenants.filter(Boolean) : [];
  const joined = candidates.join(' ').toLowerCase().replace(/[^a-z0-9]/g, '');
  for (const kt of known) {
    const norm = String(kt).toLowerCase().replace(/[^a-z0-9]/g, '');
    if (norm && joined.includes(norm)) return String(kt).toLowerCase();
  }

  if (groupLabel) return groupLabel.toLowerCase();
  return 'unassigned';
}

function requestJson(rawUrl, opts = {}) {
  return new Promise((resolve, reject) => {
    let urlObj;
    try {
      urlObj = new URL(String(rawUrl));
    } catch {
      return reject(new Error('URL tidak valid: ' + rawUrl));
    }
    if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
      return reject(new Error('Protokol URL harus http atau https'));
    }

    const client = urlObj.protocol === 'https:' ? https : http;
    const method = (opts.method || 'GET').toUpperCase();
    const payload = opts.body != null
      ? (typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body))
      : null;

    const headers = {
      accept: 'application/json',
      ...(opts.headers || {}),
    };
    if (payload != null) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = Buffer.byteLength(payload, 'utf8');
    }

    const timeoutMs = Number(opts.timeoutMs) > 0 ? Number(opts.timeoutMs) : 20000;
    const req = client.request(
      urlObj,
      {
        method,
        headers,
        timeout: timeoutMs,
        rejectUnauthorized: urlObj.protocol === 'https:' ? !opts.allowSelfSigned : undefined,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try {
            json = text ? JSON.parse(text) : null;
          } catch {
            json = null;
          }
          if (res.statusCode >= 200 && res.statusCode < 300) {
            return resolve({ status: res.statusCode, json, text });
          }
          const detail = json?.error?.reason || json?.error || json?.message || text.slice(0, 220) || ('HTTP ' + res.statusCode);
          const err = new Error('HTTP ' + res.statusCode + ': ' + detail);
          err.status = res.statusCode;
          reject(err);
        });
      },
    );

    req.on('timeout', () => req.destroy(new Error('Timeout (' + timeoutMs + ' ms) menghubungi ' + urlObj.origin)));
    req.on('error', reject);
    if (payload != null) req.write(payload);
    req.end();
  });
}

function buildWazuhIndexUrl(baseUrl, indexPattern, suffix) {
  const cleanBase = String(baseUrl || '').trim().replace(/\/+$/, '');
  const idx = String(indexPattern || 'wazuh-alerts-*').trim() || 'wazuh-alerts-*';
  const encodedIdx = idx.split(',').map((part) => encodeURIComponent(part.trim())).join(',');
  return cleanBase + '/' + encodedIdx + suffix;
}

function parseJsonFromAiText(rawText) {
  const s = String(rawText || '').trim();
  if (!s) return null;
  try {
    return JSON.parse(s);
  } catch {
    const fenced = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
    if (fenced && fenced[1]) {
      try { return JSON.parse(fenced[1].trim()); } catch {}
    }
    const startObj = s.indexOf('{');
    const endObj = s.lastIndexOf('}');
    if (startObj >= 0 && endObj > startObj) {
      try { return JSON.parse(s.slice(startObj, endObj + 1)); } catch {}
    }
    const startArr = s.indexOf('[');
    const endArr = s.lastIndexOf(']');
    if (startArr >= 0 && endArr > startArr) {
      try { return JSON.parse(s.slice(startArr, endArr + 1)); } catch {}
    }
    return null;
  }
}

function chunkAlertsForPromote(alerts, maxPerCase = MAX_ALERTS_PER_CASE) {
  const chunks = [];
  for (let i = 0; i < alerts.length; i += maxPerCase) {
    chunks.push(alerts.slice(i, i + maxPerCase));
  }
  return chunks;
}

function createTriageEngine(options = {}) {
  const dataDir = options.dataDir || path.resolve(__dirname, '..', '..', 'data');
  const getKnownTenants = typeof options.getKnownTenants === 'function' ? options.getKnownTenants : () => [];

  const configPath = path.join(dataDir, 'server-config.json');
  const statePath = path.join(dataDir, 'triage-state.json');
  const historyPath = path.join(dataDir, 'case-history.json');

  let config = loadConfig();
  let state = loadState();
  let caseHistory = loadCaseHistory();

  let pollTimer = null;
  let pollLock = Promise.resolve();
  let ollamaLock = Promise.resolve();
  let pollInFlight = false;
  const sseClients = new Set();

  function loadConfig() {
    const def = defaultConfig();
    const raw = readJsonSafe(configPath, null);
    if (!raw || typeof raw !== 'object') return def;
    const mergedWazuh = { ...def.wazuh, ...(raw.wazuh || {}) };
    mergedWazuh.minRuleLevel = Math.max(0, Math.min(15, Number(mergedWazuh.minRuleLevel ?? 7)));
    mergedWazuh.maxRuleLevel = Math.max(mergedWazuh.minRuleLevel, Math.min(20, Number(mergedWazuh.maxRuleLevel ?? 15)));
    mergedWazuh.pollIntervalMin = Math.max(1, Math.min(120, Number(mergedWazuh.pollIntervalMin ?? 3)));
    mergedWazuh.liveRefreshSec = Math.max(3, Math.min(300, Number(mergedWazuh.liveRefreshSec ?? 10)));
    if (!mergedWazuh.tenantMapping || typeof mergedWazuh.tenantMapping !== 'object' || Array.isArray(mergedWazuh.tenantMapping)) {
      mergedWazuh.tenantMapping = {};
    }

    const mergedOllama = { ...def.ollama, ...(raw.ollama || {}) };
    if (!String(mergedOllama.systemPrompt || '').trim()) {
      mergedOllama.systemPrompt = DEFAULT_SYSTEM_PROMPT;
    }
    const temp = Number(mergedOllama.temperature);
    mergedOllama.temperature = Number.isFinite(temp) ? Math.max(0, Math.min(2, temp)) : 0.1;

    const rules = Array.isArray(raw.exclusionRules)
      ? raw.exclusionRules.map((r, i) => sanitizeExclusionRule(r, i)).filter(Boolean)
      : def.exclusionRules;

    return {
      workerEnabled: Boolean(raw.workerEnabled),
      wazuh: mergedWazuh,
      ollama: mergedOllama,
      exclusionRules: rules,
      updatedAt: raw.updatedAt || null,
    };
  }

  function loadState() {
    const def = defaultTriageState();
    const raw = readJsonSafe(statePath, null);
    if (!raw || typeof raw !== 'object') return def;
    return {
      watermarkTimestamp: raw.watermarkTimestamp || null,
      groups: Array.isArray(raw.groups) ? raw.groups : [],
      processedAlertIds: Array.isArray(raw.processedAlertIds) ? raw.processedAlertIds : [],
      dismissedAlertIds: Array.isArray(raw.dismissedAlertIds) ? raw.dismissedAlertIds : [],
      caseCreatedAlertIds: Array.isArray(raw.caseCreatedAlertIds) ? raw.caseCreatedAlertIds : [],
      excludedAlertMap: raw.excludedAlertMap && typeof raw.excludedAlertMap === 'object' ? raw.excludedAlertMap : {},
      workerStatus: { ...def.workerStatus, ...(raw.workerStatus || {}), running: false },
    };
  }

  function loadCaseHistory() {
    const raw = readJsonSafe(historyPath, []);
    return Array.isArray(raw) ? raw : [];
  }

  function saveConfig() {
    writeJsonAtomic(configPath, config);
  }

  function saveState() {
    state.processedAlertIds = trimArray(state.processedAlertIds, MAX_SEEN_IDS);
    state.dismissedAlertIds = trimArray(state.dismissedAlertIds, MAX_SEEN_IDS);
    state.caseCreatedAlertIds = trimArray(state.caseCreatedAlertIds, MAX_SEEN_IDS);
    const exKeys = Object.keys(state.excludedAlertMap || {});
    if (exKeys.length > 5000) {
      for (const k of exKeys.slice(0, exKeys.length - 5000)) {
        delete state.excludedAlertMap[k];
      }
    }
    state.groups = state.groups.slice(0, MAX_ACTIVE_GROUPS);
    writeJsonAtomic(statePath, state);
  }

  function saveCaseHistory() {
    caseHistory = caseHistory.slice(0, MAX_CASE_HISTORY);
    writeJsonAtomic(historyPath, caseHistory);
  }

  function sanitizeConfigForClient(cfg = config) {
    const out = cloneJson(cfg);
    const hasPw = Boolean(out.wazuh?.password);
    if (out.wazuh) {
      delete out.wazuh.password;
      out.wazuh.hasPassword = hasPw;
    }
    return out;
  }

  function summarizeCounts(groups = state.groups) {
    const counts = { TRUE_POSITIVE: 0, NEEDS_REVIEW: 0, FALSE_POSITIVE: 0, total: groups.length, totalAlerts: 0 };
    for (const g of groups) {
      if (g.verdict === 'TRUE_POSITIVE') counts.TRUE_POSITIVE++;
      else if (g.verdict === 'FALSE_POSITIVE') counts.FALSE_POSITIVE++;
      else counts.NEEDS_REVIEW++;
      counts.totalAlerts += Number(g.alert_count || g.alerts?.length || 0);
    }
    return counts;
  }

  function getQueueSnapshot(filters = {}) {
    let items = state.groups.slice();
    const verdict = String(filters.verdict || '').trim().toUpperCase();
    const tenant = String(filters.tenant || '').trim().toLowerCase();
    const q = String(filters.q || '').trim().toLowerCase();

    if (verdict && VALID_VERDICTS.includes(verdict)) {
      items = items.filter((g) => g.verdict === verdict);
    }
    if (tenant) {
      items = items.filter((g) => String(g.tenant_mapped || '').toLowerCase() === tenant);
    }
    if (q) {
      items = items.filter((g) => {
        const hay = [
          g.incident_title,
          g.ai_reasoning,
          g.tenant_mapped,
          ...(g.source_ips || []),
          ...(g.rule_ids || []),
          ...(g.agents || []).map((a) => a.name),
          ...(g.alerts || []).map((a) => a.alert_id),
        ].join(' ').toLowerCase();
        return hay.includes(q);
      });
    }

    const order = { TRUE_POSITIVE: 0, NEEDS_REVIEW: 1, FALSE_POSITIVE: 2 };
    items.sort((a, b) => {
      const vo = (order[a.verdict] ?? 9) - (order[b.verdict] ?? 9);
      if (vo !== 0) return vo;
      return Date.parse(b.last_seen || 0) - Date.parse(a.last_seen || 0);
    });

    const tenantsSet = new Set(state.groups.map((g) => g.tenant_mapped).filter(Boolean));

    return {
      ok: true,
      workerEnabled: Boolean(config.workerEnabled),
      workerStatus: { ...state.workerStatus, running: pollInFlight },
      watermarkTimestamp: state.watermarkTimestamp,
      counts: summarizeCounts(state.groups),
      tenants: [...tenantsSet].sort(),
      groups: items,
      historyCount: caseHistory.length,
    };
  }

  function broadcastSse(eventName, payload) {
    if (!sseClients.size) return;
    const msg = `event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`;
    for (const res of sseClients) {
      try {
        res.write(msg);
      } catch {
        sseClients.delete(res);
      }
    }
  }

  function subscribeSse(res) {
    res.writeHead(200, {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
    });
    res.write(`event: state\ndata: ${JSON.stringify(getQueueSnapshot())}\n\n`);
    sseClients.add(res);
    res.on('close', () => sseClients.delete(res));
  }

  function buildWazuhAuthHeaders(wazuhCfg) {
    const headers = {};
    const u = String(wazuhCfg?.username || '').trim();
    const p = String(wazuhCfg?.password || '');
    if (u || p) {
      headers.authorization = 'Basic ' + Buffer.from(u + ':' + p, 'utf8').toString('base64');
    }
    return headers;
  }

  function resolveEffectiveWazuhConfig(override = {}) {
    const w = { ...config.wazuh, ...(override || {}) };
    if (!w.password && !override?.clearPassword) {
      w.password = config.wazuh.password || '';
    }
    return w;
  }

  async function testWazuhConnection(overrideWazuh) {
    const w = resolveEffectiveWazuhConfig(overrideWazuh);
    if (!String(w.url || '').trim()) {
      throw Object.assign(new Error('Wazuh Indexer URL wajib diisi.'), { status: 400 });
    }
    const started = Date.now();
    const headers = buildWazuhAuthHeaders(w);
    const cleanBase = String(w.url).trim().replace(/\/+$/, '');
    const levelQuery = {
      range: {
        'rule.level': {
          gte: Number(w.minRuleLevel ?? 7),
          lte: Number(w.maxRuleLevel ?? 15),
        },
      },
    };

    let docCount = null;
    try {
      const countRes = await requestJson(buildWazuhIndexUrl(cleanBase, w.indexPattern, '/_count'), {
        method: 'POST',
        headers,
        allowSelfSigned: w.allowSelfSigned,
        timeoutMs: 12000,
        body: { query: levelQuery },
      });
      if (typeof countRes.json?.count === 'number') docCount = countRes.json.count;
    } catch (countErr) {
      if (countErr?.status === 403 || countErr?.status === 405) {
        const searchRes = await requestJson(buildWazuhIndexUrl(cleanBase, w.indexPattern, '/_search'), {
          method: 'POST',
          headers,
          allowSelfSigned: w.allowSelfSigned,
          timeoutMs: 12000,
          body: { size: 0, track_total_hits: true, query: levelQuery },
        });
        const rawTotal = searchRes.json?.hits?.total;
        docCount = typeof rawTotal === 'number'
          ? rawTotal
          : (typeof rawTotal?.value === 'number' ? rawTotal.value : null);
      } else {
        throw countErr;
      }
    }

    let clusterName = 'Wazuh Indexer (' + (w.indexPattern || 'wazuh-alerts-*') + ')';
    let status = 'read-only';
    try {
      const info = await requestJson(cleanBase + '/_cluster/health', {
        method: 'GET',
        headers,
        allowSelfSigned: w.allowSelfSigned,
        timeoutMs: 4000,
      });
      clusterName = info.json?.cluster_name || info.json?.name || clusterName;
      status = info.json?.status || 'connected';
    } catch {
      // Optional cluster monitor check; least-privilege read-only users lack cluster:monitor/main
    }

    return {
      ok: true,
      latencyMs: Date.now() - started,
      clusterName,
      status,
      docCount,
    };
  }

  async function testOllamaConnection(overrideOllama) {
    const o = { ...config.ollama, ...(overrideOllama || {}) };
    if (!String(o.baseUrl || '').trim()) {
      throw Object.assign(new Error('Ollama Base URL wajib diisi.'), { status: 400 });
    }
    const cleanBase = String(o.baseUrl).trim().replace(/\/+$/, '');
    const started = Date.now();
    const res = await requestJson(cleanBase + '/api/tags', {
      method: 'GET',
      timeoutMs: 10000,
    });
    const models = Array.isArray(res.json?.models) ? res.json.models.map((m) => m.name || m.model).filter(Boolean) : [];
    const target = String(o.model || '').trim();
    const modelAvailable = Boolean(target && models.some((m) => m === target || m.startsWith(target)));
    return {
      ok: true,
      latencyMs: Date.now() - started,
      models,
      modelAvailable,
    };
  }

  async function queryWazuhAlerts({ sinceIso = null, untilIso = null, inclusiveSince = false, size = 500, minLevel, maxLevel } = {}) {
    const w = config.wazuh;
    if (!String(w.url || '').trim()) {
      throw Object.assign(new Error('Wazuh Indexer URL belum dikonfigurasi.'), { status: 400 });
    }
    const gte = Number(minLevel ?? w.minRuleLevel ?? 7);
    const lte = Number(maxLevel ?? w.maxRuleLevel ?? 15);
    const filter = [{ range: { 'rule.level': { gte, lte } } }];
    if (sinceIso || untilIso) {
      const tsRange = {};
      if (sinceIso) tsRange[inclusiveSince ? 'gte' : 'gt'] = sinceIso;
      if (untilIso) tsRange.lte = untilIso;
      filter.push({ range: { '@timestamp': tsRange } });
    }

    const body = {
      size: Math.min(Math.max(1, Number(size) || 500), 1000),
      track_total_hits: true,
      sort: [{ '@timestamp': { order: 'desc' } }],
      query: { bool: { filter } },
    };

    const res = await requestJson(buildWazuhIndexUrl(w.url, w.indexPattern, '/_search'), {
      method: 'POST',
      headers: buildWazuhAuthHeaders(w),
      allowSelfSigned: w.allowSelfSigned,
      timeoutMs: 25000,
      body,
    });

    const rawTotal = res.json?.hits?.total;
    const totalHits = typeof rawTotal === 'number'
      ? rawTotal
      : (typeof rawTotal?.value === 'number' ? rawTotal.value : (res.json?.hits?.hits?.length || 0));

    const hits = (res.json?.hits?.hits || []).map((hit) => {
      const src = hit?._source || {};
      const alertId = String(hit?._id || src.id || crypto.randomBytes(8).toString('hex'));
      return {
        alert_id: alertId,
        raw_wazuh_alert: src,
      };
    });

    return { totalHits, hits };
  }

  async function fetchWazuhByIds(ids = []) {
    const cleanIds = [...new Set((ids || []).map((x) => String(x || '').trim()).filter(Boolean))].slice(0, 1000);
    if (!cleanIds.length) return { ok: true, total: 0, alerts: [] };
    const w = config.wazuh;
    if (!String(w.url || '').trim()) {
      throw Object.assign(new Error('Wazuh Indexer URL belum dikonfigurasi.'), { status: 400 });
    }

    const body = {
      size: cleanIds.length,
      sort: [{ '@timestamp': { order: 'desc' } }],
      query: {
        bool: {
          should: [
            { ids: { values: cleanIds } },
            { terms: { 'id.keyword': cleanIds } },
            { terms: { id: cleanIds } },
          ],
          minimum_should_match: 1,
        },
      },
    };

    const res = await requestJson(buildWazuhIndexUrl(w.url, w.indexPattern, '/_search'), {
      method: 'POST',
      headers: buildWazuhAuthHeaders(w),
      allowSelfSigned: w.allowSelfSigned,
      timeoutMs: 25000,
      body,
    });

    const alerts = (res.json?.hits?.hits || []).map((hit) => ({
      alert_id: String(hit?._id || hit?._source?.id || ''),
      raw_wazuh_alert: hit?._source || {},
    }));
    return { ok: true, total: alerts.length, alerts };
  }

  function withOllamaLock(task) {
    const run = ollamaLock.then(task, task);
    ollamaLock = run.then(() => {}, () => {});
    return run;
  }

  async function runOllamaMicroBatch(tenant, candidates, existingGroupKeys = []) {
    const o = config.ollama;
    const baseUrl = String(o.baseUrl || '').trim().replace(/\/+$/, '');
    if (!baseUrl) {
      throw new Error('Ollama Base URL kosong');
    }

    const summaryCandidates = candidates.map((c) => ({
      candidate_id: c.candidateId,
      tenant,
      rule_id: c.ruleId,
      rule_level: c.maxRuleLevel,
      rule_description: c.ruleDesc,
      mitre: c.mitre,
      agent_names: c.agents.map((a) => a.name).slice(0, 8),
      source_ip_count: c.sourceIps.length,
      source_ips: c.sourceIps.slice(0, 5),
      http_statuses: c.httpStatuses || {},
      normalized_path: c.normalizedPath,
      alert_count: c.alerts.length,
      samples: c.samples,
    }));

    const promptLines = [
      `Tenant target: "${tenant}". Semua kandidat di bawah HANYA milik tenant "${tenant}".`,
      'Tugas: Klasifikasikan tiap candidate_id (TRUE_POSITIVE | NEEDS_REVIEW | FALSE_POSITIVE) dan berikan group_key semantik agar kampanye serangan sejenis (mis. scanning /.env lintas agent) bisa menyatu, sementara trafik legit (mis. /login.php, /mhs/nim) terpisah walau rule_id sama.',
      'Format JSON WAJIB:',
      '{"results":[{"candidate_id":"...","verdict":"TRUE_POSITIVE|NEEDS_REVIEW|FALSE_POSITIVE","group_key":"slug-singkat","incident_title":"Judul insiden ringkas","ai_reasoning":"Alasan teknis singkat"}]}',
    ];
    if (Array.isArray(existingGroupKeys) && existingGroupKeys.length > 0) {
      promptLines.push(
        `Grup aktif yang sudah ada pada tenant ini (gunakan group_key yang sama jika insiden berlanjut): ${JSON.stringify(existingGroupKeys.slice(0, 20))}`
      );
    }
    promptLines.push('', 'Kandidat batch:', JSON.stringify(summaryCandidates));
    const userPrompt = promptLines.join('\n');

    const res = await withOllamaLock(() => requestJson(baseUrl + '/api/chat', {
      method: 'POST',
      timeoutMs: 90000,
      body: {
        model: o.model,
        stream: false,
        think: false,
        keep_alive: '2m',
        format: TRIAGE_RESPONSE_SCHEMA,
        options: {
          temperature: Number(o.temperature ?? 0.1),
          num_ctx: 12288,
          num_predict: 2048,
          top_p: 0.85,
          top_k: 20,
          repeat_penalty: 1.05,
        },
        messages: [
          { role: 'system', content: o.systemPrompt || DEFAULT_SYSTEM_PROMPT },
          { role: 'user', content: userPrompt },
        ],
      },
    }));

    const content = res.json?.message?.content ?? res.json?.response ?? '';
    const parsed = parseJsonFromAiText(content);
    const list = Array.isArray(parsed)
      ? parsed
      : (Array.isArray(parsed?.results) ? parsed.results : (Array.isArray(parsed?.groups) ? parsed.groups : null));

    if (!list) {
      throw new Error('Respons Ollama bukan JSON array/results valid');
    }

    const byCandidateId = new Map();
    for (const item of list) {
      const cid = String(item?.candidate_id || item?.id || '').trim();
      if (cid) byCandidateId.set(cid, item);
    }
    return byCandidateId;
  }

  function recomputeGroupMetadata(group) {
    const alerts = Array.isArray(group.alerts) ? group.alerts : [];
    const agentMap = new Map();
    const ipSet = new Set();
    const ruleSet = new Set();
    let maxLvl = 0;

    for (const item of alerts) {
      const raw = item?.raw_wazuh_alert || {};
      const agId = String(raw.agent?.id || '');
      const agName = String(raw.agent?.name || '').trim();
      if (agName) {
        const key = agId + '|' + agName;
        if (!agentMap.has(key)) agentMap.set(key, { id: agId, name: agName });
      }
      const ip = extractSrcIp(raw);
      if (ip) ipSet.add(ip);
      const rid = String(raw.rule?.id || '').trim();
      if (rid) ruleSet.add(rid);
      const lvl = Number(raw.rule?.level || 0);
      if (lvl > maxLvl) maxLvl = lvl;
    }

    group.agents = [...agentMap.values()];
    group.agent_name = group.agents.map((a) => a.name).join(', ');
    group.source_ips = [...ipSet];
    group.rule_ids = [...ruleSet];
    group.max_rule_level = maxLvl;
    group.severity_label = severityLabel(maxLvl);
    group.alert_count = alerts.length;

    const times = alerts
      .map((a) => extractAlertTimestamp(a.raw_wazuh_alert))
      .filter(Boolean)
      .sort((a, b) => Date.parse(a) - Date.parse(b));
    if (times.length) {
      group.first_seen = times[0];
      group.last_seen = times[times.length - 1];
    } else {
      group.first_seen = null;
      group.last_seen = null;
    }
    return group;
  }

  function mergeAlertWrappersIntoGroup(targetGroup, incoming) {
    const seenAlertIds = new Set((targetGroup.alerts || []).map((a) => a.alert_id));
    for (const item of incoming.alerts || []) {
      if (!seenAlertIds.has(item.alert_id)) {
        seenAlertIds.add(item.alert_id);
        targetGroup.alerts.push(item);
      }
    }

    const agentMap = new Map();
    for (const a of [...(targetGroup.agents || []), ...(incoming.agents || [])]) {
      const key = (a.id || '') + '|' + (a.name || '');
      if (a.name && !agentMap.has(key)) agentMap.set(key, { id: a.id || '', name: a.name });
    }
    targetGroup.agents = [...agentMap.values()];
    targetGroup.agent_name = targetGroup.agents.map((a) => a.name).join(', ');

    targetGroup.source_ips = [...new Set([...(targetGroup.source_ips || []), ...(incoming.source_ips || [])].filter(Boolean))];
    targetGroup.rule_ids = [...new Set([...(targetGroup.rule_ids || []), ...(incoming.rule_ids || [])].filter(Boolean))];
    targetGroup.max_rule_level = Math.max(Number(targetGroup.max_rule_level || 0), Number(incoming.max_rule_level || 0));
    targetGroup.severity_label = severityLabel(targetGroup.max_rule_level);
    targetGroup.alert_count = targetGroup.alerts.length;

    const times = targetGroup.alerts
      .map((a) => extractAlertTimestamp(a.raw_wazuh_alert))
      .filter(Boolean)
      .sort((a, b) => Date.parse(a) - Date.parse(b));
    if (times.length) {
      targetGroup.first_seen = times[0];
      targetGroup.last_seen = times[times.length - 1];
    }
    if (incoming.ai_reasoning && !targetGroup.ai_reasoning) {
      targetGroup.ai_reasoning = incoming.ai_reasoning;
    }
  }

  function preGroupByTenant(hits) {
    const processedSet = new Set(state.processedAlertIds);
    const dismissedSet = new Set(state.dismissedAlertIds);
    const createdSet = new Set(state.caseCreatedAlertIds);
    const knownTenants = getKnownTenants();

    let excludedCount = 0;
    const byTenantBuckets = new Map();

    for (const hit of hits) {
      const id = hit.alert_id;
      if (processedSet.has(id) || dismissedSet.has(id) || createdSet.has(id) || state.excludedAlertMap[id]) {
        continue;
      }

      const raw = hit.raw_wazuh_alert || {};
      const ex = evaluateExclusions(raw, config.exclusionRules);
      if (ex.excluded) {
        state.excludedAlertMap[id] = { ruleLabel: ex.ruleLabel, at: new Date().toISOString() };
        state.processedAlertIds.push(id);
        excludedCount++;
        continue;
      }

      const tenant = resolveTenant(raw, config.wazuh.tenantMapping, knownTenants);
      const ruleId = String(raw.rule?.id || 'unknown');
      const ruleLevel = Number(raw.rule?.level || 0);
      const ruleDesc = String(raw.rule?.description || 'Security Alert');
      const agentId = String(raw.agent?.id || '');
      const agentName = String(raw.agent?.name || 'unknown-agent');
      const srcIp = extractSrcIp(raw) || 'none';
      const pathCands = extractPathCandidates(raw);
      const normPath = normalizePath(pathCands[0] || '') || 'none';
      const httpStatus = extractHttpStatus(raw);
      const ua = extractUserAgent(raw);

      const bucketKey = [tenant, ruleId, normPath].join('|');
      if (!byTenantBuckets.has(tenant)) byTenantBuckets.set(tenant, new Map());
      const tenantMap = byTenantBuckets.get(tenant);

      if (!tenantMap.has(bucketKey)) {
        tenantMap.set(bucketKey, {
          candidateId: 'cand_' + (tenantMap.size + 1) + '_' + crypto.randomBytes(2).toString('hex'),
          tenant,
          ruleId,
          ruleDesc,
          mitre: raw.rule?.mitre || null,
          maxRuleLevel: ruleLevel,
          normalizedPath: normPath === 'none' ? '' : normPath,
          httpStatuses: {},
          agents: [],
          sourceIps: [],
          alerts: [],
          samples: [],
          _agentKeys: new Set(),
          _ipKeys: new Set(),
          _sampleKeys: new Set(),
        });
      }

      const cand = tenantMap.get(bucketKey);
      cand.maxRuleLevel = Math.max(cand.maxRuleLevel, ruleLevel);
      if (httpStatus) {
        cand.httpStatuses[httpStatus] = (cand.httpStatuses[httpStatus] || 0) + 1;
      }
      const agKey = agentId + '|' + agentName;
      if (!cand._agentKeys.has(agKey)) {
        cand._agentKeys.add(agKey);
        cand.agents.push({ id: agentId, name: agentName });
      }
      if (srcIp !== 'none' && !cand._ipKeys.has(srcIp)) {
        cand._ipKeys.add(srcIp);
        cand.sourceIps.push(srcIp);
      }
      cand.alerts.push({ alert_id: id, raw_wazuh_alert: raw });
      const sampleUrl = pathCands[0] || '';
      const sampleKey = [sampleUrl, httpStatus, ua].join('|');
      if (cand.samples.length < 3 && !cand._sampleKeys.has(sampleKey)) {
        cand._sampleKeys.add(sampleKey);
        cand.samples.push({
          url: sampleUrl,
          http_status: httpStatus || undefined,
          user_agent: ua,
          full_log: String(raw.full_log || '').slice(0, 300),
        });
      }
    }

    return { excludedCount, byTenantBuckets };
  }

  async function processHitsIntoQueue(hits) {
    const { excludedCount, byTenantBuckets } = preGroupByTenant(hits);
    let analyzedCount = 0;

    for (const [tenant, bucketMap] of byTenantBuckets.entries()) {
      const candidates = [...bucketMap.values()];
      if (!candidates.length) continue;

      const existingGroupKeys = [
        ...new Set(state.groups.filter((g) => g.tenant_mapped === tenant && g.group_key).map((g) => g.group_key)),
      ].slice(0, 20);

      const aiMap = new Map();
      const chunkErrors = new Map();
      for (let i = 0; i < candidates.length; i += OLLAMA_MICRO_BATCH_SIZE) {
        const chunk = candidates.slice(i, i + OLLAMA_MICRO_BATCH_SIZE);
        try {
          const partMap = await runOllamaMicroBatch(tenant, chunk, existingGroupKeys);
          for (const [cid, val] of partMap.entries()) aiMap.set(cid, val);
        } catch (err) {
          const msg = err.message || 'Ollama tidak terjangkau';
          for (const c of chunk) chunkErrors.set(c.candidateId, msg);
        }
      }

      const mergedInTenant = new Map();

      for (const cand of candidates) {
        const ai = aiMap.get(cand.candidateId) || null;
        const fallbackErr = chunkErrors.get(cand.candidateId) || null;
        const rawVerdict = String(ai?.verdict || '').trim().toUpperCase();
        const verdict = VALID_VERDICTS.includes(rawVerdict) ? rawVerdict : 'NEEDS_REVIEW';
        const unanalyzed = !ai || !VALID_VERDICTS.includes(rawVerdict);
        const groupKey = String(ai?.group_key || (cand.ruleId + '-' + (cand.normalizedPath || 'general'))).trim().slice(0, 96);
        const incidentTitle = String(
          ai?.incident_title ||
          (cand.ruleDesc + (cand.normalizedPath ? ' (' + cand.normalizedPath + ')' : ''))
        ).trim().slice(0, 180);
        const aiReasoning = String(
          ai?.ai_reasoning ||
          (fallbackErr
            ? `Unanalyzed (Ollama fallback: ${fallbackErr}). Alert tetap dimasukkan ke Needs Review agar tidak terlewat.`
            : 'Dikelompokkan otomatis sesuai konteks alert.')
        ).trim();

        const semanticBucketKey = tenant + '::' + verdict + '::' + groupKey;
        const chunkPayload = {
          group_id: 'grp-' + new Date().toISOString().slice(0, 10).replace(/-/g, '') + '-' + crypto.randomBytes(3).toString('hex'),
          verdict,
          unanalyzed,
          group_key: groupKey,
          incident_title: incidentTitle,
          tenant_mapped: tenant,
          max_rule_level: cand.maxRuleLevel,
          severity_label: severityLabel(cand.maxRuleLevel),
          agents: cand.agents.slice(),
          agent_name: cand.agents.map((a) => a.name).join(', '),
          source_ips: cand.sourceIps.slice(),
          rule_ids: [cand.ruleId],
          alert_count: cand.alerts.length,
          ai_reasoning: aiReasoning,
          first_seen: null,
          last_seen: null,
          alerts: cand.alerts.slice(),
        };

        if (mergedInTenant.has(semanticBucketKey)) {
          const acc = mergedInTenant.get(semanticBucketKey);
          acc.unanalyzed = acc.unanalyzed && chunkPayload.unanalyzed;
          mergeAlertWrappersIntoGroup(acc, chunkPayload);
        } else {
          mergeAlertWrappersIntoGroup(chunkPayload, { alerts: [] });
          mergedInTenant.set(semanticBucketKey, chunkPayload);
        }

        for (const a of cand.alerts) {
          state.processedAlertIds.push(a.alert_id);
          analyzedCount++;
        }
      }

      for (const groupPayload of mergedInTenant.values()) {
        const existing = state.groups.find(
          (g) =>
            g.tenant_mapped === groupPayload.tenant_mapped &&
            g.verdict === groupPayload.verdict &&
            g.group_key === groupPayload.group_key
        );
        if (existing) {
          mergeAlertWrappersIntoGroup(existing, groupPayload);
        } else {
          state.groups.unshift(groupPayload);
        }
      }
    }

    return { excludedCount, analyzedCount };
  }

  const POLL_RANGE_MS = {
    '15m': 15 * 60 * 1000,
    '30m': 30 * 60 * 1000,
    '1h': 60 * 60 * 1000,
    '6h': 6 * 60 * 60 * 1000,
    '12h': 12 * 60 * 60 * 1000,
    '24h': 24 * 60 * 60 * 1000,
    '7d': 7 * 24 * 60 * 60 * 1000,
  };

  function resolvePollWindow(opts = {}) {
    const range = String(opts?.range || '').trim().toLowerCase();
    const hasCustomBounds = Boolean(opts?.from || opts?.to);
    if (range === 'custom' || hasCustomBounds) {
      let sinceIso = null;
      let untilIso = null;
      if (opts?.from) {
        const ms = Date.parse(opts.from);
        if (Number.isNaN(ms)) {
          throw Object.assign(new Error('Format waktu mulai (Dari) tidak valid.'), { status: 400 });
        }
        sinceIso = new Date(ms).toISOString();
      }
      if (opts?.to) {
        const ms = Date.parse(opts.to);
        if (Number.isNaN(ms)) {
          throw Object.assign(new Error('Format waktu akhir (Sampai) tidak valid.'), { status: 400 });
        }
        untilIso = new Date(ms).toISOString();
      }
      if (sinceIso && untilIso && Date.parse(sinceIso) > Date.parse(untilIso)) {
        throw Object.assign(new Error('Waktu mulai (Dari) tidak boleh lebih besar dari waktu akhir (Sampai).'), { status: 400 });
      }
      return { sinceIso, untilIso, inclusiveSince: true };
    }

    if (Object.prototype.hasOwnProperty.call(POLL_RANGE_MS, range)) {
      return {
        sinceIso: new Date(Date.now() - POLL_RANGE_MS[range]).toISOString(),
        untilIso: null,
        inclusiveSince: true,
      };
    }

    return {
      sinceIso: state.watermarkTimestamp,
      untilIso: null,
      inclusiveSince: false,
    };
  }

  function pollOnce(opts = {}) {
    const win = resolvePollWindow(opts);
    const maxSize = Math.min(Math.max(1, Number(opts?.size) || 500), 1000);
    const run = pollLock.then(async () => {
      if (!String(config.wazuh.url || '').trim()) {
        return { ok: false, skipped: true, reason: 'Wazuh Indexer URL belum diatur' };
      }
      pollInFlight = true;
      state.workerStatus.lastPollAt = new Date().toISOString();
      broadcastSse('worker', { running: true, lastPollAt: state.workerStatus.lastPollAt });

      try {
        const { hits } = await queryWazuhAlerts({
          sinceIso: win.sinceIso,
          untilIso: win.untilIso,
          inclusiveSince: win.inclusiveSince,
          size: maxSize,
          minLevel: config.wazuh.minRuleLevel,
          maxLevel: config.wazuh.maxRuleLevel,
        });
        const { excludedCount, analyzedCount } = await processHitsIntoQueue(hits);
        state.workerStatus.lastSuccessAt = new Date().toISOString();
        state.workerStatus.lastError = null;
        state.workerStatus.lastBatchCount = hits.length;
        state.workerStatus.lastExcludedCount = excludedCount;
        state.workerStatus.lastAnalyzedCount = analyzedCount;
        saveState();
        broadcastSse('state', getQueueSnapshot());
        return {
          ok: true,
          fetchedCount: hits.length,
          excludedCount,
          analyzedCount,
          window: { sinceIso: win.sinceIso, untilIso: win.untilIso },
          snapshot: getQueueSnapshot(),
        };
      } catch (err) {
        state.workerStatus.lastError = err.message || 'Gagal polling Wazuh Indexer';
        saveState();
        broadcastSse('state', getQueueSnapshot());
        throw err;
      } finally {
        pollInFlight = false;
      }
    });

    pollLock = run.then(() => {}, () => {});
    return run;
  }

  function applyScheduler() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
    if (config.workerEnabled && String(config.wazuh.url || '').trim()) {
      const intervalMs = Math.max(1, Number(config.wazuh.pollIntervalMin || 3)) * 60 * 1000;
      pollTimer = setInterval(() => {
        pollOnce().catch(() => {});
      }, intervalMs);
      if (typeof pollTimer.unref === 'function') pollTimer.unref();
    }
  }

  function updateConfig(patch = {}) {
    const next = cloneJson(config);
    if (patch.workerEnabled !== undefined) next.workerEnabled = Boolean(patch.workerEnabled);

    if (patch.wazuh && typeof patch.wazuh === 'object') {
      const pwIn = patch.wazuh;
      if (pwIn.url !== undefined) next.wazuh.url = String(pwIn.url || '').trim().replace(/\/+$/, '');
      if (pwIn.indexPattern !== undefined) next.wazuh.indexPattern = String(pwIn.indexPattern || 'wazuh-alerts-*').trim() || 'wazuh-alerts-*';
      if (pwIn.username !== undefined) next.wazuh.username = String(pwIn.username || '').trim();
      if (pwIn.clearPassword === true) {
        next.wazuh.password = '';
      } else if (typeof pwIn.password === 'string' && pwIn.password.length > 0) {
        next.wazuh.password = pwIn.password;
      }
      if (pwIn.allowSelfSigned !== undefined) next.wazuh.allowSelfSigned = Boolean(pwIn.allowSelfSigned);
      if (pwIn.severityPreset !== undefined) next.wazuh.severityPreset = String(pwIn.severityPreset || 'medium_critical');
      if (pwIn.minRuleLevel !== undefined) next.wazuh.minRuleLevel = Math.max(0, Math.min(15, Number(pwIn.minRuleLevel) || 0));
      if (pwIn.maxRuleLevel !== undefined) next.wazuh.maxRuleLevel = Math.max(next.wazuh.minRuleLevel, Math.min(20, Number(pwIn.maxRuleLevel) || 15));
      if (pwIn.pollIntervalMin !== undefined) next.wazuh.pollIntervalMin = Math.max(1, Math.min(120, Number(pwIn.pollIntervalMin) || 3));
      if (pwIn.liveRefreshSec !== undefined) next.wazuh.liveRefreshSec = Math.max(3, Math.min(300, Number(pwIn.liveRefreshSec) || 10));
      if (pwIn.tenantMapping && typeof pwIn.tenantMapping === 'object' && !Array.isArray(pwIn.tenantMapping)) {
        const cleanMap = {};
        for (const [k, v] of Object.entries(pwIn.tenantMapping)) {
          const kk = String(k || '').trim();
          const vv = String(v || '').trim();
          if (kk && vv) cleanMap[kk] = vv;
        }
        next.wazuh.tenantMapping = cleanMap;
      }
    }

    if (patch.ollama && typeof patch.ollama === 'object') {
      const po = patch.ollama;
      if (po.baseUrl !== undefined) next.ollama.baseUrl = String(po.baseUrl || '').trim().replace(/\/+$/, '');
      if (po.model !== undefined) next.ollama.model = String(po.model || '').trim() || defaultConfig().ollama.model;
      if (po.temperature !== undefined) {
        const t = Number(po.temperature);
        next.ollama.temperature = Number.isFinite(t) ? Math.max(0, Math.min(2, t)) : 0.1;
      }
      if (po.systemPrompt !== undefined) {
        next.ollama.systemPrompt = String(po.systemPrompt || '').trim() || DEFAULT_SYSTEM_PROMPT;
      }
    }

    if (Array.isArray(patch.exclusionRules)) {
      next.exclusionRules = patch.exclusionRules.map((r, i) => sanitizeExclusionRule(r, i)).filter(Boolean);
    }

    next.updatedAt = new Date().toISOString();
    config = next;
    saveConfig();
    applyScheduler();
    broadcastSse('state', getQueueSnapshot());
    return sanitizeConfigForClient(config);
  }

  function annotateLiveHitStatus(hit, knownTenants) {
    const id = hit.alert_id;
    const raw = hit.raw_wazuh_alert || {};
    const tenant = resolveTenant(raw, config.wazuh.tenantMapping, knownTenants);
    const createdSet = new Set(state.caseCreatedAlertIds);
    const dismissedSet = new Set(state.dismissedAlertIds);

    let statusCode = 'pending';
    let statusLabel = 'Menunggu Triage';
    let matchedGroupId = null;

    if (createdSet.has(id)) {
      statusCode = 'case_created';
      statusLabel = 'Case Created (Lihat di History)';
    } else if (state.excludedAlertMap[id]) {
      statusCode = 'excluded';
      statusLabel = 'Excluded (Matched Rule: ' + state.excludedAlertMap[id].ruleLabel + ')';
    } else if (dismissedSet.has(id)) {
      statusCode = 'dismissed';
      statusLabel = 'Dismissed (Diabaikan)';
    } else {
      const grp = state.groups.find((g) => (g.alerts || []).some((a) => a.alert_id === id));
      if (grp) {
        matchedGroupId = grp.group_id;
        statusCode = grp.verdict === 'TRUE_POSITIVE' ? 'queued_tp' : grp.verdict === 'FALSE_POSITIVE' ? 'queued_fp' : 'queued_review';
        const verdictText = grp.verdict === 'TRUE_POSITIVE'
          ? 'True Positive'
          : grp.verdict === 'FALSE_POSITIVE'
            ? 'False Positive'
            : (grp.unanalyzed ? 'Needs Review - Unanalyzed' : 'Needs Review');
        statusLabel = 'Queued (' + verdictText + ')';
      } else {
        const liveEx = evaluateExclusions(raw, config.exclusionRules);
        if (liveEx.excluded) {
          statusCode = 'excluded';
          statusLabel = 'Excluded (Matched Rule: ' + liveEx.ruleLabel + ')';
        }
      }
    }

    const level = Number(raw.rule?.level || 0);
    return {
      alert_id: id,
      timestamp: extractAlertTimestamp(raw),
      tenant,
      agent_name: String(raw.agent?.name || '—'),
      agent_id: String(raw.agent?.id || ''),
      rule_id: String(raw.rule?.id || '—'),
      rule_level: level,
      severity_label: severityLabel(level),
      rule_description: String(raw.rule?.description || '—'),
      src_ip: extractSrcIp(raw) || '—',
      path: extractPathCandidates(raw)[0] || '',
      status_code: statusCode,
      status_label: statusLabel,
      group_id: matchedGroupId,
      raw_wazuh_alert: raw,
    };
  }

  async function getLiveFeed(opts = {}) {
    const scope = opts.scope === '24h' ? '24h' : 'watermark';
    const sinceIso = scope === '24h'
      ? new Date(Date.now() - 24 * 3600 * 1000).toISOString()
      : state.watermarkTimestamp;

    const { totalHits, hits } = await queryWazuhAlerts({
      sinceIso,
      size: Number(opts.size || 500),
      minLevel: config.wazuh.minRuleLevel,
      maxLevel: config.wazuh.maxRuleLevel,
    });

    const knownTenants = getKnownTenants();
    const allItems = hits.map((h) => annotateLiveHitStatus(h, knownTenants));
    const q = String(opts.q || '').trim().toLowerCase();
    const tenantFilter = String(opts.tenant || '').trim().toLowerCase();
    const statusFilter = String(opts.status || '').trim();

    let filtered = allItems;
    if (tenantFilter) filtered = filtered.filter((it) => it.tenant.toLowerCase() === tenantFilter);
    if (statusFilter) filtered = filtered.filter((it) => it.status_code === statusFilter);
    if (q) {
      filtered = filtered.filter((it) => {
        const hay = [
          it.alert_id,
          it.tenant,
          it.agent_name,
          it.rule_id,
          it.rule_description,
          it.src_ip,
          it.path,
          it.status_label,
          it.raw_wazuh_alert?.full_log,
        ].join(' ').toLowerCase();
        return hay.includes(q);
      });
    }

    return {
      ok: true,
      totalHits,
      rawCount: allItems.length,
      displayedCount: filtered.length,
      parityMatch: totalHits === allItems.length,
      scope,
      watermarkTimestamp: state.watermarkTimestamp,
      fetchedAt: new Date().toISOString(),
      items: filtered,
    };
  }

  function mergeGroups(groupIds = []) {
    const ids = [...new Set((groupIds || []).map((id) => String(id || '').trim()).filter(Boolean))];
    if (ids.length < 2) {
      throw Object.assign(new Error('Pilih minimal 2 grup untuk digabungkan.'), { status: 400 });
    }
    const selected = state.groups.filter((g) => ids.includes(g.group_id));
    if (selected.length < 2) {
      throw Object.assign(new Error('Grup yang dipilih tidak ditemukan di antrean aktif.'), { status: 404 });
    }

    const tenants = [...new Set(selected.map((g) => String(g.tenant_mapped || '').trim().toLowerCase()))];
    if (tenants.length > 1) {
      throw Object.assign(new Error('Tidak dapat menggabungkan grup dari tenant yang berbeda.'), { status: 400 });
    }

    const base = cloneJson(selected[0]);
    base.group_id = 'grp-' + new Date().toISOString().slice(0, 10).replace(/-/g, '') + '-' + crypto.randomBytes(3).toString('hex');
    const verdictPriority = { TRUE_POSITIVE: 0, NEEDS_REVIEW: 1, FALSE_POSITIVE: 2 };
    for (let i = 1; i < selected.length; i++) {
      const other = selected[i];
      if ((verdictPriority[other.verdict] ?? 9) < (verdictPriority[base.verdict] ?? 9)) {
        base.verdict = other.verdict;
      }
      mergeAlertWrappersIntoGroup(base, other);
    }
    if (selected.length > 1) {
      base.incident_title = base.incident_title + ' (+' + (selected.length - 1) + ' grup digabung)';
    }

    const selectedSet = new Set(selected.map((g) => g.group_id));
    state.groups = [base, ...state.groups.filter((g) => !selectedSet.has(g.group_id))];
    saveState();
    broadcastSse('state', getQueueSnapshot());
    return { ok: true, group: base, snapshot: getQueueSnapshot() };
  }

  function removeAlertsFromGroup({ groupId, alertIds = [] } = {}) {
    const gid = String(groupId || '').trim();
    if (!gid) {
      throw Object.assign(new Error('groupId wajib diisi.'), { status: 400 });
    }
    const idSet = new Set((Array.isArray(alertIds) ? alertIds : []).map((x) => String(x || '').trim()).filter(Boolean));
    if (!idSet.size) {
      throw Object.assign(new Error('Pilih minimal 1 alert untuk dihilangkan.'), { status: 400 });
    }
    const grp = state.groups.find((g) => g.group_id === gid);
    if (!grp) {
      throw Object.assign(new Error('Grup triage tidak ditemukan.'), { status: 404 });
    }

    const removed = [];
    const remaining = [];
    for (const al of grp.alerts || []) {
      if (idSet.has(al.alert_id)) removed.push(al);
      else remaining.push(al);
    }
    if (!removed.length) {
      throw Object.assign(new Error('Alert yang dipilih tidak ditemukan dalam grup ini.'), { status: 404 });
    }

    for (const al of removed) {
      state.dismissedAlertIds.push(al.alert_id);
      state.processedAlertIds.push(al.alert_id);
    }

    let groupRemoved = false;
    if (remaining.length === 0) {
      state.groups = state.groups.filter((g) => g.group_id !== gid);
      groupRemoved = true;
    } else {
      grp.alerts = remaining;
      recomputeGroupMetadata(grp);
    }

    saveState();
    broadcastSse('state', getQueueSnapshot());
    return {
      ok: true,
      removedCount: removed.length,
      groupRemoved,
      group: groupRemoved ? null : grp,
      snapshot: getQueueSnapshot(),
    };
  }

  function splitGroupAlerts({ groupId, alertIds = [], incidentTitle = '', verdict = '' } = {}) {
    const gid = String(groupId || '').trim();
    if (!gid) {
      throw Object.assign(new Error('groupId wajib diisi.'), { status: 400 });
    }
    const idSet = new Set((Array.isArray(alertIds) ? alertIds : []).map((x) => String(x || '').trim()).filter(Boolean));
    if (!idSet.size) {
      throw Object.assign(new Error('Pilih minimal 1 alert untuk dipisahkan.'), { status: 400 });
    }
    const grpIndex = state.groups.findIndex((g) => g.group_id === gid);
    if (grpIndex === -1) {
      throw Object.assign(new Error('Grup triage tidak ditemukan.'), { status: 404 });
    }
    const grp = state.groups[grpIndex];

    const moved = [];
    const remaining = [];
    for (const al of grp.alerts || []) {
      if (idSet.has(al.alert_id)) moved.push(al);
      else remaining.push(al);
    }
    if (!moved.length) {
      throw Object.assign(new Error('Alert yang dipilih tidak ditemukan dalam grup ini.'), { status: 404 });
    }
    if (!remaining.length) {
      throw Object.assign(new Error('Tidak dapat memisahkan semua alert dari grup; sisakan minimal 1 alert di grup asal.'), { status: 400 });
    }

    grp.alerts = remaining;
    recomputeGroupMetadata(grp);

    const firstRaw = moved[0]?.raw_wazuh_alert || {};
    const firstPath = extractPathCandidates(firstRaw)[0] || '';
    const firstDesc = String(firstRaw.rule?.description || '').trim();
    const fallbackTitle = firstDesc
      ? firstDesc + (firstPath ? ' (' + normalizePath(firstPath) + ')' : '')
      : (grp.incident_title || 'Security Incident') + ' (Dipisah)';

    const reqVerdict = String(verdict || '').trim().toUpperCase();
    const newGroup = {
      group_id: 'grp-' + new Date().toISOString().slice(0, 10).replace(/-/g, '') + '-' + crypto.randomBytes(3).toString('hex'),
      verdict: VALID_VERDICTS.includes(reqVerdict) ? reqVerdict : grp.verdict,
      unanalyzed: false,
      group_key: (grp.group_key || 'split') + '-split-' + crypto.randomBytes(2).toString('hex'),
      incident_title: String(incidentTitle || '').trim() || fallbackTitle,
      tenant_mapped: grp.tenant_mapped,
      max_rule_level: 0,
      severity_label: 'Low',
      agents: [],
      agent_name: '',
      source_ips: [],
      rule_ids: [],
      alert_count: moved.length,
      ai_reasoning: `Dipisahkan manual oleh analis dari grup "${grp.incident_title || grp.group_id}".`,
      first_seen: null,
      last_seen: null,
      alerts: moved,
    };
    recomputeGroupMetadata(newGroup);

    state.groups.splice(grpIndex + 1, 0, newGroup);
    saveState();
    broadcastSse('state', getQueueSnapshot());
    return {
      ok: true,
      sourceGroup: grp,
      newGroup,
      snapshot: getQueueSnapshot(),
    };
  }

  function dismissGroups({ groupIds = [], verdict = '' } = {}) {
    const idSet = new Set((groupIds || []).map((id) => String(id || '').trim()).filter(Boolean));
    const vFilter = String(verdict || '').trim().toUpperCase();
    const toRemove = [];
    const remaining = [];

    for (const g of state.groups) {
      const matchId = idSet.size > 0 && idSet.has(g.group_id);
      const matchVerdict = vFilter && g.verdict === vFilter;
      if (matchId || matchVerdict) toRemove.push(g);
      else remaining.push(g);
    }

    for (const g of toRemove) {
      for (const a of g.alerts || []) {
        state.dismissedAlertIds.push(a.alert_id);
        state.processedAlertIds.push(a.alert_id);
      }
    }

    state.groups = remaining;
    saveState();
    broadcastSse('state', getQueueSnapshot());
    return {
      ok: true,
      dismissedGroups: toRemove.length,
      snapshot: getQueueSnapshot(),
    };
  }

  function resetQueue(watermarkIso) {
    const newWatermark = watermarkIso && !Number.isNaN(Date.parse(watermarkIso))
      ? new Date(watermarkIso).toISOString()
      : new Date().toISOString();

    const clearedGroups = state.groups.length;
    for (const g of state.groups) {
      for (const a of g.alerts || []) {
        state.processedAlertIds.push(a.alert_id);
      }
    }
    state.groups = [];
    state.watermarkTimestamp = newWatermark;
    saveState();
    broadcastSse('state', getQueueSnapshot());
    return {
      ok: true,
      clearedGroups,
      watermarkTimestamp: state.watermarkTimestamp,
      snapshot: getQueueSnapshot(),
    };
  }

  function purgeTriageDatabase({ clearState = true, includeHistory = false, resetWatermarkToNow = false } = {}) {
    const doClearState = clearState !== false;
    const doIncludeHistory = Boolean(includeHistory);
    const clearedGroups = doClearState ? state.groups.length : 0;
    const clearedProcessed = doClearState ? state.processedAlertIds.length : 0;
    const clearedDismissed = doClearState ? state.dismissedAlertIds.length : 0;
    const clearedHistory = doIncludeHistory ? caseHistory.length : 0;

    if (doClearState) {
      state = defaultTriageState();
      if (resetWatermarkToNow === true) {
        state.watermarkTimestamp = new Date().toISOString();
      }
      saveState();
    }
    if (doIncludeHistory) {
      caseHistory = [];
      saveCaseHistory();
    }

    broadcastSse('state', getQueueSnapshot());
    return {
      ok: true,
      clearState: doClearState,
      includeHistory: doIncludeHistory,
      clearedGroups,
      clearedProcessed,
      clearedDismissed,
      clearedHistory,
      snapshot: getQueueSnapshot(),
    };
  }

  function promoteToCase(payload = {}, user = null) {
    const groupId = String(payload.groupId || '').trim();
    const wantedAlertIds = Array.isArray(payload.alertIds) && payload.alertIds.length
      ? new Set(payload.alertIds.map((x) => String(x || '').trim()).filter(Boolean))
      : null;

    let resolvedTenant = String(payload.tenant || '').trim();
    let incidentTitle = String(payload.incidentTitle || '').trim();
    let aiVerdict = String(payload.aiVerdict || 'MANUAL_PROMOTE').trim();
    let alertWrappers = [];

    if (groupId) {
      const grp = state.groups.find((g) => g.group_id === groupId);
      if (!grp) {
        throw Object.assign(new Error('Grup triage tidak ditemukan.'), { status: 404 });
      }
      resolvedTenant = resolvedTenant || grp.tenant_mapped;
      incidentTitle = incidentTitle || grp.incident_title;
      aiVerdict = grp.verdict || aiVerdict;
      alertWrappers = (grp.alerts || []).filter((a) => !wantedAlertIds || wantedAlertIds.has(a.alert_id));
    } else if (Array.isArray(payload.rawAlerts) && payload.rawAlerts.length) {
      const knownTenants = getKnownTenants();
      const rawList = payload.rawAlerts;
      const detectedTenants = new Set();
      alertWrappers = rawList.map((item, idx) => {
        const raw = item?.raw_wazuh_alert ? item.raw_wazuh_alert : item;
        const alertId = String(item?.alert_id || raw?._id || raw?.id || ('manual_' + idx + '_' + crypto.randomBytes(3).toString('hex')));
        detectedTenants.add(resolveTenant(raw, config.wazuh.tenantMapping, knownTenants));
        return { alert_id: alertId, raw_wazuh_alert: raw };
      });
      if (!resolvedTenant) {
        if (detectedTenants.size > 1) {
          throw Object.assign(new Error('Tidak dapat membuat 1 case dari alert lintas tenant berbeda.'), { status: 400 });
        }
        resolvedTenant = [...detectedTenants][0] || 'unassigned';
      }
      incidentTitle = incidentTitle || String(alertWrappers[0]?.raw_wazuh_alert?.rule?.description || 'Manual Promote dari Realtime Feed');
    } else {
      throw Object.assign(new Error('groupId atau rawAlerts wajib disertakan.'), { status: 400 });
    }

    if (!alertWrappers.length) {
      throw Object.assign(new Error('Tidak ada alert valid untuk dipromosikan.'), { status: 400 });
    }

    const rawPayloads = alertWrappers.map((a) => a.raw_wazuh_alert);
    const chunks = chunkAlertsForPromote(rawPayloads, MAX_ALERTS_PER_CASE);

    const agentNames = [...new Set(alertWrappers.map((a) => a.raw_wazuh_alert?.agent?.name).filter(Boolean))];
    const sourceIps = [...new Set(alertWrappers.map((a) => extractSrcIp(a.raw_wazuh_alert)).filter(Boolean))];
    const ruleIds = [...new Set(alertWrappers.map((a) => String(a.raw_wazuh_alert?.rule?.id || '')).filter(Boolean))];
    const wazuhAlertIds = alertWrappers.map((a) => a.alert_id);

    const nowIso = new Date().toISOString();
    const historyEntry = {
      history_id: 'hist-' + nowIso.slice(0, 10).replace(/-/g, '') + '-' + crypto.randomBytes(3).toString('hex'),
      created_at: nowIso,
      created_by: user ? (user.displayName || user.username) : (payload.createdBy || null),
      workspace: payload.workspace === 'asoc' ? 'asoc' : 'soc',
      tenant: resolvedTenant,
      iris_case_id: payload.irisCaseId || null,
      iris_ticket_number: payload.irisTicketNumber || null,
      incident_title: incidentTitle || 'Security Incident',
      ai_verdict: aiVerdict,
      agents: agentNames,
      source_ips: sourceIps,
      rule_ids: ruleIds,
      alert_count: alertWrappers.length,
      wazuh_alert_ids: wazuhAlertIds,
    };

    caseHistory.unshift(historyEntry);
    saveCaseHistory();

    for (const id of wazuhAlertIds) {
      state.caseCreatedAlertIds.push(id);
      state.processedAlertIds.push(id);
    }

    const shouldResetWatermark = payload.resetWatermark !== false;
    if (shouldResetWatermark) {
      for (const g of state.groups) {
        for (const a of g.alerts || []) {
          state.processedAlertIds.push(a.alert_id);
        }
      }
      state.groups = [];
      state.watermarkTimestamp = nowIso;
    } else if (groupId) {
      const grp = state.groups.find((g) => g.group_id === groupId);
      if (grp) {
        const promotedSet = new Set(wazuhAlertIds);
        grp.alerts = (grp.alerts || []).filter((a) => !promotedSet.has(a.alert_id));
        if (grp.alerts.length === 0) {
          state.groups = state.groups.filter((g) => g.group_id !== groupId);
        } else {
          recomputeGroupMetadata(grp);
        }
      }
    }

    saveState();
    broadcastSse('state', getQueueSnapshot());

    return {
      ok: true,
      tenant: resolvedTenant,
      incidentTitle,
      chunkCount: chunks.length,
      chunks,
      watermarkTimestamp: state.watermarkTimestamp,
      historyEntry,
      snapshot: getQueueSnapshot(),
    };
  }

  function listCaseHistory(filters = {}) {
    let items = caseHistory.slice();
    const tenant = String(filters.tenant || '').trim().toLowerCase();
    const q = String(filters.q || '').trim().toLowerCase();
    const limit = Math.min(Math.max(1, Number(filters.limit) || 200), 1000);

    if (tenant) items = items.filter((it) => String(it.tenant || '').toLowerCase() === tenant);
    if (q) {
      items = items.filter((it) => {
        const hay = [
          it.history_id,
          it.iris_case_id,
          it.iris_ticket_number,
          it.tenant,
          it.incident_title,
          it.ai_verdict,
          ...(it.agents || []),
          ...(it.source_ips || []),
          ...(it.rule_ids || []),
          ...(it.wazuh_alert_ids || []),
        ].join(' ').toLowerCase();
        return hay.includes(q);
      });
    }

    const tenants = [...new Set(caseHistory.map((it) => it.tenant).filter(Boolean))].sort();
    return {
      ok: true,
      total: caseHistory.length,
      tenants,
      items: items.slice(0, limit),
    };
  }

  async function fetchHistoryWazuhDetails(historyId) {
    const entry = caseHistory.find((it) => it.history_id === historyId);
    if (!entry) {
      throw Object.assign(new Error('Entri Audit Triage tidak ditemukan.'), { status: 404 });
    }
    const fetched = await fetchWazuhByIds(entry.wazuh_alert_ids || []);
    return { ok: true, entry, ...fetched };
  }

  function start() {
    applyScheduler();
  }

  function stop() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
    for (const res of sseClients) {
      try { res.end(); } catch {}
    }
    sseClients.clear();
  }

  return {
    DEFAULT_SYSTEM_PROMPT,
    DEFAULT_EXCLUSION_RULES,
    getConfig: () => sanitizeConfigForClient(config),
    updateConfig,
    testWazuhConnection,
    testOllamaConnection,
    queryWazuhAlerts,
    fetchWazuhByIds,
    evaluateExclusions,
    resolveTenant,
    pollOnce,
    getQueueSnapshot,
    getLiveFeed,
    subscribeSse,
    mergeGroups,
    splitGroupAlerts,
    removeAlertsFromGroup,
    dismissGroups,
    resetQueue,
    purgeTriageDatabase,
    promoteToCase,
    listCaseHistory,
    fetchHistoryWazuhDetails,
    start,
    stop,
  };
}

module.exports = {
  createTriageEngine,
  DEFAULT_SYSTEM_PROMPT,
  DEFAULT_EXCLUSION_RULES,
  evaluateExclusions,
  normalizePath,
  resolveTenant,
  severityLabel,
  chunkAlertsForPromote,
};

