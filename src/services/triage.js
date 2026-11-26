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
const OLLAMA_MICRO_BATCH_SIZE = 8;
const VALID_VERDICTS = ['TRUE_POSITIVE', 'NEEDS_REVIEW', 'FALSE_POSITIVE'];
const VALID_EXCLUSION_TARGETS = [
  'path',
  'filename',
  'rule_description',
  'rule_id',
  'http_status',
  'src_ip',
  'agent_name',
  'user_agent',
  'referer',
  'full_log',
];
const VALID_EXCLUSION_MODES = ['wildcard', 'contains', 'starts_with', 'regex'];
const ATTACK_SIGNATURE_RULE_IDS = new Set([
  '31103', '31104', '31105', '31106', '31107', '31109', '31110',
  '31166', '31167', '31168', '31169',
]);
const EXCLUSION_SUGGEST_SCHEMA = {
  type: 'object',
  properties: {
    reasoning: { type: 'string' },
    rules: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          tenant: { type: 'string' },
          target: { type: 'string', enum: VALID_EXCLUSION_TARGETS },
          mode: { type: 'string', enum: VALID_EXCLUSION_MODES },
          pattern: { type: 'string' },
          ruleIds: { type: 'array', items: { type: 'string' } },
          httpStatuses: { type: 'array', items: { type: 'string' } },
          srcIps: { type: 'array', items: { type: 'string' } },
          userAgent: { type: 'string' },
          referer: { type: 'string' },
          note: { type: 'string' },
        },
        required: ['target', 'mode', 'pattern', 'note'],
        additionalProperties: false,
      },
    },
  },
  required: ['reasoning', 'rules'],
  additionalProperties: false,
};
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
  'Skala Severity Wazuh Resmi (WAJIB dipatuhi dalam reasoning):',
  '- Level 0–6: Low',
  '- Level 7–11: Medium (contoh: Rule Level 10 adalah Medium, BUKAN High atau Critical)',
  '- Level 12–14: High',
  '- Level 15+: Critical',
  '',
  'Aturan Klasifikasi:',
  '1. TRUE_POSITIVE: Indikasi kuat eksploitasi CVE, serangan aktif, brute-force berhasil, web scanning ke file sensitif (/.env, /.git, /phpmyadmin, shell), SQLi, XSS, atau C2.',
  '2. NEEDS_REVIEW: Aktivitas anomali mencurigakan yang butuh verifikasi konteks (misal: vulnerability scanner tanpa eksploitasi berhasil, perubahan konfigurasi sistem, atau lonjakan error 500 tidak wajar).',
  '3. FALSE_POSITIVE: Trafik pengguna normal/legit yang memicu rule sensitif (misal: error 400/404 pada endpoint aplikasi valid seperti /login.php, /api/v1/items, kesalahan input user biasa, atau crawler/healthcheck internal).',
  '',
  'Aturan Pengelompokan:',
  '- Pisahkan pengelompokan (group_key) antara trafik legit dan aktivitas serangan meskipun memiliki rule.id Wazuh yang sama.',
  '- Gabungkan kandidat yang merupakan kampanye serangan yang sama ke dalam satu insiden walaupun menyasar beberapa agent berbeda di dalam tenant ini.',
  'Keluarkan output HANYA dalam format JSON valid sesuai skema yang diminta.',
].join('\n');

const DEFAULT_EXCLUSION_RULES = [
  { id: 'ex-path-login', target: 'path', mode: 'contains', pattern: '/login.php', enabled: true, source: 'default', note: 'Login page aplikasi' },
  { id: 'ex-path-health', target: 'path', mode: 'contains', pattern: '/healthz', enabled: true, source: 'default', note: 'Endpoint healthcheck' },
  { id: 'ex-path-favicon', target: 'path', mode: 'contains', pattern: '/favicon.ico', enabled: true, source: 'default', note: 'Favicon browser' },
  { id: 'ex-path-assets', target: 'path', mode: 'starts_with', pattern: '/assets/', enabled: true, source: 'default', note: 'Static assets' },
  { id: 'ex-log-healthcheck', target: 'full_log', mode: 'contains', pattern: 'HealthCheck', enabled: true, source: 'default', note: 'Health check internal' },
  { id: 'ex-log-wordfence', target: 'full_log', mode: 'contains', pattern: 'Wordfence', enabled: true, source: 'default', note: 'Plugin security noise' },
  { id: 'ex-log-loopback', target: 'full_log', mode: 'contains', pattern: '127.0.0.1', enabled: true, source: 'default', note: 'Loopback noise' },
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
      numCtx: 12288,
      numPredict: 4096,
      topP: 0.85,
      topK: 20,
      repeatPenalty: 1.05,
      microBatchSize: OLLAMA_MICRO_BATCH_SIZE,
      timeoutSec: 90,
      keepAlive: '2m',
      think: false,
      useJsonSchema: true,
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
      phase: 'idle',
      phaseMessage: '',
      aiActive: false,
      aiModel: '',
      activeTenant: '',
      fetchedCount: 0,
      excludedCount: 0,
      candidateCount: 0,
      analyzedCount: 0,
      processedChunks: 0,
      totalChunks: 0,
      lastDurationMs: 0,
      lastPollAt: null,
      lastSuccessAt: null,
      lastError: null,
      lastBatchCount: 0,
      lastExcludedCount: 0,
      lastAnalyzedCount: 0,
      nextPollAt: null,
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
  const direct = String(
    rawAlert?.data?.http_user_agent ||
    rawAlert?.data?.user_agent ||
    rawAlert?.data?.http?.user_agent ||
    rawAlert?.user_agent ||
    ''
  ).trim();
  if (direct && direct !== '-') return direct;
  const fullLog = String(rawAlert?.full_log || '');
  const m = fullLog.match(/HTTP\/[12](?:\.\d)?"\s+[1-5]\d\d\s+\S+\s+"[^"]*"\s+"([^"]+)"/);
  return m && m[1] && m[1] !== '-' ? m[1].trim() : '';
}

function extractReferer(rawAlert) {
  const direct = String(
    rawAlert?.data?.http_referer ||
    rawAlert?.data?.referer ||
    rawAlert?.data?.http?.referer ||
    rawAlert?.referer ||
    ''
  ).trim();
  if (direct && direct !== '-') return direct;
  const fullLog = String(rawAlert?.full_log || '');
  const m = fullLog.match(/HTTP\/[12](?:\.\d)?"\s+[1-5]\d\d\s+\S+\s+"([^"]+)"/);
  return m && m[1] && m[1] !== '-' ? m[1].trim() : '';
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

function normalizeStringList(val, maxItems = 12, maxItemLen = 64) {
  const rawArr = Array.isArray(val)
    ? val
    : (typeof val === 'string' ? val.split(/[\s,;]+/) : []);
  const out = [];
  for (const item of rawArr) {
    const s = String(item ?? '').trim().slice(0, maxItemLen);
    if (s && !out.includes(s)) out.push(s);
    if (out.length >= maxItems) break;
  }
  return out;
}

function normalizeTenantScope(val) {
  const s = String(val ?? '').trim().toLowerCase();
  if (!s || s === '*' || s === 'all' || s === 'global') return '';
  return s.slice(0, 80);
}

function sanitizeExclusionRule(raw, idx = 0) {
  const rawTarget = String(raw?.target || 'path').trim();
  const target = VALID_EXCLUSION_TARGETS.includes(rawTarget) ? rawTarget : 'path';
  const rawMode = String(raw?.mode || 'contains').trim();
  const mode = VALID_EXCLUSION_MODES.includes(rawMode) ? rawMode : 'contains';
  const pattern = String(raw?.pattern ?? '').trim();
  if (!pattern) return null;
  const id = String(raw?.id || ('ex_' + idx + '_' + crypto.randomBytes(3).toString('hex')));
  const rawSource = String(raw?.source || '').trim();
  const inferredDefault = id.startsWith('ex-path-') || id.startsWith('ex-log-');
  const source = ['auto_ignore', 'default', 'manual', 'ai_suggest'].includes(rawSource)
    ? rawSource
    : (inferredDefault ? 'default' : 'manual');
  return {
    id,
    tenant: normalizeTenantScope(raw?.tenant),
    target,
    mode,
    pattern,
    ruleIds: normalizeStringList(raw?.ruleIds ?? raw?.rule_ids, 10, 24),
    httpStatuses: normalizeStringList(raw?.httpStatuses ?? raw?.http_statuses, 10, 8),
    srcIps: normalizeStringList(raw?.srcIps ?? raw?.src_ips, 12, 64),
    userAgent: String(raw?.userAgent ?? raw?.user_agent ?? '').trim().slice(0, 120),
    referer: String(raw?.referer ?? '').trim().slice(0, 160),
    enabled: raw?.enabled !== false,
    source,
    createdAt: raw?.createdAt || null,
    note: String(raw?.note ?? '').trim().slice(0, 120),
  };
}

function extractFilenameCandidates(rawAlert) {
  const candidates = [];
  const push = (v) => {
    const s = String(v ?? '').trim();
    if (!s) return;
    if (!candidates.includes(s)) candidates.push(s);
    const base = s.split('?')[0].split(/[\\/]/).filter(Boolean).pop() || '';
    if (base && !candidates.includes(base)) candidates.push(base);
  };
  push(rawAlert?.syscheck?.path);
  push(rawAlert?.data?.win?.eventdata?.targetFilename);
  push(rawAlert?.data?.file);
  push(rawAlert?.data?.filename);
  push(rawAlert?.data?.path);

  for (const urlPath of extractPathCandidates(rawAlert)) {
    const noQuery = urlPath.split('?')[0].trim();
    const lastSeg = noQuery.split('/').filter(Boolean).pop() || '';
    if (/\.[a-z0-9]{1,8}$/i.test(lastSeg)) {
      if (!candidates.includes(noQuery)) candidates.push(noQuery);
      if (!candidates.includes(lastSeg)) candidates.push(lastSeg);
    }
  }
  return candidates;
}

function isOverlyBroadPathPattern(pattern) {
  const s = String(pattern || '').trim();
  if (!s || s === '/' || s === '*' || s === '/*' || s === '**' || s === '/**') return true;
  const cleaned = s.replace(/\?.*$/, '');
  const segs = cleaned.split('/').filter(Boolean);
  if (segs.length <= 1 && (cleaned.endsWith('/') || segs[0] === '*' || segs[0] === '**')) return true;
  if (segs.length === 2 && (segs[1] === '*' || segs[1] === '**') && cleaned.startsWith('/')) return true;
  return false;
}

function longestCommonSubstring(strings = [], minLen = 12) {
  if (!strings.length) return '';
  if (strings.length === 1) return strings[0];
  const base = strings.reduce((a, b) => (a.length <= b.length ? a : b));
  for (let len = Math.min(base.length, 100); len >= minLen; len--) {
    for (let start = 0; start <= base.length - len; start++) {
      const sub = base.slice(start, start + len);
      if (sub.trim().length < minLen) continue;
      if (strings.every((s) => s.includes(sub))) return sub.trim();
    }
  }
  return '';
}

function commonPathPrefix(paths = []) {
  if (paths.length < 2) return '';
  let prefix = paths[0];
  for (let i = 1; i < paths.length; i++) {
    while (prefix && !paths[i].startsWith(prefix)) {
      prefix = prefix.slice(0, -1);
    }
    if (!prefix) break;
  }
  const slashIdx = prefix.lastIndexOf('/');
  const clean = slashIdx > 0 ? prefix.slice(0, slashIdx + 1) : '';
  const segCount = clean.split('/').filter(Boolean).length;
  // Require at least 2 path segments (e.g. /service/mhs/) so 1-segment roots like /service/ or /api/ are never used
  return segCount >= 2 && clean.length >= 6 ? clean : '';
}

function isPrivateIp(ip) {
  const s = String(ip || '').trim();
  return /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fc|fd|fe80)/i.test(s);
}

function extractSafeQueryLock(rawUrl) {
  const s = String(rawUrl || '').trim();
  const qIdx = s.indexOf('?');
  if (qIdx === -1) return { cleanPath: s, queryParamLock: '' };
  const cleanPath = s.slice(0, qIdx).trim();
  const queryStr = s.slice(qIdx + 1);
  if (!/\/(?:webservice\/rest\/server\.php|lib\/ajax\/service(?:-nologin)?\.php|apicms)/i.test(cleanPath)) {
    return { cleanPath, queryParamLock: '' };
  }
  const params = queryStr.split('&');
  for (const p of params) {
    const [k, v] = p.split('=');
    if (!k || !v) continue;
    const keyLow = k.toLowerCase();
    if ((keyLow === 'wsfunction' || keyLow === 'info') && /^[a-z0-9_.-]{3,80}$/i.test(v)) {
      return { cleanPath, queryParamLock: `${k}=${v}` };
    }
  }
  return { cleanPath, queryParamLock: '' };
}

function deriveLocksForBucket(bucketRaws = [], cleanPath = '') {
  const ruleSet = new Set();
  const statusSet = new Set();
  const ipSet = new Set();
  const uaCounts = new Map();
  const refHostSet = new Set();

  for (const r of bucketRaws) {
    const rid = String(r?.rule?.id || '').trim();
    if (rid && !ATTACK_SIGNATURE_RULE_IDS.has(rid)) ruleSet.add(rid);
    const st = extractHttpStatus(r);
    if (st) statusSet.add(st);
    const ip = extractSrcIp(r);
    if (ip) ipSet.add(ip);
    const ua = extractUserAgent(r);
    if (ua) {
      const tokenMatch = ua.match(/(MoodleMobile|HealthCheck|UptimeRobot|GuzzleHttp|okhttp|WordPress|Googlebot|Bingbot|curl|python-requests)/i);
      const key = tokenMatch ? tokenMatch[1] : (ua.length <= 40 ? ua : '');
      if (key) uaCounts.set(key, (uaCounts.get(key) || 0) + 1);
    }
    const ref = extractReferer(r);
    if (ref) {
      try {
        refHostSet.add(new URL(ref).hostname.toLowerCase());
      } catch {
        const hm = ref.match(/^https?:\/\/([^/:?#]+)/i);
        if (hm && hm[1]) refHostSet.add(hm[1].toLowerCase());
      }
    }
  }

  const ruleIds = [...ruleSet].slice(0, 5);
  const httpStatuses = statusSet.size >= 1 && statusSet.size <= 3 ? [...statusSet] : [];

  let userAgent = '';
  if (uaCounts.size > 0 && bucketRaws.length > 0) {
    const topUa = [...uaCounts.entries()].sort((a, b) => b[1] - a[1])[0];
    if (topUa && topUa[1] >= Math.max(1, Math.ceil(bucketRaws.length * 0.8))) {
      userAgent = topUa[0];
    }
  }

  let srcIps = [];
  if (ipSet.size === 1) {
    const singleIp = [...ipSet][0];
    if (isPrivateIp(singleIp) || /\/(?:api|apicms|webservice|webhook|sync|cron)/i.test(cleanPath)) {
      srcIps = [singleIp];
    }
  }

  let referer = '';
  if (refHostSet.size === 1 && (statusSet.has('303') || /\/(?:edit\.php|quiz|cms)/i.test(cleanPath))) {
    referer = [...refHostSet][0];
  }

  return { ruleIds, httpStatuses, srcIps, userAgent, referer };
}

function buildSpecificPathRule(normPath, exactPath, note, nowIso, extra = {}) {
  const np = String(normPath || '').trim();
  const hasParam = /\/:(?:id|uuid|hex)\b/.test(np);
  const locks = extra.locks || {};
  const tenant = normalizeTenantScope(extra.tenant);
  const qLock = String(extra.queryParamLock || '').trim();

  if (qLock && !hasParam) {
    return {
      tenant,
      target: 'path',
      mode: 'contains',
      pattern: `${String(exactPath || np)}?${qLock}`.slice(0, 160),
      ruleIds: locks.ruleIds || [],
      httpStatuses: locks.httpStatuses || [],
      srcIps: locks.srcIps || [],
      userAgent: locks.userAgent || '',
      referer: locks.referer || '',
      enabled: true,
      source: 'auto_ignore',
      createdAt: nowIso,
      note,
    };
  }

  if (hasParam) {
    const wildcardPattern = np.replace(/\/:(?:id|uuid|hex)\b/g, '/*').slice(0, 160);
    if (!isOverlyBroadPathPattern(wildcardPattern)) {
      return {
        tenant,
        target: 'path',
        mode: 'wildcard',
        pattern: wildcardPattern,
        ruleIds: locks.ruleIds || [],
        httpStatuses: locks.httpStatuses || [],
        srcIps: locks.srcIps || [],
        userAgent: locks.userAgent || '',
        referer: locks.referer || '',
        enabled: true,
        source: 'auto_ignore',
        createdAt: nowIso,
        note,
      };
    }
  }
  return {
    tenant,
    target: 'path',
    mode: 'contains',
    pattern: String(exactPath || np).slice(0, 140),
    ruleIds: locks.ruleIds || [],
    httpStatuses: locks.httpStatuses || [],
    srcIps: locks.srcIps || [],
    userAgent: locks.userAgent || '',
    referer: locks.referer || '',
    enabled: true,
    source: 'auto_ignore',
    createdAt: nowIso,
    note,
  };
}

function deriveExclusionRulesFromAlerts(alerts = [], fallbackTitle = '', tenant = '') {
  const raws = (Array.isArray(alerts) ? alerts : [alerts])
    .map((a) => (a && a.raw_wazuh_alert ? a.raw_wazuh_alert : a))
    .filter((r) => r && typeof r === 'object');
  const firstDesc = String(raws[0]?.rule?.description || '').trim();
  const note = ('Auto-exclude: ' + String(fallbackTitle || firstDesc || 'Abaikan analis').trim()).slice(0, 120);
  const nowIso = new Date().toISOString();
  const tenantSlug = normalizeTenantScope(tenant || raws[0]?.agent?.labels?.tenant);

  // Priority 1: Non-trivial URL/request paths grouped per normalized endpoint (+ safe query/AND locks)
  const rawPaths = [];
  const normBuckets = new Map();
  for (const r of raws) {
    const p = extractPathCandidates(r)[0] || '';
    const { cleanPath, queryParamLock } = extractSafeQueryLock(p);
    if (!cleanPath || cleanPath === '/' || cleanPath.length < 2) continue;
    rawPaths.push(cleanPath);
    const np = normalizePath(cleanPath) || cleanPath;
    if (!np || np === '/') continue;
    const bKey = queryParamLock ? `${np}?${queryParamLock}` : np;
    let bucket = normBuckets.get(bKey);
    if (!bucket) {
      bucket = { normPath: np, count: 0, sampleExact: cleanPath, queryParamLock, raws: [] };
      normBuckets.set(bKey, bucket);
    }
    bucket.count++;
    bucket.raws.push(r);
  }

  if (normBuckets.size > 0) {
    const MAX_AUTO_RULES = 8;
    const sorted = [...normBuckets.values()].sort((a, b) => b.count - a.count);
    const chosen = sorted.length <= MAX_AUTO_RULES ? sorted : null;
    if (chosen) {
      return chosen.map((b) => buildSpecificPathRule(b.normPath, b.sampleExact, note, nowIso, {
        tenant: tenantSlug,
        queryParamLock: b.queryParamLock,
        locks: deriveLocksForBucket(b.raws, b.sampleExact),
      }));
    }
    const sharedPrefix = commonPathPrefix(rawPaths);
    if (sharedPrefix && !isOverlyBroadPathPattern(sharedPrefix)) {
      const locks = deriveLocksForBucket(raws, sharedPrefix);
      return [{
        tenant: tenantSlug,
        target: 'path',
        mode: 'starts_with',
        pattern: sharedPrefix,
        ...locks,
        enabled: true,
        source: 'auto_ignore',
        createdAt: nowIso,
        note,
      }];
    }
    return sorted.slice(0, MAX_AUTO_RULES).map((b) => buildSpecificPathRule(b.normPath, b.sampleExact, note, nowIso, {
      tenant: tenantSlug,
      queryParamLock: b.queryParamLock,
      locks: deriveLocksForBucket(b.raws, b.sampleExact),
    }));
  }

  const allLocks = deriveLocksForBucket(raws, '');

  // Priority 1B: Filename / syscheck targets when alert is file-centric rather than HTTP
  const fileNames = [];
  for (const r of raws) {
    const f = r?.syscheck?.path || r?.data?.win?.eventdata?.targetFilename || r?.data?.filename || r?.data?.file || '';
    const cleanF = String(f || '').trim();
    if (cleanF && !fileNames.includes(cleanF)) fileNames.push(cleanF);
  }
  if (fileNames.length > 0 && fileNames.length <= 5) {
    return fileNames.map((fn) => {
      const wildcarded = fn.replace(/\d{4,}/g, '*');
      const useWild = wildcarded !== fn && wildcarded.includes('*');
      return {
        tenant: tenantSlug,
        target: 'filename',
        mode: useWild ? 'wildcard' : 'contains',
        pattern: (useWild ? wildcarded : fn).slice(0, 140),
        ruleIds: allLocks.ruleIds,
        enabled: true,
        source: 'auto_ignore',
        createdAt: nowIso,
        note,
      };
    });
  }

  // Priority 2: Common full_log signature
  const cleanLogs = raws
    .map((r) => String(r.full_log || '')
      .replace(/^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+/, '')
      .replace(/^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+/, '')
      .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '')
      .replace(/\s+/g, ' ')
      .trim())
    .filter((s) => s.length >= 6);

  if (cleanLogs.length >= 2) {
    const common = longestCommonSubstring(cleanLogs.slice(0, 5), 12);
    if (common) {
      return [{
        tenant: tenantSlug,
        target: 'full_log',
        mode: 'contains',
        pattern: common.slice(0, 100),
        ...allLocks,
        enabled: true,
        source: 'auto_ignore',
        createdAt: nowIso,
        note,
      }];
    }
  } else if (cleanLogs.length === 1) {
    return [{
      tenant: tenantSlug,
      target: 'full_log',
      mode: 'contains',
      pattern: cleanLogs[0].slice(0, 90),
      ...allLocks,
      enabled: true,
      source: 'auto_ignore',
      createdAt: nowIso,
      note,
    }];
  }

  // Priority 3: Rule Description fallback
  const fallback = String(firstDesc || fallbackTitle || '').trim().slice(0, 100);
  if (!fallback) return [];
  return [{
    tenant: tenantSlug,
    target: 'rule_description',
    mode: 'contains',
    pattern: fallback,
    ...allLocks,
    enabled: true,
    source: 'auto_ignore',
    createdAt: nowIso,
    note,
  }];
}

function deriveExclusionRuleFromAlerts(alerts = [], fallbackTitle = '', tenant = '') {
  return deriveExclusionRulesFromAlerts(alerts, fallbackTitle, tenant)[0] || null;
}

function compileWildcardRegex(pattern, target) {
  const escaped = String(pattern || '')
    .trim()
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000DBL\u0000')
    .replace(/\*/g, (target === 'path' || target === 'filename') ? '[^/]*' : '.*')
    .replace(/\u0000DBL\u0000/g, '.*');
  const anchored = ['path', 'filename', 'rule_id', 'src_ip', 'agent_name'].includes(target);
  return new RegExp(anchored ? '^' + escaped + '$' : escaped, 'i');
}

function matchesRule(candidates, rule) {
  if (!rule || !rule.enabled || !rule.pattern) return false;
  const needle = String(rule.pattern).trim();
  if (!needle) return false;
  const needleLower = needle.toLowerCase();

  let compiledRe = null;
  if (rule.mode === 'regex') {
    try {
      compiledRe = new RegExp(needle, 'i');
    } catch {
      return false;
    }
  } else if (rule.mode === 'wildcard') {
    try {
      compiledRe = compileWildcardRegex(needle, rule.target);
    } catch {
      return false;
    }
  }

  for (const val of candidates) {
    let str = String(val || '');
    if (!str) continue;
    if (rule.mode === 'regex') {
      if (compiledRe && compiledRe.test(str)) return true;
    } else if (rule.mode === 'wildcard') {
      if (rule.target === 'path' && !needle.includes('?') && !needle.includes('=')) {
        str = str.split('?')[0].trim();
      }
      if (compiledRe && compiledRe.test(str)) return true;
    } else if (rule.mode === 'starts_with') {
      if (str.toLowerCase().startsWith(needleLower)) return true;
    } else {
      if (str.toLowerCase().includes(needleLower)) return true;
    }
  }
  return false;
}

function matchesTextFilter(value, filterExpr) {
  const f = String(filterExpr || '').trim();
  if (!f) return true;
  const v = String(value || '');
  if (!v) return false;
  if (f.includes('*')) {
    return compileWildcardRegex(f, 'full_log').test(v);
  }
  return v.toLowerCase().includes(f.toLowerCase());
}

function evaluateExclusions(rawAlert, rules, resolvedTenant = '') {
  const activeRules = Array.isArray(rules) ? rules.filter((r) => r && r.enabled && r.pattern) : [];
  if (!activeRules.length) return { excluded: false };

  const alertTenant = normalizeTenantScope(resolvedTenant || rawAlert?.agent?.labels?.tenant);
  const byTarget = {};
  const getTargets = (target) => {
    if (byTarget[target]) return byTarget[target];
    let list = [];
    if (target === 'path') {
      list = extractPathCandidates(rawAlert);
    } else if (target === 'filename') {
      list = extractFilenameCandidates(rawAlert);
    } else if (target === 'rule_description') {
      list = [rawAlert?.rule?.description].filter(Boolean);
    } else if (target === 'rule_id') {
      list = rawAlert?.rule?.id != null ? [String(rawAlert.rule.id)] : [];
    } else if (target === 'http_status') {
      list = [extractHttpStatus(rawAlert)].filter(Boolean);
    } else if (target === 'src_ip') {
      list = [extractSrcIp(rawAlert)].filter(Boolean);
    } else if (target === 'agent_name') {
      list = [rawAlert?.agent?.name].filter(Boolean);
    } else if (target === 'user_agent') {
      list = [extractUserAgent(rawAlert)].filter(Boolean);
    } else if (target === 'referer') {
      list = [extractReferer(rawAlert)].filter(Boolean);
    } else {
      list = [
        rawAlert?.full_log,
        rawAlert?.rule?.description,
        extractUserAgent(rawAlert),
        rawAlert?.data?.url,
      ].filter(Boolean);
    }
    byTarget[target] = list;
    return list;
  };

  for (const rule of activeRules) {
    // 1. Tenant isolation check (empty rule.tenant means Global)
    const ruleTenant = normalizeTenantScope(rule.tenant);
    if (ruleTenant && alertTenant !== ruleTenant) continue;

    // 2. Primary target match
    const targets = getTargets(rule.target);
    if (!matchesRule(targets, rule)) continue;

    // 3. Multi-condition AND locks
    if (Array.isArray(rule.ruleIds) && rule.ruleIds.length) {
      const alertRuleId = String(rawAlert?.rule?.id || '').trim();
      if (!alertRuleId || !rule.ruleIds.includes(alertRuleId)) continue;
    }
    if (Array.isArray(rule.httpStatuses) && rule.httpStatuses.length) {
      const st = extractHttpStatus(rawAlert);
      if (!st || !rule.httpStatuses.includes(st)) continue;
    }
    if (Array.isArray(rule.srcIps) && rule.srcIps.length) {
      const ip = extractSrcIp(rawAlert);
      if (!ip) continue;
      const ipMatched = rule.srcIps.some((pat) => (
        pat.includes('*')
          ? compileWildcardRegex(pat, 'src_ip').test(ip)
          : ip.toLowerCase() === pat.toLowerCase()
      ));
      if (!ipMatched) continue;
    }
    if (rule.userAgent && !matchesTextFilter(extractUserAgent(rawAlert), rule.userAgent)) {
      continue;
    }
    if (rule.referer && !matchesTextFilter(extractReferer(rawAlert), rule.referer)) {
      continue;
    }

    return {
      excluded: true,
      ruleId: rule.id,
      ruleLabel: rule.pattern,
    };
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

function stripThinkTags(rawText) {
  return String(rawText || '').replace(/<think>[\s\S]*?<\/think>/gi, '').trim();
}

function parseJsonFromAiText(rawText) {
  const s = stripThinkTags(rawText);
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

function extractTriageResultsList(rawText) {
  const s = stripThinkTags(rawText);
  if (!s) return null;
  const parsed = parseJsonFromAiText(s);
  if (Array.isArray(parsed)) return parsed;
  if (Array.isArray(parsed?.results)) return parsed.results;
  if (Array.isArray(parsed?.groups)) return parsed.groups;
  if (parsed && typeof parsed === 'object' && parsed.candidate_id) return [parsed];

  // Salvage complete result objects from truncated JSON output (e.g. when num_predict hits limit)
  const salvaged = [];
  const braceStack = [];
  let inString = false;
  let escaped = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
    } else if (ch === '{') {
      braceStack.push(i);
    } else if (ch === '}' && braceStack.length > 0) {
      const start = braceStack.pop();
      const slice = s.slice(start, i + 1);
      if (slice.includes('"candidate_id"')) {
        try {
          const obj = JSON.parse(slice);
          if (obj && typeof obj === 'object' && obj.candidate_id && !Array.isArray(obj.results)) {
            salvaged.push(obj);
          }
        } catch {}
      }
    }
  }
  return salvaged.length ? salvaged : null;
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
  const batch24hPath = path.join(dataDir, 'triage-24h.json');
  const historyPath = path.join(dataDir, 'case-history.json');

  function defaultBatch24hState() {
    return {
      groups: [],
      job: {
        running: false,
        phase: 'idle',
        percent: 0,
        message: 'Siap menarik alert 24 jam terakhir',
        range: '24h',
        sinceIso: null,
        untilIso: null,
        fetchedCount: 0,
        excludedCount: 0,
        totalCandidates: 0,
        processedChunks: 0,
        totalChunks: 0,
        currentTenant: null,
        startedAt: null,
        finishedAt: null,
        error: null,
      },
    };
  }

  function loadBatch24h() {
    const def = defaultBatch24hState();
    const raw = readJsonSafe(batch24hPath, null);
    if (!raw || typeof raw !== 'object') return def;
    const job = { ...def.job, ...(raw.job || {}) };
    if (job.running) {
      job.running = false;
      job.phase = 'idle';
      job.message = 'Job sebelumnya terhenti saat server restart.';
    }
    return {
      groups: Array.isArray(raw.groups) ? raw.groups : [],
      job,
    };
  }

  let config = loadConfig();
  let state = loadState();
  let batch24h = loadBatch24h();
  let caseHistory = loadCaseHistory();

  let pollTimer = null;
  let pollLock = Promise.resolve();
  let ollamaLock = Promise.resolve();
  let pollEpoch = 0;
  let batch24hEpoch = 0;
  let pollInFlight = false;
  const sseClients = new Set();
  const liveWorker = {
    phase: 'idle',
    phaseMessage: String(state.workerStatus?.phaseMessage || ''),
    aiActive: false,
    activeTenant: '',
    fetchedCount: 0,
    excludedCount: 0,
    candidateCount: 0,
    analyzedCount: 0,
    processedChunks: 0,
    totalChunks: 0,
    lastDurationMs: Number(state.workerStatus?.lastDurationMs || 0),
    nextPollAt: null,
  };

  function buildWorkerStatusSnapshot() {
    const model = String(config.ollama?.model || '').trim();
    const baseUrl = String(config.wazuh?.url || '').trim();
    const ollamaUrl = String(config.ollama?.baseUrl || '').trim();
    return {
      ...state.workerStatus,
      ...liveWorker,
      running: pollInFlight,
      aiModel: model,
      ollamaConfigured: Boolean(ollamaUrl && model),
      wazuhConfigured: Boolean(baseUrl),
    };
  }

  function setLiveWorker(patch = {}, broadcast = true) {
    Object.assign(liveWorker, patch);
    if (broadcast) broadcastSse('worker', buildWorkerStatusSnapshot());
  }

  function sanitizeOllamaConfig(po = {}, base = defaultConfig().ollama) {
    const out = { ...base };
    if (po.baseUrl !== undefined) out.baseUrl = String(po.baseUrl || '').trim().replace(/\/+$/, '');
    if (po.model !== undefined) out.model = String(po.model || '').trim() || defaultConfig().ollama.model;

    const pickNum = (val, min, max, fallback, isInt = false) => {
      if (val === undefined || val === null || val === '') return fallback;
      const n = Number(val);
      if (!Number.isFinite(n)) return fallback;
      const clamped = Math.max(min, Math.min(max, n));
      return isInt ? Math.round(clamped) : clamped;
    };

    out.temperature = pickNum(po.temperature, 0, 2, out.temperature, false);
    out.numCtx = pickNum(po.numCtx ?? po.num_ctx, 2048, 131072, out.numCtx, true);
    out.numPredict = pickNum(po.numPredict ?? po.num_predict, 256, 32768, out.numPredict, true);
    out.topP = pickNum(po.topP ?? po.top_p, 0.05, 1, out.topP, false);
    out.topK = pickNum(po.topK ?? po.top_k, 1, 200, out.topK, true);
    out.repeatPenalty = pickNum(po.repeatPenalty ?? po.repeat_penalty, 0.8, 2, out.repeatPenalty, false);
    out.microBatchSize = pickNum(po.microBatchSize ?? po.micro_batch_size, 1, 30, out.microBatchSize, true);
    out.timeoutSec = pickNum(po.timeoutSec ?? po.timeout_sec, 15, 600, out.timeoutSec, true);

    const rawKeep = po.keepAlive ?? po.keep_alive;
    if (rawKeep !== undefined) {
      const ka = String(rawKeep || '').trim().slice(0, 20);
      out.keepAlive = ka || '2m';
    }
    if (po.think !== undefined) out.think = Boolean(po.think);
    const rawSchema = po.useJsonSchema ?? po.use_json_schema;
    if (rawSchema !== undefined) out.useJsonSchema = Boolean(rawSchema);

    if (po.systemPrompt !== undefined) {
      out.systemPrompt = String(po.systemPrompt || '').trim() || DEFAULT_SYSTEM_PROMPT;
    } else if (!String(out.systemPrompt || '').trim()) {
      out.systemPrompt = DEFAULT_SYSTEM_PROMPT;
    }
    return out;
  }

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

    const mergedOllama = sanitizeOllamaConfig(raw.ollama || {}, def.ollama);

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

  function saveBatch24h() {
    batch24h.groups = (batch24h.groups || []).slice(0, MAX_ACTIVE_GROUPS);
    writeJsonAtomic(batch24hPath, batch24h);
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

  function filterAndSortGroups(groupsList = [], filters = {}) {
    let items = groupsList.slice();
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
    return items;
  }

  function getQueueSnapshot(filters = {}) {
    const items = filterAndSortGroups(state.groups, filters);
    const tenantsSet = new Set(state.groups.map((g) => g.tenant_mapped).filter(Boolean));

    return {
      ok: true,
      workerEnabled: Boolean(config.workerEnabled),
      workerStatus: buildWorkerStatusSnapshot(),
      watermarkTimestamp: state.watermarkTimestamp,
      counts: summarizeCounts(state.groups),
      tenants: [...tenantsSet].sort(),
      groups: items,
      historyCount: caseHistory.length,
      exclusionRulesCount: config.exclusionRules.length,
      enabledExclusionRulesCount: config.exclusionRules.filter((r) => r.enabled !== false).length,
    };
  }

  function getTriageStats() {
    const excludedMap = state.excludedAlertMap && typeof state.excludedAlertMap === 'object' ? state.excludedAlertMap : {};
    const excludedSet = new Set(Object.keys(excludedMap));
    const activeAlertIds = new Set();
    const verdicts = {
      TRUE_POSITIVE: { groups: 0, alerts: 0 },
      NEEDS_REVIEW: { groups: 0, alerts: 0 },
      FALSE_POSITIVE: { groups: 0, alerts: 0 },
    };

    const tenantMap = new Map();
    const ensureTenantRow = (rawTenant) => {
      const key = normalizeTenantScope(rawTenant) || 'unassigned';
      if (!tenantMap.has(key)) {
        tenantMap.set(key, {
          tenant: key,
          activeGroups: 0,
          activeAlerts: 0,
          tpAlerts: 0,
          reviewAlerts: 0,
          fpAlerts: 0,
          casesCreated: 0,
          caseAlerts: 0,
          exclusionRules: 0,
        });
      }
      return tenantMap.get(key);
    };

    for (const grp of state.groups || []) {
      const cnt = Number(grp.alert_count || grp.alerts?.length || 0);
      for (const al of grp.alerts || []) {
        if (al?.alert_id) activeAlertIds.add(al.alert_id);
      }
      const v = VALID_VERDICTS.includes(grp.verdict) ? grp.verdict : 'NEEDS_REVIEW';
      verdicts[v].groups++;
      verdicts[v].alerts += cnt;

      const tRow = ensureTenantRow(grp.tenant_mapped);
      tRow.activeGroups++;
      tRow.activeAlerts += cnt;
      if (v === 'TRUE_POSITIVE') tRow.tpAlerts += cnt;
      else if (v === 'FALSE_POSITIVE') tRow.fpAlerts += cnt;
      else tRow.reviewAlerts += cnt;
    }

    const historyAlertIds = new Set();
    let historyAlertSum = 0;
    for (const h of caseHistory || []) {
      const ids = Array.isArray(h?.wazuh_alert_ids) ? h.wazuh_alert_ids : [];
      for (const id of ids) {
        if (id) historyAlertIds.add(String(id));
      }
      const hAlerts = Number(h?.alert_count || ids.length || 0);
      historyAlertSum += hAlerts;
      if (h?.tenant) {
        const tRow = ensureTenantRow(h.tenant);
        tRow.casesCreated++;
        tRow.caseAlerts += hAlerts;
      }
    }

    for (const rule of config.exclusionRules || []) {
      const tSlug = normalizeTenantScope(rule?.tenant);
      if (tSlug) {
        ensureTenantRow(tSlug).exclusionRules++;
      }
    }

    const caseAlertSet = new Set([...(state.caseCreatedAlertIds || []).map(String), ...historyAlertIds]);
    const dismissedSet = new Set((state.dismissedAlertIds || []).map(String));
    const aiTriagedSet = new Set();
    for (const id of [
      ...(state.processedAlertIds || []),
      ...activeAlertIds,
      ...dismissedSet,
      ...caseAlertSet,
    ]) {
      const s = String(id || '');
      if (s && !excludedSet.has(s)) aiTriagedSet.add(s);
    }

    const activeQueueAlerts = verdicts.TRUE_POSITIVE.alerts + verdicts.NEEDS_REVIEW.alerts + verdicts.FALSE_POSITIVE.alerts;
    const caseAlerts = Math.max(caseAlertSet.size, historyAlertSum);

    const ruleHits = new Map();
    for (const entry of Object.values(excludedMap)) {
      const label = String(entry?.ruleLabel || '').trim() || '(Tanpa label)';
      const cur = ruleHits.get(label) || { ruleLabel: label, count: 0, lastAt: null };
      cur.count++;
      if (entry?.at && (!cur.lastAt || String(entry.at) > cur.lastAt)) {
        cur.lastAt = String(entry.at);
      }
      ruleHits.set(label, cur);
    }

    const topExcludedRules = [...ruleHits.values()]
      .sort((a, b) => b.count - a.count || String(b.lastAt || '').localeCompare(String(a.lastAt || '')))
      .slice(0, 10);

    const perTenant = [...tenantMap.values()].sort((a, b) => {
      const scoreA = a.activeAlerts + a.caseAlerts + a.exclusionRules;
      const scoreB = b.activeAlerts + b.caseAlerts + b.exclusionRules;
      return scoreB - scoreA || a.tenant.localeCompare(b.tenant);
    });

    return {
      ok: true,
      summary: {
        totalHandledAlerts: aiTriagedSet.size + excludedSet.size,
        aiTriagedAlerts: aiTriagedSet.size,
        excludedAlerts: excludedSet.size,
        caseAlerts,
        casesCreated: (caseHistory || []).length,
        dismissedAlerts: dismissedSet.size,
        activeQueueGroups: (state.groups || []).length,
        activeQueueAlerts,
        activeExclusionRules: config.exclusionRules.filter((r) => r.enabled !== false).length,
        totalExclusionRules: config.exclusionRules.length,
      },
      verdicts,
      perTenant,
      topExcludedRules,
      workerEnabled: Boolean(config.workerEnabled),
      workerStatus: buildWorkerStatusSnapshot(),
      watermarkTimestamp: state.watermarkTimestamp,
    };
  }

  function getBatch24hSnapshot(filters = {}) {
    const items = filterAndSortGroups(batch24h.groups, filters);
    const tenantsSet = new Set(batch24h.groups.map((g) => g.tenant_mapped).filter(Boolean));
    return {
      ok: true,
      job: { ...batch24h.job },
      counts: summarizeCounts(batch24h.groups),
      tenants: [...tenantsSet].sort(),
      groups: items,
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
    res.write(`event: batch24h\ndata: ${JSON.stringify(getBatch24hSnapshot())}\n\n`);
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

  async function callSingleOllamaBatch(tenant, candidates, existingGroupKeys = [], opts = {}) {
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
      severity_label: severityLabel(c.maxRuleLevel),
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
      'Skala Severity Wazuh (WAJIB): Level 0-6 = Low, Level 7-11 = Medium (contoh: rule level 10 adalah Medium, BUKAN Critical/High), Level 12-14 = High, Level 15+ = Critical.',
      'Tugas: Klasifikasikan tiap candidate_id (TRUE_POSITIVE | NEEDS_REVIEW | FALSE_POSITIVE) dan berikan group_key semantik agar kampanye serangan sejenis (mis. scanning /.env lintas agent) bisa menyatu, sementara trafik legit (mis. /login.php, /api/v1/items) terpisah walau rule_id sama.',
      'Buat ai_reasoning ringkas (maksimal 1-2 kalimat singkat & padat) dan pastikan JSON tertutup lengkap.',
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
      timeoutMs: (Number(o.timeoutSec) || 90) * 1000,
      body: {
        model: o.model,
        stream: false,
        think: Boolean(o.think),
        keep_alive: String(o.keepAlive || '2m'),
        format: (opts.useJsonMode || o.useJsonSchema === false) ? 'json' : TRIAGE_RESPONSE_SCHEMA,
        options: {
          temperature: Number(o.temperature ?? 0.1),
          num_ctx: Number(o.numCtx || 12288),
          num_predict: Number(o.numPredict || 4096),
          top_p: Number(o.topP ?? 0.85),
          top_k: Number(o.topK ?? 20),
          repeat_penalty: Number(o.repeatPenalty ?? 1.05),
        },
        messages: [
          { role: 'system', content: o.systemPrompt || DEFAULT_SYSTEM_PROMPT },
          { role: 'user', content: userPrompt },
        ],
      },
    }));

    const content = String(res.json?.message?.content ?? res.json?.response ?? '').trim();
    const thinking = String(res.json?.message?.thinking ?? '').trim();
    let list = extractTriageResultsList(content);
    if (!list && thinking) {
      list = extractTriageResultsList(thinking);
    }

    if (!list) {
      const reason = res.json?.done_reason || (content ? 'malformed' : 'empty');
      const err = new Error(`Respons Ollama bukan JSON array/results valid (${reason}, len=${content.length})`);
      err.isAiFormatError = true;
      throw err;
    }

    const byCandidateId = new Map();
    for (const item of list) {
      const cid = String(item?.candidate_id || item?.id || '').trim();
      if (cid) byCandidateId.set(cid, item);
    }
    if (!byCandidateId.size) {
      const err = new Error('Respons Ollama tidak memuat candidate_id valid');
      err.isAiFormatError = true;
      throw err;
    }
    return byCandidateId;
  }

  async function runOllamaMicroBatch(tenant, candidates, existingGroupKeys = []) {
    try {
      const byCandidateId = await callSingleOllamaBatch(tenant, candidates, existingGroupKeys, { useJsonMode: false });
      const missing = candidates.filter((c) => !byCandidateId.has(c.candidateId));
      if (missing.length > 0 && missing.length < candidates.length) {
        try {
          const recovered = await callSingleOllamaBatch(tenant, missing, existingGroupKeys, { useJsonMode: true });
          for (const [k, v] of recovered.entries()) byCandidateId.set(k, v);
        } catch {}
      }
      return byCandidateId;
    } catch (err) {
      if (!err?.isAiFormatError) throw err;
      if (candidates.length > 1) {
        const mid = Math.ceil(candidates.length / 2);
        const merged = new Map();
        const left = await callSingleOllamaBatch(tenant, candidates.slice(0, mid), existingGroupKeys, { useJsonMode: true });
        for (const [k, v] of left.entries()) merged.set(k, v);
        const right = await callSingleOllamaBatch(tenant, candidates.slice(mid), existingGroupKeys, { useJsonMode: true });
        for (const [k, v] of right.entries()) merged.set(k, v);
        return merged;
      }
      return callSingleOllamaBatch(tenant, candidates, existingGroupKeys, { useJsonMode: true });
    }
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

  function preGroupByTenant(hits, opts = {}) {
    const skipSeen = opts.skipSeen !== false;
    const mutateExclusions = opts.mutateExclusions !== false;
    const tenantFilter = String(opts.tenantFilter || '').trim().toLowerCase();
    const processedSet = skipSeen ? new Set(state.processedAlertIds) : null;
    const dismissedSet = skipSeen ? new Set(state.dismissedAlertIds) : null;
    const createdSet = skipSeen ? new Set(state.caseCreatedAlertIds) : null;
    const knownTenants = getKnownTenants();

    let excludedCount = 0;
    const byTenantBuckets = new Map();

    for (const hit of hits) {
      const id = hit.alert_id;
      if (skipSeen && (processedSet.has(id) || dismissedSet.has(id) || createdSet.has(id) || state.excludedAlertMap[id])) {
        continue;
      }

      const raw = hit.raw_wazuh_alert || {};
      const tenant = resolveTenant(raw, config.wazuh.tenantMapping, knownTenants);
      if (tenantFilter && tenant.toLowerCase() !== tenantFilter) {
        continue;
      }

      const ex = evaluateExclusions(raw, config.exclusionRules, tenant);
      if (ex.excluded) {
        if (mutateExclusions) {
          state.excludedAlertMap[id] = { ruleLabel: ex.ruleLabel, at: new Date().toISOString() };
          state.processedAlertIds.push(id);
        }
        excludedCount++;
        continue;
      }

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

  function appendSemanticGroupsToList(targetList, groupPayloads) {
    for (const groupPayload of groupPayloads) {
      const existing = targetList.find(
        (g) =>
          g.tenant_mapped === groupPayload.tenant_mapped &&
          g.verdict === groupPayload.verdict &&
          g.group_key === groupPayload.group_key
      );
      if (existing) {
        mergeAlertWrappersIntoGroup(existing, groupPayload);
      } else {
        targetList.unshift(groupPayload);
      }
    }
  }

  async function runAiOnTenantBuckets(byTenantBuckets, hooks = {}) {
    const isAborted = typeof hooks.isAborted === 'function' ? hooks.isAborted : () => false;
    const getExistingGroupKeys = typeof hooks.getExistingGroupKeys === 'function' ? hooks.getExistingGroupKeys : () => [];
    const onChunkStart = typeof hooks.onChunkStart === 'function' ? hooks.onChunkStart : null;
    const onChunkProgress = typeof hooks.onChunkProgress === 'function' ? hooks.onChunkProgress : null;
    const onTenantMerged = typeof hooks.onTenantMerged === 'function' ? hooks.onTenantMerged : null;

    let analyzedCount = 0;
    let processedChunks = 0;

    for (const [tenant, bucketMap] of byTenantBuckets.entries()) {
      if (isAborted()) return { analyzedCount, aborted: true };
      const candidates = [...bucketMap.values()];
      if (!candidates.length) continue;

      const existingGroupKeys = getExistingGroupKeys(tenant);
      const aiMap = new Map();
      const chunkErrors = new Map();

      const batchSize = Math.max(1, Math.min(30, Number(config.ollama?.microBatchSize || OLLAMA_MICRO_BATCH_SIZE)));
      for (let i = 0; i < candidates.length; i += batchSize) {
        if (isAborted()) return { analyzedCount, aborted: true };
        const chunk = candidates.slice(i, i + batchSize);
        if (onChunkStart) {
          onChunkStart({
            tenant,
            chunkIndex: processedChunks + 1,
            chunkSize: chunk.length,
          });
        }
        try {
          const partMap = await runOllamaMicroBatch(tenant, chunk, existingGroupKeys);
          for (const [cid, val] of partMap.entries()) aiMap.set(cid, val);
        } catch (err) {
          const msg = err.message || 'Ollama tidak terjangkau';
          for (const c of chunk) chunkErrors.set(c.candidateId, msg);
        }
        processedChunks++;
        const analyzedInChunk = chunk.reduce((sum, c) => sum + (c.alerts?.length || 0), 0);
        if (onChunkProgress) onChunkProgress({ tenant, processedChunks, analyzedInChunk });
      }

      if (isAborted()) return { analyzedCount, aborted: true };

      const mergedInTenant = new Map();
      const processedAlertsInTenant = [];

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
          processedAlertsInTenant.push(a.alert_id);
          analyzedCount++;
        }
      }

      if (onTenantMerged) {
        onTenantMerged({ tenant, groupPayloads: [...mergedInTenant.values()], processedAlertIds: processedAlertsInTenant });
      }
    }

    return { analyzedCount, aborted: false };
  }

  async function processHitsIntoQueue(hits, runEpoch = null, onStage = null) {
    if (runEpoch != null && runEpoch !== pollEpoch) {
      return { excludedCount: 0, analyzedCount: 0, aborted: true };
    }
    const { excludedCount, byTenantBuckets } = preGroupByTenant(hits, { skipSeen: true, mutateExclusions: true });
    const batchSize = Math.max(1, Math.min(30, Number(config.ollama?.microBatchSize || OLLAMA_MICRO_BATCH_SIZE)));
    let candidateCount = 0;
    let totalChunks = 0;
    for (const bucketMap of byTenantBuckets.values()) {
      candidateCount += bucketMap.size;
      if (bucketMap.size > 0) totalChunks += Math.ceil(bucketMap.size / batchSize);
    }
    if (onStage) onStage('filtered', { excludedCount, candidateCount, totalChunks });

    let chunkAnalyzedSum = 0;
    const { analyzedCount, aborted } = await runAiOnTenantBuckets(byTenantBuckets, {
      isAborted: () => runEpoch != null && runEpoch !== pollEpoch,
      getExistingGroupKeys: (tenant) =>
        [...new Set(state.groups.filter((g) => g.tenant_mapped === tenant && g.group_key).map((g) => g.group_key))].slice(0, 20),
      onChunkStart: ({ tenant, chunkIndex, chunkSize }) => {
        if (onStage) onStage('ai_chunk_start', { tenant, chunkIndex, totalChunks, chunkSize });
      },
      onChunkProgress: ({ tenant, processedChunks, analyzedInChunk }) => {
        chunkAnalyzedSum += analyzedInChunk || 0;
        if (onStage) {
          onStage('ai_chunk_done', {
            tenant,
            processedChunks,
            totalChunks,
            analyzedCount: chunkAnalyzedSum,
          });
        }
      },
      onTenantMerged: ({ tenant, groupPayloads, processedAlertIds }) => {
        appendSemanticGroupsToList(state.groups, groupPayloads);
        for (const id of processedAlertIds) state.processedAlertIds.push(id);
        if (onStage) onStage('tenant_merged', { tenant });
      },
    });
    return { excludedCount, analyzedCount, candidateCount, totalChunks, aborted };
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
    const runEpoch = pollEpoch;
    const run = pollLock.then(async () => {
      if (runEpoch !== pollEpoch) {
        return { ok: true, aborted: true, fetchedCount: 0, excludedCount: 0, analyzedCount: 0, snapshot: getQueueSnapshot() };
      }
      if (!String(config.wazuh.url || '').trim()) {
        return { ok: false, skipped: true, reason: 'Wazuh Indexer URL belum diatur' };
      }
      const startedMs = Date.now();
      pollInFlight = true;
      state.workerStatus.lastPollAt = new Date().toISOString();
      setLiveWorker({
        phase: 'fetching_wazuh',
        aiActive: false,
        activeTenant: '',
        fetchedCount: 0,
        excludedCount: 0,
        candidateCount: 0,
        analyzedCount: 0,
        processedChunks: 0,
        totalChunks: 0,
        phaseMessage: 'Menarik alert dari Wazuh Indexer…',
      });

      try {
        const { hits } = await queryWazuhAlerts({
          sinceIso: win.sinceIso,
          untilIso: win.untilIso,
          inclusiveSince: win.inclusiveSince,
          size: maxSize,
          minLevel: config.wazuh.minRuleLevel,
          maxLevel: config.wazuh.maxRuleLevel,
        });
        if (runEpoch !== pollEpoch) {
          return { ok: true, aborted: true, fetchedCount: 0, excludedCount: 0, analyzedCount: 0, snapshot: getQueueSnapshot() };
        }

        setLiveWorker({
          phase: 'filtering',
          fetchedCount: hits.length,
          phaseMessage: `Ditarik ${hits.length} alert · menyaring aturan Exclude…`,
        });

        const { excludedCount, analyzedCount, aborted } = await processHitsIntoQueue(hits, runEpoch, (stage, info = {}) => {
          if (stage === 'filtered') {
            if (info.totalChunks > 0) {
              setLiveWorker({
                phase: 'analyzing_ai',
                aiActive: true,
                excludedCount: info.excludedCount,
                candidateCount: info.candidateCount,
                totalChunks: info.totalChunks,
                processedChunks: 0,
                phaseMessage: `AI Ollama menganalisis ${info.candidateCount} kandidat (${info.totalChunks} batch)…`,
              });
            } else {
              setLiveWorker({
                excludedCount: info.excludedCount,
                candidateCount: 0,
                totalChunks: 0,
                phaseMessage: hits.length
                  ? `Semua ${hits.length} alert tersaring Exclude / sudah diproses.`
                  : 'Tidak ada alert baru pada rentang ini.',
              });
            }
          } else if (stage === 'ai_chunk_start') {
            setLiveWorker({
              phase: 'analyzing_ai',
              aiActive: true,
              activeTenant: info.tenant || '',
              totalChunks: info.totalChunks || 0,
              phaseMessage: `AI Ollama menganalisis ${info.tenant || 'tenant'} (batch ${info.chunkIndex}/${info.totalChunks})…`,
            });
          } else if (stage === 'ai_chunk_done') {
            setLiveWorker({
              phase: 'analyzing_ai',
              aiActive: true,
              activeTenant: info.tenant || '',
              processedChunks: info.processedChunks || 0,
              totalChunks: info.totalChunks || 0,
              analyzedCount: info.analyzedCount || 0,
              phaseMessage: `AI Ollama selesai batch ${info.processedChunks}/${info.totalChunks} (${info.tenant || 'tenant'})…`,
            });
          } else if (stage === 'tenant_merged') {
            broadcastSse('state', getQueueSnapshot());
          }
        });
        if (aborted || runEpoch !== pollEpoch) {
          return { ok: true, aborted: true, fetchedCount: 0, excludedCount: 0, analyzedCount: 0, snapshot: getQueueSnapshot() };
        }
        const durationMs = Date.now() - startedMs;
        const intervalMs = Math.max(1, Number(config.wazuh.pollIntervalMin || 3)) * 60 * 1000;
        const nextPollIso = config.workerEnabled ? new Date(Date.now() + intervalMs).toISOString() : null;
        const doneMsg = hits.length
          ? `Selesai · ${hits.length} ditarik · ${excludedCount} excluded · ${analyzedCount} dianalisis AI`
          : 'Tidak ada alert baru pada rentang ini';
        pollInFlight = false;
        state.workerStatus.lastSuccessAt = new Date().toISOString();
        state.workerStatus.lastError = null;
        state.workerStatus.lastBatchCount = hits.length;
        state.workerStatus.lastExcludedCount = excludedCount;
        state.workerStatus.lastAnalyzedCount = analyzedCount;
        state.workerStatus.lastDurationMs = durationMs;
        state.workerStatus.phaseMessage = doneMsg;
        setLiveWorker({
          phase: 'done',
          aiActive: false,
          activeTenant: '',
          fetchedCount: hits.length,
          excludedCount,
          analyzedCount,
          lastDurationMs: durationMs,
          nextPollAt: nextPollIso,
          phaseMessage: doneMsg,
        }, false);
        saveState();
        broadcastSse('worker', buildWorkerStatusSnapshot());
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
        if (runEpoch !== pollEpoch) {
          return { ok: true, aborted: true, fetchedCount: 0, excludedCount: 0, analyzedCount: 0, snapshot: getQueueSnapshot() };
        }
        const durationMs = Date.now() - startedMs;
        const errMsg = `Gagal: ${err.message || 'Gagal polling Wazuh Indexer'}`;
        pollInFlight = false;
        state.workerStatus.lastError = err.message || 'Gagal polling Wazuh Indexer';
        state.workerStatus.lastDurationMs = durationMs;
        state.workerStatus.phaseMessage = errMsg;
        setLiveWorker({
          phase: 'error',
          aiActive: false,
          activeTenant: '',
          lastDurationMs: durationMs,
          phaseMessage: errMsg,
        }, false);
        saveState();
        broadcastSse('worker', buildWorkerStatusSnapshot());
        broadcastSse('state', getQueueSnapshot());
        throw err;
      } finally {
        pollInFlight = false;
        if (
          liveWorker.aiActive ||
          liveWorker.phase === 'fetching_wazuh' ||
          liveWorker.phase === 'filtering' ||
          liveWorker.phase === 'analyzing_ai'
        ) {
          setLiveWorker({ phase: 'idle', aiActive: false, activeTenant: '' });
        }
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
      liveWorker.nextPollAt = new Date(Date.now() + intervalMs).toISOString();
      pollTimer = setInterval(() => {
        if (!config.workerEnabled) return;
        pollOnce().catch(() => {});
      }, intervalMs);
      if (typeof pollTimer.unref === 'function') pollTimer.unref();
    } else {
      liveWorker.nextPollAt = null;
    }
  }

  function updateConfig(patch = {}) {
    const wasEnabled = Boolean(config.workerEnabled);
    const next = cloneJson(config);
    if (patch.workerEnabled !== undefined) next.workerEnabled = Boolean(patch.workerEnabled);
    if ((wasEnabled && !next.workerEnabled) || patch.workerEnabled === false) {
      pollEpoch++;
    }

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
      next.ollama = sanitizeOllamaConfig(patch.ollama, next.ollama);
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
        const liveEx = evaluateExclusions(raw, config.exclusionRules, tenant);
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
      http_status: extractHttpStatus(raw) || '',
      full_log: String(raw.full_log || ''),
      status_code: statusCode,
      status_label: statusLabel,
      group_id: matchedGroupId,
      raw_wazuh_alert: raw,
    };
  }

  async function getLiveFeed(opts = {}) {
    const range = String(opts.range || opts.scope || 'watermark').trim().toLowerCase() || 'watermark';
    const win = resolvePollWindow({ range, from: opts.from, to: opts.to });
    const maxSize = Math.min(Math.max(1, Number(opts.size) || 500), 1000);

    const { totalHits, hits } = await queryWazuhAlerts({
      sinceIso: win.sinceIso,
      untilIso: win.untilIso,
      inclusiveSince: win.inclusiveSince,
      size: maxSize,
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
      scope: range,
      range,
      window: { sinceIso: win.sinceIso, untilIso: win.untilIso },
      watermarkTimestamp: state.watermarkTimestamp,
      fetchedAt: new Date().toISOString(),
      items: filtered,
    };
  }

  function mergeGroupsInList(list, groupIds = []) {
    const ids = [...new Set((groupIds || []).map((id) => String(id || '').trim()).filter(Boolean))];
    if (ids.length < 2) {
      throw Object.assign(new Error('Pilih minimal 2 grup untuk digabungkan.'), { status: 400 });
    }
    const selected = list.filter((g) => ids.includes(g.group_id));
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
    const nextList = [base, ...list.filter((g) => !selectedSet.has(g.group_id))];
    return { nextList, base };
  }

  function removeAlertsFromGroupInList(list, { groupId, alertIds = [] } = {}) {
    const gid = String(groupId || '').trim();
    if (!gid) {
      throw Object.assign(new Error('groupId wajib diisi.'), { status: 400 });
    }
    const idSet = new Set((Array.isArray(alertIds) ? alertIds : []).map((x) => String(x || '').trim()).filter(Boolean));
    if (!idSet.size) {
      throw Object.assign(new Error('Pilih minimal 1 alert untuk dihilangkan.'), { status: 400 });
    }
    const grp = list.find((g) => g.group_id === gid);
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

    let nextList = list;
    let groupRemoved = false;
    if (remaining.length === 0) {
      nextList = list.filter((g) => g.group_id !== gid);
      groupRemoved = true;
    } else {
      grp.alerts = remaining;
      recomputeGroupMetadata(grp);
    }
    return { nextList, removed, groupRemoved, group: groupRemoved ? null : grp };
  }

  function splitGroupAlertsInList(list, { groupId, alertIds = [], incidentTitle = '', verdict = '' } = {}) {
    const gid = String(groupId || '').trim();
    if (!gid) {
      throw Object.assign(new Error('groupId wajib diisi.'), { status: 400 });
    }
    const idSet = new Set((Array.isArray(alertIds) ? alertIds : []).map((x) => String(x || '').trim()).filter(Boolean));
    if (!idSet.size) {
      throw Object.assign(new Error('Pilih minimal 1 alert untuk dipisahkan.'), { status: 400 });
    }
    const grpIndex = list.findIndex((g) => g.group_id === gid);
    if (grpIndex === -1) {
      throw Object.assign(new Error('Grup triage tidak ditemukan.'), { status: 404 });
    }
    const grp = list[grpIndex];

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

    const nextList = list.slice();
    nextList.splice(grpIndex + 1, 0, newGroup);
    return { nextList, sourceGroup: grp, newGroup };
  }

  function dismissGroupsInList(list, { groupIds = [], verdict = '' } = {}) {
    const idSet = new Set((groupIds || []).map((id) => String(id || '').trim()).filter(Boolean));
    const vFilter = String(verdict || '').trim().toUpperCase();
    const toRemove = [];
    const remaining = [];

    for (const g of list) {
      const matchId = idSet.size > 0 && idSet.has(g.group_id);
      const matchVerdict = vFilter && g.verdict === vFilter;
      if (matchId || matchVerdict) toRemove.push(g);
      else remaining.push(g);
    }
    return { toRemove, remaining };
  }

  function mergeGroups(groupIds = []) {
    const { nextList, base } = mergeGroupsInList(state.groups, groupIds);
    state.groups = nextList;
    saveState();
    broadcastSse('state', getQueueSnapshot());
    return { ok: true, group: base, snapshot: getQueueSnapshot() };
  }

  function removeAlertsFromGroup(opts = {}) {
    const { nextList, removed, groupRemoved, group } = removeAlertsFromGroupInList(state.groups, opts);
    state.groups = nextList;
    for (const al of removed) {
      state.dismissedAlertIds.push(al.alert_id);
      state.processedAlertIds.push(al.alert_id);
    }
    saveState();
    broadcastSse('state', getQueueSnapshot());
    return {
      ok: true,
      removedCount: removed.length,
      groupRemoved,
      group,
      snapshot: getQueueSnapshot(),
    };
  }

  function splitGroupAlerts(opts = {}) {
    const { nextList, sourceGroup, newGroup } = splitGroupAlertsInList(state.groups, opts);
    state.groups = nextList;
    saveState();
    broadcastSse('state', getQueueSnapshot());
    return {
      ok: true,
      sourceGroup,
      newGroup,
      snapshot: getQueueSnapshot(),
    };
  }

  function exclusionDedupKey(r) {
    return [
      normalizeTenantScope(r.tenant),
      r.target,
      r.mode,
      String(r.pattern || '').trim().toLowerCase(),
      (r.ruleIds || []).slice().sort().join(','),
      (r.httpStatuses || []).slice().sort().join(','),
      (r.srcIps || []).slice().sort().join(','),
      String(r.userAgent || '').trim().toLowerCase(),
      String(r.referer || '').trim().toLowerCase(),
    ].join('|');
  }

  function upsertExclusionRule(ruleInput) {
    const candidate = sanitizeExclusionRule(ruleInput, config.exclusionRules.length);
    if (!candidate || !candidate.pattern) {
      throw Object.assign(new Error('Pola exclusion rule wajib diisi.'), { status: 400 });
    }
    const cKey = exclusionDedupKey(candidate);
    const existing = config.exclusionRules.find((r) => exclusionDedupKey(r) === cKey);
    if (existing) {
      let dirty = false;
      if (!existing.enabled) {
        existing.enabled = true;
        dirty = true;
      }
      if (dirty) {
        config.updatedAt = new Date().toISOString();
        saveConfig();
        broadcastSse('state', getQueueSnapshot());
      }
      return { rule: cloneJson(existing), alreadyExisted: true };
    }
    config.exclusionRules.push(candidate);
    config.updatedAt = new Date().toISOString();
    saveConfig();
    broadcastSse('state', getQueueSnapshot());
    return { rule: cloneJson(candidate), alreadyExisted: false };
  }

  function listExclusionRules() {
    const rules = cloneJson(config.exclusionRules || []);
    return {
      ok: true,
      rules,
      total: rules.length,
      enabledCount: rules.filter((r) => r.enabled !== false).length,
    };
  }

  function addExclusionRule(payload = {}) {
    let candidate = null;
    if (payload.rawAlert || (Array.isArray(payload.alerts) && payload.alerts.length)) {
      const list = Array.isArray(payload.alerts) && payload.alerts.length ? payload.alerts : [payload.rawAlert];
      const firstRaw = list[0]?.raw_wazuh_alert || list[0] || {};
      const resolvedT = payload.tenant || resolveTenant(firstRaw, config.wazuh.tenantMapping, getKnownTenants());
      candidate = deriveExclusionRuleFromAlerts(list, payload.fallbackTitle || '', resolvedT);
      if (!candidate) {
        throw Object.assign(new Error('Tidak dapat mendeteksi pola exclusion otomatis dari alert tersebut.'), { status: 400 });
      }
    } else {
      candidate = {
        tenant: payload.tenant,
        target: payload.target,
        mode: payload.mode,
        pattern: payload.pattern,
        ruleIds: payload.ruleIds,
        httpStatuses: payload.httpStatuses,
        srcIps: payload.srcIps,
        userAgent: payload.userAgent,
        referer: payload.referer,
        enabled: payload.enabled !== false,
        source: ['auto_ignore', 'ai_suggest'].includes(payload.source) ? payload.source : 'manual',
        createdAt: new Date().toISOString(),
        note: payload.note || '',
      };
    }
    const { rule, alreadyExisted } = upsertExclusionRule(candidate);
    return {
      ok: true,
      rule,
      alreadyExisted,
      rules: cloneJson(config.exclusionRules),
      total: config.exclusionRules.length,
    };
  }

  function updateExclusionRule(id, patch = {}) {
    const ruleId = String(id || '').trim();
    const idx = config.exclusionRules.findIndex((r) => r.id === ruleId);
    if (idx === -1) {
      throw Object.assign(new Error('Aturan exclude tidak ditemukan.'), { status: 404 });
    }
    const cur = config.exclusionRules[idx];
    const next = sanitizeExclusionRule({
      id: cur.id,
      tenant: patch.tenant !== undefined ? patch.tenant : cur.tenant,
      target: patch.target !== undefined ? patch.target : cur.target,
      mode: patch.mode !== undefined ? patch.mode : cur.mode,
      pattern: patch.pattern !== undefined ? patch.pattern : cur.pattern,
      ruleIds: patch.ruleIds !== undefined ? patch.ruleIds : cur.ruleIds,
      httpStatuses: patch.httpStatuses !== undefined ? patch.httpStatuses : cur.httpStatuses,
      srcIps: patch.srcIps !== undefined ? patch.srcIps : cur.srcIps,
      userAgent: patch.userAgent !== undefined ? patch.userAgent : cur.userAgent,
      referer: patch.referer !== undefined ? patch.referer : cur.referer,
      enabled: patch.enabled !== undefined ? patch.enabled : cur.enabled,
      source: cur.source,
      createdAt: cur.createdAt,
      note: patch.note !== undefined ? patch.note : cur.note,
    }, idx);
    if (!next || !next.pattern) {
      throw Object.assign(new Error('Pola exclusion rule tidak boleh kosong.'), { status: 400 });
    }
    config.exclusionRules[idx] = next;
    config.updatedAt = new Date().toISOString();
    saveConfig();
    broadcastSse('state', getQueueSnapshot());
    return {
      ok: true,
      rule: cloneJson(next),
      rules: cloneJson(config.exclusionRules),
      total: config.exclusionRules.length,
    };
  }

  function deleteExclusionRule(id) {
    const ruleId = String(id || '').trim();
    const before = config.exclusionRules.length;
    config.exclusionRules = config.exclusionRules.filter((r) => r.id !== ruleId);
    if (config.exclusionRules.length === before) {
      throw Object.assign(new Error('Aturan exclude tidak ditemukan.'), { status: 404 });
    }
    config.updatedAt = new Date().toISOString();
    saveConfig();
    broadcastSse('state', getQueueSnapshot());
    return {
      ok: true,
      deletedId: ruleId,
      rules: cloneJson(config.exclusionRules),
      total: config.exclusionRules.length,
    };
  }

  function ignoreAndExcludeInList(list, opts = {}, { isQueue = true } = {}) {
    const groupId = String(opts.groupId || '').trim();
    const alertIds = Array.isArray(opts.alertIds) ? opts.alertIds.map((x) => String(x || '').trim()).filter(Boolean) : [];
    const groupIds = Array.isArray(opts.groupIds)
      ? opts.groupIds.map((x) => String(x || '').trim()).filter(Boolean)
      : (groupId ? [groupId] : []);

    const rulesAdded = [];
    const rulesExisting = [];
    let removedGroups = 0;
    let removedAlerts = 0;
    let nextList = list;
    let groupRemoved = false;

    const recordExcludedAlerts = (alerts, rule) => {
      removedAlerts += alerts.length;
      if (!isQueue) return;
      for (const al of alerts) {
        state.excludedAlertMap[al.alert_id] = { ruleId: rule.id, ruleLabel: rule.pattern };
        state.processedAlertIds.push(al.alert_id);
      }
    };

    const applyRulesList = (alerts, rulePayloads = []) => {
      const firstApplied = [];
      for (const candidate of rulePayloads) {
        const { rule, alreadyExisted } = upsertExclusionRule(candidate);
        if (alreadyExisted) {
          if (!rulesExisting.some((x) => x.id === rule.id)) rulesExisting.push(rule);
        } else {
          if (!rulesAdded.some((x) => x.id === rule.id)) rulesAdded.push(rule);
        }
        firstApplied.push(rule);
      }
      if (firstApplied.length) recordExcludedAlerts(alerts, firstApplied[0]);
      return firstApplied;
    };

    const explicitRules = Array.isArray(opts.rules)
      ? opts.rules.map((r, i) => sanitizeExclusionRule(r, i)).filter((r) => r && r.enabled !== false && r.pattern)
      : null;

    if (explicitRules !== null && explicitRules.length === 0) {
      throw Object.assign(new Error('Minimal 1 rule exclude dengan pola valid harus dipilih.'), { status: 400 });
    }

    const applyForGroupOrAlerts = (alerts, title, tenant = '') => {
      if (explicitRules && explicitRules.length) {
        return applyRulesList(alerts, explicitRules);
      }
      const derivedList = deriveExclusionRulesFromAlerts(alerts, title, tenant);
      if (!derivedList.length) return [];
      return applyRulesList(alerts, derivedList);
    };

    if (groupId && alertIds.length > 0) {
      const grp = nextList.find((g) => g.group_id === groupId);
      if (!grp) {
        throw Object.assign(new Error('Grup triage tidak ditemukan.'), { status: 404 });
      }
      const res = removeAlertsFromGroupInList(nextList, { groupId, alertIds });
      nextList = res.nextList;
      groupRemoved = res.groupRemoved;
      if (groupRemoved) removedGroups = 1;
      const applied = applyForGroupOrAlerts(res.removed, grp.incident_title || '', grp.tenant_mapped || '');
      if (!applied.length) {
        throw Object.assign(new Error('Tidak dapat mendeteksi pola exclusion otomatis dari alert terpilih.'), { status: 400 });
      }
    } else if (groupIds.length > 0) {
      const { toRemove, remaining } = dismissGroupsInList(nextList, { groupIds });
      if (!toRemove.length) {
        throw Object.assign(new Error('Grup triage tidak ditemukan.'), { status: 404 });
      }
      nextList = remaining;
      removedGroups = toRemove.length;
      groupRemoved = true;
      for (const grp of toRemove) {
        applyForGroupOrAlerts(grp.alerts || [], grp.incident_title || '', grp.tenant_mapped || '');
      }
    } else {
      throw Object.assign(new Error('Pilih grup atau alert yang akan diabaikan & di-exclude.'), { status: 400 });
    }

    return {
      nextList,
      rulesAdded,
      rulesExisting,
      removedGroups,
      removedAlerts,
      groupRemoved,
    };
  }

  function resolveAlertsForExclusionRequest(opts = {}) {
    const source = String(opts.source || 'queue').trim().toLowerCase();
    const explicitTenant = normalizeTenantScope(opts.tenant || '');
    if (Array.isArray(opts.rawAlerts) && opts.rawAlerts.length) {
      const alerts = opts.rawAlerts.map((a, idx) => ({
        alert_id: String(a?.alert_id || a?._id || `raw_${idx}`),
        raw_wazuh_alert: a?.raw_wazuh_alert || a || {},
      }));
      const firstRaw = alerts[0]?.raw_wazuh_alert || {};
      const resolvedTenant = explicitTenant || normalizeTenantScope(
        resolveTenant(firstRaw, config.wazuh.tenantMapping, getKnownTenants()),
      );
      return {
        alerts,
        tenant: resolvedTenant,
        fallbackTitle: String(opts.title || firstRaw?.rule?.description || '').trim(),
      };
    }
    const list = source === 'batch24h' ? batch24h.groups : state.groups;
    const groupId = String(opts.groupId || '').trim();
    const alertIds = Array.isArray(opts.alertIds) ? opts.alertIds.map((x) => String(x || '').trim()).filter(Boolean) : [];
    const groupIds = Array.isArray(opts.groupIds)
      ? opts.groupIds.map((x) => String(x || '').trim()).filter(Boolean)
      : (groupId ? [groupId] : []);

    if (groupId && alertIds.length > 0) {
      const grp = list.find((g) => g.group_id === groupId);
      if (!grp) throw Object.assign(new Error('Grup triage tidak ditemukan.'), { status: 404 });
      const idSet = new Set(alertIds);
      const picked = (grp.alerts || []).filter((a) => idSet.has(a.alert_id));
      if (!picked.length) throw Object.assign(new Error('Alert yang dipilih tidak ditemukan di grup ini.'), { status: 404 });
      return {
        alerts: picked,
        tenant: explicitTenant || normalizeTenantScope(grp.tenant_mapped || ''),
        fallbackTitle: grp.incident_title || '',
      };
    }
    if (groupIds.length > 0) {
      const matched = list.filter((g) => groupIds.includes(g.group_id));
      if (!matched.length) throw Object.assign(new Error('Grup triage tidak ditemukan.'), { status: 404 });
      const combined = matched.flatMap((g) => g.alerts || []);
      const tenants = new Set(matched.map((g) => normalizeTenantScope(g.tenant_mapped || '')).filter(Boolean));
      const inferredTenant = explicitTenant || (tenants.size === 1 ? [...tenants][0] : '');
      return {
        alerts: combined,
        tenant: inferredTenant,
        fallbackTitle: matched[0]?.incident_title || '',
      };
    }
    throw Object.assign(new Error('groupId, groupIds, atau rawAlerts wajib diisi.'), { status: 400 });
  }

  function suggestExclusionRules(opts = {}) {
    const { alerts, tenant, fallbackTitle } = resolveAlertsForExclusionRequest(opts);
    const rules = deriveExclusionRulesFromAlerts(alerts, fallbackTitle, tenant);
    return {
      ok: true,
      tenant,
      title: fallbackTitle,
      alertCount: alerts.length,
      rules,
    };
  }

  async function aiSuggestExclusionRules(opts = {}) {
    const { alerts, tenant, fallbackTitle } = resolveAlertsForExclusionRequest(opts);
    const o = config.ollama || {};
    const baseUrl = String(o.baseUrl || '').trim().replace(/\/+$/, '');
    if (!baseUrl) {
      throw Object.assign(new Error('Ollama Base URL belum dikonfigurasi.'), { status: 400 });
    }

    const seenSample = new Set();
    const compactSamples = [];
    for (const al of alerts) {
      const raw = al?.raw_wazuh_alert || {};
      const sampleTenant = tenant || normalizeTenantScope(
        resolveTenant(raw, config.wazuh.tenantMapping, getKnownTenants()),
      );
      const sample = {
        tenant: sampleTenant,
        path: extractPathCandidates(raw)[0] || '',
        filename: extractFilenameCandidates(raw)[0] || '',
        rule_id: String(raw.rule?.id || ''),
        rule_description: String(raw.rule?.description || ''),
        http_status: extractHttpStatus(raw),
        agent_name: String(raw.agent?.name || ''),
        src_ip: extractSrcIp(raw),
        user_agent: extractUserAgent(raw).slice(0, 100),
        referer: extractReferer(raw).slice(0, 120),
        full_log: String(raw.full_log || '').slice(0, 220),
      };
      const fp = `${sample.tenant}|${sample.rule_id}|${sample.http_status}|${normalizePath(sample.path)}|${sample.filename}|${sample.full_log.slice(0, 60)}`;
      if (seenSample.has(fp)) continue;
      seenSample.add(fp);
      compactSamples.push(sample);
      if (compactSamples.length >= 12) break;
    }

    const sysPrompt = [
      'Anda adalah Analis SOC Senior yang bertugas merancang aturan Exclusion Whitelist Wazuh yang presisi dengan Multi-Condition Locking (AND logic) agar trafik jinak (False Positive) tersaring sebelum ke AI, TANPA membuka blind spot terhadap eksploitasi.',
      'Target utama yang tersedia:',
      '- path: URL / Request path (sertakan query parameter aman jika relevan, mis. *wsfunction=core_course_view_course*)',
      '- filename: nama file atau path file (mis. syscheck / laravel.log / *.tmp)',
      '- rule_description: teks deskripsi rule Wazuh',
      '- rule_id: ID rule Wazuh (mis. 31151)',
      '- http_status: kode status HTTP (mis. 200, 303, 419)',
      '- src_ip: IP sumber internal/gateway tepercaya',
      '- agent_name: nama host/agent tertentu',
      '- user_agent: string HTTP User-Agent',
      '- referer: URL Referer HTTP',
      '- full_log: substring / pola pada full_log',
      'Aturan KEAMANAN PENGUNCIAN WAJIB:',
      '1. Kunci `tenant` ke tenant asal insiden (jangan kosong/global kecuali aturan memang lintas tenant).',
      '2. Kunci `ruleIds` HANYA ke rule berbasis frekuensi (mis. 31151, 31153, 31154). DILARANG KERAS mengecualikan rule signature serangan (31103 SQLi, 31104 Path Traversal, 31105 XSS, 31106 Command Injection, 31109, 31110).',
      '3. Untuk path sensitif seperti endpoint autentikasi (/login), REST/RPC API (/api/*, /webservice/*), atau endpoint form dinamis, WAJIB isi syarat pengunci AND (`httpStatuses`, `srcIps` gateway internal, `userAgent` klien resmi, atau `referer` domain internal) dan gunakan * untuk ID/parameter dinamis.',
      '4. LARANGAN KERAS: JANGAN buat pola terlalu umum seperti "/", "/*", "/service/", "/service/*", atau "/api/" tanpa syarat pengunci.',
      'Mode pencocokan: wildcard (pakai *), contains, starts_with, regex. Keluarkan JSON valid sesuai schema dengan reasoning singkat dalam Bahasa Indonesia.',
    ].join('\n');

    const userPrompt = [
      `Tenant target: ${tenant || 'global'}`,
      `Judul insiden: ${fallbackTitle || '—'}`,
      `Total alert: ${alerts.length}`,
      'Sampel alert unik:',
      JSON.stringify(compactSamples),
    ].join('\n');

    const res = await withOllamaLock(() => requestJson(baseUrl + '/api/chat', {
      method: 'POST',
      timeoutMs: (Number(o.timeoutSec) || 90) * 1000,
      body: {
        model: o.model,
        stream: false,
        think: Boolean(o.think),
        keep_alive: String(o.keepAlive || '2m'),
        format: o.useJsonSchema === false ? 'json' : EXCLUSION_SUGGEST_SCHEMA,
        options: {
          temperature: Number(o.temperature ?? 0.1),
          num_ctx: Math.min(Number(o.numCtx || 12288), 16384),
          num_predict: Math.min(Number(o.numPredict || 4096), 4096),
          top_p: Number(o.topP ?? 0.85),
          top_k: Number(o.topK ?? 20),
          repeat_penalty: Number(o.repeatPenalty ?? 1.05),
        },
        messages: [
          { role: 'system', content: sysPrompt },
          { role: 'user', content: userPrompt },
        ],
      },
    }));

    const content = res.json?.message?.content ?? res.json?.response ?? '';
    const parsed = parseJsonFromAiText(content);
    const rawRules = Array.isArray(parsed?.rules) ? parsed.rules : [];
    const cleaned = [];
    const seenKeys = new Set();
    for (let i = 0; i < rawRules.length; i++) {
      const san = sanitizeExclusionRule({
        ...rawRules[i],
        tenant: rawRules[i]?.tenant || tenant,
        enabled: true,
        source: 'ai_suggest',
      }, i);
      if (!san || !san.pattern) continue;
      if (san.target === 'path' && isOverlyBroadPathPattern(san.pattern)) continue;
      const dedupKey = exclusionDedupKey(san);
      if (seenKeys.has(dedupKey)) continue;
      seenKeys.add(dedupKey);
      cleaned.push(san);
    }

    return {
      ok: true,
      tenant,
      reasoning: String(parsed?.reasoning || 'Saran exclusion dihasilkan oleh AI berdasarkan pola sampel alert.').trim(),
      rules: cleaned.length ? cleaned : deriveExclusionRulesFromAlerts(alerts, fallbackTitle, tenant),
    };
  }

  function ignoreAndExcludeGroups(opts = {}) {
    const res = ignoreAndExcludeInList(state.groups, opts, { isQueue: true });
    state.groups = res.nextList;
    saveState();
    broadcastSse('state', getQueueSnapshot());
    return {
      ok: true,
      rulesAdded: res.rulesAdded,
      rulesExisting: res.rulesExisting,
      removedGroups: res.removedGroups,
      removedAlerts: res.removedAlerts,
      groupRemoved: res.groupRemoved,
      exclusionRules: cloneJson(config.exclusionRules),
      snapshot: getQueueSnapshot(),
    };
  }

  function dismissGroups(opts = {}) {
    const { toRemove, remaining } = dismissGroupsInList(state.groups, opts);
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
    pollEpoch++;
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
    if (doClearState) pollEpoch++;
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

  function buildPromotePackage(groupList, payload = {}, user = null) {
    const groupId = String(payload.groupId || '').trim();
    const wantedAlertIds = Array.isArray(payload.alertIds) && payload.alertIds.length
      ? new Set(payload.alertIds.map((x) => String(x || '').trim()).filter(Boolean))
      : null;

    let resolvedTenant = String(payload.tenant || '').trim();
    let incidentTitle = String(payload.incidentTitle || '').trim();
    let aiVerdict = String(payload.aiVerdict || 'MANUAL_PROMOTE').trim();
    let alertWrappers = [];

    if (groupId) {
      const grp = groupList.find((g) => g.group_id === groupId);
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

    return {
      groupId,
      resolvedTenant,
      incidentTitle,
      chunks,
      wazuhAlertIds,
      nowIso,
      historyEntry,
    };
  }

  function promoteToCase(payload = {}, user = null) {
    const {
      groupId,
      resolvedTenant,
      incidentTitle,
      chunks,
      wazuhAlertIds,
      nowIso,
      historyEntry,
    } = buildPromotePackage(state.groups, payload, user);

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

  /* ---------------- Isolated 24h Batch Pull & Progress Job ---------------- */

  function startBatch24hPull(opts = {}) {
    if (!String(config.wazuh.url || '').trim()) {
      throw Object.assign(new Error('Wazuh Indexer URL belum dikonfigurasi.'), { status: 400 });
    }
    if (batch24h.job.running) {
      throw Object.assign(new Error('Penarikan 24 Jam sedang berjalan. Tunggu selesai atau klik Batalkan.'), { status: 409 });
    }
    const range = String(opts?.range || '24h').trim() || '24h';
    const win = resolvePollWindow({ range, from: opts?.from, to: opts?.to });
    const maxSize = Math.min(Math.max(10, Number(opts?.size) || 500), 1000);
    const tenantFilter = String(opts?.tenantFilter || '').trim();

    batch24hEpoch++;
    const runEpoch = batch24hEpoch;

    batch24h.groups = [];
    batch24h.job = {
      running: true,
      phase: 'fetching',
      percent: 5,
      message: 'Menarik alert dari Wazuh Indexer…',
      range,
      sinceIso: win.sinceIso,
      untilIso: win.untilIso,
      fetchedCount: 0,
      excludedCount: 0,
      totalCandidates: 0,
      processedChunks: 0,
      totalChunks: 0,
      currentTenant: tenantFilter || null,
      startedAt: new Date().toISOString(),
      finishedAt: null,
      error: null,
    };
    saveBatch24h();
    broadcastSse('batch24h', getBatch24hSnapshot());

    void (async () => {
      try {
        const { hits } = await queryWazuhAlerts({
          sinceIso: win.sinceIso,
          untilIso: win.untilIso,
          inclusiveSince: true,
          size: maxSize,
          minLevel: config.wazuh.minRuleLevel,
          maxLevel: config.wazuh.maxRuleLevel,
        });
        if (runEpoch !== batch24hEpoch) return;

        batch24h.job.phase = 'grouping';
        batch24h.job.percent = 20;
        batch24h.job.fetchedCount = hits.length;
        batch24h.job.message = `Mengelompokkan ${hits.length} alert…`;
        broadcastSse('batch24h', getBatch24hSnapshot());

        const { excludedCount, byTenantBuckets } = preGroupByTenant(hits, {
          skipSeen: false,
          mutateExclusions: false,
          tenantFilter,
        });
        if (runEpoch !== batch24hEpoch) return;

        const batchSize24 = Math.max(1, Math.min(30, Number(config.ollama?.microBatchSize || OLLAMA_MICRO_BATCH_SIZE)));
        let totalCandidates = 0;
        let totalChunks = 0;
        for (const bucketMap of byTenantBuckets.values()) {
          const n = bucketMap.size;
          if (n > 0) {
            totalCandidates += n;
            totalChunks += Math.ceil(n / batchSize24);
          }
        }

        batch24h.job.excludedCount = excludedCount;
        batch24h.job.totalCandidates = totalCandidates;
        batch24h.job.totalChunks = totalChunks;

        if (totalChunks === 0) {
          batch24h.job.running = false;
          batch24h.job.phase = 'done';
          batch24h.job.percent = 100;
          batch24h.job.currentTenant = null;
          batch24h.job.finishedAt = new Date().toISOString();
          batch24h.job.message = `Selesai · 0 kandidat dari ${hits.length} alert (Excluded: ${excludedCount})`;
          saveBatch24h();
          broadcastSse('batch24h', getBatch24hSnapshot());
          return;
        }

        batch24h.job.phase = 'analyzing';
        batch24h.job.percent = 25;
        batch24h.job.message = `Menganalisis AI (${totalChunks} batch, ${totalCandidates} kandidat)…`;
        broadcastSse('batch24h', getBatch24hSnapshot());

        const { aborted } = await runAiOnTenantBuckets(byTenantBuckets, {
          isAborted: () => runEpoch !== batch24hEpoch,
          getExistingGroupKeys: (tenant) =>
            [...new Set(batch24h.groups.filter((g) => g.tenant_mapped === tenant && g.group_key).map((g) => g.group_key))].slice(0, 20),
          onChunkProgress: ({ tenant, processedChunks }) => {
            if (runEpoch !== batch24hEpoch) return;
            batch24h.job.processedChunks = processedChunks;
            batch24h.job.currentTenant = tenant;
            batch24h.job.percent = 25 + Math.round((processedChunks / Math.max(1, totalChunks)) * 70);
            batch24h.job.message = `Menganalisis AI batch ${processedChunks}/${totalChunks} (tenant: ${tenant})…`;
            broadcastSse('batch24h', getBatch24hSnapshot());
          },
          onTenantMerged: ({ groupPayloads }) => {
            if (runEpoch !== batch24hEpoch) return;
            appendSemanticGroupsToList(batch24h.groups, groupPayloads);
            broadcastSse('batch24h', getBatch24hSnapshot());
          },
        });
        if (aborted || runEpoch !== batch24hEpoch) return;

        batch24h.job.running = false;
        batch24h.job.phase = 'done';
        batch24h.job.percent = 100;
        batch24h.job.currentTenant = null;
        batch24h.job.finishedAt = new Date().toISOString();
        batch24h.job.message = `Selesai · ${batch24h.groups.length} grup dari ${hits.length} alert (Excluded: ${excludedCount})`;
        saveBatch24h();
        broadcastSse('batch24h', getBatch24hSnapshot());
      } catch (err) {
        if (runEpoch !== batch24hEpoch) return;
        batch24h.job.running = false;
        batch24h.job.phase = 'error';
        batch24h.job.error = err.message || 'Gagal menarik 24 jam';
        batch24h.job.currentTenant = null;
        batch24h.job.finishedAt = new Date().toISOString();
        batch24h.job.message = `Gagal: ${batch24h.job.error}`;
        saveBatch24h();
        broadcastSse('batch24h', getBatch24hSnapshot());
      }
    })();

    return { ok: true, started: true, snapshot: getBatch24hSnapshot() };
  }

  function cancelBatch24hPull() {
    batch24hEpoch++;
    batch24h.job.running = false;
    batch24h.job.phase = 'cancelled';
    batch24h.job.currentTenant = null;
    batch24h.job.finishedAt = new Date().toISOString();
    batch24h.job.message = 'Penarikan dibatalkan oleh analis';
    saveBatch24h();
    broadcastSse('batch24h', getBatch24hSnapshot());
    return { ok: true, snapshot: getBatch24hSnapshot() };
  }

  function clearBatch24h() {
    batch24hEpoch++;
    const clearedGroups = batch24h.groups.length;
    batch24h = defaultBatch24hState();
    saveBatch24h();
    broadcastSse('batch24h', getBatch24hSnapshot());
    return { ok: true, clearedGroups, snapshot: getBatch24hSnapshot() };
  }

  function mergeBatch24hGroups(groupIds = []) {
    const { nextList, base } = mergeGroupsInList(batch24h.groups, groupIds);
    batch24h.groups = nextList;
    saveBatch24h();
    broadcastSse('batch24h', getBatch24hSnapshot());
    return { ok: true, group: base, snapshot: getBatch24hSnapshot() };
  }

  function splitBatch24hAlerts(opts = {}) {
    const { nextList, sourceGroup, newGroup } = splitGroupAlertsInList(batch24h.groups, opts);
    batch24h.groups = nextList;
    saveBatch24h();
    broadcastSse('batch24h', getBatch24hSnapshot());
    return { ok: true, sourceGroup, newGroup, snapshot: getBatch24hSnapshot() };
  }

  function removeBatch24hAlerts(opts = {}) {
    const { nextList, removed, groupRemoved, group } = removeAlertsFromGroupInList(batch24h.groups, opts);
    batch24h.groups = nextList;
    saveBatch24h();
    broadcastSse('batch24h', getBatch24hSnapshot());
    return {
      ok: true,
      removedCount: removed.length,
      groupRemoved,
      group,
      snapshot: getBatch24hSnapshot(),
    };
  }

  function dismissBatch24hGroups(opts = {}) {
    const { toRemove, remaining } = dismissGroupsInList(batch24h.groups, opts);
    batch24h.groups = remaining;
    saveBatch24h();
    broadcastSse('batch24h', getBatch24hSnapshot());
    return {
      ok: true,
      dismissedGroups: toRemove.length,
      snapshot: getBatch24hSnapshot(),
    };
  }

  function ignoreAndExcludeBatch24h(opts = {}) {
    const res = ignoreAndExcludeInList(batch24h.groups, opts, { isQueue: false });
    batch24h.groups = res.nextList;
    saveBatch24h();
    broadcastSse('batch24h', getBatch24hSnapshot());
    return {
      ok: true,
      rulesAdded: res.rulesAdded,
      rulesExisting: res.rulesExisting,
      removedGroups: res.removedGroups,
      removedAlerts: res.removedAlerts,
      groupRemoved: res.groupRemoved,
      exclusionRules: cloneJson(config.exclusionRules),
      snapshot: getBatch24hSnapshot(),
    };
  }

  function promoteBatch24hToCase(payload = {}, user = null) {
    const {
      groupId,
      resolvedTenant,
      incidentTitle,
      chunks,
      wazuhAlertIds,
      historyEntry,
    } = buildPromotePackage(batch24h.groups, payload, user);

    if (groupId) {
      const grp = batch24h.groups.find((g) => g.group_id === groupId);
      if (grp) {
        const promotedSet = new Set(wazuhAlertIds);
        grp.alerts = (grp.alerts || []).filter((a) => !promotedSet.has(a.alert_id));
        if (grp.alerts.length === 0) {
          batch24h.groups = batch24h.groups.filter((g) => g.group_id !== groupId);
        } else {
          recomputeGroupMetadata(grp);
        }
      }
    }

    saveBatch24h();
    broadcastSse('batch24h', getBatch24hSnapshot());
    broadcastSse('state', getQueueSnapshot());

    return {
      ok: true,
      tenant: resolvedTenant,
      incidentTitle,
      chunkCount: chunks.length,
      chunks,
      historyEntry,
      snapshot: getBatch24hSnapshot(),
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
    listExclusionRules,
    addExclusionRule,
    updateExclusionRule,
    deleteExclusionRule,
    suggestExclusionRules,
    aiSuggestExclusionRules,
    testWazuhConnection,
    testOllamaConnection,
    queryWazuhAlerts,
    fetchWazuhByIds,
    evaluateExclusions,
    resolveTenant,
    pollOnce,
    getQueueSnapshot,
    getTriageStats,
    getLiveFeed,
    subscribeSse,
    mergeGroups,
    splitGroupAlerts,
    removeAlertsFromGroup,
    dismissGroups,
    ignoreAndExcludeGroups,
    resetQueue,
    purgeTriageDatabase,
    promoteToCase,
    getBatch24hSnapshot,
    startBatch24hPull,
    cancelBatch24hPull,
    clearBatch24h,
    mergeBatch24hGroups,
    splitBatch24hAlerts,
    removeBatch24hAlerts,
    dismissBatch24hGroups,
    ignoreAndExcludeBatch24h,
    promoteBatch24hToCase,
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
  VALID_EXCLUSION_TARGETS,
  VALID_EXCLUSION_MODES,
  evaluateExclusions,
  deriveExclusionRuleFromAlerts,
  deriveExclusionRulesFromAlerts,
  normalizePath,
  resolveTenant,
  severityLabel,
  chunkAlertsForPromote,
};

