/* Diptera Unified — Multi-form SOC/ASOC intake untuk Alpha Reporter v2 & Charlie Reporter (n8n).
 * Fitur:
 *   - 1 platform dengan 2 workspace terisolasi: ASOC (Alpha Reporter) & SOC (Charlie Reporter)
 *   - Shared server-side counters & Riwayat Bersama terpisah per workspace
 *   - Auto-increment antrean nomor tiket per tenant (ASOC & SOC) + Case ID global (SOC)
 *   - ASOC: Auto-IRIS Case ID, Mode Reporting vs Mode Repeating, dual polling + callback
 *   - SOC: Manual Case ID (#1001 -> #1002), payload 4-field kompatibel Charlie Reporter
 */
'use strict';

(function () {
  const X = window.IrisExtract || {};
  const N = window.IrisNumbering || {};
  const STORAGE_KEY = 'diptera.unified.v3';
  const CONFIG = window.DIPTERA_CONFIG || {};

  const WORKSPACE_META = {
    asoc: {
      code: 'ASOC',
      subtitle: 'Alpha Reporter',
      defaultBaseUrl: 'http://10.20.100.65:5678',
      defaultFormPath: 'alpha-form',
      defaultIrisBaseUrl: 'https://10.20.100.66',
      defaultCaseIdMode: 'auto_iris',
      defaultTenants: ['wicida', 'instikibali', 'petra', 'praditauniversity', 'sgu', 'ikmicirebon'],
      hasRepeating: true,
      hasIrisAuto: true,
    },
    soc: {
      code: 'SOC',
      subtitle: 'Charlie Reporter',
      defaultBaseUrl: 'http://10.20.100.134:5678',
      defaultFormPath: 'Job-Creator',
      defaultIrisBaseUrl: '',
      defaultCaseIdMode: 'manual',
      defaultTenants: ['petra', 'praditauniversity', 'wicida', 'instikibali', 'ikmicirebon', 'sgu'],
      hasRepeating: false,
      hasIrisAuto: false,
    },
  };

  const REPEAT_PRESETS = {
    md_only: {
      createIrisCase: false,
      updateIrisSummary: false,
      requireApproval: false,
      sendEmailPdf: false,
      uploadGdoc: false,
      appendSheet: false,
      returnMarkdown: true,
    },
    gdoc_sheet: {
      createIrisCase: false,
      updateIrisSummary: false,
      requireApproval: false,
      sendEmailPdf: false,
      uploadGdoc: true,
      appendSheet: true,
      returnMarkdown: true,
    },
    update_iris: {
      createIrisCase: false,
      updateIrisSummary: true,
      requireApproval: true,
      sendEmailPdf: true,
      uploadGdoc: true,
      appendSheet: true,
      returnMarkdown: true,
    },
  };

  function isLocalPage() {
    const host = String(window.location.hostname || '').toLowerCase();
    return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]' || host === '0.0.0.0';
  }

  function guessBaseUrl() {
    try {
      const loc = window.location;
      if (!loc.hostname || isLocalPage()) return 'http://localhost:5678';
      return (loc.protocol === 'https:' ? 'https://' : 'http://') + loc.hostname + ':5678';
    } catch {
      return 'http://localhost:5678';
    }
  }

  function wsServerCfg(ws) {
    if (CONFIG.workspaces && CONFIG.workspaces[ws]) return CONFIG.workspaces[ws];
    return ws === 'asoc' ? CONFIG : {};
  }

  function buildDefaultFields(ws) {
    const sc = wsServerCfg(ws);
    const meta = WORKSPACE_META[ws];
    const tenants = Array.isArray(sc.tenantOptions) && sc.tenantOptions.length ? sc.tenantOptions : meta.defaultTenants;
    return [
      {
        key: 'field-0',
        label: 'Nomor Tiket IRIS (Opsional)',
        type: 'text',
        placeholder: ws === 'soc' ? 'Mis. 10101' : 'Mis. 30073',
        role: 'ticket',
      },
      {
        key: 'field-1',
        label: 'Tenant / Organisasi',
        type: 'select',
        options: tenants.slice(),
        role: 'tenant',
      },
      {
        key: 'field-2',
        label: 'IRIS Case ID',
        type: 'text',
        required: ws === 'soc',
        placeholder: 'Contoh: #412',
        role: 'caseId',
      },
      {
        key: 'field-3',
        label: 'Raw Alert JSON',
        type: 'textarea',
        required: true,
        json: true,
        placeholder: 'Tempel satu/beberapa alert JSON (NDJSON juga boleh) atau respons OpenSearch hits.hits.',
        role: 'alert',
      },
    ];
  }

  function buildDefaultSettings(ws) {
    const sc = wsServerCfg(ws);
    const meta = WORKSPACE_META[ws];
    const baseUrl = (typeof sc.baseUrl === 'string' && sc.baseUrl.trim())
      ? sc.baseUrl.trim().replace(/\/+$/, '')
      : meta.defaultBaseUrl;
    const formPath = (typeof sc.formPath === 'string' && sc.formPath.trim())
      ? sc.formPath.trim()
      : meta.defaultFormPath;
    const irisBaseUrl = (typeof sc.irisBaseUrl === 'string' && sc.irisBaseUrl.trim())
      ? sc.irisBaseUrl.trim().replace(/\/+$/, '')
      : meta.defaultIrisBaseUrl;
    const caseIdMode = meta.hasIrisAuto
      ? (sc.caseIdMode === 'manual' ? 'manual' : 'auto_iris')
      : 'manual';

    return {
      baseUrl,
      formPath,
      irisBaseUrl,
      caseIdMode,
      submitMode: 'sequential',
      timeoutMin: 30,
      autoCollapse: true,
      autoResume: true,
      rewriteHost: true,
      desktopNotify: false,
      autoNumber: true,
      fields: buildDefaultFields(ws),
    };
  }

  function buildInitialWorkspaceState(ws) {
    const sc = wsServerCfg(ws);
    const meta = WORKSPACE_META[ws];
    return {
      activeMode: 'reporting',
      repeatOptions: clone(REPEAT_PRESETS.md_only),
      settings: buildDefaultSettings(ws),
      counters: {
        lastIrisCaseId: sc.initialCaseId || null,
        ticketsByTenant: clone(sc.initialTickets || {}),
        tenants: Array.isArray(sc.tenantOptions) && sc.tenantOptions.length
          ? sc.tenantOptions.slice()
          : meta.defaultTenants.slice(),
        updatedAt: null,
      },
      cards: [],
      submitAllRunning: false,
    };
  }

  const STATUS_LABEL = {
    idle: 'Menunggu',
    queued: 'Antrian',
    running: 'Diproses',
    awaiting_approval: 'Menunggu Approval',
    done: 'Selesai',
    error: 'Gagal',
  };

  /* ---------------- Util ---------------- */

  const $ = (sel, root = document) => root.querySelector(sel);
  const esc = (v) =>
    String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const uid = () => 'c_' + Math.random().toString(36).slice(2, 9) + Date.now().toString(36).slice(-4);
  function clone(v) { return JSON.parse(JSON.stringify(v)); }
  const joinUrl = (base, p) => String(base || '').replace(/\/+$/, '') + p;
  const safeJson = (text) => { try { return JSON.parse(text); } catch { return null; } };
  const sleep = (ms, signal) =>
    new Promise((resolve, reject) => {
      const t = setTimeout(resolve, ms);
      if (signal) {
        const onAbort = () => { clearTimeout(t); reject(new DOMException('Dibatalkan', 'AbortError')); };
        if (signal.aborted) onAbort();
        else signal.addEventListener('abort', onAbort, { once: true });
      }
    });
  const abortErr = () => new DOMException('Dibatalkan', 'AbortError');

  function fmtDuration(ms) {
    if (!Number.isFinite(ms) || ms < 0) return '';
    const s = Math.round(ms / 1000);
    if (s < 60) return s + 'd';
    const m = Math.floor(s / 60);
    return m + 'm ' + (s % 60) + 'd';
  }

  function fmtWib(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return String(iso);
    const wib = new Date(d.getTime() + 7 * 3600 * 1000);
    const p = (n) => String(n).padStart(2, '0');
    return `${p(wib.getUTCDate())}/${p(wib.getUTCMonth() + 1)} ${p(wib.getUTCHours())}:${p(wib.getUTCMinutes())}`;
  }

  function cleanCaseIdDigits(val) {
    return String(val ?? '').trim().replace(/^#+/, '').trim();
  }

  function formatCaseIdBadge(val) {
    const d = cleanCaseIdDigits(val);
    return d ? '#' + d : '—';
  }

  function effectiveCallbackUrl(ws = 'asoc') {
    const sc = wsServerCfg(ws);
    if (sc && typeof sc.callbackUrl === 'string' && sc.callbackUrl.trim()) {
      return sc.callbackUrl.trim();
    }
    return window.location.origin + '/api/n8n-callback';
  }

  function irisCaseLink(caseId, ws = state.activeWorkspace) {
    const d = cleanCaseIdDigits(caseId);
    if (!d) return null;
    const base = String(wsState(ws).settings.irisBaseUrl || '').trim().replace(/\/+$/, '');
    return base ? (base + '/case?cid=' + encodeURIComponent(d)) : null;
  }

  async function copyText(text, label) {
    const str = String(text ?? '');
    if (!str) return false;
    let ok = false;
    if (navigator?.clipboard?.writeText) {
      try {
        await navigator.clipboard.writeText(str);
        ok = true;
      } catch {}
    }
    if (!ok) {
      try {
        const ta = document.createElement('textarea');
        ta.value = str;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        ok = document.execCommand('copy');
        document.body.removeChild(ta);
      } catch {}
    }
    if (ok) toast({ type: 'success', title: (label || 'Teks') + ' disalin', body: str.length > 80 ? str.slice(0, 77) + '…' : str });
    else toast({ type: 'error', title: 'Gagal menyalin', body: 'Silakan salin manual dari kotak teks.' });
    return ok;
  }

  /* ---------------- JSON inspector (advisory) ---------------- */

  function inspectJson(text) {
    const s = String(text ?? '').trim();
    if (!s) return { state: 'empty', msg: '' };
    try {
      const v = JSON.parse(s);
      const count = Array.isArray(v) ? v.length : Array.isArray(v?.hits?.hits) ? v.hits.hits.length : 1;
      return { state: 'ok', msg: `JSON valid (${count} alert · ${(s.length / 1024).toFixed(1)} KB)` };
    } catch {
      const lines = s.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      let okLines = 0;
      for (const l of lines) { try { JSON.parse(l); okLines++; } catch {} }
      if (okLines > 1) return { state: 'ok', msg: `NDJSON (${okLines} objek · ${(s.length / 1024).toFixed(1)} KB)` };
      if (/\{[\s\S]*\}/.test(s)) return { state: 'warn', msg: `JSON longgar / teks campuran (${(s.length / 1024).toFixed(1)} KB) — tetap bisa dikirim` };
      return { state: 'warn', msg: 'Bukan JSON standar — tetap bisa dikirim apa adanya ke n8n' };
    }
  }

  /* ---------------- State ---------------- */

  const defaultWs = CONFIG.defaultWorkspace === 'soc' ? 'soc' : 'asoc';
  let state = {
    activeWorkspace: defaultWs,
    settingsWorkspace: defaultWs,
    historyWorkspace: defaultWs,
    view: 'queue',
    serverOnline: false,
    workspaces: {
      asoc: buildInitialWorkspaceState('asoc'),
      soc: buildInitialWorkspaceState('soc'),
    },
    history: [],
    historyCounts: { asoc: 0, soc: 0 },
    expandedHistoryId: null,
  };

  let persistTimer = null;
  let sharedPollTimer = null;
  let ticketPropagateTimer = null;
  const refs = new Map();

  const wsState = (ws = state.activeWorkspace) => state.workspaces[ws === 'soc' ? 'soc' : 'asoc'];

  function normalizeCard(raw, ws = 'asoc') {
    const meta = WORKSPACE_META[ws];
    const mode = meta.hasRepeating && raw.mode === 'repeating' ? 'repeating' : 'reporting';
    const card = {
      id: raw.id || uid(),
      workspace: ws,
      mode,
      repeatOptions: mode === 'repeating'
        ? { ...clone(REPEAT_PRESETS.md_only), ...(raw.repeatOptions || {}) }
        : null,
      forceManualCaseId: Boolean(raw.forceManualCaseId),
      values: raw.values && typeof raw.values === 'object' ? { ...raw.values } : {},
      status: raw.status || 'idle',
      collapsed: Boolean(raw.collapsed),
      ticketAuto: Boolean(raw.ticketAuto),
      ticketFor: raw.ticketFor || '',
      caseIdAuto: Boolean(raw.caseIdAuto),
      busy: false,
      abort: null,
      historyId: raw.historyId || null,
      waitingUrl: raw.waitingUrl || null,
      execId: raw.execId || null,
      irisCaseId: raw.irisCaseId || null,
      nsStatus: raw.nsStatus || null,
      resumed: Boolean(raw.resumed),
      startedAt: raw.startedAt || null,
      elapsedMs: raw.elapsedMs ?? null,
      result: raw.result || null,
      errorMsg: raw.errorMsg || null,
      errorHint: raw.errorHint || null,
      errorDetail: raw.errorDetail || null,
    };
    if (card.status === 'running' || card.status === 'queued') {
      if (!card.waitingUrl && !card.historyId) {
        card.status = 'error';
        card.errorMsg = 'Terputus saat halaman dimuat ulang';
      }
    }
    return card;
  }

  function loadLocalState() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const saved = JSON.parse(raw);
      if (saved.activeWorkspace === 'soc' || saved.activeWorkspace === 'asoc') {
        state.activeWorkspace = saved.activeWorkspace;
        state.settingsWorkspace = saved.activeWorkspace;
        state.historyWorkspace = saved.activeWorkspace;
      }
      for (const ws of ['asoc', 'soc']) {
        const sWs = saved.workspaces?.[ws];
        if (!sWs) continue;
        const target = state.workspaces[ws];
        const defSet = buildDefaultSettings(ws);
        if (sWs.settings && typeof sWs.settings === 'object') {
          target.settings = {
            ...defSet,
            ...sWs.settings,
            fields: Array.isArray(sWs.settings.fields) && sWs.settings.fields.length
              ? sWs.settings.fields
              : defSet.fields,
          };
          if (!WORKSPACE_META[ws].hasIrisAuto) target.settings.caseIdMode = 'manual';
        }
        if (WORKSPACE_META[ws].hasRepeating && sWs.activeMode === 'repeating') {
          target.activeMode = 'repeating';
        }
        if (sWs.repeatOptions && typeof sWs.repeatOptions === 'object') {
          target.repeatOptions = { ...clone(REPEAT_PRESETS.md_only), ...sWs.repeatOptions };
        }
        if (Array.isArray(sWs.cards)) {
          target.cards = sWs.cards.map((c) => normalizeCard(c, ws));
        }
      }
    } catch {}
  }

  function serializeWorkspace(ws) {
    const w = state.workspaces[ws];
    return {
      activeMode: w.activeMode,
      repeatOptions: w.repeatOptions,
      settings: w.settings,
      cards: w.cards.map((c) => ({
        id: c.id,
        workspace: ws,
        mode: c.mode,
        repeatOptions: c.repeatOptions,
        forceManualCaseId: c.forceManualCaseId,
        values: c.values,
        status: c.status,
        collapsed: c.collapsed,
        ticketAuto: c.ticketAuto,
        ticketFor: c.ticketFor,
        caseIdAuto: c.caseIdAuto,
        historyId: c.historyId,
        waitingUrl: c.waitingUrl,
        execId: c.execId,
        irisCaseId: c.irisCaseId,
        nsStatus: c.nsStatus,
        resumed: c.resumed,
        startedAt: c.startedAt,
        elapsedMs: c.elapsedMs,
        result: c.result,
        errorMsg: c.errorMsg,
        errorHint: c.errorHint,
        errorDetail: c.errorDetail,
      })),
    };
  }

  function persist() {
    clearTimeout(persistTimer);
    persistTimer = setTimeout(flushPersist, 350);
  }

  function flushPersist() {
    clearTimeout(persistTimer);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({
        activeWorkspace: state.activeWorkspace,
        workspaces: {
          asoc: serializeWorkspace('asoc'),
          soc: serializeWorkspace('soc'),
        },
      }));
    } catch {}
  }

  /* ---------------- Server API (Dual-Workspace Counters & History) ---------------- */

  async function apiFetch(path, opts = {}) {
    const res = await fetch(path, {
      ...opts,
      headers: { 'content-type': 'application/json', ...(opts.headers || {}) },
    });
    const text = await res.text();
    const json = safeJson(text);
    if (!res.ok) throw new Error(json?.error || ('HTTP ' + res.status));
    return json;
  }

  async function fetchSharedState(silent = false) {
    try {
      const data = await apiFetch('/api/state');
      state.serverOnline = true;
      for (const ws of ['asoc', 'soc']) {
        const wsData = data?.workspaces?.[ws];
        if (wsData?.counters) {
          state.workspaces[ws].counters = wsData.counters;
          applyTenantsFromServer(ws);
        }
        if (typeof wsData?.historyCount === 'number') {
          state.historyCounts[ws] = wsData.historyCount;
        }
      }
      renderSharedBar();
      updateHistoryTabCounts();
      recomputeQueueTickets(state.activeWorkspace, { noPersist: true });
      if (!silent) populateHistoryTenantFilter();
    } catch {
      state.serverOnline = false;
      renderSharedBar();
    }
  }

  function applyTenantsFromServer(ws) {
    const w = wsState(ws);
    const serverTenants = Array.isArray(w.counters.tenants) ? w.counters.tenants : [];
    if (!serverTenants.length) return;
    const tenantField = w.settings.fields.find((f) => f.role === 'tenant');
    if (tenantField) {
      tenantField.options = Array.from(new Set([...serverTenants, ...(tenantField.options || [])]));
    }
    if (ws !== state.activeWorkspace) return;
    populateHistoryTenantFilter();
    for (const card of w.cards) {
      const r = refs.get(card.id);
      const tField = w.settings.fields.find((f) => f.role === 'tenant');
      if (r && tField && r.inputs[tField.key]) {
        const sel = r.inputs[tField.key];
        const cur = card.values[tField.key] || '';
        const existing = Array.from(sel.options).map((o) => o.value);
        const wanted = ['', ...(tField.options || [])];
        if (existing.join('|') !== wanted.join('|')) {
          sel.innerHTML = '<option value="">— Pilih tenant —</option>' +
            (tField.options || []).map((t) => `<option value="${esc(t)}">${esc(t)}</option>`).join('');
          sel.value = cur;
        }
      }
    }
  }

  function updateHistoryTabCounts() {
    const activeWs = state.activeWorkspace;
    $('#tab-history-label').textContent = 'Riwayat ' + WORKSPACE_META[activeWs].code;
    $('#tab-history-count').textContent = String(state.historyCounts[activeWs] ?? 0);
    $('#hist-count-asoc').textContent = String(state.historyCounts.asoc ?? 0);
    $('#hist-count-soc').textContent = String(state.historyCounts.soc ?? 0);
  }

  function renderSharedBar() {
    const ws = state.activeWorkspace;
    const w = wsState(ws);
    const meta = WORKSPACE_META[ws];
    const caseEl = $('#shared-last-case');
    const ticketsEl = $('#shared-tickets');
    const syncEl = $('#shared-sync-status');

    $('#shared-ws-badge').textContent = meta.code;
    $('#shared-case-label').textContent = ws === 'asoc' ? 'Last IRIS Case' : 'Last Case ID';

    const lastCase = w.counters.lastIrisCaseId;
    if (lastCase) {
      const href = irisCaseLink(lastCase, ws);
      caseEl.innerHTML = href
        ? `<a class="iris-link" href="${esc(href)}" target="_blank" rel="noopener">${esc(formatCaseIdBadge(lastCase))}</a>`
        : esc(formatCaseIdBadge(lastCase));
    } else {
      caseEl.textContent = 'Belum ada';
    }

    const map = w.counters.ticketsByTenant || {};
    const tenants = Array.from(new Set([...(w.counters.tenants || []), ...Object.keys(map)]));
    const chips = tenants
      .filter((t) => map[t])
      .map((t) => `<span class="ticket-ref-chip">${esc(t)} <strong>${esc(map[t])}</strong></span>`);
    ticketsEl.innerHTML = chips.length
      ? chips.join('')
      : '<span class="ticket-ref-empty">Belum ada nomor tiket tercatat di server</span>';

    if (state.serverOnline) {
      syncEl.className = 'sync-pill';
      syncEl.textContent = w.counters.updatedAt ? 'Tersinkron · ' + fmtWib(w.counters.updatedAt) : 'Tersinkron';
    } else {
      syncEl.className = 'sync-pill offline';
      syncEl.textContent = 'Offline (lokal)';
    }
  }

  async function fetchHistory() {
    const ws = state.historyWorkspace;
    const params = new URLSearchParams({ workspace: ws, limit: '200' });
    const q = ($('#hist-search')?.value || '').trim();
    const tenant = $('#hist-filter-tenant')?.value || '';
    const mode = $('#hist-filter-mode')?.value || '';
    if (q) params.set('q', q);
    if (tenant) params.set('tenant', tenant);
    if (mode && ws === 'asoc') params.set('mode', mode);

    const tbody = $('#history-tbody');
    const emptyEl = $('#history-empty');
    const wrap = $('.history-table-wrap');
    if (tbody && wrap) {
      wrap.hidden = false;
      if (emptyEl) emptyEl.hidden = true;
      tbody.innerHTML = `<tr><td colspan="8" class="hist-loading-cell">Memuat riwayat ${esc(WORKSPACE_META[ws].code)}…</td></tr>`;
    }

    try {
      const data = await apiFetch('/api/history?' + params.toString());
      state.history = Array.isArray(data.items) ? data.items : [];
      if (data.counts) {
        state.historyCounts = data.counts;
      } else if (typeof data.total === 'number') {
        state.historyCounts[ws] = data.total;
      }
      if (data.counters) {
        state.workspaces[ws].counters = data.counters;
        if (ws === state.activeWorkspace) renderSharedBar();
      }
      updateHistoryTabCounts();
      renderHistoryTable();
    } catch (e) {
      toast({ type: 'error', title: 'Gagal memuat riwayat', body: e.message });
    }
  }

  /* ---------------- Mode, Field Roles & Queue Numbering ---------------- */

  function roleKey(role, ws = state.activeWorkspace) {
    const f = wsState(ws).settings.fields.find((x) => x.role === role);
    return f ? f.key : null;
  }

  function readVal(card, role, ws = card.workspace || state.activeWorkspace) {
    const k = roleKey(role, ws);
    return k ? String(card.values[k] ?? '').trim() : '';
  }

  function effectiveRunOptions(card) {
    const ws = card.workspace || state.activeWorkspace;
    const w = wsState(ws);
    if (ws === 'asoc' && card.mode === 'repeating') {
      const r = card.repeatOptions || w.repeatOptions;
      return {
        caseIdMode: r.createIrisCase ? w.settings.caseIdMode : 'manual',
        createIrisCase: Boolean(r.createIrisCase),
        updateIrisSummary: Boolean(r.updateIrisSummary),
        requireApproval: Boolean(r.requireApproval),
        sendEmailPdf: Boolean(r.sendEmailPdf),
        uploadGdoc: Boolean(r.uploadGdoc),
        appendSheet: Boolean(r.appendSheet),
        returnMarkdown: r.returnMarkdown !== false,
      };
    }
    return {
      caseIdMode: w.settings.caseIdMode,
      createIrisCase: true,
      updateIrisSummary: true,
      requireApproval: true,
      sendEmailPdf: true,
      uploadGdoc: true,
      appendSheet: true,
      returnMarkdown: true,
    };
  }

  function caseIdControlSpec(card) {
    const ws = card.workspace || state.activeWorkspace;
    const w = wsState(ws);
    if (ws === 'soc') {
      return {
        showInput: true,
        required: true,
        hint: 'Mode SOC (Charlie Reporter) — wajib isi Case ID (otomatis berurutan jika acuan tersedia).',
      };
    }
    const opts = effectiveRunOptions(card);
    if (card.mode === 'repeating' && !opts.createIrisCase) {
      const needsExisting = opts.updateIrisSummary || opts.uploadGdoc || opts.appendSheet || opts.requireApproval;
      if (needsExisting) {
        return {
          showInput: true,
          required: true,
          hint: 'Wajib isi Case ID IRIS existing untuk target repeating yang dipilih.',
        };
      }
      return {
        showInput: false,
        required: false,
        canOverride: true,
        autoLabel: 'Tidak diperlukan (Markdown saja)',
        hint: 'Tidak membuat/mengubah case di IRIS.',
      };
    }
    if (w.settings.caseIdMode === 'auto_iris' && !card.forceManualCaseId) {
      return {
        showInput: false,
        required: false,
        canOverride: true,
        autoLabel: 'Otomatis dari IRIS',
        hint: 'Nomor Case ID diambil otomatis setelah Alpha Reporter membuat case di IRIS.',
      };
    }
    return {
      showInput: true,
      required: true,
      canReturnAuto: w.settings.caseIdMode === 'auto_iris',
      hint: 'Mode manual — nilai dikirim sebagai IRIS Case ID.',
    };
  }

  function recomputeQueueTickets(ws = state.activeWorkspace, opts = {}) {
    const w = wsState(ws);
    const tk = roleKey('ticket', ws);
    const tn = roleKey('tenant', ws);
    const ck = roleKey('caseId', ws);
    const isActive = ws === state.activeWorkspace;

    // 1. Per-tenant ticket auto-increment
    if (tk && tn && N.computeQueueTickets) {
      const changedIds = N.computeQueueTickets(w.cards, w.counters.ticketsByTenant || {}, {
        autoNumber: w.settings.autoNumber !== false,
        ticketKey: tk,
        tenantKey: tn,
        skipCardId: opts.skipCardId || null,
      });
      if (isActive) {
        for (const id of changedIds) {
          const c = w.cards.find((x) => x.id === id);
          if (c) {
            syncCardInput(c, tk);
            refreshCard(c);
          }
        }
      }
    }

    // 2. Global Case ID auto-increment for SOC (manual Case ID workflow)
    if (ws === 'soc' && ck && N.nextValue && w.settings.autoNumber !== false) {
      let cursor = w.counters.lastIrisCaseId || null;
      for (const card of w.cards) {
        if (card.id === opts.skipCardId) {
          const v = String(card.values[ck] ?? '').trim();
          if (v && N.lastNumber(v) != null) cursor = v;
          continue;
        }
        const curVal = String(card.values[ck] ?? '').trim();
        const eligible = card.status === 'idle' && (card.caseIdAuto || !curVal);
        if (eligible && cursor) {
          const next = N.nextValue(cursor);
          if (next) {
            const changed = curVal !== next || !card.caseIdAuto;
            card.values[ck] = next;
            card.caseIdAuto = true;
            cursor = next;
            if (isActive && changed) {
              syncCardInput(card, ck);
              refreshCard(card);
            }
          }
        } else if (curVal && N.lastNumber(curVal) != null) {
          const curNum = N.lastNumber(curVal).value;
          const baseNum = cursor && N.lastNumber(cursor) ? N.lastNumber(cursor).value : null;
          if (!cursor || (card.status === 'idle' && !card.caseIdAuto) || baseNum == null || curNum >= baseNum) {
            cursor = curVal;
          }
        }
      }
    }

    if (!opts.noPersist) persist();
  }

  function syncCardInput(card, key) {
    const r = refs.get(card.id);
    const el = r && r.inputs[key];
    if (!el) return;
    const v = card.values[key] ?? '';
    if (el.value !== v) el.value = v;
  }

  /* ---------------- Mode & Workspace Switching ---------------- */

  function updateWorkspaceChrome() {
    const ws = state.activeWorkspace;
    const meta = WORKSPACE_META[ws];
    document.documentElement.dataset.workspace = ws;
    $('#brand-subtitle').textContent = meta.subtitle;

    for (const id of ['asoc', 'soc']) {
      const btn = $('#ws-' + id);
      const active = id === ws;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-pressed', String(active));
    }

    $('#asoc-mode-switch').hidden = !meta.hasRepeating;
    $('#repeat-panel').hidden = !(meta.hasRepeating && wsState(ws).activeMode === 'repeating');

    $('#empty-state-desc').textContent = ws === 'asoc'
      ? 'Tambahkan form baru dalam mode Reporting atau Repeating, atau ulangi langsung dari Riwayat ASOC.'
      : 'Tambahkan form baru untuk Charlie Reporter, atau duplikat ulang dari Riwayat SOC.';

    updateWorkspaceBadges();
  }

  function updateWorkspaceBadges() {
    for (const ws of ['asoc', 'soc']) {
      const running = wsState(ws).cards.filter((c) => c.status === 'running' || c.status === 'queued').length;
      const badge = $('#ws-' + ws + '-running');
      if (badge) {
        badge.hidden = running === 0;
        badge.textContent = String(running);
      }
    }
    const totalRunning = ['asoc', 'soc'].reduce(
      (sum, ws) => sum + wsState(ws).cards.filter((c) => c.status === 'running' || c.status === 'queued').length,
      0,
    );
    document.title = (totalRunning ? `(${totalRunning}) ` : '') + `Diptera — ${WORKSPACE_META[state.activeWorkspace].code} (${WORKSPACE_META[state.activeWorkspace].subtitle})`;
  }

  function switchWorkspace(nextWs) {
    const ws = nextWs === 'soc' ? 'soc' : 'asoc';
    if (state.activeWorkspace === ws) return;
    state.activeWorkspace = ws;
    state.settingsWorkspace = ws;
    state.historyWorkspace = ws;

    updateWorkspaceChrome();
    setActiveMode(wsState(ws).activeMode, { skipPersist: true });
    updateFormLink();
    renderSharedBar();
    updateHistoryTabCounts();
    populateHistoryTenantFilter();
    renderAllCards();

    if (!$('#settings-panel').hidden) {
      fillSettingsForm(ws);
    }
    if (state.view === 'history') {
      syncHistoryWorkspaceTabs();
      fetchHistory();
    }
    persist();
  }

  function updateRepeatDependencyHint() {
    const r = wsState('asoc').repeatOptions;
    const hint = $('#repeat-dependency-hint');
    if (!hint) return;
    const parts = [];
    if (!r.createIrisCase && (r.updateIrisSummary || r.uploadGdoc || r.appendSheet || r.requireApproval)) {
      parts.push('<strong>IRIS Case ID manual wajib diisi</strong> pada kartu karena opsi tidak membuat Case IRIS baru.');
    } else if (r.createIrisCase) {
      parts.push('Akan membuat <strong>Case IRIS baru</strong> dan memperbarui acuan Last IRIS Case di server.');
    } else {
      parts.push('Mode <strong>Markdown Saja</strong> — hasil langsung tampil di kartu Diptera tanpa menulis ke IRIS/Drive/Sheets.');
    }
    if (r.sendEmailPdf && !r.requireApproval) {
      parts.push('Email &amp; PDF akan menggunakan alamat fallback jika tanpa ambil kontak dari approval IRIS.');
    }
    hint.innerHTML = parts.join(' ');

    document.querySelectorAll('.preset-btn[data-preset]').forEach((btn) => {
      const p = REPEAT_PRESETS[btn.dataset.preset];
      const match = p && Object.keys(p).every((k) => Boolean(p[k]) === Boolean(r[k]));
      btn.classList.toggle('active', match);
    });
  }

  function syncRepeatPanelInputs() {
    const r = wsState('asoc').repeatOptions;
    $('#rep-create-iris').checked = Boolean(r.createIrisCase);
    $('#rep-update-iris').checked = Boolean(r.updateIrisSummary);
    $('#rep-approval').checked = Boolean(r.requireApproval);
    $('#rep-email').checked = Boolean(r.sendEmailPdf);
    $('#rep-gdoc').checked = Boolean(r.uploadGdoc);
    $('#rep-sheet').checked = Boolean(r.appendSheet);
    $('#rep-md').checked = r.returnMarkdown !== false;
    updateRepeatDependencyHint();
  }

  function setActiveMode(mode, opts = {}) {
    const ws = state.activeWorkspace;
    const w = wsState(ws);
    const meta = WORKSPACE_META[ws];
    const resolved = meta.hasRepeating && mode === 'repeating' ? 'repeating' : 'reporting';
    w.activeMode = resolved;
    const isRep = resolved === 'repeating';

    $('#mode-reporting').classList.toggle('active', !isRep);
    $('#mode-reporting').setAttribute('aria-pressed', String(!isRep));
    $('#mode-repeating').classList.toggle('active', isRep);
    $('#mode-repeating').setAttribute('aria-pressed', String(isRep));
    $('#repeat-panel').hidden = !(meta.hasRepeating && isRep);

    for (const card of w.cards) {
      if (card.status === 'idle' && !readVal(card, 'alert', ws)) {
        card.mode = resolved;
        card.repeatOptions = isRep ? clone(w.repeatOptions) : null;
        rebuildCardFields(card);
        refreshCard(card);
      }
    }
    recomputeQueueTickets(ws, { noPersist: true });
    updateToolbar();
    if (!opts.skipPersist) persist();
  }

  /* ---------------- Card Rendering ---------------- */

  function newCard(prefill = {}, ws = state.activeWorkspace) {
    const w = wsState(ws);
    const meta = WORKSPACE_META[ws];
    const mode = meta.hasRepeating ? (prefill.mode || w.activeMode) : 'reporting';
    const card = normalizeCard({
      id: uid(),
      workspace: ws,
      mode,
      repeatOptions: mode === 'repeating' ? clone(prefill.repeatOptions || w.repeatOptions) : null,
      forceManualCaseId: Boolean(prefill.forceManualCaseId),
      values: prefill.values ? clone(prefill.values) : {},
      status: 'idle',
      collapsed: false,
    }, ws);

    if (mode === 'reporting' && w.settings.autoNumber !== false && N.computeQueueTickets) {
      const tk = roleKey('ticket', ws);
      const tn = roleKey('tenant', ws);
      if (tk && tn && !readVal(card, 'ticket', ws)) {
        N.computeQueueTickets([...w.cards, card], w.counters.ticketsByTenant || {}, {
          autoNumber: true,
          ticketKey: tk,
          tenantKey: tn,
        });
      }
      if (ws === 'soc') {
        const ck = roleKey('caseId', ws);
        if (ck && !readVal(card, 'caseId', ws) && N.nextValue) {
          let cursor = w.counters.lastIrisCaseId || null;
          for (const prev of w.cards) {
            const pv = String(prev.values[ck] ?? '').trim();
            if (pv && N.lastNumber(pv) != null) cursor = pv;
          }
          const nextCid = cursor ? N.nextValue(cursor) : null;
          if (nextCid) {
            card.values[ck] = nextCid;
            card.caseIdAuto = true;
          }
        }
      }
    }
    return card;
  }

  function cardLabel(card) {
    const ws = card.workspace || state.activeWorkspace;
    const idx = wsState(ws).cards.indexOf(card) + 1;
    return 'Form #' + idx;
  }

  function buildCardElement(card) {
    const el = document.createElement('article');
    el.className = 'card';
    el.dataset.id = card.id;

    el.innerHTML = `
      <div class="card-head">
        <button class="card-head-toggle" type="button" aria-expanded="true">
          <svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M6 9l6 6 6-6" />
          </svg>
          <span class="card-title"></span>
          <span class="chip mode-chip"></span>
          <span class="card-summary"></span>
        </button>
        <div class="card-head-right">
          <span class="chip case-chip" hidden></span>
          <span class="chip sev-chip" hidden></span>
          <span class="chip status-chip"></span>
          <button class="chip-del" type="button" title="Hapus form ini">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6" />
            </svg>
            <span class="sr-only">Hapus</span>
          </button>
        </div>
      </div>
      <div class="card-body">
        <div class="card-form-wrap">
          <div class="card-fields"></div>
          <div class="card-actions">
            <button class="btn accent btn-sm btn-send-one" type="button" title="Kirim kartu ini (Ctrl+Enter)">Kirim</button>
            <button class="btn ghost btn-sm btn-dup" type="button">Duplikat</button>
            <button class="btn ghost btn-sm btn-recheck" type="button" hidden>Periksa Hasil Lagi</button>
            <span class="spacer"></span>
          </div>
        </div>
        <div class="error-box" hidden></div>
        <div class="result-box" hidden></div>
      </div>
    `;

    const ref = {
      el,
      head: $('.card-head', el),
      toggleBtn: $('.card-head-toggle', el),
      title: $('.card-title', el),
      modeChip: $('.mode-chip', el),
      summary: $('.card-summary', el),
      caseChip: $('.case-chip', el),
      sevChip: $('.sev-chip', el),
      statusChip: $('.status-chip', el),
      delBtn: $('.chip-del', el),
      formWrap: $('.card-form-wrap', el),
      fieldsWrap: $('.card-fields', el),
      sendBtn: $('.btn-send-one', el),
      dupBtn: $('.btn-dup', el),
      recheckBtn: $('.btn-recheck', el),
      errorBox: $('.error-box', el),
      resultBox: $('.result-box', el),
      inputs: {},
      msgs: {},
    };
    refs.set(card.id, ref);

    ref.toggleBtn.addEventListener('click', () => toggleCollapse(card));
    ref.delBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      removeCard(card);
    });
    ref.sendBtn.addEventListener('click', () => submitCard(card));
    ref.dupBtn.addEventListener('click', () => duplicateCard(card));
    ref.recheckBtn.addEventListener('click', () => recheckCard(card));

    rebuildCardFields(card);
    refreshCard(card);
    return el;
  }

  function rebuildCardFields(card) {
    const r = refs.get(card.id);
    if (!r) return;
    const ws = card.workspace || state.activeWorkspace;
    const w = wsState(ws);
    r.fieldsWrap.innerHTML = '';
    r.inputs = {};
    r.msgs = {};

    const caseSpec = caseIdControlSpec(card);

    for (const field of w.settings.fields) {
      const wrap = document.createElement('div');
      wrap.className = 'field' + (field.type === 'textarea' ? ' field-wide' : '');

      const labelEl = document.createElement('label');
      labelEl.className = 'field-label';
      const isCaseId = field.role === 'caseId';
      const isReq = isCaseId ? caseSpec.required : Boolean(field.required);
      labelEl.innerHTML = esc(field.label) + (isReq ? ' <span style="color:var(--rose)">*</span>' : '');
      wrap.appendChild(labelEl);

      if (isCaseId && !caseSpec.showInput) {
        const box = document.createElement('div');
        box.className = 'auto-case-box';
        box.innerHTML = `
          <span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M12 3v3m0 12v3M4.93 4.93l2.12 2.12m9.9 9.9 2.12 2.12M3 12h3m12 0h3M4.93 19.07l2.12-2.12m9.9-9.9 2.12-2.12" />
            </svg>
            ${esc(caseSpec.autoLabel)}
          </span>
        `;
        if (caseSpec.canOverride) {
          const btn = document.createElement('button');
          btn.type = 'button';
          btn.className = 'link-btn';
          btn.textContent = 'Isi manual';
          btn.addEventListener('click', () => {
            card.forceManualCaseId = true;
            rebuildCardFields(card);
            const inp = refs.get(card.id)?.inputs[field.key];
            if (inp) inp.focus();
            persist();
          });
          box.appendChild(btn);
        }
        wrap.appendChild(box);
        const msg = document.createElement('div');
        msg.className = 'field-msg auto';
        msg.textContent = caseSpec.hint;
        wrap.appendChild(msg);
        r.msgs[field.key] = msg;
        r.fieldsWrap.appendChild(wrap);
        continue;
      }

      const inputId = 'f-' + card.id + '-' + field.key;
      let control;
      if (field.type === 'select') {
        control = document.createElement('select');
        const opts = field.options || [];
        control.innerHTML = '<option value="">— Pilih tenant —</option>' +
          opts.map((o) => `<option value="${esc(o)}">${esc(o)}</option>`).join('');
        control.value = card.values[field.key] ?? '';
      } else if (field.type === 'textarea') {
        control = document.createElement('textarea');
        control.rows = 6;
        control.setAttribute('wrap', 'off');
        control.spellcheck = false;
        control.placeholder = field.placeholder || '';
        control.value = card.collapsed ? '' : (card.values[field.key] ?? '');
      } else {
        control = document.createElement('input');
        control.type = 'text';
        control.spellcheck = false;
        control.placeholder = field.placeholder || '';
        control.value = card.values[field.key] ?? '';
      }
      control.id = inputId;
      labelEl.htmlFor = inputId;

      if (isCaseId && caseSpec.canReturnAuto) {
        const backBtn = document.createElement('button');
        backBtn.type = 'button';
        backBtn.className = 'link-btn';
        backBtn.style.marginLeft = 'auto';
        backBtn.textContent = 'Kembali otomatis';
        backBtn.addEventListener('click', () => {
          card.forceManualCaseId = false;
          card.values[field.key] = '';
          rebuildCardFields(card);
          persist();
        });
        labelEl.appendChild(backBtn);
      }

      const msg = document.createElement('div');
      msg.className = 'field-msg';
      if (isCaseId && caseSpec.hint) msg.textContent = caseSpec.hint;

      control.addEventListener('input', () => onFieldChange(card, field, control, msg));
      control.addEventListener('change', () => onFieldChange(card, field, control, msg));

      r.inputs[field.key] = control;
      r.msgs[field.key] = msg;
      wrap.appendChild(control);
      wrap.appendChild(msg);
      r.fieldsWrap.appendChild(wrap);

      if (field.json) {
        const info = inspectJson(card.values[field.key] || '');
        msg.textContent = info.msg;
        msg.className = 'field-msg ' + (info.state === 'ok' ? 'ok' : info.state === 'warn' ? 'warn' : '');
      }
    }
  }

  function onFieldChange(card, field, control, msgEl) {
    const ws = card.workspace || state.activeWorkspace;
    card.values[field.key] = control.value;
    if (control.getAttribute('aria-invalid') === 'true') {
      control.removeAttribute('aria-invalid');
      if (msgEl && msgEl.classList.contains('err')) {
        msgEl.textContent = '';
        msgEl.className = 'field-msg';
      }
    }
    if (field.role === 'ticket') {
      card.ticketAuto = false;
      card.ticketFor = readVal(card, 'tenant', ws);
      control.classList.remove('input-auto');
      clearTimeout(ticketPropagateTimer);
      ticketPropagateTimer = setTimeout(() => {
        recomputeQueueTickets(ws, { skipCardId: card.id });
      }, 300);
    } else if (field.role === 'caseId') {
      card.caseIdAuto = false;
      control.classList.remove('input-auto');
      clearTimeout(ticketPropagateTimer);
      ticketPropagateTimer = setTimeout(() => {
        recomputeQueueTickets(ws, { skipCardId: card.id });
      }, 300);
    } else if (field.role === 'tenant') {
      recomputeQueueTickets(ws);
    }
    if (field.json) {
      const info = inspectJson(control.value);
      msgEl.textContent = info.msg;
      msgEl.className = 'field-msg ' + (info.state === 'ok' ? 'ok' : info.state === 'warn' ? 'warn' : '');
    }
    refreshCard(card);
    persist();
  }

  function refreshCard(card) {
    const r = refs.get(card.id);
    if (!r) return;
    const ws = card.workspace || state.activeWorkspace;

    r.el.className = `card status-${card.status} mode-${card.mode}` + (card.collapsed ? ' collapsed' : '');
    if (r.toggleBtn) r.toggleBtn.setAttribute('aria-expanded', String(!card.collapsed));
    r.title.textContent = cardLabel(card);

    r.modeChip.textContent = ws === 'soc' ? 'SOC' : (card.mode === 'repeating' ? 'Repeating' : 'Reporting');
    r.modeChip.className = 'chip mode-chip mode-' + card.mode;

    const tenant = readVal(card, 'tenant', ws);
    const ticket = readVal(card, 'ticket', ws);
    const summaryParts = [];
    if (card.result?.caseName) {
      summaryParts.push(card.result.caseName);
    } else {
      if (tenant) summaryParts.push(tenant);
      if (ticket) summaryParts.push('Tiket ' + ticket);
      const manualCid = readVal(card, 'caseId', ws);
      if (manualCid) summaryParts.push(formatCaseIdBadge(manualCid));
    }
    r.summary.textContent = summaryParts.join(' · ') || 'Belum diisi';

    const resolvedCid = card.irisCaseId || card.result?.caseId;
    if (resolvedCid) {
      r.caseChip.hidden = false;
      r.caseChip.textContent = (ws === 'asoc' ? 'IRIS ' : 'Case ') + formatCaseIdBadge(resolvedCid);
    } else {
      r.caseChip.hidden = true;
    }

    if (card.result?.severity) {
      r.sevChip.hidden = false;
      r.sevChip.textContent = card.result.severity;
      r.sevChip.className = 'chip sev-chip sev-' + card.result.severity;
    } else {
      r.sevChip.hidden = true;
    }

    const N8N_STATUS_LABEL = {
      'form-waiting': 'menunggu hasil',
      waiting: 'menunggu',
      running: 'berjalan',
      crashed: 'terhenti',
      error: 'error',
      success: 'selesai',
    };
    const dur = card.elapsedMs != null ? ' · ' + fmtDuration(card.elapsedMs) : '';
    const statusText = STATUS_LABEL[card.status] || card.status;
    const nsFriendly = card.nsStatus ? (N8N_STATUS_LABEL[card.nsStatus] || card.nsStatus) : '';
    r.statusChip.textContent = card.status === 'running' && nsFriendly
      ? `${statusText} (${nsFriendly})`
      : statusText + dur;
    r.statusChip.className = 'chip status-chip status-' + card.status;

    const tk = roleKey('ticket', ws);
    if (tk && r.inputs[tk]) {
      r.inputs[tk].classList.toggle('input-auto', Boolean(card.ticketAuto && card.mode === 'reporting'));
      if (r.msgs[tk]) {
        r.msgs[tk].textContent = card.ticketAuto && card.mode === 'reporting'
          ? `Otomatis lanjutan antrean (${card.ticketFor || tenant}) — bisa diubah`
          : '';
        r.msgs[tk].className = 'field-msg ' + (card.ticketAuto ? 'auto' : '');
      }
    }

    const ck = roleKey('caseId', ws);
    if (ws === 'soc' && ck && r.inputs[ck]) {
      r.inputs[ck].classList.toggle('input-auto', Boolean(card.caseIdAuto));
    }

    const editable = card.status === 'idle' || card.status === 'error';
    r.sendBtn.disabled = card.busy;
    r.sendBtn.textContent = card.status === 'error' ? 'Coba Lagi' : (card.mode === 'repeating' ? 'Jalankan Repeat' : 'Kirim');
    r.sendBtn.className = 'btn btn-sm btn-send-one ' + (card.mode === 'repeating' ? 'amber' : 'accent');
    r.recheckBtn.hidden = !(card.status === 'error' && (card.waitingUrl || card.historyId));

    const hideForm = card.status === 'done' && Boolean(card.result);
    r.formWrap.hidden = hideForm;
    for (const inp of Object.values(r.inputs)) {
      inp.disabled = !editable;
    }

    if (card.status === 'error' && card.errorMsg) {
      r.errorBox.hidden = false;
      r.errorBox.innerHTML =
        `<strong>${esc(card.errorMsg)}</strong>` +
        (card.errorHint ? `<div>${esc(card.errorHint)}</div>` : '') +
        (card.errorDetail ? `<div class="error-detail">${esc(card.errorDetail)}</div>` : '');
    } else {
      r.errorBox.hidden = true;
    }

    if (card.status === 'done' && card.result) {
      r.resultBox.hidden = false;
      const cid = card.irisCaseId || card.result.caseId || readVal(card, 'caseId', ws);
      const irisHref = irisCaseLink(cid, ws);
      const execHref = card.execId ? joinUrl(wsState(ws).settings.baseUrl, '/executions/' + encodeURIComponent(card.execId)) : null;
      const approvalNote = (ws === 'asoc' && card.result.awaitingApproval)
        ? '<span class="chip status-queued">Menunggu approval Telegram di n8n</span>'
        : '';

      r.resultBox.innerHTML = `
        <div class="result-meta">
          <div class="result-case-name">${esc(card.result.caseName || 'Laporan Selesai')}</div>
          <div class="result-badges">
            ${cid ? (irisHref
              ? `<a class="chip mode-reporting" href="${esc(irisHref)}" target="_blank" rel="noopener">IRIS ${esc(formatCaseIdBadge(cid))} ↗</a>`
              : `<span class="chip mode-reporting">${ws === 'asoc' ? 'IRIS ' : 'Case '}${esc(formatCaseIdBadge(cid))}</span>`) : ''}
            ${card.result.severity ? `<span class="chip sev-${esc(card.result.severity)}">${esc(card.result.severity)}</span>` : ''}
            ${card.result.classification ? `<span class="chip">${esc(card.result.classification)}</span>` : ''}
            ${approvalNote}
          </div>
        </div>
        <div class="result-actions">
          ${card.result.markdown ? '<button class="btn primary btn-sm act-copy-md" type="button">Salin Markdown</button>' : ''}
          ${card.result.caseName ? '<button class="btn ghost btn-sm act-copy-title" type="button">Salin Case Name</button>' : ''}
          ${ws === 'asoc' ? '<button class="btn ghost btn-sm act-repeat-card" type="button">Ulangi (Repeat)</button>' : ''}
          ${execHref ? `<a class="btn ghost btn-sm" href="${esc(execHref)}" target="_blank" rel="noopener">Eksekusi n8n ↗</a>` : ''}
        </div>
        ${card.result.markdown
          ? `<pre class="md-pre">${esc(card.result.markdown)}</pre>`
          : '<div class="field-hint">Workflow selesai tanpa halaman Markdown (cek n8n untuk detail).</div>'}
      `;

      const copyMdBtn = $('.act-copy-md', r.resultBox);
      if (copyMdBtn) copyMdBtn.addEventListener('click', () => copyText(card.result.markdown, 'Markdown'));
      const copyTitleBtn = $('.act-copy-title', r.resultBox);
      if (copyTitleBtn) copyTitleBtn.addEventListener('click', () => copyText(card.result.caseName, 'Case Name'));
      const repBtn = $('.act-repeat-card', r.resultBox);
      if (repBtn) repBtn.addEventListener('click', () => createRepeatFromMeta({
        workspace: ws,
        tenant: readVal(card, 'tenant', ws),
        ticketNumber: readVal(card, 'ticket', ws),
        irisCaseId: cid,
      }));
    } else {
      r.resultBox.hidden = true;
    }
  }

  function renderAllCards() {
    const ws = state.activeWorkspace;
    const w = wsState(ws);
    const container = $('#cards');
    container.innerHTML = '';
    refs.clear();
    for (const card of w.cards) {
      container.appendChild(buildCardElement(card));
    }
    updateStats();
    updateToolbar();
  }

  function syncCardTextareas(card) {
    const ws = card.workspace || state.activeWorkspace;
    const w = wsState(ws);
    const r = refs.get(card.id);
    if (!r) return;
    for (const field of w.settings.fields) {
      if (field.type === 'textarea' && r.inputs[field.key]) {
        r.inputs[field.key].value = card.collapsed ? '' : (card.values[field.key] ?? '');
      }
    }
  }

  function toggleCollapse(card) {
    card.collapsed = !card.collapsed;
    syncCardTextareas(card);
    refreshCard(card);
    updateToolbar();
    persist();
  }

  function removeCard(card) {
    const ws = card.workspace || state.activeWorkspace;
    const w = wsState(ws);
    const r = refs.get(card.id);
    const isRunning = card.busy || card.status === 'running' || card.status === 'queued';
    if (isRunning && r && r.delBtn && r.delBtn.dataset.confirm !== '1') {
      r.delBtn.dataset.confirm = '1';
      r.delBtn.classList.add('confirming');
      r.delBtn.title = 'Klik lagi untuk menghentikan proses & menghapus kartu';
      clearTimeout(r.delBtn._confirmTimer);
      r.delBtn._confirmTimer = setTimeout(() => {
        if (!r.delBtn) return;
        delete r.delBtn.dataset.confirm;
        r.delBtn.classList.remove('confirming');
        r.delBtn.title = 'Hapus form ini';
      }, 4000);
      toast({
        type: 'info',
        title: `${cardLabel(card)} sedang diproses`,
        body: 'Klik ikon hapus sekali lagi dalam 4 detik untuk membatalkan & menghapus.',
      });
      return;
    }

    const removedIndex = w.cards.indexOf(card);
    const hadContent = !isRunning && Object.values(card.values || {}).some((v) => String(v || '').trim().length > 0);
    if (card.busy && card.abort) card.abort.abort();
    if (removedIndex >= 0) w.cards.splice(removedIndex, 1);
    if (r) r.el.remove();
    refs.delete(card.id);
    recomputeQueueTickets(ws, { noPersist: true });
    for (const c of w.cards) refreshCard(c);
    updateStats();
    updateToolbar();
    updateWorkspaceBadges();
    persist();

    if (hadContent && removedIndex >= 0) {
      toast({
        type: 'info',
        title: `Form dihapus (${WORKSPACE_META[ws].code})`,
        body: 'Data kartu dapat dikembalikan dalam beberapa detik.',
        actionLabel: 'Urungkan',
        onAction: () => {
          if (w.cards.includes(card)) return;
          const insertAt = Math.min(removedIndex, w.cards.length);
          w.cards.splice(insertAt, 0, card);
          if (ws === state.activeWorkspace) renderAllCards();
          recomputeQueueTickets(ws, { noPersist: true });
          updateStats();
          updateToolbar();
          updateWorkspaceBadges();
          persist();
        },
      });
    }
  }

  function duplicateCard(card) {
    const ws = card.workspace || state.activeWorkspace;
    const w = wsState(ws);
    const nextValues = clone(card.values);
    const tk = roleKey('ticket', ws);
    const ck = roleKey('caseId', ws);
    const tenant = readVal(card, 'tenant', ws);
    if (card.mode === 'reporting' && tk) nextValues[tk] = '';
    if (ws === 'soc' && ck) nextValues[ck] = '';

    const copy = newCard({
      mode: card.mode,
      repeatOptions: card.repeatOptions,
      forceManualCaseId: card.forceManualCaseId,
      values: nextValues,
    }, ws);
    if (card.mode === 'reporting' && w.settings.autoNumber !== false && tenant) {
      copy.ticketAuto = true;
      copy.ticketFor = tenant;
    }
    w.cards.push(copy);
    if (ws === state.activeWorkspace) {
      $('#cards').appendChild(buildCardElement(copy));
    }
    recomputeQueueTickets(ws, { noPersist: true });
    updateStats();
    updateToolbar();
    persist();
  }

  function createRepeatFromMeta(meta) {
    const targetWs = meta.workspace === 'soc' ? 'soc' : 'asoc';
    if (state.activeWorkspace !== targetWs) switchWorkspace(targetWs);
    switchView('queue');
    if (targetWs === 'asoc') setActiveMode('repeating');

    const values = {};
    const tk = roleKey('ticket', targetWs);
    const tn = roleKey('tenant', targetWs);
    const cidKey = roleKey('caseId', targetWs);
    if (tk && meta.ticketNumber) values[tk] = meta.ticketNumber;
    if (tn && meta.tenant) values[tn] = meta.tenant;
    if (cidKey && meta.irisCaseId) values[cidKey] = formatCaseIdBadge(meta.irisCaseId);

    const w = wsState(targetWs);
    for (const c of w.cards) {
      if (!c.collapsed) {
        c.collapsed = true;
        refreshCard(c);
      }
    }

    const card = newCard({
      mode: targetWs === 'asoc' ? 'repeating' : 'reporting',
      repeatOptions: targetWs === 'asoc' ? clone(w.repeatOptions) : null,
      forceManualCaseId: Boolean(meta.irisCaseId),
      values,
    }, targetWs);
    w.cards.unshift(card);
    renderAllCards();

    const alertKey = roleKey('alert', targetWs);
    const alertInp = alertKey ? refs.get(card.id)?.inputs[alertKey] : null;
    if (alertInp) {
      alertInp.focus();
      alertInp.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    toast({
      type: 'info',
      title: targetWs === 'asoc' ? 'Kartu Repeating siap' : 'Kartu SOC siap',
      body: 'Tempel Raw Alert JSON lalu kirim.',
    });
    persist();
  }

  /* ---------------- Validation & Submission ---------------- */

  function validateCard(card) {
    const ws = card.workspace || state.activeWorkspace;
    const w = wsState(ws);
    const errors = [];
    const caseSpec = caseIdControlSpec(card);
    for (const field of w.settings.fields) {
      const isCaseId = field.role === 'caseId';
      const required = isCaseId ? caseSpec.required : Boolean(field.required);
      if (required && !String(card.values[field.key] ?? '').trim()) {
        errors.push({ field, message: field.label + ' wajib diisi.' });
      }
    }
    if (!w.settings.baseUrl || !w.settings.formPath) {
      errors.push({ message: `Base URL n8n dan Form path ${WORKSPACE_META[ws].code} belum diatur.` });
    }
    return errors;
  }

  async function fetchWithTimeout(url, opts, timeoutMs, outerSignal) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    const onOuter = () => ctrl.abort();
    if (outerSignal) {
      if (outerSignal.aborted) { clearTimeout(timer); throw abortErr(); }
      outerSignal.addEventListener('abort', onOuter, { once: true });
    }
    try {
      return await fetch(url, { ...opts, signal: ctrl.signal });
    } finally {
      clearTimeout(timer);
      if (outerSignal) outerSignal.removeEventListener('abort', onOuter);
    }
  }

  async function submitAll() {
    const ws = state.activeWorkspace;
    const w = wsState(ws);
    if (w.submitAllRunning) return;
    const list = w.cards.filter((c) => c.status === 'idle' || c.status === 'error');
    if (!list.length) return;
    w.submitAllRunning = true;
    updateToolbar();
    try {
      if (w.settings.submitMode === 'parallel') {
        await Promise.all(list.map((c) => submitCard(c, ws)));
      } else {
        for (const c of list) {
          if (!w.submitAllRunning) break;
          await submitCard(c, ws);
        }
      }
    } finally {
      w.submitAllRunning = false;
      updateToolbar();
    }
  }

  function cancelAll() {
    const w = wsState(state.activeWorkspace);
    w.submitAllRunning = false;
    for (const c of w.cards) {
      if (c.busy && c.abort) c.abort.abort();
    }
    updateToolbar();
  }

  async function submitCard(card, explicitWs) {
    const ws = explicitWs || card.workspace || state.activeWorkspace;
    const w = wsState(ws);
    if (card.busy || !w.cards.includes(card)) return;

    const errors = validateCard(card);
    if (errors.length) {
      card.collapsed = false;
      if (ws === state.activeWorkspace) {
        syncCardTextareas(card);
        refreshCard(card);
        const r = refs.get(card.id);
        if (r) {
          let focused = false;
          for (const err of errors) {
            if (!err.field) continue;
            const inp = r.inputs[err.field.key];
            const msg = r.msgs[err.field.key];
            if (inp) {
              inp.setAttribute('aria-invalid', 'true');
              if (!focused) {
                inp.focus();
                focused = true;
              }
            }
            if (msg) {
              msg.textContent = err.message;
              msg.className = 'field-msg err';
            }
          }
        }
      }
      toast({ type: 'error', title: `[${WORKSPACE_META[ws].code}] ${cardLabel(card)} belum lengkap`, body: errors[0].message });
      return;
    }

    const opts = effectiveRunOptions(card);
    const tenant = readVal(card, 'tenant', ws);
    const tk = roleKey('ticket', ws);
    const ck = roleKey('caseId', ws);

    // Atomic server ticket/caseId reservation
    if (card.mode === 'reporting' && state.serverOnline && (
      (tenant && tk && (card.ticketAuto || !readVal(card, 'ticket', ws))) ||
      (ws === 'soc' && ck && card.caseIdAuto)
    )) {
      try {
        const resv = await apiFetch('/api/counters/reserve', {
          method: 'POST',
          body: JSON.stringify({
            workspace: ws,
            tenant,
            reserveTicket: Boolean(tenant && tk && (card.ticketAuto || !readVal(card, 'ticket', ws))),
            reserveCaseId: Boolean(ws === 'soc' && ck && card.caseIdAuto),
          }),
        });
        if (tk && resv?.ticketNumber) {
          const localCur = readVal(card, 'ticket', ws);
          const resvNum = N.lastNumber ? N.lastNumber(resv.ticketNumber)?.value : null;
          const localNum = N.lastNumber ? N.lastNumber(localCur)?.value : null;
          if (localNum == null || (resvNum != null && resvNum >= localNum)) {
            card.values[tk] = resv.ticketNumber;
            card.ticketAuto = false;
            if (ws === state.activeWorkspace) syncCardInput(card, tk);
          } else if (localCur) {
            card.ticketAuto = false;
          }
        }
        if (ws === 'soc' && ck && resv?.irisCaseId) {
          const localCid = readVal(card, 'caseId', ws);
          const resvCidNum = N.lastNumber ? N.lastNumber(resv.irisCaseId)?.value : null;
          const localCidNum = N.lastNumber ? N.lastNumber(localCid)?.value : null;
          if (localCidNum == null || (resvCidNum != null && resvCidNum >= localCidNum)) {
            card.values[ck] = resv.irisCaseId;
            card.caseIdAuto = false;
            if (ws === state.activeWorkspace) syncCardInput(card, ck);
          } else {
            card.caseIdAuto = false;
          }
        }
        if (resv?.counters) {
          w.counters = resv.counters;
          if (ws === state.activeWorkspace) renderSharedBar();
        }
      } catch {}
    }

    const ticketNumber = readVal(card, 'ticket', ws);
    const manualCid = caseIdControlSpec(card).showInput ? readVal(card, 'caseId', ws) : '';

    card.historyId = 'job_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 7);
    if (state.serverOnline) {
      try {
        const created = await apiFetch('/api/history', {
          method: 'POST',
          body: JSON.stringify({
            id: card.historyId,
            workspace: ws,
            mode: card.mode,
            repeatOptions: ws === 'asoc' && card.mode === 'repeating' ? opts : null,
            tenant: tenant || null,
            ticketNumber: ticketNumber || null,
            irisCaseId: manualCid || null,
            status: 'running',
          }),
        });
        if (created?.counters) {
          w.counters = created.counters;
          if (ws === state.activeWorkspace) renderSharedBar();
        }
      } catch {}
    }

    card.busy = true;
    card.status = 'running';
    card.nsStatus = 'mengirim ke n8n';
    card.errorMsg = card.errorHint = card.errorDetail = null;
    card.result = null;
    card.waitingUrl = card.execId = null;
    card.irisCaseId = manualCid || null;
    card.resumed = false;
    card.startedAt = Date.now();
    card.elapsedMs = null;

    if (w.settings.autoCollapse) {
      card.collapsed = true;
      const r = refs.get(card.id);
      if (r) {
        for (const f of w.settings.fields) {
          if (f.type === 'textarea' && r.inputs[f.key]) r.inputs[f.key].value = '';
        }
      }
    }
    if (ws === state.activeWorkspace) {
      refreshCard(card);
      updateStats();
      updateToolbar();
    }
    updateWorkspaceBadges();
    persist();

    const ctrl = new AbortController();
    card.abort = ctrl;

    try {
      const formUrl = joinUrl(w.settings.baseUrl, '/form/' + encodeURIComponent(w.settings.formPath));
      const fd = new FormData();
      for (const field of w.settings.fields) {
        if (ws === 'asoc' && field.role === 'caseId' && !caseIdControlSpec(card).showInput) {
          fd.append(field.key, '');
        } else {
          fd.append(field.key, card.values[field.key] ?? '');
        }
      }
      // Hanya ASOC (Alpha Reporter v2) yang menerima field-4..field-6; SOC (Charlie Reporter) murni 4-field!
      if (ws === 'asoc') {
        fd.append('field-4', card.mode);
        fd.append('field-5', JSON.stringify(opts));
        fd.append('field-6', JSON.stringify({
          jobId: card.historyId,
          workspace: 'asoc',
          callbackUrl: effectiveCallbackUrl('asoc'),
        }));
      }

      const res = await fetchWithTimeout(formUrl, { method: 'POST', body: fd }, 180000, ctrl.signal);
      const text = await res.text();
      if (!res.ok) {
        throw {
          message: 'n8n membalas HTTP ' + res.status,
          hint: `Cek Base URL n8n & Form path (${w.settings.formPath}) di Pengaturan ${WORKSPACE_META[ws].code}.`,
          detail: (X.stripTags ? X.stripTags(text) : text).slice(0, 800),
        };
      }

      const json = safeJson(text);
      if (json && json.formWaitingUrl) {
        card.waitingUrl = X.resolveResultUrl(json.formWaitingUrl, w.settings.baseUrl, w.settings.rewriteHost);
        card.execId = X.execIdFromWaitingUrl(card.waitingUrl);
        card.nsStatus = 'workflow berjalan';
        if (ws === state.activeWorkspace) refreshCard(card);
        persist();
        const parsed = await pollForResult(card, ctrl.signal, opts, ws);
        await finishCardDone(card, parsed, ws);
      } else {
        const parsed = X.parse ? X.parse(text) : { found: false };
        if (parsed.found) {
          await finishCardDone(card, parsed, ws);
        } else if (ws === 'asoc' && json && (json.status === 200 || json.status === '200')) {
          const cbResult = await pollServerCallbackOnly(card, ctrl.signal, opts, ws);
          await finishCardDone(card, cbResult, ws);
        } else if (X.looksLikeError && X.looksLikeError(text)) {
          throw {
            message: 'Workflow gagal di n8n',
            hint: 'Periksa log eksekusi n8n.',
            detail: (parsed.pageText || text).slice(0, 800),
          };
        } else {
          throw {
            message: 'Respons n8n tidak dikenali',
            hint: `Pastikan workflow ${WORKSPACE_META[ws].subtitle} aktif di n8n.`,
            detail: (parsed.pageText || text).slice(0, 800),
          };
        }
      }
    } catch (e) {
      await failCard(card, e, ws);
    } finally {
      card.busy = false;
      card.abort = null;
      if (ws === state.activeWorkspace) {
        refreshCard(card);
        updateStats();
        updateToolbar();
      }
      updateWorkspaceBadges();
      persist();
      fetchSharedState(true);
    }
  }

  async function checkHistoryCallback(card, opts) {
    if (!state.serverOnline || !card.historyId) return null;
    try {
      const data = await apiFetch('/api/history/' + encodeURIComponent(card.historyId));
      const rec = data?.record;
      if (!rec) return null;
      if (rec.irisCaseId && rec.irisCaseId !== card.irisCaseId) {
        card.irisCaseId = rec.irisCaseId;
        if ((card.workspace || state.activeWorkspace) === state.activeWorkspace) refreshCard(card);
        fetchSharedState(true);
      }
      if (rec.status === 'done' && (rec.markdown || rec.caseName)) {
        return {
          found: true,
          caseId: rec.irisCaseId || card.irisCaseId,
          caseName: rec.caseName,
          severity: rec.severity,
          classification: rec.classification,
          markdown: rec.markdown,
          awaitingApproval: Boolean(opts.requireApproval),
          fromCallback: true,
        };
      }
    } catch {}
    return null;
  }

  async function pollServerCallbackOnly(card, signal, opts, ws) {
    const w = wsState(ws);
    const started = card.startedAt || Date.now();
    const budget = Math.max(1, Number(w.settings.timeoutMin) || 30) * 60000;
    let interval = 1500;
    for (;;) {
      if (signal?.aborted) throw abortErr();
      const cb = await checkHistoryCallback(card, opts);
      if (cb) return cb;
      if (Date.now() - started > budget) {
        return { found: false, noOutput: true, caseId: card.irisCaseId, caseName: null, severity: null, markdown: null };
      }
      await sleep(interval, signal);
      interval = Math.min(Math.round(interval * 1.2), 5000);
    }
  }

  async function pollForResult(card, signal, opts, ws) {
    const w = wsState(ws);
    const started = card.startedAt || Date.now();
    const budget = Math.max(1, Number(w.settings.timeoutMin) || 30) * 60000;
    const statusUrl = (() => {
      try {
        const u = new URL(card.waitingUrl);
        u.pathname = u.pathname.replace(/\/+$/, '') + '/n8n-execution-status';
        return u.toString();
      } catch {
        return null;
      }
    })();

    let interval = 1200;
    for (;;) {
      if (signal?.aborted) throw abortErr();
      if (Date.now() - started > budget) {
        throw {
          message: 'Melebihi batas tunggu ' + w.settings.timeoutMin + ' menit',
          hint: 'Workflow mungkin masih memproses LLM atau menunggu approval. Klik "Periksa Hasil Lagi".',
        };
      }

      if (ws === 'asoc') {
        const cbResult = await checkHistoryCallback(card, opts);
        if (cbResult) return cbResult;
      }

      if (statusUrl) {
        try {
          const stRes = await fetchWithTimeout(statusUrl, { method: 'GET' }, 15000, signal);
          if (stRes.ok) {
            const stText = (await stRes.text()).trim().replace(/^"|"$/g, '').toLowerCase();
            if (stText && stText !== card.nsStatus) {
              card.nsStatus = stText;
              if (ws === state.activeWorkspace) refreshCard(card);
            }
            if (stText === 'form-waiting' || stText === 'success') {
              const htmlRes = await fetchWithTimeout(card.waitingUrl, { method: 'GET' }, 20000, signal);
              const html = await htmlRes.text();
              const parsed = X.parse ? X.parse(html) : { found: false };
              if (parsed.found) {
                if (w.settings.autoResume && !card.resumed) {
                  card.resumed = true;
                  fetchWithTimeout(card.waitingUrl, { method: 'POST' }, 15000, null).catch(() => {});
                }
                return parsed;
              }
              if (stText === 'success') {
                if (ws === 'asoc') {
                  const finalCb = await checkHistoryCallback(card, opts);
                  if (finalCb) return finalCb;
                }
                return { found: false, noOutput: true, caseId: card.irisCaseId, caseName: null, severity: null, markdown: null };
              }
            } else if (['error', 'crashed', 'canceled', 'null'].includes(stText)) {
              throw {
                message: 'Workflow ' + stText + ' di n8n',
                hint: 'Periksa node yang error pada eksekusi #' + (card.execId || '?') + ' di n8n.',
              };
            }
          }
        } catch (e) {
          if (e?.name === 'AbortError' || e?.message?.startsWith('Workflow ')) throw e;
        }
      }

      await sleep(interval, signal);
      interval = Math.min(Math.round(interval * 1.2), 5000);
    }
  }

  async function finishCardDone(card, parsed, ws = card.workspace || state.activeWorkspace) {
    const w = wsState(ws);
    if (!w.cards.includes(card)) return;
    card.status = 'done';
    card.result = parsed;
    if (parsed?.caseId) card.irisCaseId = parsed.caseId;
    card.elapsedMs = Date.now() - (card.startedAt || Date.now());
    card.errorMsg = card.errorHint = card.errorDetail = null;

    if (state.serverOnline && card.historyId && !parsed?.fromCallback) {
      try {
        await apiFetch('/api/history/' + encodeURIComponent(card.historyId), {
          method: 'PATCH',
          body: JSON.stringify({
            workspace: ws,
            status: 'done',
            irisCaseId: card.irisCaseId || readVal(card, 'caseId', ws) || null,
            caseName: parsed?.caseName || null,
            severity: parsed?.severity || null,
            classification: parsed?.classification || null,
            markdown: parsed?.markdown || null,
            execId: card.execId || null,
          }),
        });
      } catch {}
    }

    if (ws === state.activeWorkspace) refreshCard(card);
    toast({
      type: 'success',
      title: `[${WORKSPACE_META[ws].code}] ${cardLabel(card)} selesai` + (parsed?.severity ? ' · ' + parsed.severity : ''),
      body: parsed?.caseName || 'Laporan siap',
    });
    if (w.settings.desktopNotify && document.hidden && typeof Notification !== 'undefined' && Notification.permission === 'granted') {
      try { new Notification(`Diptera ${WORKSPACE_META[ws].code} · ${cardLabel(card)} selesai`, { body: parsed?.caseName || 'Laporan siap' }); } catch {}
    }
    fetchSharedState(true);
    persist();
  }

  async function failCard(card, e, ws = card.workspace || state.activeWorkspace) {
    const w = wsState(ws);
    if (!w.cards.includes(card)) return;
    const isAbort = e && e.name === 'AbortError';
    card.status = 'error';
    card.errorMsg = isAbort ? 'Dibatalkan' : (e?.message || 'Tidak bisa menghubungi n8n');
    card.errorHint = isAbort
      ? 'Klik "Periksa Hasil Lagi" jika workflow di n8n masih berjalan.'
      : (e?.hint || 'Pastikan n8n berjalan dan Base URL benar.');
    card.errorDetail = e?.detail || null;
    card.elapsedMs = Date.now() - (card.startedAt || Date.now());

    if (state.serverOnline && card.historyId && !isAbort) {
      apiFetch('/api/history/' + encodeURIComponent(card.historyId), {
        method: 'PATCH',
        body: JSON.stringify({ workspace: ws, status: 'error', errorMsg: card.errorMsg }),
      }).catch(() => {});
    }

    if (ws === state.activeWorkspace) refreshCard(card);
    toast({ type: 'error', title: `[${WORKSPACE_META[ws].code}] ${cardLabel(card)} gagal`, body: card.errorMsg });
    persist();
  }

  async function recheckCard(card) {
    const ws = card.workspace || state.activeWorkspace;
    if (card.busy || (!card.waitingUrl && !card.historyId)) return;
    card.busy = true;
    card.status = 'running';
    card.errorMsg = card.errorDetail = card.errorHint = null;
    if (ws === state.activeWorkspace) {
      refreshCard(card);
      updateStats();
    }
    updateWorkspaceBadges();
    const ctrl = new AbortController();
    card.abort = ctrl;
    try {
      const opts = effectiveRunOptions(card);
      const parsed = card.waitingUrl
        ? await pollForResult(card, ctrl.signal, opts, ws)
        : await pollServerCallbackOnly(card, ctrl.signal, opts, ws);
      await finishCardDone(card, parsed, ws);
    } catch (e) {
      await failCard(card, e, ws);
    } finally {
      card.busy = false;
      card.abort = null;
      if (ws === state.activeWorkspace) {
        refreshCard(card);
        updateStats();
        updateToolbar();
      }
      updateWorkspaceBadges();
      persist();
    }
  }

  /* ---------------- Shared History View ---------------- */

  function syncHistoryWorkspaceTabs() {
    for (const ws of ['asoc', 'soc']) {
      const btn = $('#hist-ws-' + ws);
      const active = state.historyWorkspace === ws;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-pressed', String(active));
    }
    const modeFilter = $('#hist-filter-mode');
    if (modeFilter) {
      modeFilter.hidden = state.historyWorkspace !== 'asoc';
      if (state.historyWorkspace !== 'asoc') modeFilter.value = '';
    }
    populateHistoryTenantFilter();
  }

  function populateHistoryTenantFilter() {
    const sel = $('#hist-filter-tenant');
    if (!sel) return;
    const ws = state.view === 'history' ? state.historyWorkspace : state.activeWorkspace;
    const w = wsState(ws);
    const prev = sel.value;
    const tenants = Array.from(new Set([
      ...(w.counters.tenants || []),
      ...(w.settings.fields.find((f) => f.role === 'tenant')?.options || []),
    ]));
    sel.innerHTML = '<option value="">Semua Tenant</option>' +
      tenants.map((t) => `<option value="${esc(t)}">${esc(t)}</option>`).join('');
    sel.value = tenants.includes(prev) ? prev : '';
  }

  function renderHistoryTable() {
    const tbody = $('#history-tbody');
    const emptyEl = $('#history-empty');
    const wrap = $('.history-table-wrap');
    if (!tbody) return;

    const ws = state.historyWorkspace;
    if (!state.history.length) {
      tbody.innerHTML = '';
      wrap.hidden = true;
      emptyEl.hidden = false;
      return;
    }

    wrap.hidden = false;
    emptyEl.hidden = true;
    tbody.innerHTML = '';

    for (const item of state.history) {
      const tr = document.createElement('tr');
      const itemWs = item.workspace === 'soc' ? 'soc' : 'asoc';
      const cidHref = irisCaseLink(item.irisCaseId, itemWs);
      const cidHtml = item.irisCaseId
        ? (cidHref
          ? `<a class="iris-link" href="${esc(cidHref)}" target="_blank" rel="noopener">${esc(formatCaseIdBadge(item.irisCaseId))}</a>`
          : `<span class="mono">${esc(formatCaseIdBadge(item.irisCaseId))}</span>`)
        : '<span class="field-hint">—</span>';

      tr.innerHTML = `
        <td class="mono">${esc(fmtWib(item.createdAt))}</td>
        <td><span class="chip mode-${esc(item.mode)}">${itemWs === 'soc' ? 'SOC' : (item.mode === 'repeating' ? 'Repeating' : 'Reporting')}</span></td>
        <td>${esc(item.tenant || '—')}</td>
        <td class="mono">${esc(item.ticketNumber || '—')}</td>
        <td>${cidHtml}</td>
        <td class="hist-case-cell">
          <span class="hist-case-title" title="${esc(item.caseName || '')}">${esc(item.caseName || '(Menunggu hasil AI)')}</span>
          <span class="hist-case-sub">
            ${item.severity ? `<span class="chip sev-${esc(item.severity)}">${esc(item.severity)}</span>` : ''}
            ${item.classification ? `<span class="field-hint">${esc(item.classification)}</span>` : ''}
          </span>
        </td>
        <td><span class="chip status-${esc(item.status)}">${esc(STATUS_LABEL[item.status] || item.status)}</span></td>
        <td>
          <div class="hist-actions">
            ${item.markdown ? `<button class="btn ghost btn-xs act-toggle-md" type="button">${state.expandedHistoryId === item.id ? 'Tutup MD' : 'Lihat MD'}</button>` : ''}
            ${item.markdown ? '<button class="btn ghost btn-xs act-copy-md" type="button">Salin MD</button>' : ''}
            <button class="btn ghost btn-xs act-repeat" type="button">${ws === 'asoc' ? 'Ulangi' : 'Duplikat'}</button>
          </div>
        </td>
      `;

      const toggleBtn = $('.act-toggle-md', tr);
      if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
          state.expandedHistoryId = state.expandedHistoryId === item.id ? null : item.id;
          renderHistoryTable();
        });
      }
      const copyBtn = $('.act-copy-md', tr);
      if (copyBtn) copyBtn.addEventListener('click', () => copyText(item.markdown, 'Markdown'));
      const repeatBtn = $('.act-repeat', tr);
      if (repeatBtn) {
        repeatBtn.addEventListener('click', () => createRepeatFromMeta({
          workspace: itemWs,
          tenant: item.tenant,
          ticketNumber: item.ticketNumber,
          irisCaseId: item.irisCaseId,
        }));
      }
      tbody.appendChild(tr);

      if (state.expandedHistoryId === item.id && item.markdown) {
        const mdTr = document.createElement('tr');
        mdTr.className = 'hist-md-row';
        mdTr.innerHTML = `<td colspan="8"><pre class="md-pre">${esc(item.markdown)}</pre></td>`;
        tbody.appendChild(mdTr);
      }
    }
  }

  /* ---------------- Settings (Per-Workspace) ---------------- */

  function fillSettingsForm(ws = state.settingsWorkspace) {
    state.settingsWorkspace = ws === 'soc' ? 'soc' : 'asoc';
    const w = wsState(state.settingsWorkspace);
    const meta = WORKSPACE_META[state.settingsWorkspace];

    $('#set-ws-asoc').classList.toggle('active', state.settingsWorkspace === 'asoc');
    $('#set-ws-asoc').setAttribute('aria-pressed', String(state.settingsWorkspace === 'asoc'));
    $('#set-ws-soc').classList.toggle('active', state.settingsWorkspace === 'soc');
    $('#set-ws-soc').setAttribute('aria-pressed', String(state.settingsWorkspace === 'soc'));
    $('#settings-title').textContent = `Pengaturan Workspace ${meta.code} (${meta.subtitle})`;
    const clearBtn = $('#btn-clear-all');
    if (clearBtn) {
      delete clearBtn.dataset.confirm;
      clearTimeout(clearBtn._confirmTimer);
      clearBtn.textContent = `Hapus semua kartu ${meta.code}`;
    }
    $('#set-form-path-label').textContent = `Form path ${meta.subtitle}`;
    $('#set-iris-url-wrap').hidden = !meta.hasIrisAuto;
    $('#set-case-id-mode-wrap').hidden = !meta.hasIrisAuto;
    $('#set-last-case-label').textContent = state.settingsWorkspace === 'asoc'
      ? 'IRIS Case ID Terakhir (Acuan Server)'
      : 'Case ID Terakhir SOC (Acuan Server)';

    $('#set-base-url').value = w.settings.baseUrl;
    $('#set-form-path').value = w.settings.formPath;
    $('#set-iris-url').value = w.settings.irisBaseUrl;
    $('#set-case-id-mode').value = w.settings.caseIdMode;
    $('#set-submit-mode').value = w.settings.submitMode;
    $('#set-timeout').value = w.settings.timeoutMin;
    $('#set-auto-number').checked = w.settings.autoNumber !== false;
    $('#set-auto-collapse').checked = w.settings.autoCollapse !== false;
    $('#set-auto-resume').checked = w.settings.autoResume !== false;
    $('#set-rewrite-host').checked = w.settings.rewriteHost !== false;
    $('#set-desktop-notify').checked = Boolean(w.settings.desktopNotify);
    $('#set-last-case-id').value = w.counters.lastIrisCaseId || '';
    $('#set-fields-json').value = JSON.stringify(w.settings.fields, null, 2);
    $('#base-url-page-hint').textContent = 'Tebakan halaman ini: ' + guessBaseUrl();
    renderTenantsSettingsList(state.settingsWorkspace);
  }

  function renderTenantsSettingsList(ws = state.settingsWorkspace) {
    const w = wsState(ws);
    const list = $('#tenants-list');
    list.innerHTML = '';
    const tenants = Array.from(new Set([
      ...(w.counters.tenants || []),
      ...(w.settings.fields.find((f) => f.role === 'tenant')?.options || []),
      ...Object.keys(w.counters.ticketsByTenant || {}),
    ]));
    for (const t of tenants) {
      addTenantSettingsRow(t, (w.counters.ticketsByTenant || {})[t] || '');
    }
  }

  function addTenantSettingsRow(name, ticketNum) {
    const row = document.createElement('div');
    row.className = 'tenant-row';
    row.innerHTML = `
      <input type="text" class="t-name" aria-label="Nama tenant" placeholder="Nama tenant" value="${esc(name)}" spellcheck="false" />
      <input type="text" class="t-num" aria-label="Nomor tiket terakhir" placeholder="Nomor tiket terakhir" value="${esc(ticketNum)}" spellcheck="false" />
      <button class="tenant-del" type="button" title="Hapus tenant">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M18 6L6 18M6 6l12 12" />
        </svg>
        <span class="sr-only">Hapus</span>
      </button>
    `;
    $('.tenant-del', row).addEventListener('click', () => row.remove());
    $('#tenants-list').appendChild(row);
  }

  async function saveSettings() {
    const ws = state.settingsWorkspace;
    const w = wsState(ws);
    const meta = WORKSPACE_META[ws];
    const parsedFields = safeJson($('#set-fields-json').value);
    if (!Array.isArray(parsedFields) || !parsedFields.length) {
      toast({ type: 'error', title: 'Definisi field JSON tidak valid', body: 'Harus berupa JSON array.' });
      return;
    }

    const tenants = [];
    const ticketsByTenant = {};
    document.querySelectorAll('#tenants-list .tenant-row').forEach((row) => {
      const name = $('.t-name', row).value.trim();
      const num = $('.t-num', row).value.trim();
      if (!name) return;
      if (!tenants.includes(name)) tenants.push(name);
      if (num) ticketsByTenant[name] = num;
    });

    const tenantField = parsedFields.find((f) => f.role === 'tenant');
    if (tenantField) tenantField.options = tenants;

    w.settings = {
      baseUrl: $('#set-base-url').value.trim().replace(/\/+$/, '') || meta.defaultBaseUrl,
      formPath: $('#set-form-path').value.trim() || meta.defaultFormPath,
      irisBaseUrl: meta.hasIrisAuto
        ? ($('#set-iris-url').value.trim().replace(/\/+$/, '') || meta.defaultIrisBaseUrl)
        : '',
      caseIdMode: meta.hasIrisAuto ? ($('#set-case-id-mode').value === 'manual' ? 'manual' : 'auto_iris') : 'manual',
      submitMode: $('#set-submit-mode').value === 'parallel' ? 'parallel' : 'sequential',
      timeoutMin: Math.max(1, Number($('#set-timeout').value) || 30),
      autoNumber: $('#set-auto-number').checked,
      autoCollapse: $('#set-auto-collapse').checked,
      autoResume: $('#set-auto-resume').checked,
      rewriteHost: $('#set-rewrite-host').checked,
      desktopNotify: $('#set-desktop-notify').checked,
      fields: parsedFields,
    };

    if (w.settings.desktopNotify && typeof Notification !== 'undefined' && Notification.permission === 'default') {
      Notification.requestPermission().catch(() => {});
    }

    const lastIrisCaseId = $('#set-last-case-id').value.trim() || null;

    try {
      const resp = await apiFetch('/api/counters/sync', {
        method: 'POST',
        body: JSON.stringify({
          workspace: ws,
          force: true,
          replace: true,
          lastIrisCaseId,
          tenants,
          ticketsByTenant,
          updatedBy: 'settings',
        }),
      });
      if (resp?.counters) w.counters = resp.counters;
      state.serverOnline = true;
      toast({ type: 'success', title: `Pengaturan ${meta.code} disimpan`, body: 'Acuan server disinkronkan untuk seluruh tim.' });
    } catch (e) {
      w.counters = { ...w.counters, lastIrisCaseId, tenants, ticketsByTenant };
      toast({ type: 'error', title: 'Tersimpan lokal, gagal sinkron server', body: e.message });
    }

    recomputeQueueTickets(ws, { noPersist: true });
    if (ws === state.activeWorkspace) {
      updateFormLink();
      renderSharedBar();
      populateHistoryTenantFilter();
      for (const card of w.cards) {
        rebuildCardFields(card);
        refreshCard(card);
      }
    }
    $('#settings-panel').hidden = true;
    $('#btn-settings').setAttribute('aria-expanded', 'false');
    persist();
  }

  /* ---------------- UI Helpers ---------------- */

  function switchView(view) {
    state.view = view === 'history' ? 'history' : 'queue';
    const isHist = state.view === 'history';
    $('#view-queue').hidden = isHist;
    $('#view-history').hidden = !isHist;
    $('#tab-queue').classList.toggle('active', !isHist);
    $('#tab-queue').setAttribute('aria-selected', String(!isHist));
    $('#tab-history').classList.toggle('active', isHist);
    $('#tab-history').setAttribute('aria-selected', String(isHist));
    if (isHist) {
      state.historyWorkspace = state.activeWorkspace;
      syncHistoryWorkspaceTabs();
      fetchHistory();
    }
  }

  function updateFormLink() {
    const w = wsState(state.activeWorkspace);
    $('#link-form').href = joinUrl(w.settings.baseUrl, '/form/' + encodeURIComponent(w.settings.formPath));
  }

  function updateStats() {
    const w = wsState(state.activeWorkspace);
    const counts = { done: 0, running: 0, pending: 0, error: 0 };
    for (const c of w.cards) {
      if (c.status === 'done') counts.done++;
      else if (c.status === 'running' || c.status === 'queued') counts.running++;
      else if (c.status === 'error') counts.error++;
      else counts.pending++;
    }
    for (const [k, v] of Object.entries(counts)) {
      const b = $(`#stats .stat[data-stat="${k}"] b`);
      if (b) b.textContent = String(v);
    }
    $('#tab-queue-count').textContent = String(w.cards.length);
    $('#empty-state').hidden = w.cards.length > 0;
    updateWorkspaceBadges();
  }

  function updateToolbar() {
    const ws = state.activeWorkspace;
    const w = wsState(ws);
    const eligible = w.cards.filter((c) => c.status === 'idle' || c.status === 'error');
    const anyBusy = w.cards.some((c) => c.busy);
    $('#btn-submit-all').disabled = w.submitAllRunning || anyBusy || !eligible.length;
    $('#btn-submit-all').className = 'btn ' + (ws === 'asoc' && w.activeMode === 'repeating' ? 'amber' : 'accent');
    $('#btn-submit-all-label').textContent = (ws === 'asoc' && w.activeMode === 'repeating')
      ? `Jalankan Repeat (${eligible.length})`
      : `Kirim Semua (${eligible.length})`;
    $('#btn-cancel').hidden = !(w.submitAllRunning || anyBusy);
    const anyExpanded = w.cards.some((c) => !c.collapsed);
    $('#btn-toggle-all').textContent = anyExpanded ? 'Tutup semua' : 'Buka semua';
    const doneCount = w.cards.filter((c) => c.status === 'done').length;
    const clearDoneBtn = $('#btn-clear-done');
    if (clearDoneBtn) {
      clearDoneBtn.hidden = doneCount === 0;
      clearDoneBtn.textContent = `Hapus selesai (${doneCount})`;
    }
  }

  function toast(opts) {
    const wrap = $('#toasts');
    const el = document.createElement('div');
    el.className = 'toast ' + (opts.type || 'info');
    if (opts.type === 'error') el.setAttribute('role', 'alert');
    const bodyHtml = opts.body ? `<div class="toast-body">${esc(opts.body)}</div>` : '';
    if (opts.actionLabel && typeof opts.onAction === 'function') {
      el.innerHTML = `<div class="toast-row"><div><div class="toast-title">${esc(opts.title || '')}</div>${bodyHtml}</div><button class="toast-action" type="button">${esc(opts.actionLabel)}</button></div>`;
      $('.toast-action', el).addEventListener('click', (e) => {
        e.stopPropagation();
        opts.onAction();
        el.remove();
      });
    } else {
      el.innerHTML = `<div class="toast-title">${esc(opts.title || '')}</div>` + bodyHtml;
    }
    el.addEventListener('click', () => el.remove());
    wrap.appendChild(el);
    setTimeout(() => el.remove(), opts.actionLabel ? 6500 : 5500);
  }

  /* ---------------- Event Binding & Init ---------------- */

  function bindEvents() {
    $('#ws-asoc').addEventListener('click', () => switchWorkspace('asoc'));
    $('#ws-soc').addEventListener('click', () => switchWorkspace('soc'));

    $('#tab-queue').addEventListener('click', () => switchView('queue'));
    $('#tab-history').addEventListener('click', () => switchView('history'));

    $('#btn-refresh-shared').addEventListener('click', () => fetchSharedState(false));

    $('#btn-settings').addEventListener('click', () => {
      const panel = $('#settings-panel');
      const open = panel.hidden;
      if (open) fillSettingsForm(state.activeWorkspace);
      panel.hidden = !open;
      $('#btn-settings').setAttribute('aria-expanded', String(open));
    });
    $('#set-ws-asoc').addEventListener('click', () => fillSettingsForm('asoc'));
    $('#set-ws-soc').addEventListener('click', () => fillSettingsForm('soc'));

    $('#btn-base-from-page').addEventListener('click', () => { $('#set-base-url').value = guessBaseUrl(); });
    $('#btn-add-tenant').addEventListener('click', () => addTenantSettingsRow('', ''));
    $('#btn-save-settings').addEventListener('click', saveSettings);
    $('#btn-close-settings').addEventListener('click', () => {
      $('#settings-panel').hidden = true;
      $('#btn-settings').setAttribute('aria-expanded', 'false');
    });
    $('#btn-reset-settings').addEventListener('click', () => {
      const ws = state.settingsWorkspace;
      wsState(ws).settings = buildDefaultSettings(ws);
      fillSettingsForm(ws);
      toast({ type: 'info', title: `Pengaturan lokal ${WORKSPACE_META[ws].code} di-reset`, body: 'Klik Simpan & Sinkronkan untuk menerapkan.' });
    });
    $('#btn-clear-all').addEventListener('click', (e) => {
      const btn = e.currentTarget;
      const ws = state.settingsWorkspace;
      const meta = WORKSPACE_META[ws];
      if (btn.dataset.confirm !== '1') {
        btn.dataset.confirm = '1';
        btn.textContent = `Klik lagi untuk hapus semua kartu ${meta.code}`;
        clearTimeout(btn._confirmTimer);
        btn._confirmTimer = setTimeout(() => {
          delete btn.dataset.confirm;
          btn.textContent = `Hapus semua kartu ${WORKSPACE_META[state.settingsWorkspace].code}`;
        }, 4000);
        return;
      }
      delete btn.dataset.confirm;
      clearTimeout(btn._confirmTimer);
      btn.textContent = `Hapus semua kartu ${meta.code}`;

      const w = wsState(ws);
      w.submitAllRunning = false;
      for (const c of w.cards) {
        if (c.busy && c.abort) c.abort.abort();
      }
      w.cards = [newCard({}, ws)];
      if (ws === state.activeWorkspace) {
        renderAllCards();
      } else {
        updateWorkspaceBadges();
      }
      persist();
      toast({ type: 'info', title: `Semua kartu ${meta.code} dibersihkan`, body: 'Satu form kosong baru telah disiapkan.' });
    });

    $('#mode-reporting').addEventListener('click', () => setActiveMode('reporting'));
    $('#mode-repeating').addEventListener('click', () => setActiveMode('repeating'));

    document.querySelectorAll('.preset-btn[data-preset]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const p = REPEAT_PRESETS[btn.dataset.preset];
        if (!p) return;
        wsState('asoc').repeatOptions = clone(p);
        syncRepeatPanelInputs();
        applyRepeatOptionsToIdleCards();
      });
    });

    const bindRepeatCheck = (id, key) => {
      $(id).addEventListener('change', (e) => {
        wsState('asoc').repeatOptions[key] = e.target.checked;
        updateRepeatDependencyHint();
        applyRepeatOptionsToIdleCards();
      });
    };
    bindRepeatCheck('#rep-create-iris', 'createIrisCase');
    bindRepeatCheck('#rep-update-iris', 'updateIrisSummary');
    bindRepeatCheck('#rep-approval', 'requireApproval');
    bindRepeatCheck('#rep-email', 'sendEmailPdf');
    bindRepeatCheck('#rep-gdoc', 'uploadGdoc');
    bindRepeatCheck('#rep-sheet', 'appendSheet');
    bindRepeatCheck('#rep-md', 'returnMarkdown');

    const addFormAction = () => {
      const ws = state.activeWorkspace;
      const w = wsState(ws);
      const card = newCard({}, ws);
      w.cards.push(card);
      $('#cards').appendChild(buildCardElement(card));
      updateStats();
      updateToolbar();
      persist();
    };
    $('#btn-add').addEventListener('click', addFormAction);
    $('#btn-add-empty').addEventListener('click', addFormAction);
    $('#btn-submit-all').addEventListener('click', submitAll);
    $('#btn-cancel').addEventListener('click', cancelAll);
    $('#btn-toggle-all').addEventListener('click', () => {
      const w = wsState(state.activeWorkspace);
      const collapse = w.cards.some((c) => !c.collapsed);
      for (const c of w.cards) {
        c.collapsed = collapse;
        syncCardTextareas(c);
        refreshCard(c);
      }
      updateToolbar();
      persist();
    });
    $('#btn-clear-done').addEventListener('click', () => {
      const ws = state.activeWorkspace;
      const w = wsState(ws);
      const before = w.cards.length;
      w.cards = w.cards.filter((c) => c.status !== 'done');
      if (!w.cards.length) w.cards.push(newCard({}, ws));
      renderAllCards();
      persist();
      const removed = before - w.cards.length;
      if (removed > 0) {
        toast({ type: 'info', title: `${removed} kartu selesai dibersihkan` });
      }
    });

    $('#hist-ws-asoc').addEventListener('click', () => {
      state.historyWorkspace = 'asoc';
      syncHistoryWorkspaceTabs();
      fetchHistory();
    });
    $('#hist-ws-soc').addEventListener('click', () => {
      state.historyWorkspace = 'soc';
      syncHistoryWorkspaceTabs();
      fetchHistory();
    });

    let searchTimer = null;
    $('#hist-search').addEventListener('input', () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(fetchHistory, 200);
    });
    $('#hist-filter-tenant').addEventListener('change', fetchHistory);
    $('#hist-filter-mode').addEventListener('change', fetchHistory);
    $('#btn-hist-refresh').addEventListener('click', fetchHistory);

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && !$('#settings-panel').hidden) {
        e.preventDefault();
        $('#settings-panel').hidden = true;
        $('#btn-settings').setAttribute('aria-expanded', 'false');
        $('#btn-settings').focus();
      } else if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && state.view === 'queue') {
        e.preventDefault();
        const cardEl = document.activeElement?.closest?.('.card[data-id]');
        if (cardEl) {
          const w = wsState(state.activeWorkspace);
          const card = w.cards.find((c) => c.id === cardEl.dataset.id);
          if (card) {
            submitCard(card);
            return;
          }
        }
        submitAll();
      } else if (e.altKey && e.key === '1') {
        e.preventDefault();
        switchWorkspace('asoc');
      } else if (e.altKey && e.key === '2') {
        e.preventDefault();
        switchWorkspace('soc');
      }
    });

    window.addEventListener('focus', () => fetchSharedState(true));
    window.addEventListener('beforeunload', flushPersist);
  }

  function applyRepeatOptionsToIdleCards() {
    const w = wsState('asoc');
    for (const card of w.cards) {
      if (card.status === 'idle' && card.mode === 'repeating') {
        card.repeatOptions = clone(w.repeatOptions);
        rebuildCardFields(card);
        refreshCard(card);
      }
    }
    persist();
  }

  async function init() {
    loadLocalState();
    bindEvents();
    syncRepeatPanelInputs();

    for (const ws of ['asoc', 'soc']) {
      if (!state.workspaces[ws].cards.length) {
        state.workspaces[ws].cards.push(newCard({}, ws));
      }
    }

    updateWorkspaceChrome();
    setActiveMode(wsState(state.activeWorkspace).activeMode, { skipPersist: true });
    updateFormLink();
    renderAllCards();

    await fetchSharedState(false);
    sharedPollTimer = setInterval(() => fetchSharedState(true), 15000);

    for (const ws of ['asoc', 'soc']) {
      for (const card of state.workspaces[ws].cards) {
        if (card.status === 'running' && (card.waitingUrl || card.historyId)) {
          recheckCard(card);
        }
      }
    }
  }

  init();
})();
