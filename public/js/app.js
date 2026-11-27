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
        label: 'Nomor Tiket',
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
        placeholder: 'Tempel alert JSON atau NDJSON…',
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

  function renderMdSafe(markdown) {
    if (window.AlphaMarkdown && typeof window.AlphaMarkdown.renderMarkdown === 'function') {
      return window.AlphaMarkdown.renderMarkdown(markdown);
    }
    return `<pre class="md-pre">${esc(markdown)}</pre>`;
  }

  function buildMarkdownViewerHtml(markdown, { dataPreKind = '' } = {}) {
    const preAttr = dataPreKind ? ` data-pre-kind="${esc(dataPreKind)}"` : '';
    return `
      <div class="md-viewer">
        <div class="md-viewer-bar">
          <span class="md-viewer-title">Ringkasan Laporan</span>
          <div class="md-viewer-tabs" role="tablist">
            <button type="button" role="tab" class="md-mode-btn active" data-md-mode="rendered" aria-selected="true">Pratinjau</button>
            <button type="button" role="tab" class="md-mode-btn" data-md-mode="raw" aria-selected="false">Teks Markdown</button>
          </div>
        </div>
        <div class="md-rendered"${preAttr}>${renderMdSafe(markdown)}</div>
        <pre class="md-pre"${preAttr} hidden>${esc(markdown)}</pre>
      </div>
    `;
  }

  function wireMarkdownViewers(rootEl) {
    if (!rootEl) return;
    rootEl.querySelectorAll('.md-viewer').forEach((viewer) => {
      const renderedEl = $('.md-rendered', viewer);
      const rawEl = $('.md-pre', viewer);
      const btns = viewer.querySelectorAll('.md-mode-btn');
      btns.forEach((btn) => {
        btn.addEventListener('click', () => {
          const isRaw = btn.dataset.mdMode === 'raw';
          if (renderedEl) renderedEl.hidden = isRaw;
          if (rawEl) rawEl.hidden = !isRaw;
          btns.forEach((b) => {
            const active = b === btn;
            b.classList.toggle('active', active);
            b.setAttribute('aria-selected', String(active));
          });
        });
      });
    });
  }
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

  function fmtRemaining(iso) {
    if (!iso) return null;
    const targetMs = Date.parse(iso);
    if (Number.isNaN(targetMs)) return null;
    const diffMs = targetMs - Date.now();
    if (diffMs <= 0) return { text: 'Lewat batas waktu', cls: 'overdue' };
    const totalMin = Math.floor(diffMs / 60000);
    const h = Math.floor(totalMin / 60);
    const m = totalMin % 60;
    const text = h > 0 ? `Batas ${h}j ${m}m` : `Batas ${Math.max(1, m)}m`;
    return { text, cls: diffMs <= 3600000 ? 'soon' : '' };
  }

  function fmtRetryCountdown(iso) {
    if (!iso) return null;
    const targetMs = Date.parse(iso);
    if (Number.isNaN(targetMs)) return null;
    const diffMs = targetMs - Date.now();
    if (diffMs <= 0) return 'Menunggu jadwal ulang…';
    const min = Math.max(1, Math.ceil(diffMs / 60000));
    return `Auto ulang ${min}m`;
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

  function approvalEndpointUrl() {
    if (CONFIG && typeof CONFIG.publicUrl === 'string' && CONFIG.publicUrl.trim()) {
      return CONFIG.publicUrl.trim().replace(/\/+$/, '') + '/api/approvals';
    }
    return window.location.origin + '/api/approvals';
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
    approvals: [],
    approvalCounts: {
      pending: 0,
      approved: 0,
      denied: 0,
      expired: 0,
      total: 0,
      byWorkspace: { asoc: { pending: 0, total: 0 }, soc: { pending: 0, total: 0 } },
    },
    approvalStatusFilter: 'pending',
    approvalWorkspaceFilter: 'all',
    approvalSeverityFilter: '',
    analystName: '',
    knownPendingApprovalIds: null,
    expandedApprovalMdIds: new Set(),
    expandedApprovalDataIds: new Set(),
    approvalDraftReasons: new Map(),
    openRejections: [],
    rejectionCounts: { open: 0, acknowledged: 0, resolved: 0, total: 0 },
    knownOpenRejectionIds: null,
    lastRejectionBannerSig: null,
    authEnabled: Boolean(CONFIG.authEnabled),
    currentUser: null,
    appStarted: false,
    users: [],
    resetPwTargetUser: null,
  };

  const bridgeViewListeners = [];
  const bridgeAuthListeners = [];
  const bridgeLogoutListeners = [];
  let persistTimer = null;
  let sharedPollTimer = null;
  let approvalPollTimer = null;
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
      if (typeof saved.analystName === 'string') {
        state.analystName = saved.analystName;
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
        analystName: state.analystName,
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
      credentials: 'same-origin',
      ...opts,
      headers: { 'content-type': 'application/json', ...(opts.headers || {}) },
    });
    const text = await res.text();
    const json = safeJson(text);
    if (res.status === 401 && json?.code === 'AUTH_REQUIRED') {
      handleUnauthorized();
    }
    if (!res.ok) throw new Error(json?.error || ('HTTP ' + res.status));
    return json;
  }

  function stopPollingTimers() {
    if (sharedPollTimer) {
      clearInterval(sharedPollTimer);
      sharedPollTimer = null;
    }
    if (approvalPollTimer) {
      clearInterval(approvalPollTimer);
      approvalPollTimer = null;
    }
  }

  function handleUnauthorized() {
    if (!state.authEnabled) return;
    const hadUser = Boolean(state.currentUser);
    state.currentUser = null;
    stopPollingTimers();
    for (const fn of bridgeLogoutListeners) { try { fn(); } catch {} }
    setAuthUiState(null, true);
    if (hadUser) {
      toast({ type: 'info', title: 'Sesi berakhir', body: 'Silakan login kembali untuk melanjutkan.' });
    }
  }

  function setAuthUiState(user, authEnabled = state.authEnabled) {
    state.authEnabled = Boolean(authEnabled);
    state.currentUser = user || null;

    const topbar = $('.topbar');
    const appShell = $('#app-shell');
    const mainEl = $('main');
    const authScreen = $('#auth-screen');
    const userBar = $('#user-bar');
    const openFromSettingsBtn = $('#btn-open-user-modal-from-settings');
    const umTabUsers = $('#um-tab-users');
    const navUsersBtn = $('#nav-users');
    const analystInput = $('#appr-analyst-name');
    const reviewerPill = $('#appr-reviewer-pill');

    const lockedOut = state.authEnabled && !state.currentUser;
    if (authScreen) authScreen.hidden = !lockedOut;
    if (topbar) topbar.hidden = lockedOut;
    if (appShell) appShell.hidden = lockedOut;
    if (mainEl) mainEl.hidden = lockedOut;

    if (lockedOut) {
      if ($('#user-modal')) $('#user-modal').hidden = true;
      if ($('#view-settings')) $('#view-settings').hidden = true;
      const uInp = $('#login-username');
      if (uInp) setTimeout(() => uInp.focus(), 30);
      return;
    }

    if (state.currentUser) {
      const u = state.currentUser;
      const display = u.displayName || u.username;
      const initials = display.slice(0, 2).toUpperCase();
      if (userBar) userBar.hidden = false;
      if ($('#user-avatar')) $('#user-avatar').textContent = initials;
      if ($('#user-display-name')) $('#user-display-name').textContent = display;
      const badge = $('#user-role-badge');
      if (badge) {
        badge.textContent = u.role === 'admin' ? 'Admin' : 'Analyst';
        badge.className = 'role-badge ' + (u.role === 'admin' ? 'role-admin' : 'role-analyst');
      }
      if (openFromSettingsBtn) openFromSettingsBtn.hidden = false;
      if (umTabUsers) umTabUsers.hidden = u.role !== 'admin';
      if (navUsersBtn) navUsersBtn.hidden = u.role !== 'admin';
      state.analystName = display;
      if (analystInput) analystInput.hidden = true;
      if (reviewerPill) {
        reviewerPill.hidden = false;
        reviewerPill.innerHTML = `<span>${esc(display)}</span> <span class="role-badge ${u.role === 'admin' ? 'role-admin' : 'role-analyst'}">${esc(u.role === 'admin' ? 'Admin' : 'Analyst')}</span>`;
      }
    } else {
      if (userBar) userBar.hidden = true;
      if (openFromSettingsBtn) openFromSettingsBtn.hidden = true;
      if (umTabUsers) umTabUsers.hidden = true;
      if (navUsersBtn) navUsersBtn.hidden = true;
      if (analystInput) analystInput.hidden = false;
      if (reviewerPill) reviewerPill.hidden = true;
    }
  }

  function showInlineMsg(el, type, msg) {
    if (!el) return;
    if (!msg) {
      el.hidden = true;
      el.textContent = '';
      el.className = 'um-msg';
      return;
    }
    el.hidden = false;
    el.textContent = msg;
    el.className = 'um-msg ' + (type === 'ok' ? 'ok' : 'err');
  }

  async function handleLoginSubmit(e) {
    e.preventDefault();
    const errEl = $('#login-error');
    const submitBtn = $('#btn-login-submit');
    const username = ($('#login-username')?.value || '').trim();
    const password = $('#login-password')?.value || '';

    if (!username || !password) {
      if (errEl) {
        errEl.textContent = 'Username dan password wajib diisi.';
        errEl.hidden = false;
      }
      return;
    }

    if (errEl) errEl.hidden = true;
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'Memproses…';
    }
    try {
      const res = await apiFetch('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });
      if ($('#login-password')) $('#login-password').value = '';
      setAuthUiState(res.user, true);
      await startAppSession();
      toast({ type: 'success', title: 'Login berhasil', body: `Selamat datang, ${res.user.displayName || res.user.username}.` });
    } catch (err) {
      if (errEl) {
        errEl.textContent = err.message || 'Gagal login';
        errEl.hidden = false;
      }
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Masuk';
      }
    }
  }

  async function handleLogout() {
    try {
      await apiFetch('/api/auth/logout', { method: 'POST', body: '{}' });
    } catch {}
    stopPollingTimers();
    for (const fn of bridgeLogoutListeners) { try { fn(); } catch {} }
    state.users = [];
    state.knownPendingApprovalIds = null;
    state.knownOpenRejectionIds = null;
    setAuthUiState(null, state.authEnabled);
    toast({ type: 'info', title: 'Berhasil keluar' });
  }

  function switchUserModalTab(tab) {
    const isUsers = tab === 'users' && state.currentUser?.role === 'admin';
    $('#um-tab-account')?.classList.toggle('active', !isUsers);
    $('#um-tab-account')?.setAttribute('aria-selected', String(!isUsers));
    $('#um-tab-users')?.classList.toggle('active', isUsers);
    $('#um-tab-users')?.setAttribute('aria-selected', String(isUsers));
    if ($('#um-panel-account')) $('#um-panel-account').hidden = isUsers;
    if ($('#um-panel-users')) $('#um-panel-users').hidden = !isUsers;
    if (isUsers) fetchUsers();
  }

  function wireConfirmClick(btnEl, armedLabel, onConfirm) {
    if (!btnEl) return;
    const defaultLabel = btnEl.textContent;
    let timer = null;
    btnEl.addEventListener('click', async () => {
      if (btnEl.dataset.armed !== '1') {
        btnEl.dataset.armed = '1';
        btnEl.textContent = armedLabel;
        clearTimeout(timer);
        timer = setTimeout(() => {
          btnEl.dataset.armed = '0';
          btnEl.textContent = defaultLabel;
        }, 5000);
        return;
      }
      clearTimeout(timer);
      btnEl.dataset.armed = '0';
      btnEl.textContent = defaultLabel;
      await onConfirm();
    });
  }

  function openUserModal(defaultTab = 'account') {
    if (!state.currentUser) return;
    state.lastFocusBeforeModal = document.activeElement;
    const u = state.currentUser;
    if ($('#um-profile-name')) $('#um-profile-name').textContent = u.displayName || u.username;
    if ($('#um-profile-username')) $('#um-profile-username').textContent = '@' + u.username;
    const roleBadge = $('#um-profile-role');
    if (roleBadge) {
      roleBadge.textContent = u.role === 'admin' ? 'Admin' : 'Analyst';
      roleBadge.className = 'role-badge ' + (u.role === 'admin' ? 'role-admin' : 'role-analyst');
    }
    showInlineMsg($('#pw-msg'), '', '');
    showInlineMsg($('#create-user-msg'), '', '');
    if ($('#form-change-pw')) $('#form-change-pw').reset();
    if ($('#admin-reset-pw-box')) $('#admin-reset-pw-box').hidden = true;
    state.resetPwTargetUser = null;
    if ($('#user-modal')) $('#user-modal').hidden = false;
    switchUserModalTab(defaultTab);
    $('#btn-close-user-modal')?.focus();
  }

  function closeUserModal() {
    if ($('#user-modal')) $('#user-modal').hidden = true;
    state.resetPwTargetUser = null;
    if (state.lastFocusBeforeModal && typeof state.lastFocusBeforeModal.focus === 'function') {
      try { state.lastFocusBeforeModal.focus(); } catch {}
    }
    state.lastFocusBeforeModal = null;
  }

  async function handleChangeOwnPassword(e) {
    e.preventDefault();
    const msgEl = $('#pw-msg');
    const currentPassword = $('#pw-current')?.value || '';
    const newPassword = $('#pw-new')?.value || '';
    const confirmPassword = $('#pw-confirm')?.value || '';

    if (newPassword.length < 6) {
      showInlineMsg(msgEl, 'err', 'Password baru minimal 6 karakter.');
      return;
    }
    if (newPassword !== confirmPassword) {
      showInlineMsg(msgEl, 'err', 'Konfirmasi password baru tidak cocok.');
      return;
    }

    const btn = $('#btn-save-pw');
    if (btn) btn.disabled = true;
    try {
      await apiFetch('/api/auth/password', {
        method: 'POST',
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      if ($('#form-change-pw')) $('#form-change-pw').reset();
      showInlineMsg(msgEl, 'ok', 'Password berhasil diperbarui.');
      toast({ type: 'success', title: 'Password diperbarui' });
    } catch (err) {
      showInlineMsg(msgEl, 'err', err.message || 'Gagal mengganti password');
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function fetchUsers() {
    if (state.currentUser?.role !== 'admin') return;
    const tbody = $('#users-tbody');
    if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="hist-loading-cell">Memuat daftar user…</td></tr>';
    try {
      const res = await apiFetch('/api/users');
      state.users = Array.isArray(res?.users) ? res.users : [];
      renderUsersTable();
    } catch (err) {
      if (tbody) tbody.innerHTML = `<tr><td colspan="5" class="hist-loading-cell">${esc(err.message)}</td></tr>`;
    }
  }

  function renderUsersTable() {
    const tbody = $('#users-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (!state.users.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="hist-loading-cell">Belum ada user.</td></tr>';
      return;
    }
    const selfId = state.currentUser?.id;
    for (const u of state.users) {
      const isSelf = u.id === selfId;
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>
          <div><strong>${esc(u.displayName || u.username)}</strong>${isSelf ? ' <span class="chip">Anda</span>' : ''}</div>
          <div class="mono field-hint">@${esc(u.username)}</div>
        </td>
        <td><span class="role-badge ${u.role === 'admin' ? 'role-admin' : 'role-analyst'}">${esc(u.role === 'admin' ? 'Admin' : 'Analyst')}</span></td>
        <td><span class="chip ${u.isActive ? 'appr-approved' : 'appr-denied'}">${u.isActive ? 'Aktif' : 'Nonaktif'}</span></td>
        <td class="mono">${esc(fmtWib(u.createdAt))}</td>
        <td>
          <div class="hist-actions">
            <button type="button" class="btn ghost btn-xs act-user-reset-pw">Ganti Password</button>
            <button type="button" class="btn ghost btn-xs act-user-role">${u.role === 'admin' ? 'Jadikan Analyst' : 'Jadikan Admin'}</button>
            ${!isSelf ? '<button type="button" class="btn danger btn-xs act-user-del">Hapus</button>' : ''}
          </div>
        </td>
      `;

      $('.act-user-reset-pw', tr)?.addEventListener('click', () => openAdminResetPw(u));
      $('.act-user-role', tr)?.addEventListener('click', () => handleToggleUserRole(u));
      const delBtn = $('.act-user-del', tr);
      if (delBtn) {
        delBtn.addEventListener('click', () => {
          if (delBtn.dataset.confirm !== '1') {
            delBtn.dataset.confirm = '1';
            delBtn.textContent = 'Yakin Hapus?';
            setTimeout(() => {
              delete delBtn.dataset.confirm;
              delBtn.textContent = 'Hapus';
            }, 3500);
            return;
          }
          handleDeleteUser(u);
        });
      }
      tbody.appendChild(tr);
    }
  }

  async function handleCreateUser(e) {
    e.preventDefault();
    const msgEl = $('#create-user-msg');
    const username = ($('#new-user-username')?.value || '').trim();
    const displayName = ($('#new-user-displayname')?.value || '').trim();
    const role = $('#new-user-role')?.value || 'analyst';
    const password = $('#new-user-password')?.value || '';

    const btn = $('#btn-create-user');
    if (btn) btn.disabled = true;
    try {
      await apiFetch('/api/users', {
        method: 'POST',
        body: JSON.stringify({ username, displayName, role, password }),
      });
      if ($('#form-create-user')) $('#form-create-user').reset();
      showInlineMsg(msgEl, 'ok', `User "${username}" berhasil dibuat.`);
      toast({ type: 'success', title: 'User ditambahkan', body: `${displayName || username} (@${username})` });
      await fetchUsers();
    } catch (err) {
      showInlineMsg(msgEl, 'err', err.message || 'Gagal membuat user');
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function handleToggleUserRole(u) {
    const nextRole = u.role === 'admin' ? 'analyst' : 'admin';
    try {
      const res = await apiFetch('/api/users/' + encodeURIComponent(u.id), {
        method: 'PATCH',
        body: JSON.stringify({ role: nextRole }),
      });
      if (u.id === state.currentUser?.id && res?.user) {
        setAuthUiState(res.user, true);
      }
      toast({ type: 'info', title: 'Role diperbarui', body: `@${u.username} sekarang ${nextRole === 'admin' ? 'Admin' : 'Analyst'}` });
      await fetchUsers();
    } catch (err) {
      toast({ type: 'error', title: 'Gagal mengubah role', body: err.message });
    }
  }

  function openAdminResetPw(u) {
    state.resetPwTargetUser = u;
    const box = $('#admin-reset-pw-box');
    const lbl = $('#reset-pw-target-label');
    const inp = $('#reset-pw-input');
    if (lbl) lbl.textContent = `Ganti password untuk ${u.displayName || u.username} (@${u.username})`;
    if (inp) inp.value = '';
    if (box) box.hidden = false;
    if (inp) inp.focus();
  }

  async function handleAdminResetPwSubmit() {
    const u = state.resetPwTargetUser;
    if (!u) return;
    const newPassword = $('#reset-pw-input')?.value || '';
    if (newPassword.length < 6) {
      toast({ type: 'error', title: 'Password terlalu pendek', body: 'Minimal 6 karakter.' });
      return;
    }
    const btn = $('#btn-reset-pw-confirm');
    if (btn) btn.disabled = true;
    try {
      await apiFetch('/api/users/' + encodeURIComponent(u.id), {
        method: 'PATCH',
        body: JSON.stringify({ password: newPassword }),
      });
      if ($('#admin-reset-pw-box')) $('#admin-reset-pw-box').hidden = true;
      state.resetPwTargetUser = null;
      toast({ type: 'success', title: 'Password di-reset', body: `Password @${u.username} berhasil diperbarui.` });
    } catch (err) {
      toast({ type: 'error', title: 'Gagal mengganti password', body: err.message });
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function handleDeleteUser(u) {
    try {
      await apiFetch('/api/users/' + encodeURIComponent(u.id), { method: 'DELETE' });
      toast({ type: 'info', title: 'User dihapus', body: `@${u.username} telah dihapus.` });
      await fetchUsers();
    } catch (err) {
      toast({ type: 'error', title: 'Gagal menghapus user', body: err.message });
    }
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
      if (data?.approvals) {
        const prevPending = state.approvalCounts?.pending ?? 0;
        state.approvalCounts = data.approvals;
        updateApprovalTabCounts();
        updateWorkspaceBadges();
        const shouldRefreshApprovals = state.view === 'approvals' || data.approvals.pending !== prevPending || data.approvals.pending > 0;
        if (shouldRefreshApprovals && state.knownPendingApprovalIds !== null) {
          if (state.view === 'approvals' && (state.approvalStatusFilter === 'pending' || state.approvalStatusFilter === 'all')) {
            fetchApprovals(true, { notifyNew: true });
          } else {
            checkPendingApprovalsBackground(state.view === 'approvals');
          }
        }
      }
      if (data?.rejections) {
        state.rejectionCounts = data.rejections;
        state.openRejections = Array.isArray(data.rejections.openItems) ? data.rejections.openItems : [];
        notifyNewRejections(state.openRejections);
        renderRejectionBanner();
        updateWorkspaceBadges();
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
    $('#tab-history-label').textContent = 'Riwayat';
    const histTabCount = $('#tab-history-count');
    if (histTabCount) histTabCount.textContent = String(state.historyCounts[activeWs] ?? 0);
    $('#hist-count-asoc').textContent = String(state.historyCounts.asoc ?? 0);
    $('#hist-count-soc').textContent = String(state.historyCounts.soc ?? 0);
  }

  function updateApprovalTabCounts() {
    const c = state.approvalCounts || {};
    const pending = Number(c.pending) || 0;
    const tabCount = $('#tab-approvals-count');
    if (tabCount) {
      tabCount.textContent = String(pending);
      tabCount.classList.toggle('has-pending', pending > 0);
    }
    const map = {
      '#appr-count-pending': pending,
      '#appr-count-approved': Number(c.approved) || 0,
      '#appr-count-denied': Number(c.denied) || 0,
      '#appr-count-expired': Number(c.expired) || 0,
      '#appr-count-all': Number(c.total) || 0,
    };
    for (const [sel, val] of Object.entries(map)) {
      const el = $(sel);
      if (el) el.textContent = String(val);
    }
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
      tbody.innerHTML = `<tr><td colspan="9" class="hist-loading-cell">Memuat riwayat ${esc(WORKSPACE_META[ws].code)}…</td></tr>`;
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
        hint: '',
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
      ? 'Tambahkan form baru, atau ulangi laporan dari Riwayat.'
      : 'Tambahkan form baru, atau duplikat laporan dari Riwayat SOC.';

    updateWorkspaceBadges();
    updateViewHeading();
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
    const pendingAppr = Number(state.approvalCounts?.pending) || 0;
    const openRej = Number(state.rejectionCounts?.open) || 0;
    const titleParts = [];
    if (totalRunning > 0) titleParts.push(String(totalRunning));
    if (pendingAppr > 0) titleParts.push(`${pendingAppr} approval`);
    if (openRej > 0) titleParts.push(`${openRej} ditolak`);
    const prefix = titleParts.length ? `(${titleParts.join(' · ')}) ` : '';
    document.title = prefix + `Diptera — ${WORKSPACE_META[state.activeWorkspace].code} (${WORKSPACE_META[state.activeWorkspace].subtitle})`;
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

    if (state.view === 'settings') {
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
    updateViewHeading();
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
      labelEl.innerHTML = esc(field.label) + (isReq ? ' <span class="req-star">*</span>' : '');
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
        msg.hidden = !caseSpec.hint;
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
      msg.hidden = Boolean(isCaseId && !caseSpec.hint);

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
    r.summary.textContent = summaryParts.join(' · ');
    r.summary.hidden = summaryParts.length === 0;

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
        ? '<button class="chip status-queued act-open-approvals" type="button" title="Buka menu Approval di Diptera">Menunggu approval di Diptera ↗</button>'
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
          ? buildMarkdownViewerHtml(card.result.markdown)
          : '<div class="field-hint">Workflow selesai tanpa halaman Markdown (cek n8n untuk detail).</div>'}
      `;

      wireMarkdownViewers(r.resultBox);
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
      const openApprBtn = $('.act-open-approvals', r.resultBox);
      if (openApprBtn) openApprBtn.addEventListener('click', () => switchView('approvals'));
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
          createdBy: state.currentUser ? (state.currentUser.displayName || state.currentUser.username) : null,
          createdByUserId: state.currentUser?.id || null,
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

      const apprLabels = { pending: 'Approval', approved: 'Approved', denied: 'Denied', revised: 'Diperbaiki', expired: 'Expired' };
      const apprBadge = item.approvalStatus
        ? ` <span class="chip appr-${esc(item.approvalStatus)}">${esc(apprLabels[item.approvalStatus] || item.approvalStatus)}</span>`
        : '';

      const creatorName = item.createdByName || item.createdByUsername || '';
      const reviewerName = item.reviewedByName || item.reviewedByUsername || '';
      const actorsHtml = (creatorName || reviewerName)
        ? `<div class="hist-actors">
            ${creatorName ? `<div class="actor-line" title="Dibuat oleh ${esc(creatorName)}"><span class="actor-tag">Buat</span><span class="actor-name">${esc(creatorName)}</span></div>` : ''}
            ${reviewerName ? `<div class="actor-line" title="Direview oleh ${esc(reviewerName)}${item.reviewedAt ? ' · ' + fmtWib(item.reviewedAt) : ''}"><span class="actor-tag">Review</span><span class="actor-name">${esc(reviewerName)}</span></div>` : ''}
          </div>`
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
        <td><span class="chip status-${esc(item.status)}">${esc(STATUS_LABEL[item.status] || item.status)}</span>${apprBadge}</td>
        <td>${actorsHtml}</td>
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
        mdTr.innerHTML = `<td colspan="9">${buildMarkdownViewerHtml(item.markdown)}</td>`;
        wireMarkdownViewers(mdTr);
        tbody.appendChild(mdTr);
      }
    }
  }

  /* ---------------- Approval Center View ---------------- */

  const APPROVAL_STATUS_LABEL = {
    pending: 'Menunggu',
    approved: 'Disetujui',
    denied: 'Ditolak',
    revised: 'Diperbaiki',
    expired: 'Kedaluwarsa',
  };

  function safeExternalHref(rawUrl) {
    if (!rawUrl) return null;
    try {
      const u = new URL(String(rawUrl));
      return u.protocol === 'http:' || u.protocol === 'https:' ? u.toString() : null;
    } catch {
      return null;
    }
  }

  function findApprovalCardEl(id) {
    const cards = document.querySelectorAll('#approvals-list .approval-card');
    for (const el of cards) {
      if (el.dataset.apprId === id) return el;
    }
    return null;
  }

  function syncApprovalFilterControls() {
    document.querySelectorAll('.appr-status-btn[data-appr-status]').forEach((btn) => {
      const active = btn.dataset.apprStatus === state.approvalStatusFilter;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-pressed', String(active));
    });
    const wsSel = $('#appr-filter-ws');
    if (wsSel && wsSel.value !== state.approvalWorkspaceFilter) wsSel.value = state.approvalWorkspaceFilter;
    const sevSel = $('#appr-filter-sev');
    if (sevSel && sevSel.value !== state.approvalSeverityFilter) sevSel.value = state.approvalSeverityFilter;
  }

  function notifyNewApprovals(pendingItems) {
    if (state.knownPendingApprovalIds === null) {
      state.knownPendingApprovalIds = new Set(pendingItems.map((x) => x.id));
      return;
    }
    const fresh = pendingItems.filter((x) => !state.knownPendingApprovalIds.has(x.id));
    state.knownPendingApprovalIds = new Set(pendingItems.map((x) => x.id));
    if (!fresh.length) return;

    const first = fresh[0];
    const title = fresh.length === 1
      ? `Approval baru: ${first.caseName || formatCaseIdBadge(first.irisCaseId)}`
      : `${fresh.length} permintaan approval baru`;
    const body = [first.tenant, first.severity, first.workflowName].filter(Boolean).join(' · ') || 'Klik untuk meninjau di menu Approval.';

    toast({
      type: 'info',
      title,
      body,
      actionLabel: 'Buka Approval',
      onAction: () => switchView('approvals'),
    });

    const w = wsState(first.workspace || state.activeWorkspace);
    if (w.settings.desktopNotify && document.hidden && typeof Notification !== 'undefined' && Notification.permission === 'granted') {
      try { new Notification('Diptera · ' + title, { body }); } catch {}
    }
  }

  async function checkPendingApprovalsBackground(alsoRefreshView = false) {
    try {
      const data = await apiFetch('/api/approvals?status=pending&limit=200');
      const items = Array.isArray(data?.items) ? data.items : [];
      if (data?.counts) {
        state.approvalCounts = data.counts;
        updateApprovalTabCounts();
        updateWorkspaceBadges();
      }
      notifyNewApprovals(items);
      if (alsoRefreshView && state.view === 'approvals') {
        fetchApprovals(true, { notifyNew: false });
      }
    } catch {}
  }

  function updateApprovalCountdownsInPlace(items) {
    for (const item of items) {
      const cardEl = findApprovalCardEl(item.id);
      if (!cardEl) continue;
      const dlEl = $('.approval-deadline', cardEl);
      if (dlEl && item.deadlineAt) {
        const rem = fmtRemaining(item.deadlineAt);
        if (rem) {
          dlEl.textContent = rem.text;
          dlEl.className = 'approval-deadline' + (rem.cls ? ' ' + rem.cls : '');
        }
      }
      const retryEl = $('.rejection-retry-pill', cardEl);
      if (retryEl && item.nextRetryAt) {
        const retryLabel = fmtRetryCountdown(item.nextRetryAt);
        if (retryLabel) retryEl.textContent = retryLabel;
      }
    }
  }

  async function fetchApprovals(silent = false, opts = {}) {
    const status = state.approvalStatusFilter || 'pending';
    const ws = state.approvalWorkspaceFilter || 'all';
    const sev = state.approvalSeverityFilter || '';
    const q = ($('#appr-search')?.value || '').trim();

    const params = new URLSearchParams({
      status,
      workspace: ws,
      limit: '200',
    });
    if (sev) params.set('severity', sev);
    if (q) params.set('q', q);

    const listEl = $('#approvals-list');
    const emptyEl = $('#approvals-empty');

    const activeEl = document.activeElement;
    const typingTextarea = activeEl && activeEl.tagName === 'TEXTAREA' && activeEl.closest('#approvals-list');
    const activeCardId = typingTextarea ? typingTextarea.closest('.approval-card')?.dataset?.apprId : null;
    const selStart = typingTextarea ? typingTextarea.selectionStart : null;
    const selEnd = typingTextarea ? typingTextarea.selectionEnd : null;
    const apprSig = (list) =>
      list.map((x) => `${x.id}:${x.status}:${x.updatedAt}:${x.lastError || ''}:${x.rejectionStatus || ''}:${x.decidedBy || ''}:${x.createdByName || ''}`).join('|');
    const prevSig = apprSig(state.approvals);

    if (!silent && listEl) {
      if (emptyEl) emptyEl.hidden = true;
      listEl.hidden = false;
      listEl.innerHTML = '<div class="hist-loading-cell">Memuat daftar approval…</div>';
    }

    try {
      const data = await apiFetch('/api/approvals?' + params.toString());
      const nextItems = Array.isArray(data?.items) ? data.items : [];
      const nextSig = apprSig(nextItems);
      const domAlreadyRendered = nextItems.length === 0
        ? Boolean(emptyEl && !emptyEl.hidden)
        : Boolean(listEl && !listEl.hidden && listEl.querySelectorAll('.approval-card').length === nextItems.length && !listEl.querySelector('.hist-loading-cell'));

      state.approvals = nextItems;
      if (data?.counts) {
        state.approvalCounts = data.counts;
        updateApprovalTabCounts();
        updateWorkspaceBadges();
      }

      const isUnfilteredPendingSet = ws === 'all' && !sev && !q && (status === 'pending' || status === 'all');
      if (isUnfilteredPendingSet) {
        const pendingOnly = nextItems.filter((x) => x.status === 'pending');
        if (opts.notifyNew === false && state.knownPendingApprovalIds === null) {
          state.knownPendingApprovalIds = new Set(pendingOnly.map((x) => x.id));
        } else {
          notifyNewApprovals(pendingOnly);
        }
      }

      if (silent && prevSig === nextSig && domAlreadyRendered) {
        updateApprovalCountdownsInPlace(nextItems);
        return;
      }

      renderApprovalsList({ preserveScroll: silent });
      if (activeCardId) {
        const cardEl = findApprovalCardEl(activeCardId);
        const nextTa = cardEl ? $('.appr-reason-input', cardEl) : null;
        if (nextTa) {
          nextTa.focus({ preventScroll: true });
          if (selStart != null && selEnd != null) {
            try { nextTa.setSelectionRange(selStart, selEnd); } catch {}
          }
        }
      }
    } catch (e) {
      if (!silent) {
        toast({ type: 'error', title: 'Gagal memuat approval', body: e.message });
      }
    }
  }

  function renderApprovalsList(opts = {}) {
    const listEl = $('#approvals-list');
    const emptyEl = $('#approvals-empty');
    if (!listEl || !emptyEl) return;

    const preserveScroll = opts.preserveScroll !== false;
    const savedWinX = typeof window.scrollX === 'number' ? window.scrollX : 0;
    const savedWinY = typeof window.scrollY === 'number' ? window.scrollY : 0;
    const preScrollMap = new Map();
    listEl.querySelectorAll('.approval-card').forEach((card) => {
      const id = card.dataset.apprId;
      if (!id) return;
      card.querySelectorAll('[data-pre-kind]').forEach((pre) => {
        if (pre.hidden) return;
        preScrollMap.set(`${id}:${pre.dataset.preKind}`, {
          scrollTop: pre.scrollTop,
          scrollLeft: pre.scrollLeft,
        });
      });
    });

    if (!state.approvals.length) {
      listEl.replaceChildren();
      listEl.hidden = true;
      emptyEl.hidden = false;
      const hasFilters = Boolean(($('#appr-search')?.value || '').trim() || state.approvalWorkspaceFilter !== 'all' || state.approvalSeverityFilter);
      const titleMap = {
        pending: 'Tidak ada permintaan approval menunggu',
        approved: 'Belum ada approval yang disetujui',
        denied: 'Belum ada approval yang ditolak',
        expired: 'Tidak ada approval kedaluwarsa',
        all: 'Belum ada data approval tersimpan',
      };
      $('#approvals-empty-title').textContent = hasFilters
        ? 'Tidak ada approval yang cocok dengan filter'
        : (titleMap[state.approvalStatusFilter] || titleMap.all);
      $('#approvals-empty-desc').textContent = hasFilters
        ? 'Ubah kata kunci atau filter workspace/severity.'
        : 'Permintaan approval dari workflow n8n akan terkumpul di sini.';
      return;
    }

    emptyEl.hidden = true;
    listEl.hidden = false;
    const frag = document.createDocumentFragment();

    for (const item of state.approvals) {
      const cardEl = document.createElement('article');
      cardEl.className = `approval-card appr-${item.status || 'pending'}`;
      cardEl.dataset.apprId = item.id;

      const itemWs = item.workspace === 'soc' ? 'soc' : 'asoc';
      const wsMeta = WORKSPACE_META[itemWs];
      const caseHref = safeExternalHref(item.caseUrl) || irisCaseLink(item.irisCaseId, itemWs);
      const execHref = item.execId && wsState(itemWs).settings.baseUrl
        ? safeExternalHref(joinUrl(wsState(itemWs).settings.baseUrl, '/executions/' + encodeURIComponent(item.execId)))
        : null;

      const rem = item.status === 'pending' && item.deadlineAt ? fmtRemaining(item.deadlineAt) : null;
      const mdOpen = state.expandedApprovalMdIds.has(item.id);
      const dataOpen = state.expandedApprovalDataIds.has(item.id);
      const hasData = Boolean(item.alertData || item.metadata);
      const formattedData = hasData
        ? JSON.stringify(item.alertData ?? item.metadata, null, 2)
        : '';
      const draftReason = state.approvalDraftReasons.has(item.id)
        ? state.approvalDraftReasons.get(item.id)
        : (item.reason || '');

      const kvParts = [];
      if (item.createdByName || item.createdByUsername) kvParts.push(`<span class="approval-kv-item"><strong>Dibuat oleh:</strong> ${esc(item.createdByName || item.createdByUsername)}</span>`);
      if (item.workflowName) kvParts.push(`<span class="approval-kv-item"><strong>Workflow:</strong> ${esc(item.workflowName)}</span>`);
      if (item.tenant) kvParts.push(`<span class="approval-kv-item"><strong>Tenant:</strong> ${esc(item.tenant)}</span>`);
      if (item.clientName) kvParts.push(`<span class="approval-kv-item"><strong>Client:</strong> ${esc(item.clientName)}</span>`);
      if (item.ticketNumber) kvParts.push(`<span class="approval-kv-item"><strong>Tiket:</strong> <span class="mono">${esc(item.ticketNumber)}</span></span>`);
      if (item.openDate) kvParts.push(`<span class="approval-kv-item"><strong>Dibuat:</strong> ${esc(item.openDate)}</span>`);

      const auditActionLabel = item.status === 'approved'
        ? 'Disetujui'
        : (item.status === 'denied' ? 'Ditolak' : (item.status === 'revised' ? 'Diperbaiki' : 'Kedaluwarsa'));
      const auditMetaParts = [
        auditActionLabel,
        item.decidedBy ? `oleh ${item.decidedBy}` : '',
        item.decidedAt || item.updatedAt ? `pada ${fmtWib(item.decidedAt || item.updatedAt)}` : '',
        item.resumeHttpStatus ? `HTTP ${item.resumeHttpStatus}` : '',
      ].filter(Boolean).join(' ');

      let rejectionInlineHtml = '';
      if (item.status === 'denied' && item.rejectionId) {
        if (item.rejectionStatus === 'open') {
          const retryLabel = fmtRetryCountdown(item.nextRetryAt);
          rejectionInlineHtml = `
            <span class="approval-kv-row mt-4">
              ${retryLabel ? `<span class="rejection-retry-pill" title="n8n otomatis meminta approval ulang, atau klik Tandai Selesai untuk langsung meminta approval sekarang">${esc(retryLabel)}</span>` : ''}
            </span>`;
        } else if (item.rejectionStatus === 'acknowledged') {
          rejectionInlineHtml = '<span class="chip appr-approved align-start mt-4">Sudah ditangani</span>';
        } else if (item.rejectionStatus === 'resolved') {
          rejectionInlineHtml = '<span class="chip appr-expired align-start mt-4">Sudah diajukan ulang</span>';
        }
      }

      cardEl.innerHTML = `
        <div class="approval-card-head">
          <div class="approval-card-badges">
            <span class="shared-ws-pill">${esc(wsMeta.code)}</span>
            <span class="chip appr-${esc(item.status)}">${esc(APPROVAL_STATUS_LABEL[item.status] || item.status)}</span>
            ${item.severity ? `<span class="chip sev-${esc(item.severity)}">${esc(item.severity)}</span>` : ''}
            ${item.classification ? `<span class="chip">${esc(item.classification)}</span>` : ''}
            ${item.irisCaseId ? (caseHref
              ? `<a class="chip mode-reporting" href="${esc(caseHref)}" target="_blank" rel="noopener">IRIS ${esc(formatCaseIdBadge(item.irisCaseId))} ↗</a>`
              : `<span class="chip mode-reporting">Case ${esc(formatCaseIdBadge(item.irisCaseId))}</span>`) : ''}
            ${item.attempt > 1 ? `<span class="chip mode-repeating">Percobaan #${esc(item.attempt)}</span>` : ''}
          </div>
          <div class="approval-card-time">
            <span class="mono">${esc(fmtWib(item.createdAt))}</span>
            ${rem ? `<span class="approval-deadline${rem.cls ? ' ' + esc(rem.cls) : ''}" title="Deadline: ${esc(fmtWib(item.deadlineAt))}">${esc(rem.text)}</span>` : ''}
            ${item.execId ? (execHref
              ? `<a class="iris-link" href="${esc(execHref)}" target="_blank" rel="noopener">n8n #${esc(item.execId)} ↗</a>`
              : `<span class="mono">n8n #${esc(item.execId)}</span>`) : ''}
          </div>
        </div>

        <h3 class="approval-card-title">${esc(item.caseName || 'Permintaan Approval')}</h3>

        ${kvParts.length ? `<div class="approval-kv-row">${kvParts.join('')}</div>` : ''}

        ${item.summary ? `<div class="approval-summary-box">${esc(item.summary)}</div>` : ''}

        ${(item.markdown || hasData) ? `
          <div class="approval-details">
            <div class="approval-details-actions">
              ${item.markdown ? `<button class="btn ghost btn-xs act-appr-toggle-md" type="button">${mdOpen ? 'Tutup Laporan Markdown' : 'Lihat Laporan Markdown'}</button>` : ''}
              ${item.markdown ? '<button class="btn ghost btn-xs act-appr-copy-md" type="button">Salin Markdown</button>' : ''}
              ${hasData ? `<button class="btn ghost btn-xs act-appr-toggle-data" type="button">${dataOpen ? 'Tutup Data Alert' : 'Lihat Data Alert'}</button>` : ''}
            </div>
            ${mdOpen && item.markdown ? buildMarkdownViewerHtml(item.markdown, { dataPreKind: 'md' }) : ''}
            ${dataOpen && hasData ? `<pre class="md-pre" data-pre-kind="data">${esc(formattedData)}</pre>` : ''}
          </div>
        ` : ''}

        ${item.status === 'pending' ? `
          <div class="approval-decision-bar">
            ${item.lastError ? `
              <div class="error-box">
                <strong>Gagal mengirim keputusan ke n8n: ${esc(item.lastError)}</strong>
                <div>Pastikan workflow n8n masih aktif menunggu webhook resume. Jika eksekusi n8n sudah kedaluwarsa, tandai item ini sebagai kedaluwarsa.</div>
                <div class="mt-8">
                  <button class="btn ghost btn-xs act-appr-expire" type="button">Tandai Kedaluwarsa</button>
                </div>
              </div>
            ` : ''}
            <div class="approval-decision-controls">
              <div class="approval-reason-wrap">
                <label class="field-label" for="appr-reason-${esc(item.id)}">Catatan (wajib saat Deny)</label>
                <textarea id="appr-reason-${esc(item.id)}" class="appr-reason-input" rows="2" placeholder="Catatan keputusan"></textarea>
              </div>
              <div class="approval-decision-btns">
                <button class="btn accent act-appr-approve" type="button">Approve</button>
                <button class="btn danger act-appr-deny" type="button">Deny</button>
              </div>
            </div>
          </div>
        ` : `
          <div class="approval-audit-bar">
            <div class="approval-audit-info">
              <span><strong>${esc(auditMetaParts)}</strong></span>
              ${item.reason ? `<span>Alasan: ${esc(item.reason)}</span>` : ''}
              ${rejectionInlineHtml}
            </div>
            <div class="hist-actions">
              ${item.status === 'denied' ? '<button class="btn accent btn-xs act-appr-complete-rej" type="button" title="Perbaikan selesai — langsung minta approval ulang & hapus dari daftar Ditolak">Tandai Selesai</button>' : ''}
              ${item.status === 'denied' && itemWs === 'asoc' ? '<button class="btn ghost btn-xs act-appr-repeat" type="button">Ulangi (Repeat)</button>' : ''}
              <button class="btn ghost btn-xs act-appr-delete" type="button">Hapus</button>
            </div>
          </div>
        `}
      `;

      const reasonInput = $('.appr-reason-input', cardEl);
      if (reasonInput) {
        reasonInput.value = draftReason;
        reasonInput.addEventListener('input', () => {
          state.approvalDraftReasons.set(item.id, reasonInput.value);
        });
      }

      const toggleMdBtn = $('.act-appr-toggle-md', cardEl);
      if (toggleMdBtn) {
        toggleMdBtn.addEventListener('click', () => {
          if (state.expandedApprovalMdIds.has(item.id)) state.expandedApprovalMdIds.delete(item.id);
          else state.expandedApprovalMdIds.add(item.id);
          renderApprovalsList({ preserveScroll: true });
        });
      }

      const copyMdBtn = $('.act-appr-copy-md', cardEl);
      if (copyMdBtn) copyMdBtn.addEventListener('click', () => copyText(item.markdown, 'Markdown'));

      const toggleDataBtn = $('.act-appr-toggle-data', cardEl);
      if (toggleDataBtn) {
        toggleDataBtn.addEventListener('click', () => {
          if (state.expandedApprovalDataIds.has(item.id)) state.expandedApprovalDataIds.delete(item.id);
          else state.expandedApprovalDataIds.add(item.id);
          renderApprovalsList({ preserveScroll: true });
        });
      }

      wireMarkdownViewers(cardEl);
      const approveBtn = $('.act-appr-approve', cardEl);
      if (approveBtn) {
        wireConfirmClick(approveBtn, 'Konfirmasi Approve?', () =>
          submitApprovalDecision(item, 'approve', reasonInput ? reasonInput.value : '', cardEl)
        );
      }

      const denyBtn = $('.act-appr-deny', cardEl);
      if (denyBtn) {
        denyBtn.addEventListener('click', () => {
          const reason = (reasonInput ? reasonInput.value : '').trim();
          if (!reason) {
            toast({ type: 'error', title: 'Alasan penolakan wajib diisi', body: 'Isi alasan penolakan di kolom catatan sebelum Deny.' });
            if (reasonInput) reasonInput.focus();
            return;
          }
          submitApprovalDecision(item, 'deny', reason, cardEl);
        });
      }

      const expireBtn = $('.act-appr-expire', cardEl);
      if (expireBtn) {
        expireBtn.addEventListener('click', () => markApprovalExpired(item));
      }

      const deleteBtn = $('.act-appr-delete', cardEl);
      if (deleteBtn) {
        wireConfirmClick(deleteBtn, 'Klik lagi untuk Hapus', () => deleteApprovalItem(item));
      }

      const completeRejBtn = $('.act-appr-complete-rej', cardEl);
      if (completeRejBtn) {
        completeRejBtn.addEventListener('click', () => {
          if (item.rejectionId) completeRejection(item.rejectionId, completeRejBtn);
          else markApprovalRevised(item.id, completeRejBtn);
        });
      }

      const repeatRejBtn = $('.act-appr-repeat', cardEl);
      if (repeatRejBtn) {
        repeatRejBtn.addEventListener('click', () => createRepeatFromMeta({
          workspace: itemWs,
          tenant: item.tenant,
          ticketNumber: item.ticketNumber,
          irisCaseId: item.irisCaseId,
        }));
      }

      frag.appendChild(cardEl);
    }

    listEl.replaceChildren(frag);

    if (preScrollMap.size) {
      listEl.querySelectorAll('.approval-card').forEach((card) => {
        const id = card.dataset.apprId;
        if (!id) return;
        card.querySelectorAll('[data-pre-kind]').forEach((pre) => {
          if (pre.hidden) return;
          const saved = preScrollMap.get(`${id}:${pre.dataset.preKind}`);
          if (saved) {
            pre.scrollTop = saved.scrollTop;
            pre.scrollLeft = saved.scrollLeft;
          }
        });
      });
    }
    if (preserveScroll && typeof window.scrollTo === 'function') {
      window.scrollTo(savedWinX, savedWinY);
    }
  }

  function notifyNewRejections(openItems) {
    if (state.knownOpenRejectionIds === null) {
      state.knownOpenRejectionIds = new Set(openItems.map((x) => x.id));
      return;
    }
    const fresh = openItems.filter((x) => !state.knownOpenRejectionIds.has(x.id));
    state.knownOpenRejectionIds = new Set(openItems.map((x) => x.id));
    if (!fresh.length) return;

    const first = fresh[0];
    const title = fresh.length === 1
      ? `Case ditolak: ${first.caseName || formatCaseIdBadge(first.irisCaseId)}`
      : `${fresh.length} case ditolak perlu tindak lanjut`;
    const body = first.reason ? `Alasan: ${first.reason}` : 'Klik untuk melihat detail penolakan.';
    toast({
      type: 'error',
      title,
      body,
      actionLabel: 'Lihat',
      onAction: () => {
        state.approvalStatusFilter = 'denied';
        switchView('approvals');
      },
    });

    const w = wsState(first.workspace || state.activeWorkspace);
    if (w.settings.desktopNotify && document.hidden && typeof Notification !== 'undefined' && Notification.permission === 'granted') {
      try { new Notification('Diptera · ' + title, { body }); } catch {}
    }
  }

  function renderRejectionBanner() {
    const banner = $('#rejection-banner');
    const listEl = $('#rejection-banner-list');
    const countEl = $('#rejection-banner-count');
    if (!banner || !listEl || !countEl) return;

    const items = state.openRejections || [];
    const nextSig = items
      .map((x) => `${x.id}:${x.status || 'open'}:${x.updatedAt || ''}:${x.lastError || ''}:${x.createdByName || ''}:${x.decidedBy || ''}`)
      .join('|');

    if (!items.length) {
      if (state.lastRejectionBannerSig === '' && banner.hidden) return;
      state.lastRejectionBannerSig = '';
      banner.hidden = true;
      listEl.replaceChildren();
      return;
    }

    countEl.textContent = String(state.rejectionCounts?.open || items.length);

    const prevSig = state.lastRejectionBannerSig;
    state.lastRejectionBannerSig = nextSig;
    if (state.view === 'approvals' || state.rejectionDismissedSig === nextSig) {
      banner.hidden = true;
      return;
    }

    banner.hidden = false;
    const visibleItems = items.slice(0, 1);

    if (prevSig === nextSig && listEl.children.length === visibleItems.length) {
      for (const item of visibleItems) {
        const row = listEl.querySelector(`.rejection-item[data-rej-id="${(typeof CSS !== 'undefined' && typeof CSS.escape === 'function') ? CSS.escape(item.id) : item.id}"]`);
        const retryEl = row ? $('.rejection-retry-pill', row) : null;
        if (retryEl && item.nextRetryAt) {
          const retryText = fmtRetryCountdown(item.nextRetryAt);
          if (retryText) retryEl.textContent = retryText;
        }
      }
      return;
    }

    const frag = document.createDocumentFragment();

    for (const item of visibleItems) {
      const itemWs = item.workspace === 'soc' ? 'soc' : 'asoc';
      const caseHref = safeExternalHref(item.caseUrl) || irisCaseLink(item.irisCaseId, itemWs);
      const retryText = fmtRetryCountdown(item.nextRetryAt);

      const row = document.createElement('div');
      row.className = 'rejection-item';
      row.dataset.rejId = item.id;
      row.innerHTML = `
        <div class="rejection-item-main">
          <div class="rejection-item-meta">
            <span class="shared-ws-pill">${esc(WORKSPACE_META[itemWs].code)}</span>
            ${item.severity ? `<span class="chip sev-${esc(item.severity)}">${esc(item.severity)}</span>` : ''}
            ${item.classification ? `<span class="chip">${esc(item.classification)}</span>` : ''}
            ${item.irisCaseId ? (caseHref
              ? `<a class="iris-link" href="${esc(caseHref)}" target="_blank" rel="noopener">${esc(formatCaseIdBadge(item.irisCaseId))} ↗</a>`
              : `<span class="mono">${esc(formatCaseIdBadge(item.irisCaseId))}</span>`) : ''}
            ${item.clientName || item.tenant ? `<span>${esc(item.clientName || item.tenant)}</span>` : ''}
            ${item.createdByName ? `<span>Pembuat: <strong>${esc(item.createdByName)}</strong></span>` : ''}
            ${item.decidedBy ? `<span>Reviewer: <strong>${esc(item.decidedBy)}</strong></span>` : ''}
            ${retryText ? `<span class="rejection-retry-pill" title="n8n otomatis meminta approval ulang, atau klik Tandai Selesai untuk langsung meminta approval sekarang">${esc(retryText)}</span>` : ''}
          </div>
          <div class="rejection-item-title">${esc(item.caseName || 'Case Ditolak')}</div>
          <div class="rejection-item-reason">Alasan: ${esc(item.reason || 'Tidak ada alasan yang diberikan.')}</div>
          ${item.lastError ? `
            <div class="rejection-item-error">
              <span>Gagal resume n8n: ${esc(item.lastError)}</span>
              <button class="btn ghost btn-xs act-rej-skip-resume" type="button">Selesai Tanpa Resume n8n</button>
            </div>
          ` : ''}
        </div>
        <div class="rejection-item-actions">
          ${caseHref ? `<a class="btn ghost btn-xs" href="${esc(caseHref)}" target="_blank" rel="noopener">Buka IRIS ↗</a>` : ''}
          ${itemWs === 'asoc' ? '<button class="btn ghost btn-xs act-rej-repeat" type="button">Ulangi (Repeat)</button>' : ''}
          <button class="btn accent btn-xs act-rej-complete" type="button" title="Perbaikan selesai — langsung minta approval ulang">Tandai Selesai</button>
        </div>
      `;

      const repBtn = $('.act-rej-repeat', row);
      if (repBtn) {
        repBtn.addEventListener('click', () => createRepeatFromMeta({
          workspace: itemWs,
          tenant: item.tenant,
          ticketNumber: item.ticketNumber,
          irisCaseId: item.irisCaseId,
        }));
      }

      const completeBtn = $('.act-rej-complete', row);
      if (completeBtn) {
        completeBtn.addEventListener('click', () => completeRejection(item.id, completeBtn));
      }

      const skipResumeBtn = $('.act-rej-skip-resume', row);
      if (skipResumeBtn) {
        skipResumeBtn.addEventListener('click', () => completeRejection(item.id, skipResumeBtn, { skipResume: true }));
      }

      frag.appendChild(row);
    }
    listEl.replaceChildren(frag);
  }

  async function completeRejection(rejectionId, triggerBtn, opts = {}) {
    if (triggerBtn) {
      triggerBtn.disabled = true;
      triggerBtn.textContent = 'Mengirim…';
    }
    try {
      const resp = await apiFetch('/api/rejections/' + encodeURIComponent(rejectionId) + '/complete', {
        method: 'POST',
        body: JSON.stringify({
          completedBy: state.analystName.trim() || null,
          skipResume: Boolean(opts.skipResume),
        }),
      });
      if (resp?.resumedN8n) {
        toast({
          type: 'success',
          title: 'Revisi selesai — meminta approval ulang',
          body: 'Workflow n8n langsung dilanjutkan untuk meminta approval baru.',
        });
      } else {
        toast({
          type: 'info',
          title: 'Case ditandai selesai',
          body: 'Item telah dipindahkan dari daftar Ditolak.',
        });
      }
      await fetchSharedState(true);
      if (state.view === 'approvals') {
        await fetchApprovals(true, { notifyNew: false });
      }
      if (resp?.resumedN8n) {
        setTimeout(() => {
          fetchSharedState(true);
          if (state.view === 'approvals') fetchApprovals(true, { notifyNew: false });
        }, 1500);
        setTimeout(() => {
          fetchSharedState(true);
          if (state.view === 'approvals') fetchApprovals(true, { notifyNew: false });
        }, 3500);
      }
    } catch (e) {
      toast({ type: 'error', title: 'Gagal menyelesaikan revisi', body: e.message });
      await fetchSharedState(true);
      if (state.view === 'approvals') {
        await fetchApprovals(true, { notifyNew: false });
      }
    }
  }

  async function markApprovalRevised(approvalId, triggerBtn) {
    if (triggerBtn) {
      triggerBtn.disabled = true;
      triggerBtn.textContent = 'Menyimpan…';
    }
    try {
      await apiFetch('/api/approvals/' + encodeURIComponent(approvalId), {
        method: 'PATCH',
        body: JSON.stringify({ status: 'revised' }),
      });
      toast({ type: 'info', title: 'Case ditandai selesai', body: 'Item telah dihapus dari daftar Ditolak.' });
      await fetchSharedState(true);
      if (state.view === 'approvals') {
        await fetchApprovals(true, { notifyNew: false });
      }
    } catch (e) {
      toast({ type: 'error', title: 'Gagal menandai selesai', body: e.message });
    }
  }

  async function submitApprovalDecision(item, decision, reason, cardEl) {
    const approveBtn = cardEl ? $('.act-appr-approve', cardEl) : null;
    const denyBtn = cardEl ? $('.act-appr-deny', cardEl) : null;
    if (approveBtn) {
      approveBtn.disabled = true;
      if (decision === 'approve') approveBtn.textContent = 'Mengirim…';
    }
    if (denyBtn) {
      denyBtn.disabled = true;
      if (decision === 'deny') denyBtn.textContent = 'Mengirim…';
    }

    try {
      await apiFetch('/api/approvals/' + encodeURIComponent(item.id) + '/decide', {
        method: 'POST',
        body: JSON.stringify({
          decision,
          reason: String(reason || '').trim(),
          decidedBy: state.analystName.trim(),
        }),
      });
      state.approvalDraftReasons.delete(item.id);
      toast({
        type: 'success',
        title: decision === 'approve' ? 'Approval disetujui' : 'Approval ditolak',
        body: `${item.caseName || formatCaseIdBadge(item.irisCaseId)} — workflow n8n dilanjutkan.`,
      });
      await fetchApprovals(true, { notifyNew: false });
      fetchSharedState(true);
    } catch (e) {
      toast({
        type: 'error',
        title: 'Gagal mengirim keputusan ke n8n',
        body: e.message,
      });
      await fetchApprovals(true, { notifyNew: false });
      fetchSharedState(true);
    }
  }

  async function markApprovalExpired(item) {
    try {
      await apiFetch('/api/approvals/' + encodeURIComponent(item.id), {
        method: 'PATCH',
        body: JSON.stringify({ status: 'expired' }),
      });
      state.approvalDraftReasons.delete(item.id);
      toast({ type: 'info', title: 'Approval ditandai kedaluwarsa' });
      await fetchApprovals(true, { notifyNew: false });
      fetchSharedState(true);
    } catch (e) {
      toast({ type: 'error', title: 'Gagal memperbarui status', body: e.message });
    }
  }

  async function deleteApprovalItem(item) {
    try {
      await apiFetch('/api/approvals/' + encodeURIComponent(item.id), {
        method: 'DELETE',
      });
      state.approvalDraftReasons.delete(item.id);
      state.expandedApprovalMdIds.delete(item.id);
      state.expandedApprovalDataIds.delete(item.id);
      toast({ type: 'info', title: 'Item approval dihapus' });
      await fetchApprovals(true, { notifyNew: false });
      fetchSharedState(true);
    } catch (e) {
      toast({ type: 'error', title: 'Gagal menghapus item', body: e.message });
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
      <input type="text" class="t-num" aria-label="Nomor tiket terakhir" placeholder="Nomor tiket" value="${esc(ticketNum)}" spellcheck="false" />
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
    persist();
  }

  /* ---------------- UI Helpers ---------------- */

  const isMobileViewport = () => window.matchMedia('(max-width: 900px)').matches;

  function setSidebarOpen(open) {
    const shell = $('#app-shell');
    const btn = $('#btn-sidebar-toggle');
    const backdrop = $('#sidebar-backdrop');
    const isOpen = Boolean(open);
    if (shell) shell.classList.toggle('sidebar-open', isOpen);
    if (btn && isMobileViewport()) btn.setAttribute('aria-expanded', String(isOpen));
    if (backdrop) backdrop.hidden = !isOpen;
  }

  function toggleSidebar() {
    const shell = $('#app-shell');
    const btn = $('#btn-sidebar-toggle');
    if (!shell) return;
    if (isMobileViewport()) {
      setSidebarOpen(!shell.classList.contains('sidebar-open'));
      return;
    }
    const collapsed = shell.classList.toggle('sidebar-collapsed');
    shell.classList.remove('sidebar-open');
    if ($('#sidebar-backdrop')) $('#sidebar-backdrop').hidden = true;
    if (btn) btn.setAttribute('aria-expanded', String(!collapsed));
  }

  function updateViewHeading() {
    const ws = state.activeWorkspace;
    const w = wsState(ws);
    const heading = $('#view-heading');
    if (!heading) return;
    if (state.view === 'history') heading.textContent = 'Riwayat';
    else if (state.view === 'approvals') heading.textContent = 'Approval';
    else if (state.view === 'triage') heading.textContent = 'AI Triage Queue';
    else if (state.view === 'triage-24h') heading.textContent = 'Tarik Alert 24 Jam Terakhir';
    else if (state.view === 'live-feed') heading.textContent = 'Realtime Wazuh Feed (1:1)';
    else if (state.view === 'triage-history') heading.textContent = 'Audit Case Triage';
    else if (state.view === 'triage-exclusions') heading.textContent = 'Daftar Exclusion Rules';
    else if (state.view === 'triage-stats') heading.textContent = 'Statistik AI Triage';
    else if (state.view === 'triage-inspector') heading.textContent = 'Inspector Alert (Wazuh View)';
    else if (state.view === 'settings') heading.textContent = 'Pengaturan';
    else heading.textContent = (ws === 'asoc' && w.activeMode === 'repeating') ? 'Antrian (Repeating)' : 'Antrian';
  }

  function syncSidebarItemState(el, isActive) {
    if (!el) return;
    el.classList.toggle('active', isActive);
    if (isActive) el.setAttribute('aria-current', 'page');
    else el.removeAttribute('aria-current');
  }

  function switchView(view) {
    const allowed = ['queue', 'history', 'approvals', 'settings', 'triage', 'triage-24h', 'live-feed', 'triage-history', 'triage-exclusions', 'triage-stats', 'triage-inspector'];
    state.view = allowed.includes(view) ? view : 'queue';
    const isQueue = state.view === 'queue';
    const isHist = state.view === 'history';
    const isAppr = state.view === 'approvals';
    const isTriage = state.view === 'triage';
    const isTriage24h = state.view === 'triage-24h';
    const isLive = state.view === 'live-feed';
    const isTrgHist = state.view === 'triage-history';
    const isTrgEx = state.view === 'triage-exclusions';
    const isTrgStats = state.view === 'triage-stats';
    const isTrgInsp = state.view === 'triage-inspector';
    const isSettings = state.view === 'settings';

    $('#view-queue').hidden = !isQueue;
    $('#view-history').hidden = !isHist;
    $('#view-approvals').hidden = !isAppr;
    if ($('#view-triage')) $('#view-triage').hidden = !isTriage;
    if ($('#view-triage-24h')) $('#view-triage-24h').hidden = !isTriage24h;
    if ($('#view-live-feed')) $('#view-live-feed').hidden = !isLive;
    if ($('#view-triage-history')) $('#view-triage-history').hidden = !isTrgHist;
    if ($('#view-triage-exclusions')) $('#view-triage-exclusions').hidden = !isTrgEx;
    if ($('#view-triage-stats')) $('#view-triage-stats').hidden = !isTrgStats;
    if ($('#view-triage-inspector')) $('#view-triage-inspector').hidden = !isTrgInsp;
    $('#view-settings').hidden = !isSettings;

    syncSidebarItemState($('#tab-queue'), isQueue);
    syncSidebarItemState($('#tab-history'), isHist);
    syncSidebarItemState($('#tab-approvals'), isAppr);
    syncSidebarItemState($('#tab-triage'), isTriage);
    syncSidebarItemState($('#tab-triage-24h'), isTriage24h);
    syncSidebarItemState($('#tab-live-feed'), isLive);
    syncSidebarItemState($('#tab-triage-history'), isTrgHist);
    syncSidebarItemState($('#tab-triage-exclusions'), isTrgEx);
    syncSidebarItemState($('#tab-triage-stats'), isTrgStats);
    syncSidebarItemState($('#tab-settings'), isSettings);

    if (isMobileViewport()) setSidebarOpen(false);
    updateViewHeading();
    renderRejectionBanner();
    for (const fn of bridgeViewListeners) { try { fn(state.view); } catch {} }

    if (isHist) {
      state.historyWorkspace = state.activeWorkspace;
      syncHistoryWorkspaceTabs();
      fetchHistory();
    } else if (isAppr) {
      const epEl = $('#appr-endpoint-url');
      if (epEl) epEl.textContent = 'POST ' + approvalEndpointUrl();
      const nameEl = $('#appr-analyst-name');
      if (nameEl && nameEl.value !== state.analystName) nameEl.value = state.analystName;
      syncApprovalFilterControls();
      fetchApprovals(false);
    } else if (isSettings) {
      fillSettingsForm(state.activeWorkspace);
      const epEl = $('#appr-endpoint-url');
      if (epEl) epEl.textContent = 'POST ' + approvalEndpointUrl();
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
    const errCard = $('#stats .stat[data-stat="error"]');
    if (errCard) errCard.hidden = counts.error === 0;
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
    $('#tab-approvals').addEventListener('click', () => switchView('approvals'));
    $('#tab-settings').addEventListener('click', () => switchView('settings'));
    $('#nav-users')?.addEventListener('click', () => {
      if (isMobileViewport()) setSidebarOpen(false);
      openUserModal('users');
    });
    $('#btn-sidebar-toggle')?.addEventListener('click', toggleSidebar);
    $('#sidebar-backdrop')?.addEventListener('click', () => setSidebarOpen(false));
    window.addEventListener('resize', () => {
      const shell = $('#app-shell');
      const btn = $('#btn-sidebar-toggle');
      if (!isMobileViewport()) {
        shell?.classList.remove('sidebar-open');
        if ($('#sidebar-backdrop')) $('#sidebar-backdrop').hidden = true;
        if (btn) btn.setAttribute('aria-expanded', String(!shell?.classList.contains('sidebar-collapsed')));
      } else if (btn) {
        btn.setAttribute('aria-expanded', String(Boolean(shell?.classList.contains('sidebar-open'))));
      }
    });

    $('#btn-refresh-shared').addEventListener('click', () => fetchSharedState(false));

    $('#btn-settings')?.addEventListener('click', () => switchView('settings'));
    $('#set-ws-asoc').addEventListener('click', () => fillSettingsForm('asoc'));
    $('#set-ws-soc').addEventListener('click', () => fillSettingsForm('soc'));

    $('#btn-base-from-page').addEventListener('click', () => { $('#set-base-url').value = guessBaseUrl(); });
    $('#btn-add-tenant').addEventListener('click', () => addTenantSettingsRow('', ''));
    $('#btn-save-settings').addEventListener('click', saveSettings);
    $('#btn-close-settings').addEventListener('click', () => switchView('queue'));
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
    const wireDoubleConfirm = (btnEl, confirmLabel, onConfirm) => {
      if (!btnEl) return;
      const defaultLabel = btnEl.textContent;
      let timer = null;
      btnEl.addEventListener('click', async () => {
        if (btnEl.dataset.armed !== '1') {
          btnEl.dataset.armed = '1';
          btnEl.textContent = confirmLabel;
          clearTimeout(timer);
          timer = setTimeout(() => {
            btnEl.dataset.armed = '0';
            btnEl.textContent = defaultLabel;
          }, 5000);
          return;
        }
        clearTimeout(timer);
        btnEl.dataset.armed = '0';
        btnEl.textContent = defaultLabel;
        await onConfirm();
      });
    };

    $('#btn-hist-refresh').addEventListener('click', fetchHistory);
    wireDoubleConfirm($('#btn-hist-clear'), 'Klik lagi untuk Kosongkan Riwayat', async () => {
      try {
        const ws = state.historyWorkspace || 'all';
        const res = await apiFetch('/api/history?workspace=' + encodeURIComponent(ws), { method: 'DELETE' });
        await fetchHistory();
        fetchSharedState(true);
        toast({
          type: 'info',
          title: 'Riwayat dikosongkan',
          body: `${res.deletedCount || 0} entri riwayat (${String(ws).toUpperCase()}) dihapus.`,
        });
      } catch (e) {
        toast({ type: 'error', title: 'Gagal mengosongkan riwayat', body: e.message });
      }
    });

    document.querySelectorAll('.appr-status-btn[data-appr-status]').forEach((btn) => {
      btn.addEventListener('click', () => {
        state.approvalStatusFilter = btn.dataset.apprStatus || 'pending';
        syncApprovalFilterControls();
        fetchApprovals(false);
      });
    });

    let apprSearchTimer = null;
    $('#appr-search').addEventListener('input', () => {
      clearTimeout(apprSearchTimer);
      apprSearchTimer = setTimeout(() => fetchApprovals(false), 200);
    });
    $('#appr-filter-ws').addEventListener('change', (e) => {
      state.approvalWorkspaceFilter = e.target.value || 'all';
      fetchApprovals(false);
    });
    $('#appr-filter-sev').addEventListener('change', (e) => {
      state.approvalSeverityFilter = e.target.value || '';
      fetchApprovals(false);
    });
    $('#btn-appr-refresh').addEventListener('click', () => fetchApprovals(false));
    wireDoubleConfirm($('#btn-appr-clear'), 'Klik lagi untuk Kosongkan Approval', async () => {
      try {
        const ws = state.approvalWorkspaceFilter || 'all';
        const st = state.approvalStatusFilter || 'all';
        const qs = new URLSearchParams({ workspace: ws, status: st });
        const res = await apiFetch('/api/approvals?' + qs.toString(), { method: 'DELETE' });
        await fetchApprovals(true, { notifyNew: false });
        fetchSharedState(true);
        toast({
          type: 'info',
          title: 'Approval dikosongkan',
          body: `${res.deletedCount || 0} item approval dihapus.`,
        });
      } catch (e) {
        toast({ type: 'error', title: 'Gagal mengosongkan approval', body: e.message });
      }
    });
    $('#btn-copy-appr-url').addEventListener('click', () => copyText(approvalEndpointUrl(), 'Endpoint Approval'));
    $('#appr-analyst-name').addEventListener('input', (e) => {
      state.analystName = e.target.value;
      persist();
    });
    $('#btn-rejection-open-tab').addEventListener('click', () => {
      state.approvalStatusFilter = 'denied';
      switchView('approvals');
    });
    $('#btn-rejection-dismiss').addEventListener('click', () => {
      state.rejectionDismissedSig = state.lastRejectionBannerSig;
      $('#rejection-banner').hidden = true;
    });

    $('#login-form')?.addEventListener('submit', handleLoginSubmit);
    $('#btn-toggle-login-pw')?.addEventListener('click', () => {
      const inp = $('#login-password');
      const btn = $('#btn-toggle-login-pw');
      if (!inp || !btn) return;
      const show = inp.type === 'password';
      inp.type = show ? 'text' : 'password';
      btn.textContent = show ? 'Tutup' : 'Lihat';
    });
    $('#btn-logout')?.addEventListener('click', handleLogout);
    $('#btn-user-modal')?.addEventListener('click', () => openUserModal('account'));
    $('#btn-open-user-modal-from-settings')?.addEventListener('click', () => {
      openUserModal(state.currentUser?.role === 'admin' ? 'users' : 'account');
    });
    $('#btn-close-user-modal')?.addEventListener('click', closeUserModal);
    $('#user-modal')?.addEventListener('click', (e) => {
      if (e.target === $('#user-modal')) closeUserModal();
    });
    $('#um-tab-account')?.addEventListener('click', () => switchUserModalTab('account'));
    $('#um-tab-users')?.addEventListener('click', () => switchUserModalTab('users'));
    $('#form-change-pw')?.addEventListener('submit', handleChangeOwnPassword);
    $('#form-create-user')?.addEventListener('submit', handleCreateUser);
    $('#btn-reset-pw-confirm')?.addEventListener('click', handleAdminResetPwSubmit);
    $('#btn-reset-pw-cancel')?.addEventListener('click', () => {
      if ($('#admin-reset-pw-box')) $('#admin-reset-pw-box').hidden = true;
      state.resetPwTargetUser = null;
    });

    document.addEventListener('keydown', (e) => {
      const authVisible = $('#auth-screen') && !$('#auth-screen').hidden;
      const rawModalOpen = $('#raw-json-modal') && !$('#raw-json-modal').hidden;
      const exModalOpen = $('#exclude-preview-modal') && !$('#exclude-preview-modal').hidden;
      const userModalOpen = $('#user-modal') && !$('#user-modal').hidden;
      const anyModalOpen = rawModalOpen || exModalOpen || userModalOpen;

      if (e.key === 'Escape') {
        if (rawModalOpen) {
          e.preventDefault();
          $('#btn-close-raw-json')?.click();
        } else if (exModalOpen) {
          e.preventDefault();
          $('#btn-close-ex-modal')?.click();
        } else if ($('#app-shell')?.classList.contains('sidebar-open')) {
          e.preventDefault();
          setSidebarOpen(false);
        } else if (userModalOpen) {
          e.preventDefault();
          closeUserModal();
        } else if (state.view === 'settings') {
          const tag = document.activeElement?.tagName || '';
          if (!['INPUT', 'TEXTAREA', 'SELECT'].includes(tag)) {
            e.preventDefault();
            switchView('queue');
            $('#tab-settings')?.focus();
          }
        }
        return;
      }

      if (authVisible || anyModalOpen) return;

      if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        const tag = document.activeElement?.tagName || '';
        if (!['INPUT', 'TEXTAREA', 'SELECT'].includes(tag)) {
          const searchMap = {
            history: '#hist-search',
            approvals: '#appr-search',
            triage: '#trg-search',
            'triage-24h': '#b24-search',
            'live-feed': '#live-search',
            'triage-history': '#trghist-search',
            'triage-exclusions': '#ex-search',
            'triage-inspector': '#insp-search',
          };
          const targetSearch = searchMap[state.view] ? $(searchMap[state.view]) : null;
          if (targetSearch && !targetSearch.hidden) {
            e.preventDefault();
            targetSearch.focus();
            return;
          }
        }
      }

      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && state.view === 'queue') {
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

  async function startAppSession() {
    if (!state.appStarted) {
      state.appStarted = true;
      updateWorkspaceChrome();
      setActiveMode(wsState(state.activeWorkspace).activeMode, { skipPersist: true });
      updateFormLink();
      renderAllCards();
      updateApprovalTabCounts();
      const epEl = $('#appr-endpoint-url');
      if (epEl) epEl.textContent = 'POST ' + approvalEndpointUrl();
    }

    const nameEl = $('#appr-analyst-name');
    if (nameEl) nameEl.value = state.analystName;

    await fetchSharedState(false);
    await fetchApprovals(true, { notifyNew: false });

    stopPollingTimers();
    sharedPollTimer = setInterval(() => fetchSharedState(true), 15000);
    approvalPollTimer = setInterval(() => {
      if (state.view === 'approvals') fetchApprovals(true, { notifyNew: true });
    }, 5000);

    for (const ws of ['asoc', 'soc']) {
      for (const card of state.workspaces[ws].cards) {
        if (card.status === 'running' && (card.waitingUrl || card.historyId)) {
          recheckCard(card);
        }
      }
    }
    for (const fn of bridgeAuthListeners) { try { fn(state.currentUser); } catch {} }
  }

  function promoteTriageAlertsToForm({ tenant, chunks, workspace } = {}) {
    const targetWs = workspace === 'asoc' ? 'asoc' : (workspace === 'soc' ? 'soc' : state.activeWorkspace);
    if (state.activeWorkspace !== targetWs) switchWorkspace(targetWs);
    switchView('queue');
    if (targetWs === 'asoc') setActiveMode('reporting');

    const w = wsState(targetWs);
    for (const c of w.cards) {
      if (!c.collapsed) {
        c.collapsed = true;
        refreshCard(c);
      }
    }

    const tnKey = roleKey('tenant', targetWs);
    const tkKey = roleKey('ticket', targetWs);
    const cidKey = roleKey('caseId', targetWs);
    const alertKey = roleKey('alert', targetWs);
    const listChunks = Array.isArray(chunks) && chunks.length ? chunks : [];

    // Match tenant case-insensitively against configured dropdown options when available
    let resolvedTenantVal = String(tenant || '').trim();
    const tenantField = w.settings.fields.find((f) => f.key === tnKey);
    if (tenantField && Array.isArray(tenantField.options) && resolvedTenantVal) {
      const low = resolvedTenantVal.toLowerCase();
      const matchedOpt = tenantField.options.find((opt) => String(opt).toLowerCase() === low || String(opt).toLowerCase().includes(low) || low.includes(String(opt).toLowerCase()));
      if (matchedOpt) resolvedTenantVal = matchedOpt;
      else if (!tenantField.options.includes(resolvedTenantVal)) {
        tenantField.options.push(resolvedTenantVal);
      }
    }

    const createdCards = [];
    for (let i = listChunks.length - 1; i >= 0; i--) {
      const chunk = listChunks[i];
      const values = {};
      if (tnKey && resolvedTenantVal) values[tnKey] = resolvedTenantVal;
      if (alertKey) {
        values[alertKey] = chunk.length === 1
          ? JSON.stringify(chunk[0], null, 2)
          : JSON.stringify(chunk, null, 2);
      }
      const card = newCard({ mode: 'reporting', values }, targetWs);
      w.cards.unshift(card);
      createdCards.unshift(card);
    }

    recomputeQueueTickets(targetWs, { noPersist: true });
    renderAllCards();

    const firstCard = createdCards[0] || null;
    if (firstCard && alertKey) {
      const alertInp = refs.get(firstCard.id)?.inputs[alertKey];
      if (alertInp) {
        alertInp.focus();
        alertInp.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }
    persist();

    return {
      workspace: targetWs,
      tenant: resolvedTenantVal,
      ticketNumber: firstCard && tkKey ? (firstCard.values[tkKey] || null) : null,
      irisCaseId: firstCard && cidKey ? (firstCard.values[cidKey] || null) : null,
      cardCount: createdCards.length,
    };
  }

  function previewNextCardMeta(tenant, ws = state.activeWorkspace) {
    const targetWs = ws === 'soc' ? 'soc' : 'asoc';
    const w = wsState(targetWs);
    const tkKey = roleKey('ticket', targetWs);
    const tnKey = roleKey('tenant', targetWs);
    const cidKey = roleKey('caseId', targetWs);
    let resolvedTenant = String(tenant || '').trim();
    const tenantField = w.settings.fields.find((f) => f.key === tnKey);
    if (tenantField && Array.isArray(tenantField.options) && resolvedTenant) {
      const low = resolvedTenant.toLowerCase();
      const matchedOpt = tenantField.options.find((opt) => String(opt).toLowerCase() === low || String(opt).toLowerCase().includes(low) || low.includes(String(opt).toLowerCase()));
      if (matchedOpt) resolvedTenant = matchedOpt;
    }

    let ticketNumber = null;
    if (tkKey && tnKey && resolvedTenant && N.computeQueueTickets && w.settings.autoNumber !== false) {
      const tempCards = w.cards.map((c) => ({ id: c.id, status: c.status, ticketAuto: c.ticketAuto, values: { ...c.values } }));
      const tempCard = { id: '__preview__', status: 'idle', ticketAuto: true, values: { [tnKey]: resolvedTenant } };
      tempCards.push(tempCard);
      N.computeQueueTickets(tempCards, w.counters.ticketsByTenant || {}, {
        autoNumber: true,
        ticketKey: tkKey,
        tenantKey: tnKey,
      });
      ticketNumber = tempCard.values[tkKey] || null;
    }

    let irisCaseId = null;
    if (targetWs === 'soc' && cidKey && N.nextValue) {
      let cursor = w.counters.lastIrisCaseId || null;
      for (const prev of w.cards) {
        const pv = String(prev.values[cidKey] ?? '').trim();
        if (pv && N.lastNumber(pv) != null) cursor = pv;
      }
      irisCaseId = cursor ? N.nextValue(cursor) : null;
    }
    return { workspace: targetWs, tenant: resolvedTenant, ticketNumber, irisCaseId };
  }

  window.DipteraBridge = {
    apiFetch,
    toast,
    copyText,
    fmtWib,
    esc,
    switchView,
    previewNextCardMeta,
    promoteTriageAlertsToForm,
    getActiveWorkspace: () => state.activeWorkspace,
    getKnownTenants: () => wsState(state.activeWorkspace).counters?.tenants || [],
    onViewChange: (fn) => { if (typeof fn === 'function') bridgeViewListeners.push(fn); },
    onAuthReady: (fn) => {
      if (typeof fn === 'function') {
        bridgeAuthListeners.push(fn);
        if (state.appStarted) fn(state.currentUser);
      }
    },
    onLogout: (fn) => { if (typeof fn === 'function') bridgeLogoutListeners.push(fn); },
  };

  async function init() {
    loadLocalState();
    bindEvents();
    syncRepeatPanelInputs();

    for (const ws of ['asoc', 'soc']) {
      if (!state.workspaces[ws].cards.length) {
        state.workspaces[ws].cards.push(newCard({}, ws));
      }
    }

    try {
      const me = await apiFetch('/api/auth/me');
      const authEnabled = Boolean(me?.authEnabled);
      if (authEnabled && !me?.authenticated) {
        setAuthUiState(null, true);
        return;
      }
      setAuthUiState(me?.user || null, authEnabled);
      await startAppSession();
    } catch {
      // Fallback bila gagal cek /api/auth/me: ikuti flag CONFIG.authEnabled
      if (state.authEnabled) {
        setAuthUiState(null, true);
      } else {
        setAuthUiState(null, false);
        await startAppSession();
      }
    }
  }

  init();
})();
