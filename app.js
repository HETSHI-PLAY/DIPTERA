/* Diptera — kirim banyak form ke workflow Charlie Reporter (n8n).
 *
 * Alur n8n 2.x yang dipakai:
 *   POST {base}/form/{path}        (multipart, field-0..field-N)  -> 200 { formWaitingUrl }
 *   GET  {formWaitingUrl}/n8n-execution-status  -> running | waiting | form-waiting | success | error | …
 *   GET  {formWaitingUrl}          -> halaman hasil (HTML berisi responseHtml workflow)
 *   POST {formWaitingUrl}          -> menandai eksekusi selesai di n8n (opsional)
 */
'use strict';

(function () {
  const X = window.IrisExtract || {};
  const N = window.IrisNumbering || {};
  const STORAGE_KEY = 'iris-multi-form.v1';
  const CONFIG = window.DIPTERA_CONFIG || {};

  // Daftar tenant disediakan lewat environment TENANT_OPTIONS (lihat .env.example).
  // Sengaja dikosongkan di kode supaya nama tenant internal tidak bocor ke repo.
  const DEFAULT_TENANTS = [];
  const tenantList = Array.isArray(CONFIG.tenantOptions) && CONFIG.tenantOptions.length ? CONFIG.tenantOptions : DEFAULT_TENANTS;

  // Inisialisasi counter tiket awal jika ada di config (mis. dari .env)
  function initInitialCounters() {
    const counters = { caseId: CONFIG.initialCaseId || null, tickets: {} };
    if (CONFIG.initialTickets && typeof CONFIG.initialTickets === 'object') {
      for (const [t, val] of Object.entries(CONFIG.initialTickets)) {
        if (t && val != null) counters.tickets[t] = String(val);
      }
    }
    return counters;
  }

  function isLocalPage() {
    const host = String(window.location.hostname || '').toLowerCase();
    return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]' || host === '0.0.0.0';
  }

  /** Tebak alamat n8n dari alamat halaman (IP yang sama, port 5678). */
  function guessBaseUrl() {
    try {
      const loc = window.location;
      const host = loc.hostname;
      if (!host || isLocalPage()) return 'http://localhost:5678';
      return (loc.protocol === 'https:' ? 'https://' : 'http://') + host + ':5678';
    } catch {
      return 'http://localhost:5678';
    }
  }

  function defaultBaseUrl() {
    const configured = CONFIG && typeof CONFIG.baseUrl === 'string' ? CONFIG.baseUrl.trim() : '';
    return (configured || guessBaseUrl()).replace(/\/+$/, '');
  }

  const DEFAULT_FIELDS = [
    {
      key: 'field-0',
      label: 'Nomor Tiket IRIS (Opsional)',
      type: 'text',
      placeholder: 'Contoh: 30073 (otomatis menjadi ASOC-2026-30073)',
      role: 'ticket',
    },
    {
      key: 'field-1',
      label: 'Tenant / Organisasi (Opsional)',
      type: 'select',
      options: tenantList,
      role: 'tenant',
    },
    {
      key: 'field-2',
      label: 'IRIS Case ID',
      type: 'text',
      required: true,
      placeholder: 'Contoh: #123',
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

  const DEFAULT_SETTINGS = {
    baseUrl: defaultBaseUrl(),
    formPath: (CONFIG && typeof CONFIG.formPath === 'string' && CONFIG.formPath.trim()) ? CONFIG.formPath.trim() : '',
    submitMode: 'sequential',
    timeoutMin: 30,
    autoCollapse: true,
    autoResume: true,
    rewriteHost: true,
    desktopNotify: false,
    autoNumber: true,
    fields: DEFAULT_FIELDS,
  };

  const STATUS_LABEL = { idle: 'Menunggu', queued: 'Antrian', running: 'Diproses', done: 'Selesai', error: 'Gagal' };
  const NS_LABEL = {
    running: 'workflow berjalan',
    waiting: 'menunggu',
    'form-waiting': 'menyiapkan hasil',
    success: 'selesai',
    new: 'masuk antrian n8n',
  };

  /* ---------------- util ---------------- */

  const $ = (sel, root = document) => root.querySelector(sel);
  const esc = (v) =>
    String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const uid = () => Math.random().toString(36).slice(2, 9) + Date.now().toString(36).slice(-4);
  const clone = (v) => JSON.parse(JSON.stringify(v));
  const sleep = (ms, signal) =>
    new Promise((resolve, reject) => {
      const t = setTimeout(resolve, ms);
      if (signal) {
        const onAbort = () => {
          clearTimeout(t);
          reject(new DOMException('Dibatalkan', 'AbortError'));
        };
        if (signal.aborted) onAbort();
        else signal.addEventListener('abort', onAbort, { once: true });
      }
    });
  const abortErr = () => new DOMException('Dibatalkan', 'AbortError');
  const joinUrl = (base, path) => String(base || '').replace(/\/+$/, '') + path;
  const safeJson = (text) => {
    try {
      return JSON.parse(text);
    } catch {
      return null;
    }
  };

  /* ---------------- pemeriksaan JSON (longgar, seperti form n8n) ----------------
   * Form n8n menerima teks apa adanya, jadi aplikasi ini tidak boleh menolak
   * kiriman hanya karena JSON.parse gagal. Yang umum ditempel pengguna:
   *   - satu objek / array JSON biasa,
   *   - beberapa alert JSON berurutan (NDJSON atau objek-objek berdempet),
   *   - JSON dengan baris baru mentah di dalam string (mis. stack trace).
   */

  function tryParseJson(text) {
    try {
      return { ok: true, value: JSON.parse(text) };
    } catch (error) {
      return { ok: false, error };
    }
  }

  /** Escape baris baru / karakter kontrol yang tidak boleh mentah di dalam string JSON. */
  function repairJsonStrings(text) {
    let out = '';
    let inString = false;
    let escaped = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (inString) {
        if (escaped) {
          out += ch;
          escaped = false;
        } else if (ch === '\\') {
          out += ch;
          escaped = true;
        } else if (ch === '"') {
          out += ch;
          inString = false;
        } else if (ch === '\n') {
          out += '\\n';
        } else if (ch === '\r') {
          out += '\\r';
        } else if (ch === '\t') {
          out += '\\t';
        } else if (ch.charCodeAt(0) < 0x20) {
          out += '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0');
        } else {
          out += ch;
        }
      } else {
        if (ch === '"') inString = true;
        out += ch;
      }
    }
    return out;
  }

  /** Pisahkan beberapa nilai JSON (objek/array) yang ditempel berdempetan. */
  function splitJsonStream(text) {
    const parts = [];
    let i = 0;
    while (i < text.length) {
      while (i < text.length && /\s/.test(text[i])) i++;
      if (i >= text.length) break;
      if (text[i] !== '{' && text[i] !== '[') return null;
      const start = i;
      let depth = 0;
      let inString = false;
      let escaped = false;
      let closed = false;
      for (; i < text.length; i++) {
        const ch = text[i];
        if (inString) {
          if (escaped) escaped = false;
          else if (ch === '\\') escaped = true;
          else if (ch === '"') inString = false;
          continue;
        }
        if (ch === '"') inString = true;
        else if (ch === '{' || ch === '[') depth++;
        else if (ch === '}' || ch === ']') {
          depth--;
          if (depth === 0) {
            i++;
            closed = true;
            break;
          }
        }
      }
      if (!closed) return null;
      parts.push(text.slice(start, i));
      while (i < text.length && /[\s,]/.test(text[i])) i++;
    }
    return parts.length ? parts : null;
  }

  /** @returns {{state:'empty'|'valid'|'lines'|'stream'|'repaired'|'invalid', message:string, count?:number}} */
  function inspectJson(text) {
    const raw = String(text ?? '');
    if (!raw.trim()) return { state: 'empty', message: '' };
    const trimmed = raw.trim();

    const direct = tryParseJson(trimmed);
    if (direct.ok) return { state: 'valid', message: '✓ JSON valid' };

    const lines = trimmed.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    if (lines.length > 1 && lines.every((line) => tryParseJson(line).ok)) {
      return {
        state: 'lines',
        count: lines.length,
        message: '✓ ' + lines.length + ' alert JSON terdeteksi (dikirim apa adanya)',
      };
    }

    const parts = splitJsonStream(trimmed);
    if (parts && parts.length > 1 && parts.every((part) => tryParseJson(part).ok)) {
      return {
        state: 'stream',
        count: parts.length,
        message: '✓ ' + parts.length + ' alert JSON terdeteksi (dikirim apa adanya)',
      };
    }

    const repaired = repairJsonStrings(trimmed);
    if (repaired !== trimmed && tryParseJson(repaired).ok) {
      return {
        state: 'repaired',
        message: '✓ JSON terbaca (ada baris baru di dalam teks) — dikirim apa adanya',
      };
    }

    return { state: 'invalid', message: '⚠ Tidak terbaca sebagai JSON — tetap bisa dikirim apa adanya' };
  }
  function fmtDuration(ms) {
    const s = Math.max(0, Math.round(ms / 1000));
    if (s < 60) return s + 's';
    const m = Math.floor(s / 60);
    if (m < 60) return m + 'm ' + String(s % 60).padStart(2, '0') + 's';
    const h = Math.floor(m / 60);
    return h + 'j ' + String(m % 60).padStart(2, '0') + 'm';
  }
  function statusUrlOf(waitingUrl) {
    try {
      const u = new URL(waitingUrl);
      u.pathname = u.pathname.replace(/\/+$/, '') + '/n8n-execution-status';
      return u.toString();
    } catch {
      return waitingUrl + '/n8n-execution-status';
    }
  }
  async function fetchWithTimeout(url, opts, timeoutMs, outerSignal) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(new DOMException('timeout', 'TimeoutError')), timeoutMs);
    const onOuterAbort = () => ctrl.abort(abortErr());
    if (outerSignal) {
      if (outerSignal.aborted) onOuterAbort();
      else outerSignal.addEventListener('abort', onOuterAbort, { once: true });
    }
    try {
      return await fetch(url, Object.assign({}, opts, { signal: ctrl.signal }));
    } finally {
      clearTimeout(timer);
      if (outerSignal) outerSignal.removeEventListener('abort', onOuterAbort);
    }
  }
  const fetchText = async (url, timeoutMs, outerSignal, opts) =>
    (await fetchWithTimeout(url, opts || {}, timeoutMs, outerSignal)).text();

  /* ---------------- state ---------------- */

  let state = { settings: clone(DEFAULT_SETTINGS), cards: [], counters: initInitialCounters() };
  let submitAllRunning = false;
  let saveTimer = null;
  const refs = new Map(); // cardId -> element refs
  const jsonTimers = new Map();
  const propagateTimers = new Map(); // role -> timer penundaan sebar nomor

  function normalizeFields(input) {
    if (!Array.isArray(input) || input.length === 0) return clone(DEFAULT_FIELDS);
    return input.map((f, i) => {
      const type = f.type || 'text';
      if (typeof f.key !== 'string' || !/^[A-Za-z0-9_-]+$/.test(f.key)) {
        throw new Error('Field #' + (i + 1) + ': "key" tidak valid (contoh: field-0).');
      }
      if (typeof f.label !== 'string' || !f.label.trim()) throw new Error('Field #' + (i + 1) + ': "label" wajib diisi.');
      if (!['text', 'textarea', 'select'].includes(type)) {
        throw new Error('Field #' + (i + 1) + ': "type" harus text/textarea/select.');
      }
      if (type === 'select' && !Array.isArray(f.options)) {
        throw new Error('Field #' + (i + 1) + ': "options" harus array untuk type select.');
      }
      return {
        key: f.key,
        label: f.label,
        type,
        options: Array.isArray(f.options) ? f.options : [],
        required: !!f.required,
        json: !!f.json,
        placeholder: f.placeholder || '',
        role: f.role || null,
      };
    });
  }

  function normalizeCard(raw, fields) {
    const card = {
      id: raw.id || uid(),
      values: {},
      collapsed: !!raw.collapsed,
      status: raw.status || 'idle',
      dirty: !!raw.dirty,
      busy: false,
      result: raw.result || null,
      errorMsg: raw.errorMsg || null,
      errorDetail: raw.errorDetail || null,
      errorHint: raw.errorHint || null,
      errorKind: raw.errorKind || null,
      elapsedMs: typeof raw.elapsedMs === 'number' ? raw.elapsedMs : null,
      startedAt: raw.startedAt || null,
      waitingUrl: raw.waitingUrl || null,
      execId: raw.execId || null,
      nsStatus: raw.nsStatus || null,
      resumed: !!raw.resumed,
      // penomoran otomatis
      caseIdAuto: !!raw.caseIdAuto,
      ticketAuto: !!raw.ticketAuto,
      ticketFor: raw.ticketFor || null,
    };
    for (const f of fields) card.values[f.key] = raw.values?.[f.key] ?? '';
    return card;
  }

  function loadState() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      const settings = Object.assign(clone(DEFAULT_SETTINGS), parsed.settings || {});
      settings.fields = normalizeFields(settings.fields);
      const cards = (Array.isArray(parsed.cards) ? parsed.cards : []).map((c) => normalizeCard(c, settings.fields));
      const counters = parsed.counters || {
        caseId: initInitialCounters().caseId,
        tickets: Object.assign({}, initInitialCounters().tickets, parsed.counters?.tickets || {}),
      };
      return { settings, cards, counters };
    } catch {
      return null;
    }
  }

  function serializeCard(card, dropResult) {
    const c = {
      id: card.id,
      values: card.values,
      collapsed: card.collapsed,
      status: card.status,
      dirty: card.dirty,
      result: dropResult ? null : card.result,
      errorMsg: card.errorMsg,
      errorDetail: card.errorDetail,
      errorHint: card.errorHint,
      errorKind: card.errorKind,
      elapsedMs: card.elapsedMs,
      startedAt: card.startedAt,
      waitingUrl: card.waitingUrl,
      execId: card.execId,
      nsStatus: card.nsStatus,
      resumed: card.resumed,
      caseIdAuto: card.caseIdAuto,
      ticketAuto: card.ticketAuto,
      ticketFor: card.ticketFor,
    };
    return c;
  }

  const SAVE_DEBOUNCE_MS = 800;
  let pendingSave = false;
  let storageWarned = false;
  let skipResultsOnSave = false;

  function payloadJson(dropResults) {
    return JSON.stringify({
      v: 1,
      settings: state.settings,
      counters: state.counters,
      cards: state.cards.map((c) => serializeCard(c, dropResults)),
    });
  }

  /** Simpan segera (dipakai saat tab disembunyikan / halaman ditutup). */
  function flushPersist(quiet) {
    clearTimeout(saveTimer);
    saveTimer = null;
    if (!pendingSave) return;
    pendingSave = false;

    const write = (dropResults) => localStorage.setItem(STORAGE_KEY, payloadJson(dropResults));
    if (!skipResultsOnSave) {
      try {
        write(false);
        return;
      } catch {
        /* mungkin penuh — coba tanpa hasil di bawah */
      }
    }
    try {
      // Hasil bisa besar; isi form tetap dipertahankan walau hasil dibuang.
      write(true);
      skipResultsOnSave = true;
    } catch {
      if (!quiet && !storageWarned) {
        storageWarned = true;
        toast({
          type: 'error',
          title: 'Penyimpanan browser penuh',
          body: 'Isi form tetap aman selama halaman terbuka, tetapi tidak bisa disimpan untuk reload.',
        });
      }
    }
  }

  function persist() {
    if (els.settingsPanel && !els.settingsPanel.hidden) updateNumberingInfo();
    pendingSave = true;
    clearTimeout(saveTimer);
    const active = document.activeElement;
    const tag = active && active.tagName;
    const typing = !!(
      active &&
      (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') &&
      active.closest('.card')
    );
    // Saat mengetik, tunda lebih lama supaya data besar tidak di-stringify
    // setiap kali berhenti sejenak. Blur / pindah tab tetap menyimpan.
    saveTimer = setTimeout(flushPersist, typing ? 2500 : SAVE_DEBOUNCE_MS);
  }

  /* ---------------- cards ---------------- */

  function newCard(values) {
    const card = normalizeCard({ values: values || {} }, state.settings.fields);
    if (values) for (const f of state.settings.fields) card.values[f.key] = values[f.key] ?? '';
    if (!values) {
      const next = nextNumberFor('caseId');
      const key = roleKey('caseId');
      if (next && key) {
        card.values[key] = next;
        card.caseIdAuto = true;
        state.counters.caseId = next;
      }
    }
    return card;
  }

  function eligibleCards() {
    return state.cards.filter(
      (c) => !c.busy && (c.status === 'idle' || c.status === 'error' || (c.status === 'done' && c.dirty)),
    );
  }

  function findCard(id) {
    return state.cards.find((c) => c.id === id) || null;
  }

  function cardIndex(card) {
    return state.cards.indexOf(card);
  }

  function cardLabel(card) {
    return 'Form #' + (cardIndex(card) + 1);
  }

  /** Ringkasan hasil untuk kartu: "Severity + case name" tanpa dobel prefiks. */
  function resultLabel(res) {
    if (!res) return '';
    const name = res.caseName || res.statusLine || (res.noOutput ? 'Terkirim ke n8n' : '');
    if (!name) return res.severity ? '[' + res.severity + ']' : '';
    // halaman hasil biasanya sudah memuat "[SEVERITY]" di case name
    if (res.severity && name.charAt(0) !== '[') return '[' + res.severity + '] ' + name;
    return name;
  }

  /* ---------------- penomoran otomatis ----------------
   * Nomor tiket: satu urutan per tenant (tenant-a 10010 -> berikutnya tenant-a 10011).
   * IRIS Case ID: satu urutan global (form 1 = #1001 -> form 2 = #1002).
   * Nilai hasil isian otomatis selalu bisa diedit manual; begitu diedit,
   * kartu itu menjadi acuan baru dan tidak ditimpa lagi.
   */

  const autoNumberOn = () => state.settings.autoNumber !== false && !!N.nextValue;

  const roleKey = (role) => {
    const f = state.settings.fields.find((x) => x.role === role);
    return f ? f.key : null;
  };

  const readVal = (card, role) => {
    const k = roleKey(role);
    return k ? String(card.values[k] ?? '').trim() : '';
  };

  /** Nilai berikutnya untuk sebuah peran (caseId / ticket+tenant). */
  function nextNumberFor(role, tenant) {
    if (!autoNumberOn()) return null;
    if (role === 'caseId') return state.counters.caseId ? N.nextValue(state.counters.caseId) : null;
    if (role === 'ticket' && tenant && state.counters.tickets[tenant]) return N.nextValue(state.counters.tickets[tenant]);
    return null;
  }

  /** Simpan nilai yang ada di kartu sebagai acuan nomor berikutnya. */
  function rememberNumber(role, card, tenantOverride) {
    if (!autoNumberOn()) return;
    const value = readVal(card, role);
    if (!value || N.lastNumber(value) == null) return;
    if (role === 'caseId') state.counters.caseId = value;
    else if (role === 'ticket') {
      const tenant = tenantOverride || readVal(card, 'tenant');
      if (tenant) state.counters.tickets[tenant] = value;
    }
  }

  /** Tulis nilai dari state ke input kartu (field yang diisi otomatis tidak sedang diketik). */
  /** Selesai -> isian tidak ditampilkan lagi; kartu hanya berisi hasil. */
  function isFormHidden(card) {
    return card.status === 'done' && !card.dirty && !!card.result;
  }

  function syncInput(card, key) {
    const r = refs.get(card.id);
    const el = r && r.inputs[key];
    if (!el) return;
    const next = card.values[key] ?? '';
    if (el.value !== next) el.value = next;
  }

  /** Isi kembali input dari state (kartu tertutup tidak menyimpan teks panjang di DOM). */
  function hydrateInputs(card) {
    if (isFormHidden(card)) return;
    const r = refs.get(card.id);
    if (!r) return;
    for (const field of state.settings.fields) {
      const el = r.inputs[field.key];
      if (!el) continue;
      const next = card.values[field.key] ?? '';
      if (el.value !== next) el.value = next;
    }
  }

  /** Lepaskan teks panjang dari DOM saat kartu ditutup; nilainya tetap ada di state. */
  function dehydrateTextareas(card) {
    const r = refs.get(card.id);
    if (!r) return;
    for (const field of state.settings.fields) {
      if (field.type !== 'textarea') continue;
      const el = r.inputs[field.key];
      if (el && el.value) el.value = '';
    }
  }

  /** Nomor tiket kartu diisi ulang sesuai tenant yang dipilih. */
  function autoFillTicket(card) {
    const key = roleKey('ticket');
    if (!key) return false;
    const tenant = readVal(card, 'tenant');
    const next = nextNumberFor('ticket', tenant);
    if (next) {
      card.values[key] = next;
      card.ticketAuto = true;
      card.ticketFor = tenant;
      state.counters.tickets[tenant] = next;
      syncInput(card, key);
      return true;
    }
    // belum ada acuan untuk tenant ini: kosongkan hanya kalau nilainya hasil isian otomatis
    if (card.ticketAuto) {
      card.values[key] = '';
      card.ticketAuto = false;
      syncInput(card, key);
    }
    card.ticketFor = tenant;
    return false;
  }

  function isEditable(card) {
    return card.status === 'idle' || card.status === 'error';
  }

  /** Sebar nomor ke kartu-kartu berikutnya yang masih otomatis/kosong (ditunda saat mengetik). */
  function schedulePropagate(role, cardId, tenantFilter) {
    if (!autoNumberOn()) return;
    clearTimeout(propagateTimers.get(role));
    propagateTimers.set(
      role,
      setTimeout(() => {
        propagateTimers.delete(role);
        propagateNow(role, cardId, tenantFilter);
      }, 400),
    );
  }

  function propagateNow(role, cardId, tenantFilter) {
    if (!autoNumberOn()) return;
    const key = roleKey(role);
    if (!key) return;
    const from = state.cards.findIndex((c) => c.id === cardId);
    if (from === -1) return;
    let cursor = String(state.cards[from].values[key] ?? '').trim();
    if (!cursor || N.lastNumber(cursor) == null) return;
    let changed = false;

    for (let i = from + 1; i < state.cards.length; i++) {
      const card = state.cards[i];
      const tenant = readVal(card, 'tenant');
      if (tenantFilter && tenant !== tenantFilter) continue;
      const value = String(card.values[key] ?? '').trim();
      const auto = role === 'caseId' ? card.caseIdAuto : card.ticketAuto;
      if ((auto || !value) && isEditable(card)) {
        const next = N.nextValue(cursor);
        if (next == null) break;
        card.values[key] = next;
        if (role === 'caseId') {
          card.caseIdAuto = true;
          state.counters.caseId = next;
        } else {
          card.ticketAuto = true;
          card.ticketFor = tenant;
          if (tenant) state.counters.tickets[tenant] = next;
        }
        syncInput(card, key);
        refreshCard(card);
        cursor = next;
        changed = true;
      } else if (value) {
        cursor = value; // kartu yang diisi manual menjadi acuan berikutnya
      }
    }
    if (changed) {
      persist();
    }
  }

  /** Isi ulang semua nomor otomatis (dipakai saat fitur baru dinyalakan). */
  function refillNumbering() {
    if (!autoNumberOn()) return;
    const caseKey = roleKey('caseId');
    const ticketKey = roleKey('ticket');
    let cursor = null;
    if (caseKey) {
      for (const card of state.cards) {
        const value = String(card.values[caseKey] ?? '').trim();
        const next = cursor ? N.nextValue(cursor) : null;
        if ((card.caseIdAuto || !value) && next && isEditable(card)) {
          card.values[caseKey] = next;
          card.caseIdAuto = true;
          state.counters.caseId = next;
          syncInput(card, caseKey);
          cursor = next;
        } else if (value) {
          cursor = value;
        }
      }
    }
    if (ticketKey) {
      for (const card of state.cards) {
        if (!readVal(card, 'tenant')) continue;
        const empty = !String(card.values[ticketKey] ?? '').trim();
        if ((card.ticketAuto || empty) && isEditable(card)) autoFillTicket(card);
      }
    }
  }

  /** Lengkapi acuan nomor dari kartu yang sudah ada (cadangan bila data lama). */
  function deriveCounters() {
    if (!autoNumberOn()) return;
    for (const card of state.cards) {
      if (!state.counters.caseId) {
        const v = readVal(card, 'caseId');
        if (v && N.lastNumber(v) != null) state.counters.caseId = v;
      }
      const tenant = readVal(card, 'tenant');
      const ticket = readVal(card, 'ticket');
      if (tenant && ticket && N.lastNumber(ticket) != null && !state.counters.tickets[tenant]) {
        state.counters.tickets[tenant] = ticket;
      }
    }
  }

  /* ---------------- rendering ---------------- */

  const els = {
    cards: null,
    empty: null,
    stats: null,
    btnSubmitAll: null,
    btnSubmitAllLabel: null,
    btnCancel: null,
    btnToggleAll: null,
    linkForm: null,
    settingsPanel: null,
  };

  function buildFieldControl(card, field) {
    const id = 'f-' + card.id + '-' + field.key;
    if (field.type === 'select') {
      const sel = document.createElement('select');
      sel.id = id;
      const empty = document.createElement('option');
      empty.value = '';
      empty.textContent = '— pilih —';
      sel.appendChild(empty);
      for (const opt of field.options) {
        const o = document.createElement('option');
        o.value = String(opt);
        o.textContent = String(opt);
        sel.appendChild(o);
      }
      sel.value = card.values[field.key] || '';
      return sel;
    }
    if (field.type === 'textarea') {
      const ta = document.createElement('textarea');
      ta.id = id;
      ta.rows = field.json ? 10 : 6;
      ta.spellcheck = false;
      ta.autocomplete = 'off';
      if (field.placeholder) ta.placeholder = field.placeholder;
      if (field.json) {
        ta.classList.add('mono', 'nowrap');
        // Log JSON panjang biasanya satu baris raksasa. Membungkus baris
        // membuat browser menghitung layout teks itu di setiap ketikan.
        ta.wrap = 'off';
      }
      // Kartu tertutup / sudah selesai tidak perlu menaruh teks panjang di DOM.
      if (!card.collapsed && !isFormHidden(card)) ta.value = card.values[field.key] || '';
      return ta;
    }
    const inp = document.createElement('input');
    inp.type = 'text';
    inp.id = id;
    inp.spellcheck = false;
    if (field.placeholder) inp.placeholder = field.placeholder;
    inp.value = card.values[field.key] || '';
    return inp;
  }

  function buildCardEl(card, index) {
    const el = document.createElement('article');
    el.className = 'card' + (card.collapsed ? ' collapsed' : '');
    el.dataset.id = card.id;
    el.innerHTML =
      '<header class="card-head" role="button" tabindex="0">' +
      '<span class="num">' + (index + 1) + '</span>' +
      '<div class="summary"><div class="summary-main"></div><div class="summary-sub"></div></div>' +
      '<div class="status">' +
      '<span class="chip idle"><i class="dot"></i><span class="chip-text">Menunggu</span></span>' +
      '<span class="elapsed"></span>' +
      '<button class="card-del" data-action="remove" type="button" title="Hapus case ini" aria-label="Hapus case ini">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M8 6V4.5A1.5 1.5 0 0 1 9.5 3h5A1.5 1.5 0 0 1 16 4.5V6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/></svg>' +
      '</button>' +
      '</div>' +
      '<svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>' +
      '</header>' +
      '<div class="progress"></div>' +
      '<div class="card-body"><div class="card-body-inner"><div class="card-pad">' +
      '<div class="fields"></div>' +
      '<section class="result" hidden></section>' +
      '<section class="error-panel" hidden></section>' +
      '<div class="actions">' +
      '<button class="btn primary btn-sm" data-action="submit" type="button">Kirim</button>' +
      '<button class="btn ghost btn-sm" data-action="duplicate" type="button">Duplikat</button>' +
      '<span class="spacer"></span>' +
      '<button class="btn ghost danger btn-sm" data-action="remove" type="button">Hapus</button>' +
      '</div>' +
      '</div></div></div>';

    const fieldsWrap = $('.fields', el);
    const inputRefs = {};
    const msgRefs = {};
    const noteRefs = {};
    for (const field of state.settings.fields) {
      const row = document.createElement('div');
      row.className = 'field-row' + (field.type === 'textarea' ? ' full' : '');
      const label = document.createElement('label');
      label.className = 'input-label';
      label.htmlFor = 'f-' + card.id + '-' + field.key;
      label.innerHTML = esc(field.label) + (field.required ? '<span class="req">*</span>' : '');
      const control = buildFieldControl(card, field);
      const msg = document.createElement('div');
      msg.className = 'field-msg';
      const note = document.createElement('div');
      note.className = 'field-note';
      row.appendChild(label);
      row.appendChild(control);
      row.appendChild(msg);
      row.appendChild(note);
      fieldsWrap.appendChild(row);
      inputRefs[field.key] = control;
      msgRefs[field.key] = msg;
      noteRefs[field.key] = note;

      control.addEventListener('input', () => onFieldInput(card, field, control));
      if (field.type === 'select') control.addEventListener('change', () => onFieldInput(card, field, control));
    }

    refs.set(card.id, {
      el,
      head: $('.card-head', el),
      num: $('.num', el),
      summaryMain: $('.summary-main', el),
      summarySub: $('.summary-sub', el),
      chip: $('.chip', el),
      chipText: $('.chip-text', el),
      elapsed: $('.elapsed', el),
      resultEl: $('.result', el),
      errorEl: $('.error-panel', el),
      btnSubmit: $('[data-action="submit"]', el),
      inputs: inputRefs,
      msgs: msgRefs,
      notes: noteRefs,
    });

    refreshCard(card);
    return el;
  }

  function renderAll() {
    els.cards.innerHTML = '';
    refs.clear();
    state.cards.forEach((card, i) => els.cards.appendChild(buildCardEl(card, i)));
    updateEmptyState();
    updateStats();
    updateToolbar();
    updateTitle();
  }

  /** Perbarui nomor urut tanpa membangun ulang seluruh kartu. */
  function refreshCardNumbers() {
    state.cards.forEach((card, i) => {
      const r = refs.get(card.id);
      if (r) r.num.textContent = String(i + 1);
    });
  }

  /** Sisipkan satu kartu baru tanpa render ulang semua kartu (penting saat log panjang). */
  function insertCardEl(card, index) {
    const el = buildCardEl(card, index);
    const next = state.cards[index + 1];
    const nextEl = next ? refs.get(next.id)?.el : null;
    if (nextEl && nextEl.parentNode === els.cards) els.cards.insertBefore(el, nextEl);
    else els.cards.appendChild(el);
    refreshCardNumbers();
    updateEmptyState();
    updateStats();
    updateToolbar();
    updateTitle();
  }

  /** Hapus satu kartu dari DOM tanpa render ulang semua kartu. */
  function removeCardEl(card) {
    const r = refs.get(card.id);
    if (r) r.el.remove();
    refs.delete(card.id);
    refreshCardNumbers();
    updateEmptyState();
    updateStats();
    updateToolbar();
    updateTitle();
  }

  function refreshCard(card) {
    const r = refs.get(card.id);
    if (!r) return;
    const fields = state.settings.fields;
    const get = (role) => {
      const f = fields.find((x) => x.role === role);
      return f ? (card.values[f.key] || '').trim() : '';
    };
    const caseId = get('caseId');
    const tenant = get('tenant');
    const ticket = get('ticket');

    r.el.classList.toggle('collapsed', card.collapsed);
    r.el.classList.toggle('is-running', card.status === 'running');
    r.el.classList.toggle('is-queued', card.status === 'queued');
    r.el.classList.toggle('is-done', card.status === 'done');
    r.el.classList.toggle('is-error', card.status === 'error');
    const formHidden = isFormHidden(card);
    r.el.classList.toggle('form-hidden', formHidden);
    if (formHidden) {
      // Lepas log panjang dari DOM; nilainya tetap di state untuk duplikat/simpan.
      dehydrateTextareas(card);
    } else if (r.wasFormHidden && !card.collapsed) {
      hydrateInputs(card);
    }
    r.wasFormHidden = formHidden;
    r.head.setAttribute('aria-expanded', String(!card.collapsed));

    r.chip.className = 'chip ' + card.status;
    r.chipText.textContent =
      STATUS_LABEL[card.status] +
      (card.status === 'running' && card.nsStatus && NS_LABEL[card.nsStatus] ? ' · ' + NS_LABEL[card.nsStatus] : '');

    if (card.status === 'running' || card.status === 'queued') {
      r.elapsed.textContent = card.startedAt ? fmtDuration(Date.now() - card.startedAt) : '';
    } else if ((card.status === 'done' || card.status === 'error') && card.elapsedMs != null) {
      r.elapsed.textContent = fmtDuration(card.elapsedMs);
    } else {
      r.elapsed.textContent = '';
    }

    let main = caseId ? esc(caseId) : '<span class="dim">Belum diisi</span>';
    if (tenant) main += ' <span class="dim">· ' + esc(tenant) + '</span>';
    r.summaryMain.innerHTML = main;

    let sub = '';
    if (card.status === 'done' && card.result) {
      sub = resultLabel(card.result);
      if (card.dirty) sub += ' · input berubah, belum dikirim ulang';
    } else if (card.status === 'error') {
      sub = card.errorMsg || 'Gagal';
    } else if (card.status === 'running') {
      sub = 'Menunggu workflow selesai di n8n…';
    } else if (card.status === 'queued') {
      sub = 'Menunggu giliran dikirim…';
    } else if (ticket) {
      sub = 'Tiket: ' + ticket;
    }
    r.summarySub.textContent = sub;
    r.summarySub.classList.toggle('err', card.status === 'error');

    for (const key of Object.keys(r.inputs)) r.inputs[key].disabled = !!card.busy;
    r.btnSubmit.disabled = !!card.busy;
    r.btnSubmit.textContent = card.status === 'running' ? 'Diproses…' : card.status === 'error' ? 'Kirim Ulang' : 'Kirim';

    renderNumberNotes(card);
    renderResult(card);
    renderError(card);
  }

  /** Tandai field yang terisi otomatis supaya jelas & tetap bisa diedit. */
  function renderNumberNotes(card) {
    const r = refs.get(card.id);
    if (!r) return;
    const autoRoles = { caseId: card.caseIdAuto, ticket: card.ticketAuto };
    for (const field of state.settings.fields) {
      const note = r.notes[field.key];
      const input = r.inputs[field.key];
      if (!note || !input) continue;
      const isAuto = !!field.role && !!autoRoles[field.role] && !card.busy;
      input.classList.toggle('auto', isAuto);
      if (!isAuto) {
        note.textContent = '';
        continue;
      }
      note.textContent =
        field.role === 'ticket'
          ? 'otomatis: lanjutan tenant ' + (card.ticketFor || readVal(card, 'tenant') || '?') + ' — bisa diubah'
          : 'otomatis: lanjutan nomor sebelumnya — bisa diubah';
    }
  }

  function renderResult(card) {
    const r = refs.get(card.id);
    if (!r) return;
    const sec = r.resultEl;
    if (card.status !== 'done' || !card.result) {
      if (!sec.hidden) {
        sec.hidden = true;
        sec.innerHTML = '';
      }
      r.renderedResult = null;
      return;
    }
    // Hasil tidak berubah antar-refresh: jangan parse ulang HTML markdown yang besar.
    if (r.renderedResult === card.result) return;
    r.renderedResult = card.result;
    const res = card.result;
    sec.hidden = false;
    if (res.noOutput) {
      sec.innerHTML =
        '<div class="result-meta"><span class="chip done"><i class="dot"></i>Terkirim</span>' +
        '<span class="meta-text">Workflow selesai, tapi tidak ada halaman hasil (Form Ending) yang dikonfigurasi.</span></div>';
      return;
    }
    const sev = String(res.severity || '').toLowerCase();
    const sevClass = sev.includes('crit') ? 'critical' : sev.includes('high') ? 'high' : sev.includes('med') ? 'medium' : sev.includes('low') ? 'low' : '';
    const meta = [];
    if (card.elapsedMs != null) meta.push(fmtDuration(card.elapsedMs));
    if (card.execId) meta.push('exec #' + card.execId);
    sec.innerHTML =
      '<div class="result-meta">' +
      (res.severity ? '<span class="chip sev ' + sevClass + '">' + esc(res.severity) + '</span>' : '') +
      '<span class="meta-text">' + esc(meta.join(' · ')) + '</span>' +
      '<span class="spacer"></span>' +
      '<button class="btn ghost btn-sm" data-action="copy-md" type="button"' + (res.markdown ? '' : ' disabled') + '>Salin Markdown</button>' +
      '<button class="btn ghost btn-sm" data-action="copy-case" type="button"' + (res.caseName ? '' : ' disabled') + '>Salin Case Name</button>' +
      '<a class="btn ghost btn-sm" href="' + esc(joinUrl(state.settings.baseUrl, '/executions')) + '" target="_blank" rel="noopener">n8n ↗</a>' +
      '</div>' +
      '<div class="result-body">' + (res.fragmentHtml || '') + '</div>';
  }

  function renderError(card) {
    const r = refs.get(card.id);
    if (!r) return;
    const sec = r.errorEl;
    if (card.status !== 'error') {
      if (!sec.hidden) {
        sec.hidden = true;
        sec.innerHTML = '';
      }
      r.renderedErrorKey = null;
      return;
    }
    const key = [card.errorMsg, card.errorHint, card.errorDetail, card.waitingUrl, state.settings.baseUrl].join('\u0000');
    if (r.renderedErrorKey === key) return;
    r.renderedErrorKey = key;
    sec.hidden = false;
    sec.innerHTML =
      '<h3>✕ ' + esc(card.errorMsg || 'Gagal') + '</h3>' +
      (card.errorHint ? '<p>' + esc(card.errorHint) + '</p>' : '') +
      (card.errorDetail ? '<pre class="error-detail">' + esc(card.errorDetail) + '</pre>' : '') +
      '<div class="actions">' +
      '<button class="btn primary btn-sm" data-action="retry" type="button">Coba Lagi</button>' +
      (card.waitingUrl
        ? '<button class="btn ghost btn-sm" data-action="recheck" type="button">Periksa Hasil Lagi</button>'
        : '') +
      '<a class="btn ghost btn-sm" href="' + esc(joinUrl(state.settings.baseUrl, '/executions')) + '" target="_blank" rel="noopener">Cek eksekusi di n8n ↗</a>' +
      '</div>';
  }

  function updateEmptyState() {
    els.empty.hidden = state.cards.length !== 0;
  }

  function updateStats() {
    const counts = { done: 0, running: 0, pending: 0, error: 0 };
    for (const c of state.cards) {
      if (c.status === 'done') counts.done++;
      else if (c.status === 'running' || c.status === 'queued') counts.running++;
      else if (c.status === 'error') counts.error++;
      else counts.pending++;
    }
    for (const stat of els.stats.querySelectorAll('.stat')) {
      stat.querySelector('b').textContent = counts[stat.dataset.stat] ?? 0;
    }
  }

  function updateToolbar() {
    const eligible = eligibleCards().length;
    els.btnSubmitAllLabel.textContent = eligible ? 'Kirim Semua (' + eligible + ')' : 'Kirim Semua';
    els.btnSubmitAll.disabled = eligible === 0 || submitAllRunning;
    els.btnSubmitAll.title = eligible
      ? 'Kirim ' + eligible + ' form yang belum dikirim / berubah, sesuai mode pengiriman'
      : 'Tidak ada form yang perlu dikirim';
    els.btnCancel.hidden = !submitAllRunning;
    const allCollapsed = state.cards.length > 0 && state.cards.every((c) => c.collapsed);
    els.btnToggleAll.textContent = allCollapsed ? 'Buka semua' : 'Tutup semua';
    els.btnToggleAll.disabled = state.cards.length === 0;
  }

  function updateTitle() {
    const active = state.cards.filter((c) => c.status === 'running' || c.status === 'queued').length;
    document.title = active ? '(' + active + ') Diptera' : 'Diptera';
  }

  function updateFieldMsg(card, field, control, msgEl) {
    if (!msgEl) return;
    if (field.json) {
      const info = inspectJson(control.value);
      if (info.state === 'empty') {
        msgEl.textContent = '';
        msgEl.className = 'field-msg';
        control.classList.remove('invalid');
        return;
      }
      msgEl.textContent = info.message;
      msgEl.className = 'field-msg ' + (info.state === 'invalid' ? 'warn' : 'ok');
      // JSON bukan syarat kirim; jangan beri bingkai merah seolah input salah.
      control.classList.remove('invalid');
      return;
    }
    msgEl.textContent = '';
    msgEl.className = 'field-msg';
    control.classList.remove('invalid');
  }

  function onFieldInput(card, field, control) {
    const prev = card.values[field.key];
    card.values[field.key] = control.value;
    if (!card.busy && (card.status === 'done' || card.status === 'error')) card.dirty = true;
    control.classList.remove('invalid');

    // ---- penomoran otomatis ----
    if (field.role === 'caseId') {
      card.caseIdAuto = false;
      rememberNumber('caseId', card);
      schedulePropagate('caseId', card.id);
    } else if (field.role === 'ticket') {
      card.ticketAuto = false;
      card.ticketFor = null;
      rememberNumber('ticket', card);
      schedulePropagate('ticket', card.id, readVal(card, 'tenant'));
    } else if (field.role === 'tenant' && prev !== control.value) {
      const ticketKey = roleKey('ticket');
      const ticket = ticketKey ? String(card.values[ticketKey] ?? '').trim() : '';
      if (ticket) rememberNumber('ticket', card, prev); // simpan nomor untuk tenant lama
      if (state.settings.autoNumber && (card.ticketAuto || !ticket)) autoFillTicket(card);
      schedulePropagate('ticket', card.id, control.value);
    }

    const r = refs.get(card.id);
    if (r) {
      const msgEl = r.msgs[field.key];
      if (field.json) {
        clearTimeout(jsonTimers.get(card.id + ':' + field.key));
        jsonTimers.set(
          card.id + ':' + field.key,
          setTimeout(() => updateFieldMsg(card, field, control, msgEl), 450),
        );
      } else if (msgEl) {
        msgEl.textContent = '';
        msgEl.className = 'field-msg';
      }
    }
    if (r) {
      // perbarui ringkasan tanpa render ulang supaya fokus ketikan tidak hilang
      const fields = state.settings.fields;
      const get = (role) => {
        const f = fields.find((x) => x.role === role);
        return f ? (card.values[f.key] || '').trim() : '';
      };
      const caseId = get('caseId');
      const tenant = get('tenant');
      const ticket = get('ticket');
      let main = caseId ? esc(caseId) : '<span class="dim">Belum diisi</span>';
      if (tenant) main += ' <span class="dim">· ' + esc(tenant) + '</span>';
      r.summaryMain.innerHTML = main;
      if (card.status === 'done' && card.result) {
        r.summarySub.textContent = resultLabel(card.result) + (card.dirty ? ' · input berubah, belum dikirim ulang' : '');
      } else if (card.status === 'idle') {
        r.summarySub.textContent = ticket ? 'Tiket: ' + ticket : '';
      }
      renderNumberNotes(card);
    }
    updateToolbar();
    persist();
  }

  function validateCard(card) {
    const errors = [];
    const r = refs.get(card.id);
    for (const field of state.settings.fields) {
      const value = (card.values[field.key] || '').trim();
      const control = r?.inputs[field.key];
      const msgEl = r?.msgs[field.key];
      if (!field.json) {
        if (control) control.classList.remove('invalid');
        if (msgEl) {
          msgEl.textContent = '';
          msgEl.className = 'field-msg';
        }
      }
      if (field.required && !value) {
        errors.push({ field, message: field.label + ' wajib diisi.' });
        if (control) control.classList.add('invalid');
        if (msgEl) {
          msgEl.textContent = field.label + ' wajib diisi.';
          msgEl.className = 'field-msg bad';
        }
        continue;
      }
      if (field.json && value) {
        const info = inspectJson(value);
        if (info.state === 'invalid') {
          // Form n8n menerima teks apa adanya. Tampilkan peringatan, tapi
          // jangan blokir — beberapa workflow memang memproses teks bebas.
          if (control) control.classList.remove('invalid');
          if (msgEl) {
            msgEl.textContent = info.message;
            msgEl.className = 'field-msg warn';
          }
        } else if (msgEl) {
          msgEl.textContent = info.message;
          msgEl.className = 'field-msg ok';
        }
      }
    }
    return errors;
  }

  /* ---------------- notifications ---------------- */

  function toast(opts) {
    const { type = 'info', title, body, onClick } = opts;
    const el = document.createElement('div');
    el.className = 'toast ' + type;
    el.innerHTML = '<div class="toast-title">' + esc(title) + '</div>' + (body ? '<div class="toast-body">' + esc(body) + '</div>' : '');
    const remove = () => {
      el.remove();
      clearTimeout(timer);
    };
    el.addEventListener('click', () => {
      remove();
      if (onClick) onClick();
    });
    $('#toasts').appendChild(el);
    const timer = setTimeout(remove, type === 'error' ? 12000 : 7000);
    while ($('#toasts').children.length > 5) $('#toasts').firstElementChild.remove();
  }

  function desktopNotify(title, body, onClick) {
    if (!state.settings.desktopNotify) return;
    if (document.hidden !== true) return;
    if (!('Notification' in window) || Notification.permission !== 'granted') return;
    try {
      const n = new Notification(title, { body, tag: 'diptera' });
      n.onclick = () => {
        window.focus();
        if (onClick) onClick();
      };
    } catch {
      /* ignore */
    }
  }

  function focusCard(card) {
    card.collapsed = false;
    hydrateInputs(card);
    refreshCard(card);
    persist();
    const r = refs.get(card.id);
    if (r) {
      r.el.classList.remove('flash');
      void r.el.offsetWidth;
      r.el.classList.add('flash');
      r.el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }

  function copyText(text, label) {
    const done = () => toast({ type: 'success', title: 'Disalin ke clipboard', body: label });
    const fallback = () => {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand('copy');
        done();
      } catch {
        toast({ type: 'error', title: 'Gagal menyalin', body: 'Salin manual dari blok di bawah.' });
      }
      ta.remove();
    };
    if (navigator.clipboard && window.isSecureContext !== false) {
      navigator.clipboard.writeText(text).then(done, fallback);
    } else {
      fallback();
    }
  }

  /* ---------------- submit & polling ---------------- */

  async function submitAll() {
    if (submitAllRunning) return;
    const list = eligibleCards();
    if (!list.length) return;
    submitAllRunning = true;
    updateToolbar();
    try {
      if (state.settings.submitMode === 'parallel') {
        await Promise.all(list.map((card) => submitCard(card)));
      } else {
        for (const card of list) {
          if (!submitAllRunning) break;
          await submitCard(card);
        }
      }
    } finally {
      submitAllRunning = false;
      updateToolbar();
    }
  }

  function cancelAll() {
    submitAllRunning = false;
    for (const card of state.cards) {
      if (card.busy && card.abort) card.abort.abort();
    }
    updateToolbar();
  }

  async function submitCard(card) {
    if (card.busy || !state.cards.includes(card)) return;
    rememberNumber('caseId', card);
    rememberNumber('ticket', card);
    const errors = validateCard(card);
    if (errors.length) {
      card.collapsed = false;
      hydrateInputs(card);
      refreshCard(card);
      toast({ type: 'error', title: cardLabel(card) + ' belum lengkap', body: errors[0].message, onClick: () => focusCard(card) });
      return;
    }
    card.busy = true;
    card.status = 'queued';
    card.errorMsg = card.errorDetail = card.errorHint = card.errorKind = null;
    card.result = null;
    card.waitingUrl = card.execId = card.nsStatus = null;
    card.resumed = false;
    card.startedAt = Date.now();
    card.elapsedMs = null;
    if (state.settings.autoCollapse) {
      card.collapsed = true;
      dehydrateTextareas(card);
    }
    refreshCard(card);
    updateStats();
    updateToolbar();
    updateTitle();
    persist();

    const ctrl = new AbortController();
    card.abort = ctrl;
    try {
      await new Promise((r) => setTimeout(r, 30));
      card.status = 'running';
      refreshCard(card);
      updateStats();
      updateTitle();

      const formUrl = joinUrl(state.settings.baseUrl, '/form/' + encodeURIComponent(state.settings.formPath));
      const fd = new FormData();
      for (const field of state.settings.fields) fd.append(field.key, card.values[field.key] ?? '');

      const res = await fetchWithTimeout(formUrl, { method: 'POST', body: fd }, 180000, ctrl.signal);
      const text = await res.text();
      if (!res.ok) {
        throw {
          kind: 'http',
          message: 'n8n membalas HTTP ' + res.status,
          hint: 'Cek Base URL, Form path, dan pastikan workflow aktif/published di n8n.',
          detail: X.stripTags ? X.stripTags(text).slice(0, 800) : text.slice(0, 800),
        };
      }

      const json = safeJson(text);
      if (json && json.formWaitingUrl) {
        // n8n mengembalikan URL pemantauan; hasil diambil setelah workflow selesai.
        card.waitingUrl = X.resolveResultUrl(json.formWaitingUrl, state.settings.baseUrl, state.settings.rewriteHost);
        card.execId = X.execIdFromWaitingUrl(card.waitingUrl);
        card.nsStatus = 'running';
        refreshCard(card);
        persist();
        const parsed = await pollForResult(card, ctrl.signal);
        finishDone(card, parsed);
      } else {
        const parsed = X.parse(text);
        if (parsed.found) {
          // Mode lain: respons POST langsung berupa halaman hasil.
          finishDone(card, parsed);
        } else if (json && (json.status === 200 || json.status === '200')) {
          finishDone(card, { found: false, noOutput: true, fragmentHtml: '', caseName: null, severity: null, markdown: null });
        } else if (X.looksLikeError && X.looksLikeError(text)) {
          throw {
            kind: 'n8n',
            message: 'Workflow gagal di n8n',
            hint: 'Buka daftar eksekusi n8n untuk melihat node yang error.',
            detail: parsed.pageText ? parsed.pageText.slice(0, 800) : text.slice(0, 800),
          };
        } else {
          throw {
            kind: 'format',
            message: 'Respons n8n tidak dikenali',
            hint: 'Pastikan Form path benar dan workflow punya node Form (Form Ending).',
            detail: (parsed.pageText || text).slice(0, 800),
          };
        }
      }
    } catch (e) {
      failCard(card, e);
    } finally {
      card.busy = false;
      card.abort = null;
      refreshCard(card);
      updateStats();
      updateToolbar();
      updateTitle();
      persist();
    }
  }

  async function pollForResult(card, signal) {
    const started = card.startedAt || Date.now();
    const budget = Math.max(1, Number(state.settings.timeoutMin) || 30) * 60000;
    let interval = 1000;
    for (;;) {
      if (signal?.aborted) throw abortErr();
      if (Date.now() - started > budget) {
        throw {
          kind: 'timeout',
          message: 'Melebihi batas tunggu ' + state.settings.timeoutMin + ' menit',
          hint: 'Workflow masih jalan? Buka n8n untuk memeriksa. Setelah selesai, klik "Periksa Hasil Lagi".',
        };
      }

      let status = '';
      try {
        status = (await fetchText(statusUrlOf(card.waitingUrl), 20000, signal)).trim();
      } catch (e) {
        if (signal?.aborted || e?.name === 'AbortError') throw abortErr();
        throw {
          kind: 'network',
          message: 'Gagal memantau status di n8n',
          hint: 'Pastikan n8n berjalan dan Base URL benar. Kalau hanya sesaat, klik "Periksa Hasil Lagi".',
          detail: String(e && e.message ? e.message : e),
        };
      }
      const nextStatus = status || 'unknown';
      if (card.nsStatus !== nextStatus) {
        card.nsStatus = nextStatus;
        refreshCard(card);
        persist();
      }

      if (status === 'form-waiting' || status === 'success') {
        let lastExcerpt = '';
        for (let attempt = 0; attempt < 4; attempt++) {
          const html = await fetchText(card.waitingUrl, 60000, signal);
          const parsed = X.parse(html);
          if (parsed.found) {
            resumeExecution(card);
            return parsed;
          }
          lastExcerpt = parsed.pageText || html.slice(0, 800);
          if (X.looksLikeError(lastExcerpt)) {
            resumeExecution(card);
            throw {
              kind: 'n8n',
              message: 'Workflow gagal di n8n',
              hint: 'Periksa node yang error di n8n (eksekusi #' + (card.execId || '?') + ').',
              detail: lastExcerpt.slice(0, 800),
            };
          }
          await sleep(1200, signal);
        }
        throw {
          kind: 'format',
          message: 'Halaman hasil tidak dikenali',
          hint: 'Buka hasilnya langsung di n8n untuk memeriksa.',
          detail: lastExcerpt.slice(0, 800),
        };
      }

      if (['error', 'crashed', 'canceled', 'null'].includes(status)) {
        let detail = '';
        try {
          const html = await fetchText(card.waitingUrl, 20000, signal);
          const parsed = X.parse(html);
          detail = (parsed.pageText || X.stripTags(html)).slice(0, 800);
        } catch (e) {
          if (signal?.aborted || e?.name === 'AbortError') throw abortErr();
          detail = '';
        }
        throw {
          kind: 'n8n',
          message: 'Workflow ' + (status === 'null' ? 'tidak ditemukan' : status + ' di n8n'),
          hint: 'Periksa node yang error di n8n (eksekusi #' + (card.execId || '?') + ').',
          detail,
        };
      }

      await sleep(interval, signal);
      interval = Math.min(Math.round(interval * 1.2), 5000);
    }
  }

  function resumeExecution(card) {
    if (!state.settings.autoResume || card.resumed || !card.waitingUrl) return;
    card.resumed = true;
    fetchWithTimeout(card.waitingUrl, { method: 'POST' }, 15000, null).catch(() => {
      /* opsional — abaikan error */
    });
  }

  function finishDone(card, parsed) {
    if (!state.cards.includes(card)) return;
    card.status = 'done';
    card.dirty = false;
    card.result = parsed;
    card.elapsedMs = Date.now() - (card.startedAt || Date.now());
    card.errorMsg = card.errorDetail = card.errorHint = card.errorKind = null;
    skipResultsOnSave = false; // hasil baru: coba simpan lengkap lagi
    refreshCard(card);
    const summary = resultLabel(parsed) || 'Hasil siap';
    const title = cardLabel(card) + ' selesai' + (parsed.severity ? ' · ' + parsed.severity : '');
    toast({ type: 'success', title, body: summary, onClick: () => focusCard(card) });
    desktopNotify('IRIS: ' + title, summary, () => focusCard(card));
    persist();
  }

  function failCard(card, e) {
    if (!state.cards.includes(card)) return;
    const kind = e && e.kind ? e.kind : e && e.name === 'AbortError' ? 'abort' : 'network';
    const now = Date.now();
    card.status = 'error';
    card.errorKind = kind;
    if (kind === 'abort') {
      card.errorMsg = 'Dibatalkan';
      card.errorHint = card.waitingUrl ? 'Klik "Periksa Hasil Lagi" untuk melanjutkan memantau hasil.' : null;
      card.errorDetail = e?.detail || null;
    } else if (kind === 'timeout') {
      card.errorMsg = e.message || 'Melebihi batas tunggu';
      card.errorHint = e.hint || null;
    } else if (kind === 'http') {
      card.errorMsg = e.message || 'HTTP error dari n8n';
      card.errorHint = e.hint || null;
      card.errorDetail = e.detail || null;
    } else if (kind === 'n8n') {
      card.errorMsg = e.message || 'Workflow gagal di n8n';
      card.errorHint = e.hint || null;
      card.errorDetail = e.detail || null;
    } else if (kind === 'format') {
      card.errorMsg = e.message || 'Format respons tidak dikenali';
      card.errorHint = e.hint || null;
      card.errorDetail = e.detail || null;
    } else if (kind === 'interrupted') {
      card.errorMsg = e.message || 'Terputus';
      card.errorHint = e.hint || null;
      card.errorDetail = e.detail || null;
    } else {
      card.errorMsg = 'Tidak bisa menghubungi n8n';
      card.errorHint = 'Pastikan n8n berjalan dan Base URL di pengaturan benar (termasuk CORS bila beda origin).';
      card.errorDetail = String(e && e.message ? e.message : e);
    }
    if (card.elapsedMs == null && card.startedAt) card.elapsedMs = now - card.startedAt;
    refreshCard(card);
    toast({ type: 'error', title: cardLabel(card) + ' gagal', body: card.errorMsg, onClick: () => focusCard(card) });
    desktopNotify('IRIS: ' + cardLabel(card) + ' gagal', card.errorMsg, () => focusCard(card));
    persist();
  }

  async function recheckCard(card) {
    if (card.busy || !card.waitingUrl) return;
    card.busy = true;
    card.status = 'running';
    card.errorMsg = card.errorDetail = card.errorHint = null;
    card.nsStatus = 'running';
    refreshCard(card);
    updateStats();
    updateTitle();
    const ctrl = new AbortController();
    card.abort = ctrl;
    try {
      const parsed = await pollForResult(card, ctrl.signal);
      finishDone(card, parsed);
    } catch (e) {
      failCard(card, e);
    } finally {
      card.busy = false;
      card.abort = null;
      refreshCard(card);
      updateStats();
      updateToolbar();
      updateTitle();
      persist();
    }
  }

  /* ---------------- settings ---------------- */

  function fillSettingsForm() {
    $('#set-base-url').value = state.settings.baseUrl;
    $('#set-form-path').value = state.settings.formPath;
    $('#set-submit-mode').value = state.settings.submitMode;
    $('#set-timeout').value = state.settings.timeoutMin;
    $('#set-auto-collapse').checked = state.settings.autoCollapse;
    $('#set-auto-resume').checked = state.settings.autoResume;
    $('#set-rewrite-host').checked = state.settings.rewriteHost;
    $('#set-desktop-notify').checked = state.settings.desktopNotify;
    $('#set-auto-number').checked = state.settings.autoNumber !== false;
    $('#set-fields-json').value = JSON.stringify(state.settings.fields, null, 2);
    const nextCaseInput = $('#set-next-case-id');
    if (nextCaseInput) {
      const nextCase = state.counters.caseId && N.nextValue ? N.nextValue(state.counters.caseId) : (state.counters.caseId || '');
      nextCaseInput.value = nextCase;
    }
    renderTenantsSettingsList();
    const pageHint = $('#base-url-page-hint');
    if (pageHint) {
      pageHint.textContent = isLocalPage()
        ? 'Halaman ini dibuka dari localhost.'
        : 'Halaman ini dibuka dari ' + window.location.host + '.';
    }
  }

  function getTenantField() {
    return state.settings.fields.find((f) => f.role === 'tenant');
  }

  function renderTenantsSettingsList() {
    const container = $('#tenants-list');
    if (!container) return;
    container.innerHTML = '';
    const tenantField = getTenantField();
    const options = tenantField && Array.isArray(tenantField.options) ? tenantField.options : [];

    if (options.length === 0) {
      container.innerHTML = '<span class=\"dim\" style=\"font-size:12px;\">Belum ada tenant. Klik \"+ Tambah Tenant\" di bawah.</span>';
      return;
    }

    options.forEach((tenant) => {
      const row = document.createElement('div');
      row.className = 'tenant-row';
      const nextTicket = state.counters.tickets[tenant] || '';
      row.innerHTML =
        '<input type=\"text\" class=\"tenant-name-input\" value=\"' + esc(tenant) + '\" placeholder=\"Nama Tenant (mis. tenant-a)\" spellcheck=\"false\" />' +
        '<input type=\"text\" class=\"tenant-ticket-input\" value=\"' + esc(nextTicket) + '\" placeholder=\"Nomor Tiket Awal (mis. 30000)\" spellcheck=\"false\" />' +
        '<button class=\"tenant-del\" type=\"button\" title=\"Hapus tenant\">\n' +
        '  <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M3 6h18\"/><path d=\"M8 6V4.5A1.5 1.5 0 0 1 9.5 3h5A1.5 1.5 0 0 1 16 4.5V6\"/><path d=\"M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6\"/><path d=\"M10 11v6M14 11v6\"/></svg>\n' +
        '</button>';

      $('.tenant-del', row).addEventListener('click', () => {
        row.remove();
        if ($('.tenant-row', container) == null) {
          container.innerHTML = '<span class=\"dim\" style=\"font-size:12px;\">Belum ada tenant. Klik \"+ Tambah Tenant\" di bawah.</span>';
        }
      });
      container.appendChild(row);
    });
  }

  /** Ringkasan nomor berikutnya (ditampilkan di panel pengaturan). */
  function updateNumberingInfo() {
    const el = $('#numbering-info');
    if (!el) return;
    if (state.settings.autoNumber === false) {
      el.innerHTML = '<span class="dim">Penomoran otomatis sedang dimatikan.</span>';
      return;
    }
    const nextCase = state.counters.caseId && N.nextValue ? N.nextValue(state.counters.caseId) : null;
    const rows = ['Case ID berikutnya: ' + (nextCase ? '<b>' + esc(nextCase) + '</b>' : '<span class="dim">belum ada</span>')];
    const tickets = Object.keys(state.counters.tickets || {}).filter((t) => state.counters.tickets[t]);
    if (tickets.length) {
      rows.push(
        'Tiket berikutnya: ' +
          tickets
            .sort()
            .map((t) => esc(t) + ' → <b>' + esc(N.nextValue(state.counters.tickets[t]) || '?') + '</b>')
            .join(' · '),
      );
    } else {
      rows.push('Tiket berikutnya: <span class="dim">belum ada (isi satu nomor dulu per tenant)</span>');
    }
    el.innerHTML = rows.join('<br>');
  }

  function resetNumbering() {
    if (!window.confirm('Lupakan acuan nomor otomatis (case ID & tiket per tenant)? Nilai yang sudah ada di form dibiarkan.')) {
      return;
    }
    state.counters = { caseId: null, tickets: {} };
    for (const card of state.cards) {
      card.caseIdAuto = false;
      card.ticketAuto = false;
      card.ticketFor = null;
    }
    renderAll();
    if (!els.settingsPanel.hidden) fillSettingsForm();
    persist();
    toast({ type: 'info', title: 'Acuan penomoran direset', body: 'Nomor berikutnya akan mengikuti isian yang kamu ketik.' });
  }

  function saveSettings() {
    const baseUrl = $('#set-base-url').value.trim();
    const formPath = $('#set-form-path').value.trim();
    if (!baseUrl) return toast({ type: 'error', title: 'Base URL wajib diisi' });
    if (!formPath) return toast({ type: 'error', title: 'Form path wajib diisi' });

    // Kumpulkan tenant & tiket dari panel tenant dinamis
    const tenantRows = document.querySelectorAll('#tenants-list .tenant-row');
    const newTenants = [];
    const newTickets = {};
    tenantRows.forEach((row) => {
      const nameInput = row.querySelector('.tenant-name-input');
      const ticketInput = row.querySelector('.tenant-ticket-input');
      if (nameInput) {
        const name = nameInput.value.trim();
        if (name && !newTenants.includes(name)) {
          newTenants.push(name);
          if (ticketInput && ticketInput.value.trim()) {
            newTickets[name] = ticketInput.value.trim();
          }
        }
      }
    });

    let fields;
    try {
      fields = normalizeFields(JSON.parse($('#set-fields-json').value));
    } catch (e) {
      return toast({ type: 'error', title: 'Definisi field tidak valid', body: e.message });
    }

    // Perbarui options pada field tenant jika ada
    const tenantField = fields.find((f) => f.role === 'tenant');
    if (tenantField) {
      tenantField.options = newTenants;
    }

    // Perbarui counter tiket
    if (Object.keys(newTickets).length > 0) {
      for (const [t, val] of Object.entries(newTickets)) {
        state.counters.tickets[t] = val;
      }
    }

    const nextCaseInput = $('#set-next-case-id');
    if (nextCaseInput && nextCaseInput.value.trim()) {
      state.counters.caseId = nextCaseInput.value.trim();
    }
    const autoNumberWas = state.settings.autoNumber !== false;
    state.settings.baseUrl = baseUrl.replace(/\/+$/, '');
    state.settings.formPath = formPath;
    state.settings.submitMode = $('#set-submit-mode').value === 'parallel' ? 'parallel' : 'sequential';
    state.settings.timeoutMin = Math.min(240, Math.max(1, Number($('#set-timeout').value) || 30));
    state.settings.autoCollapse = $('#set-auto-collapse').checked;
    state.settings.autoResume = $('#set-auto-resume').checked;
    state.settings.rewriteHost = $('#set-rewrite-host').checked;
    state.settings.desktopNotify = $('#set-desktop-notify').checked;
    state.settings.autoNumber = $('#set-auto-number').checked;
    state.settings.fields = fields;
    for (const card of state.cards) {
      for (const f of fields) if (!(f.key in card.values)) card.values[f.key] = '';
    }
    if (state.settings.autoNumber && !autoNumberWas) refillNumbering();
    updateFormLink();
    renderAll();
    persist();
    updateNumberingInfo();
    toast({ type: 'success', title: 'Pengaturan disimpan' });
  }

  function updateFormLink() {
    els.linkForm.href = joinUrl(state.settings.baseUrl, '/form/' + encodeURIComponent(state.settings.formPath));
  }

  /* ---------------- events ---------------- */

  function toggleCollapse(card) {
    card.collapsed = !card.collapsed;
    if (card.collapsed) dehydrateTextareas(card);
    else hydrateInputs(card);
    refreshCard(card);
    updateToolbar();
    persist();
  }

  function removeCard(card) {
    if (card.busy && card.abort) card.abort.abort();
    const idx = cardIndex(card);
    if (idx === -1) return;
    state.cards.splice(idx, 1);
    removeCardEl(card);
    skipResultsOnSave = false; // ruang bisa lega lagi
    persist();
  }

  function duplicateCard(card) {
    const copy = newCard(card.values);
    copy.collapsed = false;
    // nomor ikut maju supaya duplikat tidak memakai nomor yang sama
    const caseKey = roleKey('caseId');
    const ticketKey = roleKey('ticket');
    if (autoNumberOn()) {
      const nextCase = nextNumberFor('caseId');
      if (caseKey && nextCase) {
        copy.values[caseKey] = nextCase;
        copy.caseIdAuto = true;
        state.counters.caseId = nextCase;
      }
      const tenant = readVal(copy, 'tenant');
      const nextTicket = nextNumberFor('ticket', tenant);
      if (ticketKey && nextTicket) {
        copy.values[ticketKey] = nextTicket;
        copy.ticketAuto = true;
        copy.ticketFor = tenant;
        state.counters.tickets[tenant] = nextTicket;
      } else if (ticketKey && copy.values[ticketKey]) {
        copy.ticketAuto = false;
        copy.ticketFor = tenant;
      }
    }
    state.cards.splice(cardIndex(card) + 1, 0, copy);
    insertCardEl(copy, cardIndex(copy));
    persist();
  }

  function bindEvents() {
    $('#btn-add').addEventListener('click', () => {
      const card = newCard();
      state.cards.push(card);
      insertCardEl(card, state.cards.length - 1);
      persist();
      const r = refs.get(card.id);
      const first = r && Object.values(r.inputs)[0];
      if (first) first.focus();
    });
    $('#btn-add-empty').addEventListener('click', () => $('#btn-add').click());
    els.btnSubmitAll.addEventListener('click', submitAll);
    els.btnCancel.addEventListener('click', cancelAll);
    els.btnToggleAll.addEventListener('click', () => {
      const collapse = !state.cards.every((c) => c.collapsed);
      for (const c of state.cards) {
        c.collapsed = collapse;
        if (collapse) dehydrateTextareas(c);
        else hydrateInputs(c);
        const r = refs.get(c.id);
        if (r) {
          r.el.classList.toggle('collapsed', collapse);
          r.head.setAttribute('aria-expanded', String(!collapse));
        }
      }
      updateToolbar();
      persist();
    });

    $('#btn-settings').addEventListener('click', () => {
      els.settingsPanel.hidden = !els.settingsPanel.hidden;
      if (!els.settingsPanel.hidden) fillSettingsForm();
    });
    $('#btn-base-from-page').addEventListener('click', () => {
      $('#set-base-url').value = guessBaseUrl();
      toast({
        type: 'info',
        title: 'Base URL diisi dari alamat halaman',
        body: guessBaseUrl() + ' — klik Simpan pengaturan.',
      });
    });
    $('#btn-save-settings').addEventListener('click', saveSettings);
    $('#btn-add-tenant').addEventListener('click', () => {
      const container = $('#tenants-list');
      if (!container) return;
      if ($('.dim', container)) container.innerHTML = '';
      const row = document.createElement('div');
      row.className = 'tenant-row';
      row.innerHTML =
        '<input type=\"text\" class=\"tenant-name-input\" placeholder=\"Nama Tenant (mis. tenant-a)\" spellcheck=\"false\" />' +
        '<input type=\"text\" class=\"tenant-ticket-input\" placeholder=\"Nomor Tiket Awal (mis. 30000)\" spellcheck=\"false\" />' +
        '<button class=\"tenant-del\" type=\"button\" title=\"Hapus tenant\">\n' +
        '  <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M3 6h18\"/><path d=\"M8 6V4.5A1.5 1.5 0 0 1 9.5 3h5A1.5 1.5 0 0 1 16 4.5V6\"/><path d=\"M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6\"/><path d=\"M10 11v6M14 11v6\"/></svg>\n' +
        '</button>';

      $('.tenant-del', row).addEventListener('click', () => {
        row.remove();
        if ($('.tenant-row', container) == null) {
          container.innerHTML = '<span class=\"dim\" style=\"font-size:12px;\">Belum ada tenant. Klik \"+ Tambah Tenant\" di bawah.</span>';
        }
      });
      container.appendChild(row);
      const nameInput = $('.tenant-name-input', row);
      if (nameInput) nameInput.focus();
    });
    $('#btn-reset-numbering').addEventListener('click', resetNumbering);
    $('#btn-reset-settings').addEventListener('click', () => {
      state.settings = clone(DEFAULT_SETTINGS);
      state.settings.fields = normalizeFields(clone(DEFAULT_FIELDS));
      fillSettingsForm();
      updateFormLink();
      renderAll();
      persist();
      toast({ type: 'info', title: 'Pengaturan direset ke default' });
    });
    $('#btn-clear-all').addEventListener('click', () => {
      if (!state.cards.length) return toast({ type: 'info', title: 'Tidak ada form untuk dihapus' });
      if (!window.confirm('Hapus semua form beserta hasilnya? Tindakan ini tidak bisa dibatalkan.')) return;
      for (const card of state.cards) if (card.busy && card.abort) card.abort.abort();
      state.cards = [];
      skipResultsOnSave = false;
      renderAll();
      persist();
    });

    $('#set-desktop-notify').addEventListener('change', async (ev) => {
      if (!ev.target.checked) return;
      if (!('Notification' in window)) {
        ev.target.checked = false;
        toast({ type: 'info', title: 'Browser ini tidak mendukung notifikasi desktop' });
        return;
      }
      const perm = await Notification.requestPermission();
      if (perm !== 'granted') {
        ev.target.checked = false;
        toast({ type: 'info', title: 'Izin notifikasi ditolak' });
      }
    });

    // delegasi klik untuk elemen kartu
    els.cards.addEventListener('click', (ev) => {
      const cardEl = ev.target.closest('.card');
      if (!cardEl) return;
      const card = findCard(cardEl.dataset.id);
      if (!card) return;
      const head = ev.target.closest('.card-head');
      const actionBtn = ev.target.closest('[data-action]');
      if (actionBtn) {
        const action = actionBtn.dataset.action;
        if (action === 'submit') return void submitCard(card);
        if (action === 'duplicate') return void duplicateCard(card);
        if (action === 'remove') return void removeCard(card);
        if (action === 'retry') return void submitCard(card);
        if (action === 'recheck') return void recheckCard(card);
        if (action === 'copy-md') return void copyText(card.result?.markdown || '', 'Markdown ' + cardLabel(card));
        if (action === 'copy-case') return void copyText(card.result?.caseName || '', 'Case name ' + cardLabel(card));
        return;
      }
      if (head) toggleCollapse(card);
    });

    els.cards.addEventListener('keydown', (ev) => {
      if (ev.key !== 'Enter' && ev.key !== ' ') return;
      const head = ev.target.closest('.card-head');
      if (!head || ev.target !== head) return;
      ev.preventDefault();
      const card = findCard(ev.target.closest('.card').dataset.id);
      if (card) toggleCollapse(card);
    });

    // Berhenti mengetik / pindah field adalah saat yang tepat untuk menyimpan.
    els.cards.addEventListener('focusout', () => persist());

    document.addEventListener('keydown', (ev) => {
      if ((ev.ctrlKey || ev.metaKey) && ev.key === 'Enter') {
        ev.preventDefault();
        submitAll();
      }
    });

    document.addEventListener('visibilitychange', () => {
      if (document.hidden) flushPersist();
      else updateTitle();
    });
    window.addEventListener('beforeunload', () => flushPersist(true));

    // timer untuk elapsed kartu yang sedang berjalan
    setInterval(() => {
      for (const card of state.cards) {
        if (card.status === 'running' || card.status === 'queued') {
          const r = refs.get(card.id);
          if (r && card.startedAt) r.elapsed.textContent = fmtDuration(Date.now() - card.startedAt);
        }
      }
    }, 500);
  }

  /* ---------------- boot ---------------- */

  function init() {
    els.cards = $('#cards');
    els.empty = $('#empty-state');
    els.stats = $('#stats');
    els.btnSubmitAll = $('#btn-submit-all');
    els.btnSubmitAllLabel = $('#btn-submit-all-label');
    els.btnCancel = $('#btn-cancel');
    els.btnToggleAll = $('#btn-toggle-all');
    els.linkForm = $('#link-form');
    els.settingsPanel = $('#settings-panel');

    const loaded = loadState();
    if (loaded) {
      state = loaded;
    } else {
      state.cards.push(newCard());
    }
    deriveCounters();

    updateFormLink();
    renderAll();
    bindEvents();

    // Dibuka lewat IP tapi Base URL masih localhost -> tawarkan perbaikan.
    if (
      !isLocalPage() &&
      /^(https?:\/\/)?(localhost|127\.0\.0\.1|\[::1\])(?=[:/]|$)/i.test(state.settings.baseUrl)
    ) {
      toast({
        type: 'info',
        title: 'n8n Base URL masih localhost',
        body: 'Halaman dibuka lewat ' + window.location.host + '. Klik di sini untuk memakai IP halaman ini.',
        onClick: () => {
          els.settingsPanel.hidden = false;
          fillSettingsForm();
          els.settingsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
        },
      });
    }

    // pulihkan kartu yang masih dipantau saat halaman di-reload
    for (const card of state.cards) {
      if (card.status === 'running' || card.status === 'queued') {
        if (card.waitingUrl) {
          card.status = 'running';
          recheckCard(card); // sekaligus menandai busy & melanjutkan polling
        } else {
          card.status = 'queued';
          card.busy = false;
          failCard(card, {
            kind: 'interrupted',
            message: 'Terputus — halaman di-reload saat pengiriman',
            hint: 'Klik "Coba Lagi" untuk mengirim ulang form ini.',
          });
        }
      }
    }
    updateStats();
    updateToolbar();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
