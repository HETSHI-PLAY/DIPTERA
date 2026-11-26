/* Diptera Frontend Controller — Wazuh Live Feed (1:1 Parity), AI Pre-Triage & Case Audit History */
'use strict';

(function () {
  const B = window.DipteraBridge;
  if (!B) return;

  const $ = (sel, root = document) => root.querySelector(sel);

  const VERDICT_META = {
    TRUE_POSITIVE: { label: 'True Positive', cls: 'verdict-tp' },
    NEEDS_REVIEW: { label: 'Perlu Ditinjau', cls: 'verdict-review' },
    FALSE_POSITIVE: { label: 'False Positive', cls: 'verdict-fp' },
  };

  let triageState = {
    config: null,
    snapshot: null,
    verdictFilter: 'TRUE_POSITIVE',
    tenantFilter: '',
    search: '',
    selectedGroupIds: new Set(),
    expandedGroupIds: new Set(),
    liveData: null,
    liveScope: 'watermark',
    liveAutoRefresh: true,
    liveTimer: null,
    historyData: null,
    settingsTab: 'workspace',
    sse: null,
  };

  function showInlineStatus(el, ok, text) {
    if (!el) return;
    if (!text) {
      el.hidden = true;
      el.textContent = '';
      el.className = 'um-msg';
      return;
    }
    el.hidden = false;
    el.textContent = text;
    el.className = 'um-msg ' + (ok ? 'ok' : 'err');
  }

  function openRawJsonModal(title, obj) {
    const modal = $('#raw-json-modal');
    const pre = $('#raw-json-pre');
    const titleEl = $('#raw-json-title');
    if (!modal || !pre) return;
    if (titleEl) titleEl.textContent = title || 'Raw Wazuh Alert JSON';
    pre.textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
    modal.hidden = false;
  }

  function closeRawJsonModal() {
    const modal = $('#raw-json-modal');
    if (modal) modal.hidden = true;
  }

  /* ---------------- Settings Panel: Wazuh & AI Triage ---------------- */

  function switchSettingsSubTab(tab) {
    const isTriage = tab === 'triage';
    triageState.settingsTab = isTriage ? 'triage' : 'workspace';
    $('#set-mode-workspace')?.classList.toggle('active', !isTriage);
    $('#set-mode-workspace')?.setAttribute('aria-pressed', String(!isTriage));
    $('#set-mode-triage')?.classList.toggle('active', isTriage);
    $('#set-mode-triage')?.setAttribute('aria-pressed', String(isTriage));
    if ($('#settings-workspace-panel')) $('#settings-workspace-panel').hidden = isTriage;
    if ($('#settings-triage-panel')) $('#settings-triage-panel').hidden = !isTriage;
    if (isTriage) loadTriageConfig();
  }

  function renderExclusionRows(rules = []) {
    const tbody = $('#trg-exclusions-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    for (const rule of rules) {
      const tr = document.createElement('tr');
      tr.dataset.ruleId = rule.id || '';
      tr.innerHTML = `
        <td>
          <input type="checkbox" class="trg-ex-enabled" aria-label="Aktifkan aturan" ${rule.enabled !== false ? 'checked' : ''} />
        </td>
        <td>
          <select class="trg-ex-target" aria-label="Target field">
            <option value="path" ${rule.target === 'path' ? 'selected' : ''}>URL / Request Path</option>
            <option value="full_log" ${rule.target === 'full_log' ? 'selected' : ''}>Full Log</option>
          </select>
        </td>
        <td>
          <select class="trg-ex-mode" aria-label="Mode pencocokan">
            <option value="contains" ${rule.mode === 'contains' ? 'selected' : ''}>Contains</option>
            <option value="starts_with" ${rule.mode === 'starts_with' ? 'selected' : ''}>Starts With</option>
            <option value="regex" ${rule.mode === 'regex' ? 'selected' : ''}>Regex</option>
          </select>
        </td>
        <td>
          <input type="text" class="trg-ex-pattern" value="${B.esc(rule.pattern || '')}" placeholder="/login.php atau regex" spellcheck="false" aria-label="Pola pengecualian" />
        </td>
        <td>
          <input type="text" class="trg-ex-note" value="${B.esc(rule.note || '')}" placeholder="Keterangan (opsional)" aria-label="Keterangan aturan" />
        </td>
        <td>
          <button type="button" class="btn danger btn-xs trg-ex-del">Hapus</button>
        </td>
      `;
      $('.trg-ex-del', tr)?.addEventListener('click', () => tr.remove());
      tbody.appendChild(tr);
    }
  }

  function collectExclusionRows() {
    const tbody = $('#trg-exclusions-tbody');
    if (!tbody) return [];
    const rules = [];
    tbody.querySelectorAll('tr').forEach((tr) => {
      const pattern = ($('.trg-ex-pattern', tr)?.value || '').trim();
      if (!pattern) return;
      rules.push({
        id: tr.dataset.ruleId || ('ex_' + Math.random().toString(36).slice(2, 8)),
        enabled: Boolean($('.trg-ex-enabled', tr)?.checked),
        target: $('.trg-ex-target', tr)?.value === 'full_log' ? 'full_log' : 'path',
        mode: $('.trg-ex-mode', tr)?.value || 'contains',
        pattern,
        note: ($('.trg-ex-note', tr)?.value || '').trim(),
      });
    });
    return rules;
  }

  function fillTriageConfigForm(cfg) {
    if (!cfg) return;
    triageState.config = cfg;
    const w = cfg.wazuh || {};
    const o = cfg.ollama || {};
    if ($('#trg-wazuh-url')) $('#trg-wazuh-url').value = w.url || '';
    if ($('#trg-wazuh-index')) $('#trg-wazuh-index').value = w.indexPattern || 'wazuh-alerts-*';
    if ($('#trg-wazuh-user')) $('#trg-wazuh-user').value = w.username || '';
    if ($('#trg-wazuh-pass')) {
      $('#trg-wazuh-pass').value = '';
      $('#trg-wazuh-pass').placeholder = w.hasPassword ? 'Tersimpan aman di server (isi hanya untuk ganti)' : 'Masukkan password read-only';
    }
    if ($('#trg-wazuh-insecure')) $('#trg-wazuh-insecure').checked = Boolean(w.allowSelfSigned);
    if ($('#trg-sev-preset')) $('#trg-sev-preset').value = w.severityPreset || 'medium_critical';
    if ($('#trg-min-level')) $('#trg-min-level').value = String(w.minRuleLevel ?? 7);
    if ($('#trg-max-level')) $('#trg-max-level').value = String(w.maxRuleLevel ?? 15);
    if ($('#trg-poll-min')) $('#trg-poll-min').value = String(w.pollIntervalMin ?? 3);
    if ($('#trg-live-sec')) $('#trg-live-sec').value = String(w.liveRefreshSec ?? 10);
    if ($('#trg-tenant-mapping')) $('#trg-tenant-mapping').value = JSON.stringify(w.tenantMapping || {}, null, 2);

    if ($('#trg-ollama-url')) $('#trg-ollama-url').value = o.baseUrl || 'http://localhost:11434';
    if ($('#trg-ollama-model')) $('#trg-ollama-model').value = o.model || '';
    if ($('#trg-ollama-temp')) $('#trg-ollama-temp').value = String(o.temperature ?? 0.1);
    if ($('#trg-system-prompt')) $('#trg-system-prompt').value = o.systemPrompt || '';
    if ($('#trg-worker-enabled')) $('#trg-worker-enabled').checked = Boolean(cfg.workerEnabled);

    renderExclusionRows(cfg.exclusionRules || []);
    updateWorkerButtonsUi();
  }

  function buildTriageConfigPayload() {
    let tenantMapping = {};
    const rawMap = ($('#trg-tenant-mapping')?.value || '{}').trim();
    if (rawMap) {
      try {
        const parsed = JSON.parse(rawMap);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          throw new Error('Tenant Mapping harus objek JSON, mis. {"pradita-*":"pradita"}');
        }
        tenantMapping = parsed;
      } catch (e) {
        B.toast({ type: 'error', title: 'JSON Tenant Mapping tidak valid', body: e.message });
        return null;
      }
    }

    const wazuh = {
      url: ($('#trg-wazuh-url')?.value || '').trim(),
      indexPattern: ($('#trg-wazuh-index')?.value || 'wazuh-alerts-*').trim(),
      username: ($('#trg-wazuh-user')?.value || '').trim(),
      allowSelfSigned: Boolean($('#trg-wazuh-insecure')?.checked),
      severityPreset: $('#trg-sev-preset')?.value || 'medium_critical',
      minRuleLevel: Number($('#trg-min-level')?.value || 7),
      maxRuleLevel: Number($('#trg-max-level')?.value || 15),
      pollIntervalMin: Number($('#trg-poll-min')?.value || 3),
      liveRefreshSec: Number($('#trg-live-sec')?.value || 10),
      tenantMapping,
    };
    const passVal = $('#trg-wazuh-pass')?.value || '';
    if (passVal) wazuh.password = passVal;

    return {
      workerEnabled: Boolean($('#trg-worker-enabled')?.checked),
      wazuh,
      ollama: {
        baseUrl: ($('#trg-ollama-url')?.value || '').trim(),
        model: ($('#trg-ollama-model')?.value || '').trim(),
        temperature: Number($('#trg-ollama-temp')?.value ?? 0.1),
        systemPrompt: $('#trg-system-prompt')?.value || '',
      },
      exclusionRules: collectExclusionRows(),
    };
  }

  async function loadTriageConfig() {
    try {
      const res = await B.apiFetch('/api/triage/config');
      if (res?.config) fillTriageConfigForm(res.config);
    } catch (err) {
      B.toast({ type: 'error', title: 'Gagal memuat konfigurasi triage', body: err.message });
    }
  }

  async function saveTriageConfig() {
    const payload = buildTriageConfigPayload();
    if (!payload) return;
    try {
      const res = await B.apiFetch('/api/triage/config', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      if (res?.config) fillTriageConfigForm(res.config);
      B.toast({ type: 'success', title: 'Konfigurasi Wazuh & AI Triage disimpan' });
      fetchTriageQueue(true);
    } catch (err) {
      B.toast({ type: 'error', title: 'Gagal menyimpan konfigurasi triage', body: err.message });
    }
  }

  async function testWazuh() {
    const msgEl = $('#trg-wazuh-test-msg');
    const payload = buildTriageConfigPayload();
    if (!payload) return;
    showInlineStatus(msgEl, true, 'Menguji koneksi ke Wazuh Indexer…');
    try {
      const res = await B.apiFetch('/api/triage/test-wazuh', {
        method: 'POST',
        body: JSON.stringify({ wazuh: payload.wazuh }),
      });
      const countText = typeof res.docCount === 'number' ? ` · ${res.docCount} alert cocok` : '';
      showInlineStatus(msgEl, true, `Terhubung ke ${res.clusterName} (${res.status}) · ${res.latencyMs} ms${countText}`);
    } catch (err) {
      showInlineStatus(msgEl, false, err.message);
    }
  }

  async function testOllama() {
    const msgEl = $('#trg-ollama-test-msg');
    const payload = buildTriageConfigPayload();
    if (!payload) return;
    showInlineStatus(msgEl, true, 'Menguji koneksi ke Ollama…');
    try {
      const res = await B.apiFetch('/api/triage/test-ollama', {
        method: 'POST',
        body: JSON.stringify({ ollama: payload.ollama }),
      });
      const modelNote = res.modelAvailable
        ? 'model ditemukan'
        : `model belum terdaftar di /api/tags (${res.models?.length || 0} model tersedia)`;
      showInlineStatus(msgEl, true, `Ollama aktif (${res.latencyMs} ms) · ${modelNote}`);
    } catch (err) {
      showInlineStatus(msgEl, false, err.message);
    }
  }

  /* ---------------- Triage Queue (View: triage) ---------------- */

  function updateSidebarBadges(snap) {
    if (!snap) return;
    const c = snap.counts || {};
    const badge = $('#tab-triage-count');
    if (badge) {
      const activeCount = Number(c.TRUE_POSITIVE || 0) + Number(c.NEEDS_REVIEW || 0);
      badge.textContent = String(c.total || 0);
      badge.classList.toggle('has-pending', activeCount > 0);
    }
    const histBadge = $('#tab-triage-history-count');
    if (histBadge && typeof snap.historyCount === 'number') {
      histBadge.textContent = String(snap.historyCount);
    }
    const tpEl = $('#trg-count-tp');
    const revEl = $('#trg-count-review');
    const fpEl = $('#trg-count-fp');
    const allEl = $('#trg-count-all');
    if (tpEl) tpEl.textContent = String(c.TRUE_POSITIVE || 0);
    if (revEl) revEl.textContent = String(c.NEEDS_REVIEW || 0);
    if (fpEl) fpEl.textContent = String(c.FALSE_POSITIVE || 0);
    if (allEl) allEl.textContent = String(c.total || 0);
  }

  function updateWorkerButtonsUi() {
    const enabled = Boolean(triageState.snapshot?.workerEnabled ?? triageState.config?.workerEnabled);
    const running = Boolean(triageState.snapshot?.workerStatus?.running);
    const btn = $('#btn-triage-worker-toggle');
    if (btn) {
      btn.textContent = enabled ? 'Pause Worker' : 'Start Worker';
      btn.className = 'btn btn-sm ' + (enabled ? 'amber' : 'accent');
    }
    const statusEl = $('#trg-worker-pill');
    if (statusEl) {
      if (running) {
        statusEl.textContent = 'Polling…';
        statusEl.className = 'sync-pill';
      } else if (enabled) {
        statusEl.textContent = 'Worker Aktif';
        statusEl.className = 'sync-pill';
      } else {
        statusEl.textContent = 'Worker Pause';
        statusEl.className = 'sync-pill offline';
      }
    }
  }

  function populateTriageTenantSelect(selectEl, tenants = []) {
    if (!selectEl) return;
    const prev = selectEl.value;
    selectEl.innerHTML = '<option value="">Semua Tenant</option>';
    for (const t of tenants) {
      const opt = document.createElement('option');
      opt.value = t;
      opt.textContent = t;
      selectEl.appendChild(opt);
    }
    if (tenants.includes(prev)) selectEl.value = prev;
  }

  function updateMergeBar() {
    const bar = $('#trg-merge-bar');
    const btn = $('#btn-triage-merge');
    const msg = $('#trg-merge-msg');
    if (!bar || !btn || !msg) return;

    const groups = triageState.snapshot?.groups || [];
    const selected = groups.filter((g) => triageState.selectedGroupIds.has(g.group_id));
    if (selected.length < 2) {
      bar.hidden = true;
      return;
    }

    bar.hidden = false;
    const tenants = [...new Set(selected.map((g) => String(g.tenant_mapped || '').toLowerCase()))];
    const crossTenant = tenants.length > 1;
    btn.disabled = crossTenant;
    if (crossTenant) {
      msg.textContent = `Tidak dapat menggabungkan grup dari tenant yang berbeda (${tenants.join(', ')}).`;
      msg.className = 'field-msg err';
    } else {
      const totalAlerts = selected.reduce((s, g) => s + Number(g.alert_count || g.alerts?.length || 0), 0);
      msg.textContent = `${selected.length} grup dipilih (${totalAlerts} alert) pada tenant "${tenants[0]}".`;
      msg.className = 'field-msg auto';
    }
  }

  function filterVisibleGroups(groups) {
    const v = triageState.verdictFilter;
    const tf = triageState.tenantFilter.toLowerCase();
    const q = triageState.search.trim().toLowerCase();

    return groups.filter((g) => {
      if (v && v !== 'ALL' && g.verdict !== v) return false;
      if (tf && String(g.tenant_mapped || '').toLowerCase() !== tf) return false;
      if (q) {
        const hay = [
          g.incident_title,
          g.ai_reasoning,
          g.tenant_mapped,
          ...(g.source_ips || []),
          ...(g.rule_ids || []),
          ...(g.agents || []).map((a) => a.name),
          ...(g.alerts || []).map((a) => a.alert_id),
        ].join(' ').toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }

  async function promoteFromTriage(opts) {
    try {
      const targetWs = opts.workspace || B.getActiveWorkspace();
      let candidateTenant = opts.tenant || '';
      if (!candidateTenant && opts.groupId && triageState.snapshot?.groups) {
        const grp = triageState.snapshot.groups.find((g) => g.group_id === opts.groupId);
        if (grp) candidateTenant = grp.tenant_mapped || '';
      }
      const preview = B.previewNextCardMeta ? B.previewNextCardMeta(candidateTenant, targetWs) : {};
      const payload = {
        ...opts,
        workspace: targetWs,
        irisTicketNumber: opts.irisTicketNumber || preview.ticketNumber || null,
        irisCaseId: opts.irisCaseId || preview.irisCaseId || null,
      };
      const res = await B.apiFetch('/api/triage/promote', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      const promoInfo = B.promoteTriageAlertsToForm({
        tenant: res.tenant,
        chunks: res.chunks,
        incidentTitle: res.incidentTitle,
        workspace: targetWs,
      });
      if (res.snapshot) {
        triageState.snapshot = res.snapshot;
        updateSidebarBadges(res.snapshot);
      }
      triageState.selectedGroupIds.clear();
      renderTriageView();
      B.toast({
        type: 'success',
        title: `${promoInfo.cardCount} kartu form dibuat (${res.tenant})`,
        body: `Wazuh Alert ID dicatat ke Audit Triage & watermark antrean direset.`,
      });
    } catch (err) {
      B.toast({ type: 'error', title: 'Gagal membuat case dari triage', body: err.message });
    }
  }

  function renderTriageView() {
    const snap = triageState.snapshot;
    updateSidebarBadges(snap);
    updateWorkerButtonsUi();

    const wmEl = $('#trg-watermark-info');
    if (wmEl) {
      const ws = snap?.workerStatus || {};
      const wmText = snap?.watermarkTimestamp ? B.fmtWib(snap.watermarkTimestamp) : 'Awal (belum direset)';
      const errText = ws.lastError ? ` · Error terakhir: ${ws.lastError}` : '';
      wmEl.textContent = `Watermark antrean: ${wmText}${errText}`;
    }

    document.querySelectorAll('.trg-verdict-btn[data-verdict]').forEach((btn) => {
      const active = btn.dataset.verdict === triageState.verdictFilter;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-pressed', String(active));
    });

    const allGroups = snap?.groups || [];
    populateTriageTenantSelect($('#trg-filter-tenant'), snap?.tenants || []);

    const validIds = new Set(allGroups.map((g) => g.group_id));
    for (const id of [...triageState.selectedGroupIds]) {
      if (!validIds.has(id)) triageState.selectedGroupIds.delete(id);
    }

    const visible = filterVisibleGroups(allGroups);
    const listEl = $('#triage-groups-list');
    const emptyEl = $('#triage-empty');
    if (!listEl || !emptyEl) return;

    listEl.innerHTML = '';
    updateMergeBar();

    if (!visible.length) {
      listEl.hidden = true;
      emptyEl.hidden = false;
      return;
    }

    listEl.hidden = false;
    emptyEl.hidden = true;

    for (const g of visible) {
      const vMeta = VERDICT_META[g.verdict] || VERDICT_META.NEEDS_REVIEW;
      const isExpanded = triageState.expandedGroupIds.has(g.group_id);
      const isSelected = triageState.selectedGroupIds.has(g.group_id);
      const sevCls = 'sev-' + String(g.severity_label || 'MEDIUM').toUpperCase();
      const agentList = (g.agents || []).map((a) => a.name).filter(Boolean);

      const card = document.createElement('article');
      card.className = 'triage-card ' + vMeta.cls;
      card.innerHTML = `
        <div class="triage-card-head">
          <div class="triage-card-badges">
            <label class="triage-select-wrap" title="Pilih untuk digabungkan dalam 1 tenant">
              <input type="checkbox" class="trg-group-check" ${isSelected ? 'checked' : ''} />
            </label>
            <span class="chip ${vMeta.cls}">${B.esc(vMeta.label)}</span>
            ${g.unanalyzed ? '<span class="chip verdict-unanalyzed">Unanalyzed</span>' : ''}
            <span class="chip ${sevCls}">${B.esc(g.severity_label || 'Medium')} (Lv ${B.esc(g.max_rule_level ?? '?')})</span>
            <span class="chip mode-reporting">${B.esc(g.tenant_mapped || 'unassigned')}</span>
            <span class="chip">${B.esc(g.alert_count || g.alerts?.length || 0)} alert</span>
          </div>
          <div class="triage-card-time">
            <span>${B.esc(B.fmtWib(g.first_seen))} – ${B.esc(B.fmtWib(g.last_seen))}</span>
          </div>
        </div>

        <h3 class="triage-card-title">${B.esc(g.incident_title || 'Security Incident')}</h3>

        <div class="approval-kv-row">
          <span class="approval-kv-item"><strong>Agent:</strong> ${B.esc(agentList.join(', ') || '—')}</span>
          <span class="approval-kv-item"><strong>IP Sumber:</strong> <span class="mono">${B.esc((g.source_ips || []).join(', ') || '—')}</span></span>
          <span class="approval-kv-item"><strong>Rule ID:</strong> <span class="mono">${B.esc((g.rule_ids || []).join(', ') || '—')}</span></span>
        </div>

        <div class="approval-summary-box">${B.esc(g.ai_reasoning || '—')}</div>

        <div class="triage-card-actions">
          <button type="button" class="btn accent btn-sm act-trg-promote">Buat Case</button>
          <button type="button" class="btn ghost btn-sm act-trg-toggle">${isExpanded ? 'Tutup Detail Alert' : `Lihat ${g.alerts?.length || 0} Alert`}</button>
          <button type="button" class="btn danger btn-sm act-trg-dismiss">Hapus / Abaikan</button>
        </div>

        ${isExpanded ? '<div class="triage-alerts-sublist"></div>' : ''}
      `;

      $('.trg-group-check', card)?.addEventListener('change', (e) => {
        if (e.target.checked) triageState.selectedGroupIds.add(g.group_id);
        else triageState.selectedGroupIds.delete(g.group_id);
        updateMergeBar();
      });

      $('.act-trg-promote', card)?.addEventListener('click', () => {
        promoteFromTriage({ groupId: g.group_id, workspace: B.getActiveWorkspace(), resetWatermark: true });
      });

      $('.act-trg-toggle', card)?.addEventListener('click', () => {
        if (isExpanded) triageState.expandedGroupIds.delete(g.group_id);
        else triageState.expandedGroupIds.add(g.group_id);
        renderTriageView();
      });

      $('.act-trg-dismiss', card)?.addEventListener('click', async () => {
        try {
          const res = await B.apiFetch('/api/triage/dismiss', {
            method: 'POST',
            body: JSON.stringify({ groupIds: [g.group_id] }),
          });
          triageState.snapshot = res.snapshot;
          renderTriageView();
          B.toast({ type: 'info', title: 'Grup dihapus dari antrean' });
        } catch (err) {
          B.toast({ type: 'error', title: 'Gagal menghapus grup', body: err.message });
        }
      });

      if (isExpanded) {
        const sub = $('.triage-alerts-sublist', card);
        for (const al of g.alerts || []) {
          const raw = al.raw_wazuh_alert || {};
          const row = document.createElement('div');
          row.className = 'triage-subalert-row';
          row.innerHTML = `
            <div class="triage-subalert-meta">
              <span class="mono">${B.esc(al.alert_id)}</span>
              <span>${B.esc(B.fmtWib(raw['@timestamp'] || raw.timestamp))}</span>
              <span>${B.esc(raw.agent?.name || '—')}</span>
              <span class="mono">${B.esc(raw.data?.url || raw.data?.srcip || '')}</span>
            </div>
            <div class="triage-subalert-actions">
              <button type="button" class="btn ghost btn-xs act-sub-json">Raw JSON</button>
              <button type="button" class="btn accent btn-xs act-sub-case">Buat Case Ini</button>
            </div>
          `;
          $('.act-sub-json', row)?.addEventListener('click', () => openRawJsonModal(`Wazuh Alert ${al.alert_id}`, raw));
          $('.act-sub-case', row)?.addEventListener('click', () => {
            promoteFromTriage({
              groupId: g.group_id,
              alertIds: [al.alert_id],
              workspace: B.getActiveWorkspace(),
              resetWatermark: true,
            });
          });
          sub.appendChild(row);
        }
      }

      listEl.appendChild(card);
    }
  }

  async function fetchTriageQueue(silent = false) {
    try {
      const snap = await B.apiFetch('/api/triage/queue');
      triageState.snapshot = snap;
      renderTriageView();
    } catch (err) {
      if (!silent) B.toast({ type: 'error', title: 'Gagal memuat antrean triage', body: err.message });
    }
  }

  /* ---------------- Realtime Live Feed 1:1 (View: live-feed) ---------------- */

  function renderLiveFeed() {
    const data = triageState.liveData;
    const parityEl = $('#live-parity-pill');
    const tbody = $('#live-feed-tbody');
    const emptyEl = $('#live-feed-empty');
    if (!tbody || !emptyEl) return;

    if (!data) {
      if (parityEl) parityEl.textContent = 'Belum dimuat';
      tbody.innerHTML = '';
      emptyEl.hidden = false;
      return;
    }

    if (parityEl) {
      const matchTag = data.parityMatch ? '1:1 Match' : 'Terfilter';
      parityEl.textContent = `Wazuh Hits: ${data.totalHits} | Ditampilkan: ${data.displayedCount} (${matchTag})`;
      parityEl.className = 'sync-pill ' + (data.parityMatch ? '' : 'offline');
    }

    const tabCount = $('#tab-live-count');
    if (tabCount) tabCount.textContent = String(data.totalHits ?? data.rawCount ?? 0);

    const tenants = [...new Set((data.items || []).map((i) => i.tenant).filter(Boolean))].sort();
    populateTriageTenantSelect($('#live-filter-tenant'), tenants);

    tbody.innerHTML = '';
    const items = data.items || [];
    if (!items.length) {
      emptyEl.hidden = false;
      return;
    }
    emptyEl.hidden = true;

    for (const it of items) {
      const tr = document.createElement('tr');
      const sevCls = 'sev-' + String(it.severity_label || 'Medium').toUpperCase();
      tr.innerHTML = `
        <td class="mono">${B.esc(B.fmtWib(it.timestamp))}</td>
        <td class="mono">${B.esc(it.alert_id)}</td>
        <td><span class="chip mode-reporting">${B.esc(it.tenant)}</span></td>
        <td>${B.esc(it.agent_name)}</td>
        <td class="mono">${B.esc(it.rule_id)}</td>
        <td class="hist-case-cell">
          <span class="hist-case-title" title="${B.esc(it.rule_description)}">${B.esc(it.rule_description)}</span>
          ${it.path ? `<span class="field-hint mono">${B.esc(it.path)}</span>` : ''}
        </td>
        <td><span class="chip ${sevCls}">${B.esc(it.severity_label)} (${B.esc(it.rule_level)})</span></td>
        <td class="mono">${B.esc(it.src_ip)}</td>
        <td><span class="chip">${B.esc(it.status_label)}</span></td>
        <td>
          <div class="hist-actions">
            <button type="button" class="btn ghost btn-xs act-live-json">Raw JSON</button>
            <button type="button" class="btn accent btn-xs act-live-promote">Kirim ke Form</button>
          </div>
        </td>
      `;
      $('.act-live-json', tr)?.addEventListener('click', () => openRawJsonModal(`Wazuh Alert ${it.alert_id}`, it.raw_wazuh_alert));
      $('.act-live-promote', tr)?.addEventListener('click', () => {
        promoteFromTriage({
          rawAlerts: [{ alert_id: it.alert_id, raw_wazuh_alert: it.raw_wazuh_alert }],
          tenant: it.tenant,
          incidentTitle: it.rule_description,
          aiVerdict: 'MANUAL_PROMOTE',
          workspace: B.getActiveWorkspace(),
          resetWatermark: false,
        });
      });
      tbody.appendChild(tr);
    }
  }

  async function fetchLiveFeed(silent = false) {
    const scope = $('#live-scope-select')?.value || 'watermark';
    const tenant = $('#live-filter-tenant')?.value || '';
    const status = $('#live-filter-status')?.value || '';
    const q = ($('#live-search')?.value || '').trim();
    const params = new URLSearchParams({ scope, tenant, status, q });

    try {
      const data = await B.apiFetch('/api/triage/live?' + params.toString());
      triageState.liveData = data;
      renderLiveFeed();
    } catch (err) {
      if (!silent) B.toast({ type: 'error', title: 'Gagal menarik Realtime Wazuh Feed', body: err.message });
    }
  }

  function stopLiveRefresh() {
    if (triageState.liveTimer) {
      clearInterval(triageState.liveTimer);
      triageState.liveTimer = null;
    }
  }

  function startLiveRefreshIfActive() {
    stopLiveRefresh();
    if (!$('#live-auto-refresh')?.checked) return;
    const sec = Math.max(3, Number(triageState.config?.wazuh?.liveRefreshSec || 10));
    triageState.liveTimer = setInterval(() => {
      if (!$('#view-live-feed')?.hidden) fetchLiveFeed(true);
    }, sec * 1000);
  }

  /* ---------------- Case Audit History (View: triage-history) ---------------- */

  function renderTriageHistory() {
    const data = triageState.historyData;
    const listEl = $('#triage-history-list');
    const emptyEl = $('#triage-history-empty');
    if (!listEl || !emptyEl) return;

    if (data && typeof data.total === 'number') {
      const badge = $('#tab-triage-history-count');
      if (badge) badge.textContent = String(data.total);
    }

    populateTriageTenantSelect($('#trghist-filter-tenant'), data?.tenants || []);

    const items = data?.items || [];
    listEl.innerHTML = '';
    if (!items.length) {
      listEl.hidden = true;
      emptyEl.hidden = false;
      return;
    }
    listEl.hidden = false;
    emptyEl.hidden = true;

    for (const entry of items) {
      const ids = entry.wazuh_alert_ids || [];
      const dql = '_id:(' + ids.map((id) => `"${id}"`).join(' OR ') + ')';
      const vMeta = VERDICT_META[entry.ai_verdict] || { label: entry.ai_verdict || 'Manual', cls: '' };

      const card = document.createElement('article');
      card.className = 'triage-card';
      card.innerHTML = `
        <div class="triage-card-head">
          <div class="triage-card-badges">
            <span class="chip mode-reporting">${B.esc(entry.tenant || '—')}</span>
            <span class="chip ${vMeta.cls}">${B.esc(vMeta.label)}</span>
            ${entry.iris_case_id ? `<span class="chip mono">IRIS ${B.esc(entry.iris_case_id)}</span>` : ''}
            <span class="chip">${B.esc(entry.alert_count || ids.length)} alert</span>
          </div>
          <div class="triage-card-time">
            <span>${B.esc(B.fmtWib(entry.created_at))}</span>
            ${entry.created_by ? `<span>· ${B.esc(entry.created_by)}</span>` : ''}
          </div>
        </div>

        <h3 class="triage-card-title">${B.esc(entry.incident_title || 'Security Incident')}</h3>

        <div class="approval-kv-row">
          <span class="approval-kv-item"><strong>Agent:</strong> ${B.esc((entry.agents || []).join(', ') || '—')}</span>
          <span class="approval-kv-item"><strong>IP Sumber:</strong> <span class="mono">${B.esc((entry.source_ips || []).join(', ') || '—')}</span></span>
          <span class="approval-kv-item"><strong>Rule ID:</strong> <span class="mono">${B.esc((entry.rule_ids || []).join(', ') || '—')}</span></span>
        </div>

        <div class="approval-summary-box mono">${B.esc(ids.join(', ') || '—')}</div>

        <div class="triage-card-actions">
          <button type="button" class="btn ghost btn-xs act-hist-copy-ids">Copy Alert IDs</button>
          <button type="button" class="btn ghost btn-xs act-hist-copy-dql">Copy Wazuh DQL Query</button>
          <button type="button" class="btn primary btn-xs act-hist-fetch-wazuh">Cek Detail di Wazuh</button>
        </div>
      `;

      $('.act-hist-copy-ids', card)?.addEventListener('click', () => B.copyText(ids.join(', '), 'Wazuh Alert IDs'));
      $('.act-hist-copy-dql', card)?.addEventListener('click', () => B.copyText(dql, 'Wazuh DQL Query'));
      $('.act-hist-fetch-wazuh', card)?.addEventListener('click', async () => {
        try {
          const res = await B.apiFetch('/api/triage/history/' + encodeURIComponent(entry.history_id) + '/fetch-wazuh', {
            method: 'POST',
            body: '{}',
          });
          openRawJsonModal(
            `Detail Wazuh (${res.total} dokumen · ${entry.tenant})`,
            res.alerts.map((a) => a.raw_wazuh_alert),
          );
        } catch (err) {
          B.toast({ type: 'error', title: 'Gagal menarik detail dari Wazuh', body: err.message });
        }
      });

      listEl.appendChild(card);
    }
  }

  async function fetchTriageHistory(silent = false) {
    const tenant = $('#trghist-filter-tenant')?.value || '';
    const q = ($('#trghist-search')?.value || '').trim();
    const params = new URLSearchParams({ tenant, q });
    try {
      const data = await B.apiFetch('/api/triage/history?' + params.toString());
      triageState.historyData = data;
      renderTriageHistory();
    } catch (err) {
      if (!silent) B.toast({ type: 'error', title: 'Gagal memuat Audit Triage', body: err.message });
    }
  }

  /* ---------------- SSE & Event Binding ---------------- */

  function closeSse() {
    if (triageState.sse) {
      try { triageState.sse.close(); } catch {}
      triageState.sse = null;
    }
  }

  function connectSse() {
    closeSse();
    if (typeof EventSource === 'undefined') return;
    try {
      const es = new EventSource('/api/triage/stream', { withCredentials: true });
      es.addEventListener('state', (ev) => {
        try {
          triageState.snapshot = JSON.parse(ev.data);
          renderTriageView();
        } catch {}
      });
      es.addEventListener('worker', (ev) => {
        try {
          const ws = JSON.parse(ev.data);
          if (triageState.snapshot) {
            triageState.snapshot.workerStatus = { ...triageState.snapshot.workerStatus, ...ws };
            updateWorkerButtonsUi();
          }
        } catch {}
      });
      triageState.sse = es;
    } catch {}
  }

  function bindEvents() {
    $('#tab-triage')?.addEventListener('click', () => B.switchView('triage'));
    $('#tab-live-feed')?.addEventListener('click', () => B.switchView('live-feed'));
    $('#tab-triage-history')?.addEventListener('click', () => B.switchView('triage-history'));

    $('#set-mode-workspace')?.addEventListener('click', () => switchSettingsSubTab('workspace'));
    $('#set-mode-triage')?.addEventListener('click', () => switchSettingsSubTab('triage'));
    $('#btn-add-exclusion')?.addEventListener('click', () => {
      const current = collectExclusionRows();
      current.push({ target: 'path', mode: 'contains', pattern: '', enabled: true, note: '' });
      renderExclusionRows(current);
    });
    $('#trg-sev-preset')?.addEventListener('change', (e) => {
      const val = e.target.value;
      if (val === 'medium_critical') {
        if ($('#trg-min-level')) $('#trg-min-level').value = '7';
        if ($('#trg-max-level')) $('#trg-max-level').value = '15';
      } else if (val === 'high_critical') {
        if ($('#trg-min-level')) $('#trg-min-level').value = '12';
        if ($('#trg-max-level')) $('#trg-max-level').value = '15';
      }
    });
    $('#btn-test-wazuh')?.addEventListener('click', testWazuh);
    $('#btn-test-ollama')?.addEventListener('click', testOllama);
    $('#btn-save-triage-cfg')?.addEventListener('click', saveTriageConfig);
    $('#btn-close-triage-cfg')?.addEventListener('click', () => B.switchView('triage'));
    $('#btn-reset-prompt')?.addEventListener('click', () => {
      if ($('#trg-system-prompt')) {
        $('#trg-system-prompt').value = 'Anda adalah Analis SOC L1 senior yang bertugas melakukan pre-triage alert Wazuh (severity Medium hingga Critical, level >= 7) secara micro-batch untuk SATU tenant tertentu.\nAnalisis konteks log secara mendalam (URL/URI, payload, HTTP status, User-Agent, source IP, dan sampel full_log) — JANGAN hanya bergantung pada rule.id atau rule.description.\n\nAturan Klasifikasi:\n1. TRUE_POSITIVE: Indikasi kuat eksploitasi CVE, serangan aktif, brute-force berhasil, web scanning ke file sensitif (/.env, /.git, /phpmyadmin, shell), SQLi, XSS, atau C2.\n2. NEEDS_REVIEW: Aktivitas anomali mencurigakan yang butuh verifikasi konteks (misal: vulnerability scanner tanpa eksploitasi berhasil, perubahan konfigurasi sistem, atau lonjakan error 500 tidak wajar).\n3. FALSE_POSITIVE: Trafik pengguna normal/legit yang memicu rule sensitif (misal: error 400/404 pada endpoint aplikasi valid seperti /login.php, /mhs/nim, kesalahan input user biasa, atau crawler/healthcheck internal).\n\nAturan Pengelompokan:\n- Pisahkan pengelompokan (group_key) antara trafik legit dan aktivitas serangan meskipun memiliki rule.id Wazuh yang sama.\n- Gabungkan kandidat yang merupakan kampanye serangan yang sama ke dalam satu insiden walaupun menyasar beberapa agent berbeda di dalam tenant ini.\nKeluarkan output HANYA dalam format JSON valid sesuai skema yang diminta.';
      }
    });

    // Triage Queue Toolbar
    $('#btn-triage-poll-now')?.addEventListener('click', async () => {
      const btn = $('#btn-triage-poll-now');
      if (btn) btn.disabled = true;
      try {
        const res = await B.apiFetch('/api/triage/worker', {
          method: 'POST',
          body: JSON.stringify({ action: 'poll_now' }),
        });
        if (res.skipped) {
          B.toast({ type: 'info', title: 'Wazuh URL belum diatur', body: 'Isi konfigurasi Wazuh Indexer di Pengaturan → Wazuh & AI Triage.' });
        } else {
          if (res.snapshot) triageState.snapshot = res.snapshot;
          renderTriageView();
          B.toast({
            type: 'success',
            title: 'Triage selesai',
            body: `Ditarik ${res.fetchedCount} alert · Excluded ${res.excludedCount} · Dianalisis ${res.analyzedCount}`,
          });
        }
      } catch (err) {
        B.toast({ type: 'error', title: 'Gagal menarik dari Wazuh Indexer', body: err.message });
      } finally {
        if (btn) btn.disabled = false;
      }
    });

    $('#btn-triage-worker-toggle')?.addEventListener('click', async () => {
      const enabled = Boolean(triageState.snapshot?.workerEnabled ?? triageState.config?.workerEnabled);
      try {
        const res = await B.apiFetch('/api/triage/worker', {
          method: 'POST',
          body: JSON.stringify({ action: enabled ? 'pause' : 'start' }),
        });
        if (res.config) triageState.config = res.config;
        if (res.snapshot) triageState.snapshot = res.snapshot;
        renderTriageView();
        B.toast({ type: 'info', title: enabled ? 'Worker dijeda' : 'Worker dijalankan berkala' });
      } catch (err) {
        B.toast({ type: 'error', title: 'Gagal mengubah status worker', body: err.message });
      }
    });

    $('#btn-triage-dismiss-fp')?.addEventListener('click', async () => {
      try {
        const res = await B.apiFetch('/api/triage/dismiss', {
          method: 'POST',
          body: JSON.stringify({ verdict: 'FALSE_POSITIVE' }),
        });
        triageState.snapshot = res.snapshot;
        renderTriageView();
        B.toast({ type: 'info', title: `${res.dismissedGroups} grup False Positive dihapus` });
      } catch (err) {
        B.toast({ type: 'error', title: 'Gagal menghapus False Positive', body: err.message });
      }
    });

    $('#btn-triage-reset')?.addEventListener('click', async () => {
      try {
        const res = await B.apiFetch('/api/triage/reset', {
          method: 'POST',
          body: JSON.stringify({}),
        });
        triageState.snapshot = res.snapshot;
        triageState.selectedGroupIds.clear();
        renderTriageView();
        B.toast({ type: 'info', title: 'Antrean dibersihkan & watermark direset' });
      } catch (err) {
        B.toast({ type: 'error', title: 'Gagal mereset antrean', body: err.message });
      }
    });

    document.querySelectorAll('.trg-verdict-btn[data-verdict]').forEach((btn) => {
      btn.addEventListener('click', () => {
        triageState.verdictFilter = btn.dataset.verdict || 'TRUE_POSITIVE';
        renderTriageView();
      });
    });

    $('#trg-filter-tenant')?.addEventListener('change', (e) => {
      triageState.tenantFilter = e.target.value;
      renderTriageView();
    });
    $('#trg-search')?.addEventListener('input', (e) => {
      triageState.search = e.target.value;
      renderTriageView();
    });

    $('#btn-triage-merge')?.addEventListener('click', async () => {
      try {
        const res = await B.apiFetch('/api/triage/merge', {
          method: 'POST',
          body: JSON.stringify({ groupIds: [...triageState.selectedGroupIds] }),
        });
        triageState.selectedGroupIds.clear();
        triageState.snapshot = res.snapshot;
        renderTriageView();
        B.toast({ type: 'success', title: 'Grup berhasil digabungkan dalam 1 tenant' });
      } catch (err) {
        B.toast({ type: 'error', title: 'Gagal menggabungkan grup', body: err.message });
      }
    });

    // Live Feed Controls
    $('#btn-live-refresh')?.addEventListener('click', () => fetchLiveFeed(false));
    $('#live-scope-select')?.addEventListener('change', () => fetchLiveFeed(false));
    $('#live-filter-tenant')?.addEventListener('change', () => fetchLiveFeed(false));
    $('#live-filter-status')?.addEventListener('change', () => fetchLiveFeed(false));
    $('#live-search')?.addEventListener('input', () => fetchLiveFeed(true));
    $('#live-auto-refresh')?.addEventListener('change', startLiveRefreshIfActive);

    // Case Audit History Controls
    $('#btn-trghist-refresh')?.addEventListener('click', () => fetchTriageHistory(false));
    $('#trghist-filter-tenant')?.addEventListener('change', () => fetchTriageHistory(false));
    $('#trghist-search')?.addEventListener('input', () => fetchTriageHistory(true));

    // Raw JSON Modal
    $('#btn-close-raw-json')?.addEventListener('click', closeRawJsonModal);
    $('#btn-copy-raw-json')?.addEventListener('click', () => B.copyText($('#raw-json-pre')?.textContent || '', 'Raw Wazuh JSON'));
    $('#raw-json-modal')?.addEventListener('click', (e) => {
      if (e.target === $('#raw-json-modal')) closeRawJsonModal();
    });
  }

  B.onViewChange((view) => {
    stopLiveRefresh();
    if (view === 'triage') {
      fetchTriageQueue(false);
    } else if (view === 'live-feed') {
      fetchLiveFeed(false);
      startLiveRefreshIfActive();
    } else if (view === 'triage-history') {
      fetchTriageHistory(false);
    } else if (view === 'settings' && triageState.settingsTab === 'triage') {
      loadTriageConfig();
    }
  });

  B.onAuthReady(() => {
    loadTriageConfig();
    fetchTriageQueue(true);
    fetchTriageHistory(true);
    connectSse();
  });

  B.onLogout(() => {
    stopLiveRefresh();
    closeSse();
    closeRawJsonModal();
  });

  bindEvents();
})();
