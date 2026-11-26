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

  const LIVE_AUTO_REFRESH_KEY = 'diptera.liveAutoRefresh';
  const LIVE_FIELDS_KEY = 'diptera.liveFields';
  const INSP_FIELDS_KEY = 'diptera.inspectorFields';
  const DEFAULT_LIVE_FIELDS = ['rule_description', 'agent_name', 'tenant', 'status'];
  const DEFAULT_INSP_FIELDS = ['rule_description', 'agent_name', 'src_ip', 'path'];

  const WAZUH_FIELD_CATALOG = [
    { key: 'rule_description', label: 'rule.description', aliases: ['rule.description'] },
    { key: 'rule_id', label: 'rule.id', aliases: ['rule.id'], mono: true },
    { key: 'rule_level', label: 'rule.level', aliases: ['rule.level'] },
    { key: 'agent_name', label: 'agent.name', aliases: ['agent.name'] },
    { key: 'tenant', label: 'tenant', aliases: ['agent.labels.tenant'] },
    { key: 'src_ip', label: 'data.srcip', aliases: ['data.srcip', 'data.src_ip'], mono: true },
    { key: 'path', label: 'data.url / path', aliases: ['data.url', 'data.uri', 'data.http.url'], mono: true },
    { key: 'http_status', label: 'http.status', aliases: ['data.http_status', 'data.status', 'data.http.status_code'], mono: true },
    { key: 'full_log', label: 'full_log', aliases: ['full_log'], mono: true },
    { key: 'status', label: 'status', liveOnly: true },
  ];

  const isBlockedColumnKey = (k) => k === '_id' || k === 'alert_id';

  function loadStoredFields(storageKey, fallback) {
    try {
      const parsed = JSON.parse(localStorage.getItem(storageKey) || 'null');
      if (Array.isArray(parsed) && parsed.length) {
        const filtered = parsed.filter((k) => typeof k === 'string' && k.trim() && !isBlockedColumnKey(k.trim()));
        if (filtered.length) return filtered;
      }
    } catch {}
    return fallback.slice();
  }

  function saveStoredFields(storageKey, fields) {
    try { localStorage.setItem(storageKey, JSON.stringify(fields)); } catch {}
  }

  const storedLiveAuto = (() => {
    try { return localStorage.getItem(LIVE_AUTO_REFRESH_KEY) === '1'; } catch { return false; }
  })();

  let triageState = {
    config: null,
    snapshot: null,
    verdictFilter: 'TRUE_POSITIVE',
    tenantFilter: '',
    search: '',
    selectedGroupIds: new Set(),
    expandedGroupIds: new Set(),
    selectedSubAlertsByGroup: new Map(),
    liveData: null,
    liveScope: 'watermark',
    liveAutoRefresh: storedLiveAuto,
    liveFetchSeq: 0,
    liveTimer: null,
    liveExpandedIds: new Set(),
    liveDocTabById: new Map(),
    liveFieldFilterById: new Map(),
    liveFields: loadStoredFields(LIVE_FIELDS_KEY, DEFAULT_LIVE_FIELDS),
    liveFieldsOpen: false,
    exclusions: [],
    exFilterMode: 'all',
    exSearch: '',
    exEditingId: null,
    excludePreviewCtx: null,
    inspector: {
      source: 'queue',
      returnView: 'triage',
      groupId: null,
      title: '',
      tenant: '',
      badges: [],
      alerts: [],
      search: '',
      selectedIds: new Set(),
      expandedIds: new Set(),
      docTabById: new Map(),
      fieldFilterById: new Map(),
      fields: loadStoredFields(INSP_FIELDS_KEY, DEFAULT_INSP_FIELDS),
      fieldsOpen: false,
    },
    batch24h: {
      snapshot: null,
      verdictFilter: 'TRUE_POSITIVE',
      tenantFilter: '',
      search: '',
      selectedGroupIds: new Set(),
      expandedGroupIds: new Set(),
      selectedSubAlertsByGroup: new Map(),
      pollTimer: null,
    },
    historyData: null,
    settingsTab: 'workspace',
    sse: null,
  };

  const EXCLUSION_TARGET_OPTIONS = [
    { value: 'path', label: 'URL / Request Path' },
    { value: 'filename', label: 'Nama File' },
    { value: 'rule_description', label: 'Rule Description' },
    { value: 'rule_id', label: 'Rule ID' },
    { value: 'src_ip', label: 'Source IP' },
    { value: 'agent_name', label: 'Agent Name' },
    { value: 'user_agent', label: 'User-Agent' },
    { value: 'full_log', label: 'Full Log' },
  ];
  const EXCLUSION_MODE_OPTIONS = [
    { value: 'wildcard', label: 'Wildcard (*)' },
    { value: 'contains', label: 'Contains' },
    { value: 'starts_with', label: 'Starts With' },
    { value: 'regex', label: 'Regex' },
  ];
  const getTargetLabel = (val) => EXCLUSION_TARGET_OPTIONS.find((o) => o.value === val)?.label || val || 'path';
  const getModeLabel = (val) => EXCLUSION_MODE_OPTIONS.find((o) => o.value === val)?.label || val || 'contains';
  const buildSelectOptions = (list, selected) => list
    .map((o) => `<option value="${B.esc(o.value)}" ${selected === o.value ? 'selected' : ''}>${B.esc(o.label)}</option>`)
    .join('');

  function wireDoubleConfirm(btnEl, confirmLabel, onConfirm) {
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
  }

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

  function toLocalDatetimeValue(d) {
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  /* ---------------- Shared Wazuh Discover Flattener & Table ---------------- */

  function flattenWazuhDoc(raw, alertId) {
    const entries = [];
    if (alertId) entries.push({ key: '_id', value: String(alertId), typeGlyph: 't' });
    const src = raw && typeof raw === 'object' ? raw : {};

    function walk(obj, prefix, depth) {
      if (obj == null) return;
      if (Array.isArray(obj)) {
        const primitive = obj.every((v) => v == null || typeof v !== 'object');
        entries.push({
          key: prefix,
          value: primitive ? obj.join(', ') : JSON.stringify(obj),
          typeGlyph: 't',
        });
        return;
      }
      if (typeof obj !== 'object' || depth >= 5) {
        const t = typeof obj === 'number' ? '#' : typeof obj === 'boolean' ? 'b' : 't';
        entries.push({ key: prefix, value: typeof obj === 'object' ? JSON.stringify(obj) : String(obj), typeGlyph: t });
        return;
      }
      const keys = Object.keys(obj);
      for (const k of keys) {
        if (!prefix && (k === '_id')) continue;
        const nextKey = prefix ? `${prefix}.${k}` : k;
        const val = obj[k];
        if (val == null) continue;
        if (typeof val === 'object' && !Array.isArray(val)) {
          walk(val, nextKey, depth + 1);
        } else if (Array.isArray(val)) {
          walk(val, nextKey, depth + 1);
        } else {
          const glyph = typeof val === 'number' ? '#' : typeof val === 'boolean' ? 'b' : 't';
          entries.push({ key: nextKey, value: String(val), typeGlyph: glyph });
        }
      }
    }

    walk(src, '', 0);
    const idRows = entries.filter((e) => e.key === '_id' || e.key === '_index');
    const rest = entries.filter((e) => e.key !== '_id' && e.key !== '_index').sort((a, b) => a.key.localeCompare(b.key));
    return [...idRows, ...rest];
  }

  function getDotPathValue(obj, dotPath) {
    if (!obj || typeof obj !== 'object' || !dotPath) return '';
    const parts = String(dotPath).split('.');
    let cur = obj;
    for (const p of parts) {
      if (cur == null || typeof cur !== 'object') return '';
      cur = cur[p];
    }
    if (cur == null) return '';
    return typeof cur === 'object' ? JSON.stringify(cur) : String(cur);
  }

  function resolveFieldValue(row, key) {
    const raw = row.raw_wazuh_alert || {};
    if (key === 'rule_description' || key === 'rule.description') return row.rule_description || raw.rule?.description || '—';
    if (key === 'rule_id' || key === 'rule.id') return row.rule_id || raw.rule?.id || '—';
    if (key === 'rule_level' || key === 'rule.level') {
      const lv = row.rule_level ?? raw.rule?.level;
      return lv != null && lv !== '' ? `${row.severity_label || ''} (${lv})`.trim() : '—';
    }
    if (key === 'agent_name' || key === 'agent.name') return row.agent_name || raw.agent?.name || '—';
    if (key === 'tenant' || key === 'agent.labels.tenant') return row.tenant || raw.agent?.labels?.tenant || '—';
    if (key === 'src_ip' || key === 'data.srcip' || key === 'data.src_ip') {
      return (row.src_ip && row.src_ip !== '—' ? row.src_ip : '') || raw.data?.srcip || raw.data?.src_ip || '—';
    }
    if (key === 'path' || key === 'data.url') {
      return row.path || raw.data?.url || raw.data?.uri || raw.data?.http?.url || '—';
    }
    if (key === 'http_status' || key === 'data.http_status' || key === 'data.status') {
      return row.http_status || raw.data?.http_status || raw.data?.status || raw.data?.http?.status_code || '—';
    }
    if (key === 'full_log') return row.full_log || raw.full_log || '—';
    if (key === 'status') return row.status_label || '—';
    return getDotPathValue(raw, key) || '—';
  }

  function getFieldLabel(key) {
    const meta = WAZUH_FIELD_CATALOG.find((c) => c.key === key || (c.aliases || []).includes(key));
    return meta ? meta.label : key;
  }

  function isMonoField(key) {
    const meta = WAZUH_FIELD_CATALOG.find((c) => c.key === key || (c.aliases || []).includes(key));
    return Boolean(meta?.mono) || key.includes('ip') || key.includes('url') || key.includes('id') || key.includes('log');
  }

  function formatDiscoverTime(ts) {
    if (!ts) return '—';
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return String(ts);
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'Mei', 'Jun', 'Jul', 'Agu', 'Sep', 'Okt', 'Nov', 'Des'];
    const pad2 = (n) => String(n).padStart(2, '0');
    return `${pad2(d.getDate())} ${months[d.getMonth()]} ${d.getFullYear()} @ ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
  }

  function renderFieldPickerPanel(panelEl, selectedFields, defaults, { allowStatus = false, onChange, onClose }) {
    if (!panelEl) return;
    const baseKeys = WAZUH_FIELD_CATALOG.filter((f) => allowStatus || !f.liveOnly);
    const knownKeySet = new Set(baseKeys.map((f) => f.key));
    const extras = selectedFields
      .filter((k) => !knownKeySet.has(k) && !isBlockedColumnKey(k))
      .map((k) => ({ key: k, label: k }));
    const allOptions = [...baseKeys, ...extras];

    panelEl.innerHTML = `
      <div class="wzh-field-picker-head">
        <strong>Pilih Kolom Field (Wazuh ID tetap disembunyikan sampai baris dibuka)</strong>
        <div class="triage-sublist-actions">
          <button type="button" class="btn ghost btn-xs act-fp-reset">Reset Default</button>
          <button type="button" class="btn ghost btn-xs act-fp-close">Tutup</button>
        </div>
      </div>
      <div class="wzh-field-picker-grid">
        ${allOptions.map((opt) => {
          const checked = selectedFields.includes(opt.key);
          return `
            <label class="wzh-field-chip ${checked ? 'is-selected' : ''}">
              <input type="checkbox" value="${B.esc(opt.key)}" ${checked ? 'checked' : ''} />
              <span class="mono">${B.esc(opt.label)}</span>
            </label>
          `;
        }).join('')}
      </div>
    `;

    panelEl.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
      cb.addEventListener('change', () => {
        const key = cb.value;
        let next = selectedFields.slice();
        if (cb.checked) {
          if (!next.includes(key) && !isBlockedColumnKey(key)) next.push(key);
        } else {
          next = next.filter((k) => k !== key);
          if (!next.length) {
            cb.checked = true;
            B.toast({ type: 'info', title: 'Minimal 1 kolom harus aktif' });
            return;
          }
        }
        onChange(next);
      });
    });

    $('.act-fp-reset', panelEl)?.addEventListener('click', () => onChange(defaults.slice()));
    $('.act-fp-close', panelEl)?.addEventListener('click', () => onClose());
  }

  function renderDiscoverTable(opts) {
    const {
      tableEl,
      theadEl,
      tbodyEl,
      rows = [],
      columns = ['rule_description'],
      expandedIds,
      docTabById,
      fieldFilterById,
      showCheckbox = false,
      selectedIds,
      onToggleSelect,
      onToggleExpand,
      onToggleColumn,
      onRerender,
      renderRowActions,
      renderExpandedActions,
    } = opts;

    if (!tableEl || !theadEl || !tbodyEl) return;
    const activeCols = (columns || []).filter((k) => !isBlockedColumnKey(k));
    const safeCols = activeCols.length ? activeCols : ['rule_description'];
    const hasActionsCol = typeof renderRowActions === 'function';
    const totalCols = (showCheckbox ? 1 : 0) + 2 + safeCols.length + (hasActionsCol ? 1 : 0);

    // Sync colgroup so fixed table layout spans 100% with zero horizontal overflow
    let colgroup = tableEl.querySelector('colgroup');
    if (!colgroup) {
      colgroup = document.createElement('colgroup');
      tableEl.insertBefore(colgroup, theadEl);
    }
    const colHtml = [
      showCheckbox ? '<col style="width: 32px" />' : '',
      '<col style="width: 34px" />',
      '<col style="width: 152px" />',
      ...safeCols.map((k) => (k === 'rule_description' || k === 'full_log' ? '<col style="width: 32%" />' : '<col />')),
      hasActionsCol ? '<col style="width: 96px" />' : '',
    ].join('');
    colgroup.innerHTML = colHtml;

    theadEl.innerHTML = `
      <tr>
        ${showCheckbox ? '<th class="wzh-col-check" aria-label="Pilih"></th>' : ''}
        <th class="wzh-col-chevron" aria-label="Expand"></th>
        <th>Time</th>
        ${safeCols.map((k) => `<th><span class="mono">${B.esc(getFieldLabel(k))}</span></th>`).join('')}
        ${hasActionsCol ? '<th class="wzh-col-actions">Aksi</th>' : ''}
      </tr>
    `;

    tbodyEl.innerHTML = '';
    for (const row of rows) {
      const id = row.alert_id;
      const isExpanded = expandedIds.has(id);
      const tr = document.createElement('tr');
      tr.className = 'wzh-summary-row' + (isExpanded ? ' is-expanded' : '');

      const cellsHtml = [];
      if (showCheckbox) {
        const checked = selectedIds?.has(id);
        cellsHtml.push(`
          <td class="wzh-cell-check">
            <input type="checkbox" class="triage-subalert-check wzh-row-check" ${checked ? 'checked' : ''} aria-label="Pilih alert" />
          </td>
        `);
      }
      cellsHtml.push(`
        <td class="wzh-cell-chevron">
          <button type="button" class="wzh-chevron-btn ${isExpanded ? 'is-open' : ''}" aria-expanded="${isExpanded}" aria-label="${isExpanded ? 'Tutup dokumen' : 'Buka dokumen'}">
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M6 3.5 10.5 8 6 12.5" />
            </svg>
          </button>
        </td>
      `);
      cellsHtml.push(`<td class="mono wzh-cell-time">${B.esc(formatDiscoverTime(row.timestamp))}</td>`);

      for (const colKey of safeCols) {
        const val = resolveFieldValue(row, colKey);
        if (colKey === 'tenant') {
          cellsHtml.push(`<td><span class="chip mode-reporting">${B.esc(val)}</span></td>`);
        } else if (colKey === 'status') {
          cellsHtml.push(`<td><span class="chip wzh-status-chip">${B.esc(val)}</span></td>`);
        } else if (colKey === 'rule_level') {
          const sevCls = 'sev-' + String(row.severity_label || 'Medium').toUpperCase();
          cellsHtml.push(`<td><span class="chip ${sevCls}">${B.esc(val)}</span></td>`);
        } else if (colKey === 'http_status' && val !== '—') {
          cellsHtml.push(`<td><span class="chip">${B.esc(val)}</span></td>`);
        } else {
          const cls = isMonoField(colKey) ? 'mono' : '';
          cellsHtml.push(`<td class="${cls}">${B.esc(val)}</td>`);
        }
      }

      if (hasActionsCol) {
        cellsHtml.push(`<td class="wzh-cell-actions">${renderRowActions(row)}</td>`);
      }
      tr.innerHTML = cellsHtml.join('');

      $('.wzh-row-check', tr)?.addEventListener('change', (e) => {
        e.stopPropagation();
        if (onToggleSelect) onToggleSelect(id, e.target.checked);
      });
      $('.wzh-chevron-btn', tr)?.addEventListener('click', (e) => {
        e.stopPropagation();
        onToggleExpand(id);
      });
      tr.addEventListener('click', (e) => {
        if (e.target.closest('button, input, a, select, label')) return;
        onToggleExpand(id);
      });

      tbodyEl.appendChild(tr);

      if (isExpanded) {
        const expTr = document.createElement('tr');
        expTr.className = 'wzh-expanded-row';
        const curTab = docTabById.get(id) === 'json' ? 'json' : 'table';
        const filterQ = String(fieldFilterById.get(id) || '').toLowerCase();
        const jsonDoc = { _id: id, ...(row.raw_wazuh_alert || {}) };
        const flatFields = flattenWazuhDoc(row.raw_wazuh_alert || {}, id).filter((f) => {
          if (!filterQ) return true;
          return f.key.toLowerCase().includes(filterQ) || f.value.toLowerCase().includes(filterQ);
        });

        expTr.innerHTML = `
          <td colspan="${totalCols}">
            <div class="wzh-expanded-box">
              <div class="wzh-expanded-head">
                <div class="wzh-expanded-title">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                    <path d="M14 2v6h6" />
                  </svg>
                  <strong>Expanded document</strong>
                </div>
                <div class="wzh-expanded-actions">
                  ${typeof renderExpandedActions === 'function' ? renderExpandedActions(row) : ''}
                  <button type="button" class="btn ghost btn-xs act-doc-copy-json">Salin JSON</button>
                </div>
              </div>

              <div class="wzh-expanded-tabs" role="tablist">
                <button type="button" class="wzh-tab-btn ${curTab === 'table' ? 'active' : ''}" data-doc-tab="table" aria-selected="${curTab === 'table'}">Table</button>
                <button type="button" class="wzh-tab-btn ${curTab === 'json' ? 'active' : ''}" data-doc-tab="json" aria-selected="${curTab === 'json'}">JSON</button>
                ${curTab === 'table'
                  ? `<input type="search" class="wzh-doc-filter" value="${B.esc(fieldFilterById.get(id) || '')}" placeholder="Filter field atau nilai…" aria-label="Filter field dokumen" />`
                  : ''}
              </div>

              ${curTab === 'table' ? `
                <table class="wzh-doc-table">
                  <colgroup>
                    <col style="width: 30px" />
                    <col style="width: 240px" />
                    <col />
                    <col style="width: 140px" />
                  </colgroup>
                  <tbody>
                    ${flatFields.map((f) => {
                      const canToggle = !isBlockedColumnKey(f.key);
                      const isColActive = safeCols.includes(f.key) || safeCols.some((c) => {
                        const meta = WAZUH_FIELD_CATALOG.find((m) => m.key === c);
                        return meta?.aliases?.includes(f.key);
                      });
                      return `
                        <tr>
                          <td><span class="wzh-type-glyph">${B.esc(f.typeGlyph)}</span></td>
                          <td class="mono wzh-doc-key">${B.esc(f.key)}</td>
                          <td class="mono wzh-doc-val">${B.esc(f.value)}</td>
                          <td class="wzh-doc-acts">
                            <button type="button" class="btn ghost btn-xs act-doc-copy-val" data-copy="${B.esc(f.value)}">Copy</button>
                            ${canToggle && onToggleColumn
                              ? `<button type="button" class="btn ghost btn-xs act-doc-toggle-col" data-col-key="${B.esc(f.key)}">${isColActive ? '✓ Kolom' : '+ Kolom'}</button>`
                              : ''}
                          </td>
                        </tr>
                      `;
                    }).join('')}
                  </tbody>
                </table>
              ` : `
                <pre class="wzh-json-pre">${B.esc(JSON.stringify(jsonDoc, null, 2))}</pre>
              `}
            </div>
          </td>
        `;

        expTr.querySelectorAll('.wzh-tab-btn').forEach((btn) => {
          btn.addEventListener('click', () => {
            docTabById.set(id, btn.dataset.docTab);
            onRerender();
          });
        });

        const filterInput = $('.wzh-doc-filter', expTr);
        if (filterInput) {
          filterInput.addEventListener('input', (e) => {
            const pos = e.target.selectionStart;
            fieldFilterById.set(id, e.target.value);
            onRerender();
            // Restore focus & caret to the re-rendered filter input for smooth typing
            requestAnimationFrame(() => {
              const allExpanded = tbodyEl.querySelectorAll('.wzh-expanded-row');
              for (const node of allExpanded) {
                const inp = $('.wzh-doc-filter', node);
                if (inp && inp.value === (fieldFilterById.get(id) || '')) {
                  inp.focus();
                  if (typeof pos === 'number') inp.setSelectionRange(pos, pos);
                  break;
                }
              }
            });
          });
        }

        $('.act-doc-copy-json', expTr)?.addEventListener('click', () => {
          B.copyText(JSON.stringify(jsonDoc, null, 2), 'Raw Wazuh JSON');
        });

        expTr.querySelectorAll('.act-doc-copy-val').forEach((btn) => {
          btn.addEventListener('click', () => B.copyText(btn.dataset.copy || '', 'Nilai Field'));
        });

        expTr.querySelectorAll('.act-doc-toggle-col').forEach((btn) => {
          btn.addEventListener('click', () => {
            if (onToggleColumn) onToggleColumn(btn.dataset.colKey);
          });
        });

        tbodyEl.appendChild(expTr);
      }
    }
  }

  /* ---------------- Settings Panel & Daftar Exclusion Rules ---------------- */

  function syncExclusionBadge(count) {
    const badge = $('#tab-triage-exclusions-count');
    if (badge && typeof count === 'number') badge.textContent = String(count);
  }

  function renderExclusionsPage() {
    const tbody = $('#exclusions-page-tbody');
    const emptyEl = $('#exclusions-page-empty');
    const pillEl = $('#ex-summary-pill');
    if (!tbody || !emptyEl) return;

    const allRules = triageState.exclusions || triageState.config?.exclusionRules || [];
    const enabledCount = allRules.filter((r) => r.enabled !== false).length;
    syncExclusionBadge(allRules.length);
    if (pillEl) pillEl.textContent = `${enabledCount} Aktif / ${allRules.length} Total Rule`;

    const modeFilter = $('#ex-filter-mode')?.value || triageState.exFilterMode || 'all';
    const q = ($('#ex-search')?.value || triageState.exSearch || '').trim().toLowerCase();

    const filtered = allRules.filter((r) => {
      if (modeFilter === 'enabled' && r.enabled === false) return false;
      if (modeFilter === 'disabled' && r.enabled !== false) return false;
      if (modeFilter === 'auto_ignore' && r.source !== 'auto_ignore') return false;
      if (modeFilter === 'manual' && r.source === 'auto_ignore') return false;
      if (q) {
        const hay = `${r.target} ${r.mode} ${r.pattern} ${r.note || ''} ${r.source || ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    tbody.innerHTML = '';
    if (!filtered.length) {
      emptyEl.hidden = false;
      return;
    }
    emptyEl.hidden = true;

    for (const rule of filtered) {
      const tr = document.createElement('tr');
      const isEditing = triageState.exEditingId === rule.id;
      const sourceBadge = rule.source === 'auto_ignore'
        ? '<span class="chip verdict-review">Auto-Exclude</span>'
        : rule.source === 'ai_suggest'
          ? '<span class="chip mode-reporting">AI Analisis</span>'
          : rule.source === 'default'
            ? '<span class="chip">Default</span>'
            : '<span class="chip mode-reporting">Manual</span>';

      if (isEditing) {
        tr.innerHTML = `
          <td><input type="checkbox" class="ex-edit-enabled" ${rule.enabled !== false ? 'checked' : ''} aria-label="Aktifkan aturan" /></td>
          <td><select class="ex-edit-target">${buildSelectOptions(EXCLUSION_TARGET_OPTIONS, rule.target)}</select></td>
          <td><select class="ex-edit-mode">${buildSelectOptions(EXCLUSION_MODE_OPTIONS, rule.mode)}</select></td>
          <td><input type="text" class="ex-edit-pattern" value="${B.esc(rule.pattern || '')}" spellcheck="false" /></td>
          <td><input type="text" class="ex-edit-note" value="${B.esc(rule.note || '')}" placeholder="Keterangan" /></td>
          <td>
            <div class="wzh-row-btn-group">
              <button type="button" class="btn primary btn-xs act-ex-save-edit">Simpan</button>
              <button type="button" class="btn ghost btn-xs act-ex-cancel-edit">Batal</button>
            </div>
          </td>
        `;
        $('.act-ex-save-edit', tr)?.addEventListener('click', async () => {
          const pattern = ($('.ex-edit-pattern', tr)?.value || '').trim();
          if (!pattern) {
            B.toast({ type: 'error', title: 'Pola tidak boleh kosong' });
            return;
          }
          try {
            const res = await B.apiFetch('/api/triage/exclusions/' + encodeURIComponent(rule.id), {
              method: 'PATCH',
              body: JSON.stringify({
                enabled: Boolean($('.ex-edit-enabled', tr)?.checked),
                target: $('.ex-edit-target', tr)?.value,
                mode: $('.ex-edit-mode', tr)?.value,
                pattern,
                note: ($('.ex-edit-note', tr)?.value || '').trim(),
              }),
            });
            triageState.exEditingId = null;
            if (res.rules) {
              triageState.exclusions = res.rules;
              if (triageState.config) triageState.config.exclusionRules = res.rules;
              renderExclusionRows(res.rules);
            }
            renderExclusionsPage();
            B.toast({ type: 'success', title: 'Rule exclude diperbarui' });
          } catch (err) {
            B.toast({ type: 'error', title: 'Gagal memperbarui rule', body: err.message });
          }
        });
        $('.act-ex-cancel-edit', tr)?.addEventListener('click', () => {
          triageState.exEditingId = null;
          renderExclusionsPage();
        });
      } else {
        tr.innerHTML = `
          <td><input type="checkbox" class="act-ex-toggle" ${rule.enabled !== false ? 'checked' : ''} aria-label="Toggle rule ${B.esc(rule.pattern)}" /></td>
          <td><span class="chip">${B.esc(getTargetLabel(rule.target))}</span></td>
          <td><span class="mono">${B.esc(getModeLabel(rule.mode))}</span></td>
          <td class="mono">${B.esc(rule.pattern)}</td>
          <td>
            <div class="wzh-ex-note-cell">
              ${sourceBadge}
              <span>${B.esc(rule.note || '—')}</span>
            </div>
          </td>
          <td>
            <div class="wzh-row-btn-group">
              <button type="button" class="btn ghost btn-xs act-ex-edit">Edit</button>
              <button type="button" class="btn danger btn-xs act-ex-del">Hapus</button>
            </div>
          </td>
        `;
        $('.act-ex-toggle', tr)?.addEventListener('change', async (e) => {
          try {
            const res = await B.apiFetch('/api/triage/exclusions/' + encodeURIComponent(rule.id), {
              method: 'PATCH',
              body: JSON.stringify({ enabled: Boolean(e.target.checked) }),
            });
            if (res.rules) {
              triageState.exclusions = res.rules;
              if (triageState.config) triageState.config.exclusionRules = res.rules;
              renderExclusionRows(res.rules);
            }
            renderExclusionsPage();
          } catch (err) {
            e.target.checked = !e.target.checked;
            B.toast({ type: 'error', title: 'Gagal mengubah status rule', body: err.message });
          }
        });
        $('.act-ex-edit', tr)?.addEventListener('click', () => {
          triageState.exEditingId = rule.id;
          renderExclusionsPage();
        });
        $('.act-ex-del', tr)?.addEventListener('click', async () => {
          try {
            const res = await B.apiFetch('/api/triage/exclusions/' + encodeURIComponent(rule.id), { method: 'DELETE' });
            if (res.rules) {
              triageState.exclusions = res.rules;
              if (triageState.config) triageState.config.exclusionRules = res.rules;
              renderExclusionRows(res.rules);
            }
            renderExclusionsPage();
            B.toast({ type: 'info', title: 'Rule exclude dihapus' });
          } catch (err) {
            B.toast({ type: 'error', title: 'Gagal menghapus rule', body: err.message });
          }
        });
      }
      tbody.appendChild(tr);
    }
  }

  async function fetchExclusionRules(silent = false) {
    try {
      const res = await B.apiFetch('/api/triage/exclusions');
      if (Array.isArray(res?.rules)) {
        triageState.exclusions = res.rules;
        if (triageState.config) triageState.config.exclusionRules = res.rules;
        renderExclusionRows(res.rules);
        renderExclusionsPage();
      }
    } catch (err) {
      if (!silent) B.toast({ type: 'error', title: 'Gagal memuat daftar exclude', body: err.message });
    }
  }

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
          <select class="trg-ex-target" aria-label="Target field">${buildSelectOptions(EXCLUSION_TARGET_OPTIONS, rule.target || 'path')}</select>
        </td>
        <td>
          <select class="trg-ex-mode" aria-label="Mode pencocokan">${buildSelectOptions(EXCLUSION_MODE_OPTIONS, rule.mode || 'contains')}</select>
        </td>
        <td>
          <input type="text" class="trg-ex-pattern" value="${B.esc(rule.pattern || '')}" placeholder="/service/mhs/*/ip-kemarin atau regex" spellcheck="false" aria-label="Pola pengecualian" />
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
        target: $('.trg-ex-target', tr)?.value || 'path',
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
    triageState.exclusions = Array.isArray(cfg.exclusionRules) ? cfg.exclusionRules : [];
    renderExclusionsPage();
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

  function updateVerdictCounts(prefix, snap, badgeSel) {
    if (!snap) return;
    const c = snap.counts || {};
    const badge = $(badgeSel);
    if (badge) {
      const activeCount = Number(c.TRUE_POSITIVE || 0) + Number(c.NEEDS_REVIEW || 0);
      badge.textContent = String(c.total || 0);
      badge.classList.toggle('has-pending', activeCount > 0);
    }
    if (prefix === 'trg') {
      const histBadge = $('#tab-triage-history-count');
      if (histBadge && typeof snap.historyCount === 'number') {
        histBadge.textContent = String(snap.historyCount);
      }
    }
    const tpEl = $(`#${prefix}-count-tp`);
    const revEl = $(`#${prefix}-count-review`);
    const fpEl = $(`#${prefix}-count-fp`);
    const allEl = $(`#${prefix}-count-all`);
    if (tpEl) tpEl.textContent = String(c.TRUE_POSITIVE || 0);
    if (revEl) revEl.textContent = String(c.NEEDS_REVIEW || 0);
    if (fpEl) fpEl.textContent = String(c.FALSE_POSITIVE || 0);
    if (allEl) allEl.textContent = String(c.total || 0);
  }

  function updateSidebarBadges(snap) {
    updateVerdictCounts('trg', snap, '#tab-triage-count');
    if (snap && typeof snap.exclusionRulesCount === 'number') {
      syncExclusionBadge(snap.exclusionRulesCount);
    }
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

  function getSelectedSubAlerts(mapRef, groupId) {
    let set = mapRef.get(groupId);
    if (!set) {
      set = new Set();
      mapRef.set(groupId, set);
    }
    return set;
  }

  function reconcileSelectionMaps(allGroups, selectedGroupIds, selectedSubAlertsByGroup) {
    const validIds = new Set(allGroups.map((g) => g.group_id));
    for (const id of [...selectedGroupIds]) {
      if (!validIds.has(id)) selectedGroupIds.delete(id);
    }
    for (const [gid, set] of [...selectedSubAlertsByGroup.entries()]) {
      const grp = allGroups.find((g) => g.group_id === gid);
      if (!grp) {
        selectedSubAlertsByGroup.delete(gid);
      } else {
        const alertSet = new Set((grp.alerts || []).map((a) => a.alert_id));
        for (const aid of [...set]) {
          if (!alertSet.has(aid)) set.delete(aid);
        }
        if (set.size === 0) selectedSubAlertsByGroup.delete(gid);
      }
    }
  }

  function updateMergeBarFor(groups, selectedGroupIds, barEl, btnEl, msgEl) {
    if (!barEl || !btnEl || !msgEl) return;
    const selected = groups.filter((g) => selectedGroupIds.has(g.group_id));
    if (selected.length < 2) {
      barEl.hidden = true;
      return;
    }
    barEl.hidden = false;
    const tenants = [...new Set(selected.map((g) => String(g.tenant_mapped || '').toLowerCase()))];
    const crossTenant = tenants.length > 1;
    btnEl.disabled = crossTenant;
    if (crossTenant) {
      msgEl.textContent = `Tidak dapat menggabungkan grup dari tenant yang berbeda (${tenants.join(', ')}).`;
      msgEl.className = 'field-msg err';
    } else {
      const totalAlerts = selected.reduce((s, g) => s + Number(g.alert_count || g.alerts?.length || 0), 0);
      msgEl.textContent = `${selected.length} grup dipilih (${totalAlerts} alert) pada tenant "${tenants[0]}".`;
      msgEl.className = 'field-msg auto';
    }
  }

  function filterVisibleGroupsFor(groups, bucket) {
    const v = bucket.verdictFilter;
    const tf = (bucket.tenantFilter || '').toLowerCase();
    const q = (bucket.search || '').trim().toLowerCase();

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

  function applyPromoteResult(res, targetWs, isBatch24h) {
    const promoInfo = B.promoteTriageAlertsToForm({
      tenant: res.tenant,
      chunks: res.chunks,
      incidentTitle: res.incidentTitle,
      workspace: targetWs,
    });
    if (res.snapshot) {
      if (isBatch24h) {
        triageState.batch24h.snapshot = res.snapshot;
        triageState.batch24h.selectedGroupIds.clear();
        renderBatch24hView();
      } else {
        triageState.snapshot = res.snapshot;
        triageState.selectedGroupIds.clear();
        renderTriageView();
      }
      refreshInspectorIfOpen();
    }
    B.toast({
      type: 'success',
      title: `${promoInfo.cardCount} kartu form dibuat (${res.tenant})`,
      body: isBatch24h
        ? 'Wazuh Alert ID dicatat ke Audit Triage (antrean AI Triage utama tidak terganggu).'
        : 'Wazuh Alert ID dicatat ke Audit Triage & watermark antrean direset.',
    });
  }

  async function promoteFromTriage(opts) {
    try {
      const targetWs = opts.workspace || B.getActiveWorkspace();
      let candidateTenant = opts.tenant || '';
      const isBatch24h = Boolean(opts.isBatch24h);
      const srcGroups = isBatch24h ? triageState.batch24h.snapshot?.groups : triageState.snapshot?.groups;
      if (!candidateTenant && opts.groupId && srcGroups) {
        const grp = srcGroups.find((g) => g.group_id === opts.groupId);
        if (grp) candidateTenant = grp.tenant_mapped || '';
      }
      const preview = B.previewNextCardMeta ? B.previewNextCardMeta(candidateTenant, targetWs) : {};
      const payload = {
        ...opts,
        workspace: targetWs,
        irisTicketNumber: opts.irisTicketNumber || preview.ticketNumber || null,
        irisCaseId: opts.irisCaseId || preview.irisCaseId || null,
      };
      const endpoint = isBatch24h ? '/api/triage/batch24h/promote' : '/api/triage/promote';
      const res = await B.apiFetch(endpoint, {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      applyPromoteResult(res, targetWs, isBatch24h);
    } catch (err) {
      B.toast({ type: 'error', title: 'Gagal membuat case dari triage', body: err.message });
    }
  }

  /* ---------------- Shared Inspector & Ignore+Exclude Actions ---------------- */

  function normalizeSubAlertRow(al, tenantFallback = '—') {
    const raw = al?.raw_wazuh_alert || {};
    const lv = Number(raw.rule?.level || 0);
    const sev = lv >= 15 ? 'Critical' : lv >= 12 ? 'High' : lv >= 7 ? 'Medium' : 'Low';
    return {
      alert_id: al.alert_id,
      timestamp: raw['@timestamp'] || raw.timestamp || raw.ts || null,
      tenant: tenantFallback || raw.agent?.labels?.tenant || '—',
      agent_name: raw.agent?.name || '—',
      rule_id: String(raw.rule?.id || '—'),
      rule_level: lv,
      severity_label: sev,
      rule_description: raw.rule?.description || '—',
      src_ip: raw.data?.srcip || raw.data?.src_ip || raw.data?.win?.eventdata?.ipAddress || '—',
      path: raw.data?.url || raw.data?.uri || raw.data?.http?.url || '',
      http_status: String(raw.data?.http_status || raw.data?.status || raw.data?.http?.status_code || ''),
      full_log: String(raw.full_log || ''),
      raw_wazuh_alert: raw,
    };
  }

  function renderExcludePreviewRows(rules = []) {
    const tbody = $('#ex-modal-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    for (const rule of rules) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><input type="checkbox" class="exm-enabled" ${rule.enabled !== false ? 'checked' : ''} aria-label="Gunakan rule ini" /></td>
        <td><select class="exm-target">${buildSelectOptions(EXCLUSION_TARGET_OPTIONS, rule.target || 'path')}</select></td>
        <td><select class="exm-mode">${buildSelectOptions(EXCLUSION_MODE_OPTIONS, rule.mode || 'wildcard')}</select></td>
        <td><input type="text" class="exm-pattern mono" value="${B.esc(rule.pattern || '')}" placeholder="/service/mhs/*/ip-kemarin" spellcheck="false" /></td>
        <td><input type="text" class="exm-note" value="${B.esc(rule.note || '')}" placeholder="Keterangan" /></td>
        <td><button type="button" class="btn danger btn-xs exm-del">Hapus</button></td>
      `;
      tr.dataset.source = rule.source || 'auto_ignore';
      $('.exm-del', tr)?.addEventListener('click', () => tr.remove());
      tbody.appendChild(tr);
    }
  }

  function collectExcludePreviewRows() {
    const tbody = $('#ex-modal-tbody');
    if (!tbody) return [];
    const out = [];
    tbody.querySelectorAll('tr').forEach((tr) => {
      const enabled = Boolean($('.exm-enabled', tr)?.checked);
      const pattern = ($('.exm-pattern', tr)?.value || '').trim();
      if (!enabled || !pattern) return;
      out.push({
        enabled: true,
        target: $('.exm-target', tr)?.value || 'path',
        mode: $('.exm-mode', tr)?.value || 'wildcard',
        pattern,
        source: tr.dataset.source || 'auto_ignore',
        note: ($('.exm-note', tr)?.value || '').trim(),
      });
    });
    return out;
  }

  function closeExcludePreviewModal() {
    const modal = $('#exclude-preview-modal');
    if (modal) modal.hidden = true;
    triageState.excludePreviewCtx = null;
  }

  async function openExcludePreviewModal(ctx) {
    const modal = $('#exclude-preview-modal');
    if (!modal) return;
    triageState.excludePreviewCtx = ctx;
    const msgEl = $('#ex-modal-ai-msg');
    showInlineStatus(msgEl, true, '');
    if ($('#ex-modal-subtitle')) {
      $('#ex-modal-subtitle').textContent = ctx.subtitle || 'Tinjau pola yang akan dijadikan rule exclude. Ubah manual atau klik AI Analisis Exclude.';
    }
    if ($('#btn-ex-modal-confirm')) {
      $('#btn-ex-modal-confirm').textContent = ctx.source === 'live' ? 'Simpan Rule Exclude' : 'Simpan Rule & Abaikan';
    }
    renderExcludePreviewRows([]);
    modal.hidden = false;

    try {
      const res = await B.apiFetch('/api/triage/exclusions/suggest', {
        method: 'POST',
        body: JSON.stringify({
          source: ctx.source,
          groupId: ctx.groupId,
          groupIds: ctx.groupIds,
          alertIds: ctx.alertIds,
          rawAlerts: ctx.rawAlerts,
          title: ctx.title,
        }),
      });
      renderExcludePreviewRows(res.rules || []);
    } catch (err) {
      showInlineStatus(msgEl, false, err.message);
      renderExcludePreviewRows([{ enabled: true, target: 'path', mode: 'wildcard', pattern: '', note: '', source: 'manual' }]);
    }
  }

  function showIgnoreExcludeToast(res, fallbackPrefix) {
    const added = res.rulesAdded || [];
    const existing = res.rulesExisting || [];
    if (added.length > 1) {
      const preview = added.slice(0, 3).map((r) => r.pattern).join(', ') + (added.length > 3 ? ` (+${added.length - 3} lainnya)` : '');
      B.toast({
        type: 'success',
        title: `${fallbackPrefix}: ${added.length} Rule Exclude spesifik dibuat`,
        body: preview,
      });
    } else if (added.length === 1) {
      const rule = added[0];
      B.toast({
        type: 'success',
        title: `${fallbackPrefix}: Rule Exclude otomatis dibuat`,
        body: `${rule.target} [${rule.mode}]: ${rule.pattern}`,
      });
    } else if (existing.length) {
      const rule = existing[0];
      B.toast({
        type: 'info',
        title: `${fallbackPrefix} (rule sudah terdaftar)`,
        body: `${rule.target} [${rule.mode}]: ${rule.pattern}`,
      });
    } else {
      B.toast({ type: 'info', title: `${fallbackPrefix} selesai` });
    }
  }

  function syncSnapshotAndExclusions(res, isBatch24h) {
    if (Array.isArray(res?.exclusionRules)) {
      triageState.exclusions = res.exclusionRules;
      if (triageState.config) triageState.config.exclusionRules = res.exclusionRules;
      renderExclusionRows(res.exclusionRules);
      renderExclusionsPage();
    }
    if (res?.snapshot) {
      if (isBatch24h) {
        triageState.batch24h.snapshot = res.snapshot;
        renderBatch24hView();
      } else {
        triageState.snapshot = res.snapshot;
        renderTriageView();
      }
    }
  }

  function openAlertInspector(opts) {
    const insp = triageState.inspector;
    insp.source = opts.source || 'queue';
    insp.returnView = opts.returnView || (insp.source === 'batch24h' ? 'triage-24h' : insp.source === 'history' ? 'triage-history' : 'triage');
    insp.groupId = opts.groupId || null;
    insp.search = '';
    insp.selectedIds.clear();
    insp.expandedIds.clear();
    if ($('#insp-search')) $('#insp-search').value = '';

    if (insp.source === 'history') {
      insp.title = opts.title || 'Detail Alert Riwayat';
      insp.tenant = opts.tenant || '—';
      insp.alerts = (opts.alerts || []).map((a) => normalizeSubAlertRow(a, opts.tenant));
      insp.badges = opts.badges || [];
    } else {
      const srcGroups = insp.source === 'batch24h' ? triageState.batch24h.snapshot?.groups : triageState.snapshot?.groups;
      const grp = (srcGroups || []).find((g) => g.group_id === insp.groupId);
      if (!grp) {
        B.toast({ type: 'info', title: 'Grup sudah diproses atau dihapus' });
        B.switchView(insp.returnView);
        return;
      }
      insp.title = grp.incident_title || 'Security Incident';
      insp.tenant = grp.tenant_mapped || 'unassigned';
      insp.alerts = (grp.alerts || []).map((a) => normalizeSubAlertRow(a, insp.tenant));
      const vMeta = VERDICT_META[grp.verdict] || VERDICT_META.NEEDS_REVIEW;
      insp.badges = [
        { text: vMeta.label, cls: vMeta.cls },
        { text: `${grp.severity_label || 'Medium'} (Lv ${grp.max_rule_level ?? '?'})`, cls: 'sev-' + String(grp.severity_label || 'MEDIUM').toUpperCase() },
        { text: insp.tenant, cls: 'mode-reporting' },
      ];
    }

    if (insp.alerts.length === 1) insp.expandedIds.add(insp.alerts[0].alert_id);
    renderInspectorView();
    B.switchView('triage-inspector');
  }

  function refreshInspectorIfOpen() {
    const insp = triageState.inspector;
    if (insp.source === 'history' || !insp.groupId) return;
    if ($('#view-triage-inspector')?.hidden) return;
    const srcGroups = insp.source === 'batch24h' ? triageState.batch24h.snapshot?.groups : triageState.snapshot?.groups;
    const grp = (srcGroups || []).find((g) => g.group_id === insp.groupId);
    if (!grp) {
      B.switchView(insp.returnView);
      return;
    }
    insp.title = grp.incident_title || 'Security Incident';
    insp.tenant = grp.tenant_mapped || 'unassigned';
    insp.alerts = (grp.alerts || []).map((a) => normalizeSubAlertRow(a, insp.tenant));
    const validIds = new Set(insp.alerts.map((a) => a.alert_id));
    for (const id of [...insp.selectedIds]) {
      if (!validIds.has(id)) insp.selectedIds.delete(id);
    }
    renderInspectorView();
  }

  function renderInspectorView() {
    const insp = triageState.inspector;
    const isHistory = insp.source === 'history';
    const apiPrefix = insp.source === 'batch24h' ? '/api/triage/batch24h' : '/api/triage';
    const isBatch24h = insp.source === 'batch24h';

    if ($('#insp-title')) $('#insp-title').textContent = `${insp.title} (${insp.alerts.length} alert)`;
    const badgesEl = $('#insp-badges');
    if (badgesEl) {
      badgesEl.innerHTML = insp.badges.map((b) => `<span class="chip ${B.esc(b.cls || '')}">${B.esc(b.text)}</span>`).join('');
    }

    if ($('#btn-insp-group-promote')) $('#btn-insp-group-promote').hidden = isHistory;
    if ($('#btn-insp-group-ignore')) $('#btn-insp-group-ignore').hidden = isHistory;
    if ($('#btn-insp-group-dismiss')) $('#btn-insp-group-dismiss').hidden = isHistory;
    if ($('#insp-bulk-actions')) $('#insp-bulk-actions').hidden = isHistory;

    const fieldsPanel = $('#insp-fields-panel');
    if (fieldsPanel) {
      fieldsPanel.hidden = !insp.fieldsOpen;
      if (insp.fieldsOpen) {
        renderFieldPickerPanel(fieldsPanel, insp.fields, DEFAULT_INSP_FIELDS, {
          allowStatus: false,
          onChange: (next) => {
            insp.fields = next;
            saveStoredFields(INSP_FIELDS_KEY, next);
            renderInspectorView();
          },
          onClose: () => {
            insp.fieldsOpen = false;
            renderInspectorView();
          },
        });
      }
    }

    const q = (insp.search || '').trim().toLowerCase();
    const visible = insp.alerts.filter((row) => {
      if (!q) return true;
      const hay = [
        row.alert_id,
        row.rule_id,
        row.rule_description,
        row.agent_name,
        row.src_ip,
        row.path,
        row.full_log,
      ].join(' ').toLowerCase();
      return hay.includes(q);
    });

    const selectedVisible = visible.filter((r) => insp.selectedIds.has(r.alert_id)).map((r) => r.alert_id);
    const allChecked = !isHistory && visible.length > 0 && selectedVisible.length === visible.length;
    if ($('#insp-select-all')) {
      $('#insp-select-all').hidden = isHistory;
      $('#insp-select-all').checked = allChecked;
    }
    if ($('#insp-sel-count')) {
      $('#insp-sel-count').textContent = isHistory
        ? `${visible.length} dokumen Wazuh`
        : (selectedVisible.length ? `${selectedVisible.length} dari ${visible.length} alert dipilih` : `${visible.length} alert (klik baris untuk detail Table / JSON)`);
    }
    if (!isHistory) {
      if ($('#btn-insp-split')) $('#btn-insp-split').disabled = !(selectedVisible.length > 0 && selectedVisible.length < insp.alerts.length);
      if ($('#btn-insp-ignore-sel')) $('#btn-insp-ignore-sel').disabled = selectedVisible.length === 0;
      if ($('#btn-insp-remove-sel')) $('#btn-insp-remove-sel').disabled = selectedVisible.length === 0;
      if ($('#btn-insp-promote-sel')) $('#btn-insp-promote-sel').disabled = selectedVisible.length === 0;
    }

    const emptyEl = $('#insp-empty');
    const tbody = $('#insp-tbody');
    const thead = $('#insp-thead');
    const tableEl = $('#insp-discover-table');
    if (!tbody || !thead || !tableEl || !emptyEl) return;

    if (!visible.length) {
      tbody.innerHTML = '';
      emptyEl.hidden = false;
      return;
    }
    emptyEl.hidden = true;

    renderDiscoverTable({
      tableEl,
      theadEl: thead,
      tbodyEl: tbody,
      rows: visible,
      columns: insp.fields,
      expandedIds: insp.expandedIds,
      docTabById: insp.docTabById,
      fieldFilterById: insp.fieldFilterById,
      showCheckbox: !isHistory,
      selectedIds: insp.selectedIds,
      onToggleSelect: (id, checked) => {
        if (checked) insp.selectedIds.add(id);
        else insp.selectedIds.delete(id);
        renderInspectorView();
      },
      onToggleExpand: (id) => {
        if (insp.expandedIds.has(id)) insp.expandedIds.delete(id);
        else insp.expandedIds.add(id);
        renderInspectorView();
      },
      onToggleColumn: (colKey) => {
        if (isBlockedColumnKey(colKey)) return;
        const meta = WAZUH_FIELD_CATALOG.find((m) => (m.aliases || []).includes(colKey));
        const normalizedKey = meta ? meta.key : colKey;
        if (insp.fields.includes(normalizedKey)) {
          if (insp.fields.length === 1) return B.toast({ type: 'info', title: 'Minimal 1 kolom harus aktif' });
          insp.fields = insp.fields.filter((k) => k !== normalizedKey);
        } else {
          insp.fields = [...insp.fields, normalizedKey];
        }
        saveStoredFields(INSP_FIELDS_KEY, insp.fields);
        renderInspectorView();
      },
      onRerender: renderInspectorView,
      renderRowActions: isHistory
        ? null
        : () => `<button type="button" class="btn accent btn-xs act-insp-row-case">Case</button>`,
      renderExpandedActions: isHistory
        ? null
        : () => `
          ${insp.alerts.length > 1 ? '<button type="button" class="btn ghost btn-xs act-insp-doc-split">Pisah</button>' : ''}
          <button type="button" class="btn ghost btn-xs act-insp-doc-ignore">Abaikan + Exclude</button>
          <button type="button" class="btn danger btn-xs act-insp-doc-remove">Hapus</button>
          <button type="button" class="btn accent btn-xs act-insp-doc-case">Buat Case Ini</button>
        `,
    });

    // Attach row & expanded document action handlers cleanly
    tbody.querySelectorAll('.wzh-summary-row').forEach((tr, idx) => {
      const row = visible[idx];
      if (!row) return;
      $('.act-insp-row-case', tr)?.addEventListener('click', (e) => {
        e.stopPropagation();
        promoteFromTriage({
          groupId: insp.groupId,
          alertIds: [row.alert_id],
          workspace: B.getActiveWorkspace(),
          resetWatermark: !isBatch24h,
          isBatch24h,
        });
      });
    });

    tbody.querySelectorAll('.wzh-expanded-row').forEach((expTr) => {
      const prevTr = expTr.previousElementSibling;
      const rowIdx = [...tbody.querySelectorAll('.wzh-summary-row')].indexOf(prevTr);
      const row = visible[rowIdx];
      if (!row || isHistory) return;

      $('.act-insp-doc-split', expTr)?.addEventListener('click', async () => {
        try {
          const res = await B.apiFetch(`${apiPrefix}/split`, {
            method: 'POST',
            body: JSON.stringify({ groupId: insp.groupId, alertIds: [row.alert_id] }),
          });
          syncSnapshotAndExclusions(res, isBatch24h);
          refreshInspectorIfOpen();
          B.toast({ type: 'success', title: 'Alert dipisahkan ke grup baru', body: res.newGroup?.incident_title || '' });
        } catch (err) {
          B.toast({ type: 'error', title: 'Gagal memisahkan alert', body: err.message });
        }
      });

      $('.act-insp-doc-ignore', expTr)?.addEventListener('click', () => {
        openExcludePreviewModal({
          source: insp.source,
          isBatch24h,
          groupId: insp.groupId,
          alertIds: [row.alert_id],
          title: row.rule_description || insp.title,
          subtitle: 'Pratinjau rule exclude untuk 1 alert terpilih.',
          toastTitle: 'Alert diabaikan',
        });
      });

      wireDoubleConfirm($('.act-insp-doc-remove', expTr), 'Klik lagi untuk Hapus', async () => {
        try {
          const res = await B.apiFetch(`${apiPrefix}/remove-alerts`, {
            method: 'POST',
            body: JSON.stringify({ groupId: insp.groupId, alertIds: [row.alert_id] }),
          });
          syncSnapshotAndExclusions(res, isBatch24h);
          refreshInspectorIfOpen();
          B.toast({ type: 'info', title: 'Alert dihapus dari grup' });
        } catch (err) {
          B.toast({ type: 'error', title: 'Gagal menghapus alert', body: err.message });
        }
      });

      $('.act-insp-doc-case', expTr)?.addEventListener('click', () => {
        promoteFromTriage({
          groupId: insp.groupId,
          alertIds: [row.alert_id],
          workspace: B.getActiveWorkspace(),
          resetWatermark: !isBatch24h,
          isBatch24h,
        });
      });
    });
  }

  function renderGroupCardsInto(ctx) {
    const {
      visible,
      listEl,
      emptyEl,
      bucket,
      apiPrefix,
      isBatch24h,
      onRerender,
    } = ctx;

    listEl.innerHTML = '';
    if (!visible.length) {
      listEl.hidden = true;
      emptyEl.hidden = false;
      return;
    }

    listEl.hidden = false;
    emptyEl.hidden = true;

    for (const g of visible) {
      const vMeta = VERDICT_META[g.verdict] || VERDICT_META.NEEDS_REVIEW;
      const isSelected = bucket.selectedGroupIds.has(g.group_id);
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
          <button type="button" class="btn ghost btn-sm act-trg-inspect">Lihat ${g.alerts?.length || 0} Alert</button>
          <button type="button" class="btn ghost btn-sm act-trg-ignore-exclude">Abaikan + Exclude</button>
          <button type="button" class="btn danger btn-sm act-trg-dismiss">Hapus</button>
        </div>
      `;

      $('.trg-group-check', card)?.addEventListener('change', (e) => {
        if (e.target.checked) bucket.selectedGroupIds.add(g.group_id);
        else bucket.selectedGroupIds.delete(g.group_id);
        onRerender(true);
      });

      $('.act-trg-promote', card)?.addEventListener('click', () => {
        promoteFromTriage({
          groupId: g.group_id,
          workspace: B.getActiveWorkspace(),
          resetWatermark: !isBatch24h,
          isBatch24h,
        });
      });

      $('.act-trg-inspect', card)?.addEventListener('click', () => {
        openAlertInspector({
          source: isBatch24h ? 'batch24h' : 'queue',
          returnView: isBatch24h ? 'triage-24h' : 'triage',
          groupId: g.group_id,
        });
      });

      $('.act-trg-ignore-exclude', card)?.addEventListener('click', () => {
        openExcludePreviewModal({
          source: isBatch24h ? 'batch24h' : 'queue',
          isBatch24h,
          groupIds: [g.group_id],
          title: g.incident_title || 'Security Incident',
          subtitle: `Pratinjau rule exclude untuk grup "${g.incident_title || g.group_id}" (${g.alert_count || g.alerts?.length || 0} alert).`,
          toastTitle: 'Grup diabaikan',
        });
      });

      wireDoubleConfirm($('.act-trg-dismiss', card), 'Klik lagi untuk Hapus', async () => {
        try {
          const res = await B.apiFetch(`${apiPrefix}/dismiss`, {
            method: 'POST',
            body: JSON.stringify({ groupIds: [g.group_id] }),
          });
          bucket.snapshot = res.snapshot;
          onRerender();
          B.toast({ type: 'info', title: 'Grup dihapus dari antrean (tanpa rule exclude)' });
        } catch (err) {
          B.toast({ type: 'error', title: 'Gagal menghapus grup', body: err.message });
        }
      });

      listEl.appendChild(card);
    }
  }

  function renderTriageView(mergeOnly = false) {
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
    reconcileSelectionMaps(allGroups, triageState.selectedGroupIds, triageState.selectedSubAlertsByGroup);
    updateMergeBarFor(allGroups, triageState.selectedGroupIds, $('#trg-merge-bar'), $('#btn-triage-merge'), $('#trg-merge-msg'));
    if (mergeOnly === true) return;

    const listEl = $('#triage-groups-list');
    const emptyEl = $('#triage-empty');
    if (!listEl || !emptyEl) return;

    const visible = filterVisibleGroupsFor(allGroups, triageState);
    renderGroupCardsInto({
      allGroups,
      visible,
      listEl,
      emptyEl,
      bucket: triageState,
      apiPrefix: '/api/triage',
      isBatch24h: false,
      onRerender: renderTriageView,
    });
  }

  function stopBatch24hProgressTimer() {
    if (triageState.batch24h.pollTimer) {
      clearInterval(triageState.batch24h.pollTimer);
      triageState.batch24h.pollTimer = null;
    }
  }

  function ensureBatch24hProgressTimer() {
    const running = Boolean(triageState.batch24h.snapshot?.job?.running);
    if (!running) {
      stopBatch24hProgressTimer();
      return;
    }
    if (!triageState.batch24h.pollTimer) {
      triageState.batch24h.pollTimer = setInterval(() => {
        fetchBatch24h(true);
      }, 1500);
    }
  }

  function renderBatch24hProgress(job) {
    const pill = $('#b24-status-pill');
    const runBtn = $('#btn-b24-run');
    const cancelBtn = $('#btn-b24-cancel');
    const box = $('#b24-progress-box');
    const msgEl = $('#b24-progress-msg');
    const pctEl = $('#b24-progress-pct');
    const trackEl = $('#b24-progress-track');
    const fillEl = $('#b24-progress-fill');
    const metaEl = $('#b24-progress-meta');

    const phase = job?.phase || 'idle';
    const running = Boolean(job?.running);
    const pct = Math.max(0, Math.min(100, Number(job?.percent || 0)));

    if (runBtn) runBtn.disabled = running;
    if (cancelBtn) cancelBtn.hidden = !running;

    if (pill) {
      if (running) {
        pill.textContent = `Berjalan (${pct}%)`;
        pill.className = 'sync-pill';
      } else if (phase === 'done') {
        pill.textContent = 'Selesai';
        pill.className = 'sync-pill';
      } else if (phase === 'error') {
        pill.textContent = 'Gagal';
        pill.className = 'sync-pill offline';
      } else if (phase === 'cancelled') {
        pill.textContent = 'Dibatalkan';
        pill.className = 'sync-pill offline';
      } else {
        pill.textContent = 'Siap';
        pill.className = 'sync-pill offline';
      }
    }

    if (!box) return;
    if (!running && phase === 'idle') {
      box.hidden = true;
      return;
    }
    box.hidden = false;
    if (msgEl) msgEl.textContent = job?.message || 'Memproses…';
    if (pctEl) pctEl.textContent = `${pct}%`;
    if (trackEl) trackEl.setAttribute('aria-valuenow', String(pct));
    if (fillEl) {
      fillEl.style.transform = `scaleX(${pct / 100})`;
      fillEl.className = 'triage-progress-fill' + (
        phase === 'done'
          ? ' is-done'
          : phase === 'error'
            ? ' is-error'
            : phase === 'cancelled'
              ? ' is-cancelled'
              : ''
      );
    }
    if (metaEl) {
      const tenantText = job?.currentTenant ? ` · Tenant aktif: ${job.currentTenant}` : '';
      metaEl.textContent = `Ditarik: ${job?.fetchedCount || 0} · Excluded: ${job?.excludedCount || 0} · Kandidat: ${job?.totalCandidates || 0} · Batch AI: ${job?.processedChunks || 0}/${job?.totalChunks || 0}${tenantText}`;
    }
  }

  function renderBatch24hView(mergeOnly = false) {
    const bucket = triageState.batch24h;
    const snap = bucket.snapshot;
    updateVerdictCounts('b24', snap, '#tab-triage-24h-count');
    renderBatch24hProgress(snap?.job);
    ensureBatch24hProgressTimer();

    document.querySelectorAll('.b24-verdict-btn[data-verdict]').forEach((btn) => {
      const active = btn.dataset.verdict === bucket.verdictFilter;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-pressed', String(active));
    });

    const allGroups = snap?.groups || [];
    populateTriageTenantSelect($('#b24-filter-tenant'), snap?.tenants || []);
    reconcileSelectionMaps(allGroups, bucket.selectedGroupIds, bucket.selectedSubAlertsByGroup);
    updateMergeBarFor(allGroups, bucket.selectedGroupIds, $('#b24-merge-bar'), $('#btn-b24-merge'), $('#b24-merge-msg'));
    if (mergeOnly === true) return;

    const listEl = $('#b24-groups-list');
    const emptyEl = $('#b24-empty');
    if (!listEl || !emptyEl) return;

    const visible = filterVisibleGroupsFor(allGroups, bucket);
    renderGroupCardsInto({
      allGroups,
      visible,
      listEl,
      emptyEl,
      bucket,
      apiPrefix: '/api/triage/batch24h',
      isBatch24h: true,
      onRerender: renderBatch24hView,
    });
  }

  async function fetchBatch24h(silent = false) {
    try {
      const snap = await B.apiFetch('/api/triage/batch24h');
      triageState.batch24h.snapshot = snap;
      renderBatch24hView();
    } catch (err) {
      if (!silent) B.toast({ type: 'error', title: 'Gagal memuat data Tarik 24 Jam', body: err.message });
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
    const tableEl = $('#live-discover-table');
    const thead = $('#live-feed-thead');
    const tbody = $('#live-feed-tbody');
    const emptyEl = $('#live-feed-empty');
    if (!tableEl || !thead || !tbody || !emptyEl) return;

    const fieldsPanel = $('#live-fields-panel');
    if (fieldsPanel) {
      fieldsPanel.hidden = !triageState.liveFieldsOpen;
      if (triageState.liveFieldsOpen) {
        renderFieldPickerPanel(fieldsPanel, triageState.liveFields, DEFAULT_LIVE_FIELDS, {
          allowStatus: true,
          onChange: (next) => {
            triageState.liveFields = next;
            saveStoredFields(LIVE_FIELDS_KEY, next);
            renderLiveFeed();
          },
          onClose: () => {
            triageState.liveFieldsOpen = false;
            renderLiveFeed();
          },
        });
      }
    }

    if (!data) {
      if (parityEl) {
        parityEl.textContent = 'Belum dimuat (klik Segarkan Live)';
        parityEl.className = 'sync-pill offline';
      }
      const tabCount = $('#tab-live-count');
      if (tabCount) tabCount.textContent = '0';
      thead.innerHTML = '';
      tbody.innerHTML = '';
      emptyEl.hidden = false;
      return;
    }

    const rawItems = data.items || [];
    const tenants = [...new Set(rawItems.map((i) => i.tenant).filter(Boolean))].sort();
    populateTriageTenantSelect($('#live-filter-tenant'), tenants);

    const tenantFilter = ($('#live-filter-tenant')?.value || '').trim().toLowerCase();
    const statusFilter = ($('#live-filter-status')?.value || '').trim();
    const q = ($('#live-search')?.value || '').trim().toLowerCase();

    const items = rawItems.filter((it) => {
      if (tenantFilter && String(it.tenant || '').toLowerCase() !== tenantFilter) return false;
      if (statusFilter && it.status_code !== statusFilter) return false;
      if (q) {
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
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    if (parityEl) {
      const matchTag = data.parityMatch ? '1:1 Match' : 'Terfilter';
      parityEl.textContent = `Wazuh Hits: ${data.totalHits} | Ditampilkan: ${items.length} (${matchTag})`;
      parityEl.className = 'sync-pill ' + (data.parityMatch ? '' : 'offline');
    }

    const tabCount = $('#tab-live-count');
    if (tabCount) tabCount.textContent = String(data.totalHits ?? data.rawCount ?? 0);

    if (!items.length) {
      thead.innerHTML = '';
      tbody.innerHTML = '';
      emptyEl.hidden = false;
      return;
    }
    emptyEl.hidden = true;

    renderDiscoverTable({
      tableEl,
      theadEl: thead,
      tbodyEl: tbody,
      rows: items,
      columns: triageState.liveFields,
      expandedIds: triageState.liveExpandedIds,
      docTabById: triageState.liveDocTabById,
      fieldFilterById: triageState.liveFieldFilterById,
      showCheckbox: false,
      onToggleExpand: (id) => {
        if (triageState.liveExpandedIds.has(id)) triageState.liveExpandedIds.delete(id);
        else triageState.liveExpandedIds.add(id);
        renderLiveFeed();
      },
      onToggleColumn: (colKey) => {
        if (isBlockedColumnKey(colKey)) return;
        const meta = WAZUH_FIELD_CATALOG.find((m) => (m.aliases || []).includes(colKey));
        const normalizedKey = meta ? meta.key : colKey;
        if (triageState.liveFields.includes(normalizedKey)) {
          if (triageState.liveFields.length === 1) return B.toast({ type: 'info', title: 'Minimal 1 kolom harus aktif' });
          triageState.liveFields = triageState.liveFields.filter((k) => k !== normalizedKey);
        } else {
          triageState.liveFields = [...triageState.liveFields, normalizedKey];
        }
        saveStoredFields(LIVE_FIELDS_KEY, triageState.liveFields);
        renderLiveFeed();
      },
      onRerender: renderLiveFeed,
      renderRowActions: () => `<button type="button" class="btn accent btn-xs act-live-promote">Ke Form</button>`,
      renderExpandedActions: () => `
        <button type="button" class="btn ghost btn-xs act-live-doc-exclude">Exclude Pola Ini</button>
        <button type="button" class="btn accent btn-xs act-live-doc-promote">Kirim ke Form</button>
      `,
    });

    tbody.querySelectorAll('.wzh-summary-row').forEach((tr, idx) => {
      const it = items[idx];
      if (!it) return;
      $('.act-live-promote', tr)?.addEventListener('click', (e) => {
        e.stopPropagation();
        promoteFromTriage({
          rawAlerts: [{ alert_id: it.alert_id, raw_wazuh_alert: it.raw_wazuh_alert }],
          tenant: it.tenant,
          incidentTitle: it.rule_description,
          aiVerdict: 'MANUAL_PROMOTE',
          workspace: B.getActiveWorkspace(),
          resetWatermark: false,
        });
      });
    });

    tbody.querySelectorAll('.wzh-expanded-row').forEach((expTr) => {
      const prevTr = expTr.previousElementSibling;
      const rowIdx = [...tbody.querySelectorAll('.wzh-summary-row')].indexOf(prevTr);
      const it = items[rowIdx];
      if (!it) return;

      $('.act-live-doc-promote', expTr)?.addEventListener('click', () => {
        promoteFromTriage({
          rawAlerts: [{ alert_id: it.alert_id, raw_wazuh_alert: it.raw_wazuh_alert }],
          tenant: it.tenant,
          incidentTitle: it.rule_description,
          aiVerdict: 'MANUAL_PROMOTE',
          workspace: B.getActiveWorkspace(),
          resetWatermark: false,
        });
      });

      $('.act-live-doc-exclude', expTr)?.addEventListener('click', () => {
        openExcludePreviewModal({
          source: 'live',
          rawAlerts: [{ alert_id: it.alert_id, raw_wazuh_alert: it.raw_wazuh_alert }],
          title: it.rule_description || 'Live Wazuh Alert',
          subtitle: 'Pratinjau rule exclude dari alert Live Wazuh (dapat diedit manual atau analisis AI).',
          toastTitle: 'Rule Exclude ditambahkan',
        });
      });
    });
  }

  async function fetchLiveFeed(silent = false) {
    const seq = ++triageState.liveFetchSeq;
    const range = $('#live-scope-select')?.value || 'watermark';
    const params = new URLSearchParams({ range, scope: range });
    const sizeVal = Number($('#live-size')?.value || 500);
    if (Number.isFinite(sizeVal) && sizeVal > 0) {
      params.set('size', String(Math.min(1000, Math.max(10, sizeVal))));
    }

    if (range === 'custom') {
      const rawFrom = $('#live-from')?.value || '';
      const rawTo = $('#live-to')?.value || '';
      if (!rawFrom && !rawTo) {
        if (!silent) B.toast({ type: 'error', title: 'Rentang waktu kosong', body: 'Isi minimal waktu Dari atau Sampai untuk Live Wazuh.' });
        return;
      }
      if (rawFrom) params.set('from', new Date(rawFrom).toISOString());
      if (rawTo) params.set('to', new Date(rawTo).toISOString());
    }

    try {
      const data = await B.apiFetch('/api/triage/live?' + params.toString());
      if (seq !== triageState.liveFetchSeq) return;
      triageState.liveData = data;
      renderLiveFeed();
    } catch (err) {
      if (seq !== triageState.liveFetchSeq) return;
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
    const cb = $('#live-auto-refresh');
    if (!cb || !cb.checked) return;
    const sec = Math.max(3, Number(triageState.config?.wazuh?.liveRefreshSec || 10));
    triageState.liveTimer = setInterval(() => {
      const curCb = $('#live-auto-refresh');
      if (curCb?.checked && !$('#view-live-feed')?.hidden) {
        fetchLiveFeed(true);
      } else if (!curCb?.checked) {
        stopLiveRefresh();
      }
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
          openAlertInspector({
            source: 'history',
            returnView: 'triage-history',
            title: entry.incident_title || `Audit Triage (${entry.tenant})`,
            tenant: entry.tenant,
            badges: [
              { text: entry.tenant || '—', cls: 'mode-reporting' },
              { text: vMeta.label, cls: vMeta.cls },
              ...(entry.iris_case_id ? [{ text: `IRIS ${entry.iris_case_id}`, cls: 'mono' }] : []),
            ],
            alerts: res.alerts || [],
          });
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
          refreshInspectorIfOpen();
        } catch {}
      });
      es.addEventListener('batch24h', (ev) => {
        try {
          triageState.batch24h.snapshot = JSON.parse(ev.data);
          renderBatch24hView();
          refreshInspectorIfOpen();
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
    $('#tab-triage-24h')?.addEventListener('click', () => B.switchView('triage-24h'));
    $('#tab-live-feed')?.addEventListener('click', () => B.switchView('live-feed'));
    $('#tab-triage-history')?.addEventListener('click', () => B.switchView('triage-history'));
    $('#tab-triage-exclusions')?.addEventListener('click', () => B.switchView('triage-exclusions'));

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
    $('#trg-poll-range')?.addEventListener('change', (e) => {
      const customBar = $('#trg-custom-range-bar');
      const isCustom = e.target.value === 'custom';
      if (customBar) customBar.hidden = !isCustom;
      if (isCustom) {
        const now = new Date();
        const oneHourAgo = new Date(now.getTime() - 3600 * 1000);
        if ($('#trg-poll-from') && !$('#trg-poll-from').value) $('#trg-poll-from').value = toLocalDatetimeValue(oneHourAgo);
        if ($('#trg-poll-to') && !$('#trg-poll-to').value) $('#trg-poll-to').value = toLocalDatetimeValue(now);
      }
    });

    $('#btn-triage-poll-now')?.addEventListener('click', async () => {
      const btn = $('#btn-triage-poll-now');
      const progBox = $('#trg-poll-progress');
      const progMsg = $('#trg-poll-progress-msg');
      const range = $('#trg-poll-range')?.value || '1h';
      const pollBody = { action: 'poll_now', range };
      const sizeVal = Number($('#trg-poll-size')?.value || 200);
      if (Number.isFinite(sizeVal) && sizeVal > 0) pollBody.size = Math.min(1000, Math.max(1, sizeVal));

      if (range === 'custom') {
        const rawFrom = $('#trg-poll-from')?.value || '';
        const rawTo = $('#trg-poll-to')?.value || '';
        if (!rawFrom && !rawTo) {
          B.toast({ type: 'error', title: 'Rentang waktu kosong', body: 'Isi minimal waktu Dari atau Sampai untuk menarik alert.' });
          return;
        }
        if (rawFrom) pollBody.from = new Date(rawFrom).toISOString();
        if (rawTo) pollBody.to = new Date(rawTo).toISOString();
      }

      if (btn) btn.disabled = true;
      if (progBox) progBox.hidden = false;
      if (progMsg) progMsg.textContent = `Menarik & menganalisis alert (${range})…`;
      try {
        const res = await B.apiFetch('/api/triage/worker', {
          method: 'POST',
          body: JSON.stringify(pollBody),
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
        if (progBox) progBox.hidden = true;
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

    wireDoubleConfirm($('#btn-triage-dismiss-fp'), 'Klik lagi untuk Hapus FP', async () => {
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
        triageState.selectedSubAlertsByGroup.clear();
        renderTriageView();
        B.toast({ type: 'info', title: 'Antrean dibersihkan & watermark direset' });
      } catch (err) {
        B.toast({ type: 'error', title: 'Gagal mereset antrean', body: err.message });
      }
    });

    const purgeTriageStateUi = async () => {
      try {
        const res = await B.apiFetch('/api/triage/purge', {
          method: 'POST',
          body: JSON.stringify({ clearState: true, includeHistory: false }),
        });
        triageState.snapshot = res.snapshot;
        triageState.selectedGroupIds.clear();
        triageState.expandedGroupIds.clear();
        triageState.selectedSubAlertsByGroup.clear();
        renderTriageView();
        B.toast({
          type: 'success',
          title: 'Database Triage dikosongkan',
          body: `${res.clearedGroups || 0} grup & ${res.clearedProcessed || 0} riwayat dedup alert dihapus. Konfigurasi Wazuh/Ollama tetap aman.`,
        });
      } catch (err) {
        B.toast({ type: 'error', title: 'Gagal menghapus database triage', body: err.message });
      }
    };

    const purgeTriageAuditUi = async () => {
      try {
        const res = await B.apiFetch('/api/triage/purge', {
          method: 'POST',
          body: JSON.stringify({ clearState: false, includeHistory: true }),
        });
        if (res.snapshot) {
          triageState.snapshot = res.snapshot;
          updateSidebarBadges(res.snapshot);
        }
        await fetchTriageHistory(true);
        B.toast({
          type: 'info',
          title: 'Audit Triage dikosongkan',
          body: `${res.clearedHistory || 0} entri audit dihapus.`,
        });
      } catch (err) {
        B.toast({ type: 'error', title: 'Gagal menghapus Audit Triage', body: err.message });
      }
    };

    wireDoubleConfirm($('#btn-triage-purge'), 'Klik lagi untuk Hapus DB Triage', purgeTriageStateUi);
    wireDoubleConfirm($('#btn-set-purge-triage'), 'Klik lagi untuk Kosongkan DB Triage', purgeTriageStateUi);
    wireDoubleConfirm($('#btn-triage-purge-history'), 'Klik lagi untuk Hapus Audit', purgeTriageAuditUi);
    wireDoubleConfirm($('#btn-set-purge-audit'), 'Klik lagi untuk Kosongkan Audit', purgeTriageAuditUi);

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

    // Tarik 24 Jam Terakhir Controls
    $('#b24-range')?.addEventListener('change', (e) => {
      const customBar = $('#b24-custom-range-bar');
      const isCustom = e.target.value === 'custom';
      if (customBar) customBar.hidden = !isCustom;
      if (isCustom) {
        const now = new Date();
        const dayAgo = new Date(now.getTime() - 24 * 3600 * 1000);
        if ($('#b24-from') && !$('#b24-from').value) $('#b24-from').value = toLocalDatetimeValue(dayAgo);
        if ($('#b24-to') && !$('#b24-to').value) $('#b24-to').value = toLocalDatetimeValue(now);
      }
    });

    $('#btn-b24-run')?.addEventListener('click', async () => {
      const range = $('#b24-range')?.value || '24h';
      const sizeVal = Number($('#b24-size')?.value || 500);
      const tenantFilter = ($('#b24-target-tenant')?.value || '').trim();
      const body = { range, size: Math.min(1000, Math.max(10, Number.isFinite(sizeVal) ? sizeVal : 500)), tenantFilter };

      if (range === 'custom') {
        const rawFrom = $('#b24-from')?.value || '';
        const rawTo = $('#b24-to')?.value || '';
        if (!rawFrom && !rawTo) {
          B.toast({ type: 'error', title: 'Rentang waktu kosong', body: 'Isi minimal waktu Dari atau Sampai.' });
          return;
        }
        if (rawFrom) body.from = new Date(rawFrom).toISOString();
        if (rawTo) body.to = new Date(rawTo).toISOString();
      }

      try {
        const res = await B.apiFetch('/api/triage/batch24h/run', {
          method: 'POST',
          body: JSON.stringify(body),
        });
        if (res.snapshot) {
          triageState.batch24h.snapshot = res.snapshot;
          renderBatch24hView();
        }
      } catch (err) {
        B.toast({ type: 'error', title: 'Gagal memulai penarikan 24 jam', body: err.message });
      }
    });

    $('#btn-b24-cancel')?.addEventListener('click', async () => {
      try {
        const res = await B.apiFetch('/api/triage/batch24h/cancel', { method: 'POST', body: '{}' });
        if (res.snapshot) triageState.batch24h.snapshot = res.snapshot;
        renderBatch24hView();
        B.toast({ type: 'info', title: 'Penarikan 24 jam dibatalkan' });
      } catch (err) {
        B.toast({ type: 'error', title: 'Gagal membatalkan', body: err.message });
      }
    });

    wireDoubleConfirm($('#btn-b24-dismiss-fp'), 'Klik lagi untuk Hapus FP', async () => {
      try {
        const res = await B.apiFetch('/api/triage/batch24h/dismiss', {
          method: 'POST',
          body: JSON.stringify({ verdict: 'FALSE_POSITIVE' }),
        });
        triageState.batch24h.snapshot = res.snapshot;
        renderBatch24hView();
        B.toast({ type: 'info', title: `${res.dismissedGroups} grup False Positive dihapus` });
      } catch (err) {
        B.toast({ type: 'error', title: 'Gagal menghapus False Positive', body: err.message });
      }
    });

    wireDoubleConfirm($('#btn-b24-clear'), 'Klik lagi untuk Kosongkan 24 Jam', async () => {
      try {
        const res = await B.apiFetch('/api/triage/batch24h/clear', { method: 'POST', body: '{}' });
        triageState.batch24h.snapshot = res.snapshot;
        triageState.batch24h.selectedGroupIds.clear();
        triageState.batch24h.expandedGroupIds.clear();
        triageState.batch24h.selectedSubAlertsByGroup.clear();
        renderBatch24hView();
        B.toast({ type: 'info', title: 'Hasil Tarik 24 Jam dikosongkan' });
      } catch (err) {
        B.toast({ type: 'error', title: 'Gagal mengosongkan Tarik 24 Jam', body: err.message });
      }
    });

    document.querySelectorAll('.b24-verdict-btn[data-verdict]').forEach((btn) => {
      btn.addEventListener('click', () => {
        triageState.batch24h.verdictFilter = btn.dataset.verdict || 'TRUE_POSITIVE';
        renderBatch24hView();
      });
    });
    $('#b24-filter-tenant')?.addEventListener('change', (e) => {
      triageState.batch24h.tenantFilter = e.target.value;
      renderBatch24hView();
    });
    $('#b24-search')?.addEventListener('input', (e) => {
      triageState.batch24h.search = e.target.value;
      renderBatch24hView();
    });
    $('#btn-b24-merge')?.addEventListener('click', async () => {
      try {
        const res = await B.apiFetch('/api/triage/batch24h/merge', {
          method: 'POST',
          body: JSON.stringify({ groupIds: [...triageState.batch24h.selectedGroupIds] }),
        });
        triageState.batch24h.selectedGroupIds.clear();
        triageState.batch24h.snapshot = res.snapshot;
        renderBatch24hView();
        B.toast({ type: 'success', title: 'Grup 24 jam berhasil digabungkan dalam 1 tenant' });
      } catch (err) {
        B.toast({ type: 'error', title: 'Gagal menggabungkan grup', body: err.message });
      }
    });

    // Live Feed Controls
    if ($('#live-auto-refresh')) {
      $('#live-auto-refresh').checked = Boolean(triageState.liveAutoRefresh);
    }
    $('#btn-live-fields')?.addEventListener('click', () => {
      triageState.liveFieldsOpen = !triageState.liveFieldsOpen;
      renderLiveFeed();
    });
    $('#btn-live-refresh')?.addEventListener('click', () => fetchLiveFeed(false));
    $('#btn-live-apply-custom')?.addEventListener('click', () => fetchLiveFeed(false));
    $('#btn-live-clear')?.addEventListener('click', () => {
      stopLiveRefresh();
      triageState.liveFetchSeq++;
      triageState.liveAutoRefresh = false;
      if ($('#live-auto-refresh')) $('#live-auto-refresh').checked = false;
      try { localStorage.setItem(LIVE_AUTO_REFRESH_KEY, '0'); } catch {}
      triageState.liveData = null;
      triageState.liveExpandedIds.clear();
      renderLiveFeed();
      B.toast({ type: 'info', title: 'Tampilan Live Wazuh dikosongkan' });
    });
    $('#live-scope-select')?.addEventListener('change', (e) => {
      const val = e.target.value;
      const customBar = $('#live-custom-range-bar');
      const isCustom = val === 'custom';
      if (customBar) customBar.hidden = !isCustom;
      if (isCustom) {
        const now = new Date();
        const oneHourAgo = new Date(now.getTime() - 3600 * 1000);
        if ($('#live-from') && !$('#live-from').value) $('#live-from').value = toLocalDatetimeValue(oneHourAgo);
        if ($('#live-to') && !$('#live-to').value) $('#live-to').value = toLocalDatetimeValue(now);
        return;
      }
      if (triageState.liveData !== null || $('#live-auto-refresh')?.checked) {
        fetchLiveFeed(false);
      }
    });
    $('#live-filter-tenant')?.addEventListener('change', () => renderLiveFeed());
    $('#live-filter-status')?.addEventListener('change', () => renderLiveFeed());
    $('#live-search')?.addEventListener('input', () => renderLiveFeed());
    $('#live-auto-refresh')?.addEventListener('change', (e) => {
      const enabled = Boolean(e.target.checked);
      triageState.liveAutoRefresh = enabled;
      try { localStorage.setItem(LIVE_AUTO_REFRESH_KEY, enabled ? '1' : '0'); } catch {}
      if (!enabled) {
        stopLiveRefresh();
        triageState.liveFetchSeq++;
      } else {
        fetchLiveFeed(true);
        startLiveRefreshIfActive();
      }
    });

    // Daftar Exclusion Rules Controls
    $('#btn-ex-new-toggle')?.addEventListener('click', () => {
      const form = $('#ex-add-form');
      if (form) form.hidden = !form.hidden;
    });
    $('#btn-ex-cancel-new')?.addEventListener('click', () => {
      if ($('#ex-add-form')) $('#ex-add-form').hidden = true;
    });
    $('#btn-ex-refresh')?.addEventListener('click', () => fetchExclusionRules(false));
    $('#ex-search')?.addEventListener('input', (e) => {
      triageState.exSearch = e.target.value;
      renderExclusionsPage();
    });
    $('#ex-filter-mode')?.addEventListener('change', (e) => {
      triageState.exFilterMode = e.target.value;
      renderExclusionsPage();
    });
    $('#btn-ex-save-new')?.addEventListener('click', async () => {
      const pattern = ($('#ex-new-pattern')?.value || '').trim();
      if (!pattern) {
        B.toast({ type: 'error', title: 'Pola wajib diisi' });
        return;
      }
      try {
        const res = await B.apiFetch('/api/triage/exclusions', {
          method: 'POST',
          body: JSON.stringify({
            target: $('#ex-new-target')?.value || 'path',
            mode: $('#ex-new-mode')?.value || 'contains',
            pattern,
            note: ($('#ex-new-note')?.value || '').trim(),
          }),
        });
        if ($('#ex-new-pattern')) $('#ex-new-pattern').value = '';
        if ($('#ex-new-note')) $('#ex-new-note').value = '';
        if ($('#ex-add-form')) $('#ex-add-form').hidden = true;
        if (res.rules) {
          triageState.exclusions = res.rules;
          if (triageState.config) triageState.config.exclusionRules = res.rules;
          renderExclusionRows(res.rules);
        }
        renderExclusionsPage();
        B.toast({
          type: res.alreadyExisted ? 'info' : 'success',
          title: res.alreadyExisted ? 'Rule Exclude sudah ada (diaktifkan)' : 'Rule Exclude baru disimpan',
        });
      } catch (err) {
        B.toast({ type: 'error', title: 'Gagal menyimpan rule exclude', body: err.message });
      }
    });

    // Inspector Alert (Wazuh Discover View) Controls
    $('#btn-insp-back')?.addEventListener('click', () => B.switchView(triageState.inspector.returnView || 'triage'));
    $('#btn-insp-fields')?.addEventListener('click', () => {
      triageState.inspector.fieldsOpen = !triageState.inspector.fieldsOpen;
      renderInspectorView();
    });
    $('#insp-search')?.addEventListener('input', (e) => {
      triageState.inspector.search = e.target.value;
      renderInspectorView();
    });
    $('#insp-select-all')?.addEventListener('change', (e) => {
      const insp = triageState.inspector;
      const q = (insp.search || '').trim().toLowerCase();
      const visible = insp.alerts.filter((row) => !q || [row.alert_id, row.rule_id, row.rule_description, row.agent_name, row.src_ip, row.path, row.full_log].join(' ').toLowerCase().includes(q));
      if (e.target.checked) visible.forEach((r) => insp.selectedIds.add(r.alert_id));
      else visible.forEach((r) => insp.selectedIds.delete(r.alert_id));
      renderInspectorView();
    });

    const runInspectorGroupAction = async (endpoint, body, okTitle, isIgnore = false) => {
      const insp = triageState.inspector;
      const isBatch24h = insp.source === 'batch24h';
      const prefix = isBatch24h ? '/api/triage/batch24h' : '/api/triage';
      try {
        const res = await B.apiFetch(prefix + endpoint, { method: 'POST', body: JSON.stringify(body) });
        syncSnapshotAndExclusions(res, isBatch24h);
        if (isIgnore) showIgnoreExcludeToast(res, okTitle);
        else B.toast({ type: 'info', title: okTitle });
        refreshInspectorIfOpen();
      } catch (err) {
        B.toast({ type: 'error', title: 'Gagal memproses aksi inspector', body: err.message });
      }
    };

    $('#btn-insp-group-promote')?.addEventListener('click', () => {
      const insp = triageState.inspector;
      const isBatch24h = insp.source === 'batch24h';
      promoteFromTriage({
        groupId: insp.groupId,
        workspace: B.getActiveWorkspace(),
        resetWatermark: !isBatch24h,
        isBatch24h,
      });
    });
    $('#btn-insp-group-ignore')?.addEventListener('click', () => {
      const insp = triageState.inspector;
      openExcludePreviewModal({
        source: insp.source,
        isBatch24h: insp.source === 'batch24h',
        groupIds: [insp.groupId],
        title: insp.title,
        subtitle: `Pratinjau rule exclude untuk seluruh grup "${insp.title}" (${insp.alerts.length} alert).`,
        toastTitle: 'Grup diabaikan',
      });
    });
    wireDoubleConfirm($('#btn-insp-group-dismiss'), 'Klik lagi untuk Hapus Grup', () => {
      runInspectorGroupAction('/dismiss', { groupIds: [triageState.inspector.groupId] }, 'Grup dihapus dari antrean', false);
    });
    $('#btn-insp-split')?.addEventListener('click', () => {
      const insp = triageState.inspector;
      const ids = [...insp.selectedIds];
      if (!ids.length) return;
      runInspectorGroupAction('/split', { groupId: insp.groupId, alertIds: ids }, `${ids.length} alert dipisahkan ke grup baru`, false);
    });
    $('#btn-insp-ignore-sel')?.addEventListener('click', () => {
      const insp = triageState.inspector;
      const ids = [...insp.selectedIds];
      if (!ids.length) return;
      openExcludePreviewModal({
        source: insp.source,
        isBatch24h: insp.source === 'batch24h',
        groupId: insp.groupId,
        alertIds: ids,
        title: insp.title,
        subtitle: `Pratinjau rule exclude untuk ${ids.length} alert terpilih.`,
        toastTitle: `${ids.length} alert diabaikan`,
      });
    });
    wireDoubleConfirm($('#btn-insp-remove-sel'), 'Klik lagi untuk Hapus Terpilih', () => {
      const insp = triageState.inspector;
      const ids = [...insp.selectedIds];
      if (!ids.length) return;
      runInspectorGroupAction('/remove-alerts', { groupId: insp.groupId, alertIds: ids }, `${ids.length} alert dihapus`, false);
    });
    $('#btn-insp-promote-sel')?.addEventListener('click', () => {
      const insp = triageState.inspector;
      const isBatch24h = insp.source === 'batch24h';
      const ids = [...insp.selectedIds];
      if (!ids.length) return;
      promoteFromTriage({
        groupId: insp.groupId,
        alertIds: ids,
        workspace: B.getActiveWorkspace(),
        resetWatermark: !isBatch24h,
        isBatch24h,
      });
    });

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

    // Exclude Preview Modal Controls (AI Analisis Exclude + Manual Edit)
    $('#btn-close-ex-modal')?.addEventListener('click', closeExcludePreviewModal);
    $('#btn-ex-modal-cancel')?.addEventListener('click', closeExcludePreviewModal);
    $('#exclude-preview-modal')?.addEventListener('click', (e) => {
      if (e.target === $('#exclude-preview-modal')) closeExcludePreviewModal();
    });
    $('#btn-ex-modal-add')?.addEventListener('click', () => {
      const existing = [];
      $('#ex-modal-tbody')?.querySelectorAll('tr').forEach((tr) => {
        existing.push({
          enabled: Boolean($('.exm-enabled', tr)?.checked),
          target: $('.exm-target', tr)?.value || 'path',
          mode: $('.exm-mode', tr)?.value || 'wildcard',
          pattern: $('.exm-pattern', tr)?.value || '',
          note: $('.exm-note', tr)?.value || '',
          source: tr.dataset.source || 'manual',
        });
      });
      existing.push({ enabled: true, target: 'path', mode: 'wildcard', pattern: '', note: 'Aturan manual analis', source: 'manual' });
      renderExcludePreviewRows(existing);
    });
    $('#btn-ex-modal-ai')?.addEventListener('click', async () => {
      const ctx = triageState.excludePreviewCtx;
      if (!ctx) return;
      const btn = $('#btn-ex-modal-ai');
      const msgEl = $('#ex-modal-ai-msg');
      const prevText = btn?.textContent || 'AI Analisis Exclude';
      if (btn) {
        btn.disabled = true;
        btn.textContent = 'Menganalisis AI…';
      }
      showInlineStatus(msgEl, true, 'Mengirim sampel alert ke AI Ollama untuk merumuskan rule exclude presisi…');
      try {
        const res = await B.apiFetch('/api/triage/exclusions/ai-suggest', {
          method: 'POST',
          body: JSON.stringify({
            source: ctx.source,
            groupId: ctx.groupId,
            groupIds: ctx.groupIds,
            alertIds: ctx.alertIds,
            rawAlerts: ctx.rawAlerts,
            title: ctx.title,
          }),
        });
        renderExcludePreviewRows((res.rules || []).map((r) => ({ ...r, enabled: true, source: 'ai_suggest' })));
        showInlineStatus(msgEl, true, res.reasoning || 'Saran AI berhasil dimuat. Anda dapat mengedit pola sebelum menyimpan.');
      } catch (err) {
        showInlineStatus(msgEl, false, err.message);
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = prevText;
        }
      }
    });
    $('#btn-ex-modal-confirm')?.addEventListener('click', async () => {
      const ctx = triageState.excludePreviewCtx;
      if (!ctx) return;
      const rules = collectExcludePreviewRows();
      if (!rules.length) {
        B.toast({ type: 'error', title: 'Pilih atau isi minimal 1 pola rule exclude' });
        return;
      }
      const btn = $('#btn-ex-modal-confirm');
      if (btn) btn.disabled = true;
      try {
        if (ctx.source === 'live') {
          let lastRes = null;
          for (const r of rules) {
            lastRes = await B.apiFetch('/api/triage/exclusions', {
              method: 'POST',
              body: JSON.stringify(r),
            });
          }
          if (Array.isArray(lastRes?.rules)) {
            triageState.exclusions = lastRes.rules;
            if (triageState.config) triageState.config.exclusionRules = lastRes.rules;
            renderExclusionRows(lastRes.rules);
            renderExclusionsPage();
          }
          closeExcludePreviewModal();
          B.toast({ type: 'success', title: `${rules.length} Rule Exclude disimpan` });
          fetchLiveFeed(true);
        } else {
          const apiPrefix = ctx.isBatch24h ? '/api/triage/batch24h' : '/api/triage';
          const res = await B.apiFetch(`${apiPrefix}/ignore-exclude`, {
            method: 'POST',
            body: JSON.stringify({
              groupId: ctx.groupId,
              groupIds: ctx.groupIds,
              alertIds: ctx.alertIds,
              rules,
            }),
          });
          syncSnapshotAndExclusions(res, ctx.isBatch24h);
          closeExcludePreviewModal();
          refreshInspectorIfOpen();
          showIgnoreExcludeToast(res, ctx.toastTitle || 'Diabaikan');
        }
      } catch (err) {
        B.toast({ type: 'error', title: 'Gagal menyimpan rule exclude', body: err.message });
      } finally {
        if (btn) btn.disabled = false;
      }
    });
  }

  B.onViewChange((view) => {
    stopLiveRefresh();
    if (view === 'triage') {
      fetchTriageQueue(false);
    } else if (view === 'triage-24h') {
      fetchBatch24h(false);
    } else if (view === 'live-feed') {
      renderLiveFeed();
      if ($('#live-auto-refresh')?.checked) {
        fetchLiveFeed(false);
        startLiveRefreshIfActive();
      }
    } else if (view === 'triage-history') {
      fetchTriageHistory(false);
    } else if (view === 'triage-exclusions') {
      fetchExclusionRules(false);
    } else if (view === 'triage-inspector') {
      renderInspectorView();
    } else if (view === 'settings' && triageState.settingsTab === 'triage') {
      loadTriageConfig();
    }
  });

  B.onAuthReady(() => {
    loadTriageConfig();
    fetchTriageQueue(true);
    fetchBatch24h(true);
    fetchTriageHistory(true);
    connectSse();
  });

  B.onLogout(() => {
    stopLiveRefresh();
    stopBatch24hProgressTimer();
    closeSse();
    closeRawJsonModal();
  });

  bindEvents();
})();
