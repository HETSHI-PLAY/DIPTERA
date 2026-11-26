/* IrisNumbering — bantu penomoran otomatis (nomor tiket & case ID).
 *
 * Aturan: angka **terakhir** di dalam sebuah nilai yang dimajukan 1,
 * sehingga prefiks/sufiks dan lebar nol ikut terjaga:
 *   '10010'            -> '10011'
 *   '#1001'            -> '#1002'
 *   'ASOC-2026-30073'  -> 'ASOC-2026-30074'
 *   '007'              -> '008'
 *
 * Murni string: dipakai browser maupun unit test Node.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module && module.exports) module.exports = api;
  if (root) root.IrisNumbering = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  /** Grup angka terakhir di dalam sebuah nilai (null kalau tidak ada). */
  function lastNumber(value) {
    const s = String(value ?? '');
    const re = /\d+/g;
    let m;
    let last = null;
    while ((m = re.exec(s)) !== null) last = m;
    if (!last) return null;
    return { index: last.index, text: last[0], value: Number(last[0]), width: last[0].length };
  }

  /** Nilai berikutnya (angka terakhir + 1), atau null kalau tak ada angka. */
  function nextValue(value) {
    const s = String(value ?? '').trim();
    const n = lastNumber(s);
    if (!n || !Number.isFinite(n.value)) return null;
    const next = String(n.value + 1).padStart(n.width, '0');
    return s.slice(0, n.index) + next + s.slice(n.index + n.text.length);
  }

  /**
   * Hitung ulang nomor tiket seluruh kartu antrean per tenant.
   * Memakai counter server sebagai baseline, lalu menaikkan secara berurutan
   * untuk setiap kartu reporting (idle/manual/running/done) yang bertenant sama.
   * Mengembalikan array card.id yang nilainya berubah.
   */
  function computeQueueTickets(cards, serverTicketsByTenant, opts) {
    const o = opts || {};
    const autoNumber = o.autoNumber !== false;
    const ticketKey = o.ticketKey || 'field-0';
    const tenantKey = o.tenantKey || 'field-1';
    const skipCardId = o.skipCardId || null;

    const cursorByTenant = {};
    if (serverTicketsByTenant && typeof serverTicketsByTenant === 'object') {
      for (const [k, v] of Object.entries(serverTicketsByTenant)) {
        const tenant = String(k || '').trim();
        const val = String(v ?? '').trim();
        if (tenant && val) cursorByTenant[tenant] = val;
      }
    }

    const changedIds = [];
    for (const card of Array.isArray(cards) ? cards : []) {
      if (!card || card.mode === 'repeating') continue;
      if (!card.values || typeof card.values !== 'object') card.values = {};

      const tenant = String(card.values[tenantKey] ?? '').trim();
      const curVal = String(card.values[ticketKey] ?? '').trim();
      const isIdle = card.status === 'idle';

      if (!tenant) {
        if (isIdle && card.ticketAuto && card.id !== skipCardId) {
          if (curVal !== '' || card.ticketAuto || card.ticketFor) {
            card.values[ticketKey] = '';
            card.ticketAuto = false;
            card.ticketFor = '';
            changedIds.push(card.id);
          }
        }
        continue;
      }

      const eligibleForAuto = isIdle && autoNumber && (card.ticketAuto || !curVal) && card.id !== skipCardId;
      if (eligibleForAuto) {
        const base = cursorByTenant[tenant];
        const next = base ? nextValue(base) : null;
        if (next) {
          const changed = curVal !== next || !card.ticketAuto || card.ticketFor !== tenant;
          card.values[ticketKey] = next;
          card.ticketAuto = true;
          card.ticketFor = tenant;
          cursorByTenant[tenant] = next;
          if (changed) changedIds.push(card.id);
        } else if (card.ticketAuto) {
          card.values[ticketKey] = '';
          card.ticketAuto = false;
          card.ticketFor = tenant;
          changedIds.push(card.id);
        }
      } else if (curVal && lastNumber(curVal) != null) {
        const curNum = lastNumber(curVal).value;
        const baseVal = cursorByTenant[tenant];
        const baseNum = baseVal && lastNumber(baseVal) ? lastNumber(baseVal).value : null;
        if (!baseVal || (isIdle && !card.ticketAuto) || baseNum == null || curNum >= baseNum) {
          cursorByTenant[tenant] = curVal;
        }
      }
    }
    return changedIds;
  }

  return { lastNumber, nextValue, computeQueueTickets };
});
