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

  return { lastNumber, nextValue };
});
