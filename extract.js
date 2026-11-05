/* IrisExtract — helper untuk membaca halaman hasil (Form Ending) dari n8n.
 *
 * n8n 2.x: POST ke /form/<path> membalas JSON { formWaitingUrl }.
 * GET pada formWaitingUrl menghasilkan halaman HTML yang memuat
 * "responseHtml" apa adanya ({{{responseText}}}), berisi:
 *   <h2>Informasi Case IRIS</h2> ... <h2>Laporan Markdown</h2><pre><code>...markdown...</code></pre>
 *
 * Semua fungsi di sini murni berbasis string/regex supaya bisa dipakai
 * di browser maupun di Node (unit test) tanpa dependensi apa pun.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module && module.exports) module.exports = api;
  if (root) root.IrisExtract = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const HEAD_MARKER = 'Informasi Case IRIS';
  const MD_MARKER = 'Laporan Markdown';

  /** Decode entitas HTML satu pass (naruh &amp; terakhir supaya tidak dobel decode). */
  function decodeEntities(str) {
    return String(str ?? '').replace(
      /&(?:amp|lt|gt|quot|#0?39|apos|#\d+|#x[0-9a-f]+);/gi,
      (m) => {
        const k = m.toLowerCase();
        if (k === '&amp;') return '&';
        if (k === '&lt;') return '<';
        if (k === '&gt;') return '>';
        if (k === '&quot;') return '"';
        if (k === '&apos;' || k === '&#39;' || k === '&#039;') return "'";
        const num = k.startsWith('&#x') ? parseInt(k.slice(3, -1), 16) : parseInt(k.slice(2, -1), 10);
        return Number.isFinite(num) ? String.fromCodePoint(num) : m;
      },
    );
  }

  /** Buang <script>, <style>, komentar, dan event handler inline (proteksi dasar). */
  function sanitizeFragment(html) {
    let out = String(html ?? '');
    out = out.replace(/<script\b[\s\S]*?<\/script>/gi, '');
    out = out.replace(/<style\b[\s\S]*?<\/style>/gi, '');
    out = out.replace(/<!--[\s\S]*?-->/g, '');
    out = out.replace(/<\/?(?:iframe|object|embed|link|meta|base|form)\b[^>]*>/gi, '');
    out = out.replace(/\son[a-z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '');
    out = out.replace(/(href|src)\s*=\s*(?:"javascript:[^"]*"|'javascript:[^']*')/gi, '$1="#"');
    return out.trim();
  }

  /** Ambil teks polos dari HTML (untuk pesan error / debug). */
  function stripTags(html) {
    let out = String(html ?? '');
    out = out.replace(/<script\b[\s\S]*?<\/script>/gi, ' ');
    out = out.replace(/<style\b[\s\S]*?<\/style>/gi, ' ');
    out = out.replace(/<[^>]*>/g, ' ');
    out = decodeEntities(out);
    return out.replace(/\s+/g, ' ').trim();
  }

  /** Cari semua blok <pre><code>…</code></pre> di dalam sebuah fragmen. */
  function preCodeBlocks(fragment) {
    const blocks = [];
    const re = /<pre[^>]*>\s*<code[^>]*>([\s\S]*?)<\/code>\s*<\/pre>/gi;
    let m;
    while ((m = re.exec(fragment)) !== null) blocks.push(decodeEntities(m[1]).trim());
    return blocks;
  }

  function extractSeverity(fragment) {
    let m = fragment.match(/Severity:\s*<\/strong>\s*([^<\n]+)/i);
    if (!m) m = fragment.match(/Severity:\s*([A-Za-z][A-Za-z ]*)/i);
    return m ? m[1].replace(/[\s.]+$/, '').trim() : null;
  }

  /** Apakah halaman/teks ini kelihatan seperti halaman error n8n? */
  function looksLikeError(text) {
    const t = String(text ?? '');
    return /finished with error|has finished with error|Problem in node|Workflow execution failed|Execution failed|ConflictError|ECONNREFUSED|could not be found|not registered|Internal Server Error|invalid token|Unauthorized/i.test(t);
  }

  /**
   * Parse halaman hasil n8n.
   * @returns {{
   *   found: boolean, fragmentHtml: string, caseName: string|null,
   *   severity: string|null, markdown: string|null, statusLine: string|null,
   *   pageTitle: string|null, pageText: string, reason?: string
   * }}
   */
  function parse(html) {
    const result = {
      found: false,
      fragmentHtml: '',
      caseName: null,
      severity: null,
      markdown: null,
      statusLine: null,
      pageTitle: null,
      pageText: '',
    };
    if (!html || typeof html !== 'string') {
      result.reason = 'empty';
      return result;
    }

    const titleMatch = html.match(/<title>([\s\S]*?)<\/title>/i);
    if (titleMatch) result.pageTitle = decodeEntities(titleMatch[1]).trim();
    result.pageText = stripTags(html).slice(0, 4000);

    const lower = html.toLowerCase();
    let start = -1;
    let end = html.length;
    let fragment = null;

    // 1) Format normal: responseText disisipkan apa adanya (raw HTML).
    let markerIdx = lower.indexOf(HEAD_MARKER.toLowerCase());
    if (markerIdx === -1) markerIdx = lower.indexOf(MD_MARKER.toLowerCase());

    // 1b) Kalau responseText ter-escape (&lt;h2&gt;…), marker mentah ikut terbaca —
    //     deteksi lewat posisi marker ter-escape yang muncul lebih dulu.
    const escapedIdx = lower.indexOf('&lt;h2&gt;' + HEAD_MARKER.toLowerCase());
    const useEscaped = escapedIdx !== -1 && (markerIdx === -1 || escapedIdx <= markerIdx);

    if (markerIdx !== -1 && !useEscaped) {
      const h2Idx = lower.lastIndexOf('<h2', markerIdx);
      start = h2Idx !== -1 && markerIdx - h2Idx < 200 ? h2Idx : markerIdx;
      end = sliceEnd(html, lower, start);
      fragment = html.slice(start, end);
      // jaring pengaman: fragmen tanpa tag sama sekali berarti ikut ter-escape
      if (!/<[a-z!/]/i.test(fragment)) fragment = decodeEntities('<h2>' + fragment);
    } else if (useEscaped) {
      const ESCAPED_END = '&lt;/code&gt;&lt;/pre&gt;';
      // akhir wilayah ter-escape: sebelum wrapper benar-benar berakhir
      const stops = ['&lt;/body&gt;', '</body>', '<script']
        .map((needle) => lower.indexOf(needle, escapedIdx))
        .filter((i) => i !== -1);
      const bodyStop = stops.length ? Math.min.apply(null, stops) : -1;
      let escEnd = lower.lastIndexOf(ESCAPED_END, bodyStop === -1 ? lower.length : bodyStop);
      if (escEnd === -1) escEnd = lower.indexOf(ESCAPED_END, escapedIdx);
      fragment = decodeEntities(
        html.slice(escapedIdx, escEnd === -1 ? escapedIdx + 20000 : escEnd + ESCAPED_END.length),
      );
      start = escapedIdx;
    }

    if (fragment == null) {
      result.reason = 'marker-not-found';
      return result;
    }

    const blocks = preCodeBlocks(fragment);
    result.found = true;
    result.fragmentHtml = sanitizeFragment(fragment);
    result.markdown = blocks.length ? blocks[blocks.length - 1] : null;
    result.caseName = blocks.length >= 2 ? blocks[0] : null;
    result.severity = extractSeverity(fragment);

    const statusMatch = fragment.match(/Siap disalin ke IRIS[^<]*/i);
    if (statusMatch) result.statusLine = statusMatch[0].trim();

    return result;
  }

  /** Cari titik akhir fragmen: sebelum <script>/</body> berikutnya. */
  function sliceEnd(html, lower, fromIdx) {
    const scriptIdx = lower.indexOf('<script', fromIdx);
    const bodyIdx = lower.indexOf('</body>', fromIdx);
    let candidates = [scriptIdx, bodyIdx].filter((i) => i !== -1);
    if (!candidates.length) return html.length;
    return Math.min.apply(null, candidates);
  }

  /**
   * Sesuaikan host dari formWaitingUrl dengan Base URL yang dikonfigurasi.
   * Berguna kalau n8n membalas URL internal (mis. localhost:5678) padahal
   * diakses lewat reverse proxy / port lain.
   */
  function resolveResultUrl(waitingUrl, baseUrl, rewrite) {
    const raw = String(waitingUrl ?? '');
    if (!rewrite || !baseUrl) return raw;
    try {
      const u = new URL(raw);
      const b = new URL(baseUrl);
      if (b.origin !== u.origin) {
        u.protocol = b.protocol;
        u.host = b.host;
      }
      return u.toString();
    } catch {
      return raw;
    }
  }

  /** Ambil execution id dari URL /form-waiting/<id>?signature=… */
  function execIdFromWaitingUrl(waitingUrl) {
    const m = String(waitingUrl ?? '').match(/\/form-waiting\/([^/?#]+)/);
    return m ? m[1] : null;
  }

  return {
    HEAD_MARKER,
    MD_MARKER,
    parse,
    decodeEntities,
    sanitizeFragment,
    stripTags,
    looksLikeError,
    resolveResultUrl,
    execIdFromWaitingUrl,
  };
});
