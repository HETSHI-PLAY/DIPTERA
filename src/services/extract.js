/* IrisExtract — parser halaman hasil (Form Ending) dari n8n untuk Diptera ASOC. */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module && module.exports) module.exports = api;
  if (root) root.IrisExtract = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const HEAD_MARKER = 'Informasi Case IRIS';
  const MD_MARKER = 'Laporan Markdown';

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

  function stripTags(html) {
    return decodeEntities(
      String(html ?? '')
        .replace(/<script\b[\s\S]*?<\/script>/gi, ' ')
        .replace(/<style\b[\s\S]*?<\/style>/gi, ' ')
        .replace(/<[^>]+>/g, ' ')
        .replace(/\s+/g, ' '),
    ).trim();
  }

  function preCodeBlocks(html) {
    const blocks = [];
    const re = /<pre\b[^>]*>\s*<code\b[^>]*>([\s\S]*?)<\/code>\s*<\/pre>/gi;
    let m;
    while ((m = re.exec(html)) !== null) {
      blocks.push(decodeEntities(m[1]));
    }
    return blocks;
  }

  function extractSeverity(html) {
    const m = html.match(/Severity\s*:?\s*(?:<\/strong>|<\/b>)?\s*:?\s*([A-Za-z]+)/i);
    return m ? m[1].toUpperCase() : null;
  }

  function extractCaseId(html) {
    const m = html.match(/IRIS\s+Case\s+ID\s*:?\s*(?:<\/strong>|<\/b>)?\s*:?\s*#?([0-9A-Za-z_-]+)/i);
    return m ? m[1].trim() : null;
  }

  function looksLikeError(text) {
    const t = String(text ?? '');
    return /finished with error|has finished with error|Problem in node|Workflow execution failed|Execution failed|ConflictError|ECONNREFUSED|could not be found|not registered|Internal Server Error|invalid token|Unauthorized/i.test(t);
  }

  function sliceEnd(html, lower, fromIdx) {
    const scriptIdx = lower.indexOf('<script', fromIdx);
    const bodyIdx = lower.indexOf('</body>', fromIdx);
    const candidates = [scriptIdx, bodyIdx].filter((i) => i !== -1);
    if (!candidates.length) return html.length;
    return Math.min.apply(null, candidates);
  }

  function parse(html) {
    const result = {
      found: false,
      fragmentHtml: '',
      caseName: null,
      caseId: null,
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

    let markerIdx = lower.indexOf(HEAD_MARKER.toLowerCase());
    if (markerIdx === -1) markerIdx = lower.indexOf(MD_MARKER.toLowerCase());

    const escapedIdx = lower.indexOf('&lt;h2&gt;' + HEAD_MARKER.toLowerCase());
    const useEscaped = escapedIdx !== -1 && (markerIdx === -1 || escapedIdx <= markerIdx);

    if (markerIdx !== -1 && !useEscaped) {
      const h2Idx = lower.lastIndexOf('<h2', markerIdx);
      start = h2Idx !== -1 && markerIdx - h2Idx < 200 ? h2Idx : markerIdx;
      end = sliceEnd(html, lower, start);
      fragment = html.slice(start, end);
      if (!/<[a-z!/]/i.test(fragment)) fragment = decodeEntities('<h2>' + fragment);
    } else if (useEscaped) {
      const ESCAPED_END = '&lt;/code&gt;&lt;/pre&gt;';
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
    result.caseId = extractCaseId(fragment);
    result.severity = extractSeverity(fragment);

    const statusMatch = fragment.match(/Siap disalin ke IRIS[^<]*/i);
    if (statusMatch) result.statusLine = statusMatch[0].trim();

    return result;
  }

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
