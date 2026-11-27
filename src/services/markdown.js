/* Zero-dependency XSS-safe Markdown renderer for IRIS-style report summaries.
 * Shared across Node tests (require) and browser UI (window.AlphaMarkdown).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.AlphaMarkdown = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  function escapeHtml(str) {
    return String(str ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function isSafeUrl(url) {
    const s = String(url || '').trim();
    if (!s) return false;
    if (s.startsWith('/') || s.startsWith('#')) return !s.startsWith('//');
    return /^(?:https?:|mailto:)/i.test(s);
  }

  function renderInline(raw) {
    const src = String(raw ?? '');
    const codeSpans = [];
    let withTokens = '';
    let i = 0;

    // 1. Extract inline `code` spans first so markdown syntax inside backticks stays literal
    while (i < src.length) {
      if (src[i] === '`') {
        let ticks = 0;
        while (i + ticks < src.length && src[i + ticks] === '`') ticks++;
        const closeIdx = src.indexOf('`'.repeat(ticks), i + ticks);
        if (closeIdx !== -1) {
          const codeBody = src.slice(i + ticks, closeIdx);
          const idx = codeSpans.length;
          codeSpans.push(`<code>${escapeHtml(codeBody)}</code>`);
          withTokens += `\u0000CODE${idx}\u0000`;
          i = closeIdx + ticks;
          continue;
        }
      }
      withTokens += src[i];
      i++;
    }

    // 2. Escape all HTML before applying inline Markdown replacements
    let out = escapeHtml(withTokens);

    // 3. Re-allow safe <br> inside Markdown text/tables
    out = out.replace(/&lt;br\s*\/?&gt;/gi, '<br />');

    // 4. Safe Markdown links [label](url)
    out = out.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, label, rawUrl) => {
      const decodedUrl = rawUrl
        .replace(/&amp;/g, '&')
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'");
      if (!isSafeUrl(decodedUrl)) return label;
      return `<a href="${escapeHtml(decodedUrl)}" target="_blank" rel="noopener noreferrer">${label}</a>`;
    });

    // 5. Bold + Italic / Bold / Strikethrough / Italic (snake_case-safe underscores)
    out = out.replace(/\*\*\*([^\n*]+?)\*\*\*/g, '<strong><em>$1</em></strong>');
    out = out.replace(/\*\*([^\n]+?)\*\*/g, '<strong>$1</strong>');
    out = out.replace(/__([^\n_]+?)__/g, '<strong>$1</strong>');
    out = out.replace(/~~([^\n~]+?)~~/g, '<del>$1</del>');
    out = out.replace(/\*([^*\n]+?)\*/g, '<em>$1</em>');
    out = out.replace(/(^|[\s(>])_([^_\n]+?)_(?=$|[\s.,;:!?<)])/g, '$1<em>$2</em>');

    // 6. Restore inline code spans
    out = out.replace(/\u0000CODE(\d+)\u0000/g, (_, idx) => codeSpans[Number(idx)] || '');
    return out;
  }

  function splitTableRow(line) {
    let s = String(line || '').trim();
    if (s.startsWith('|')) s = s.slice(1);
    if (s.endsWith('|')) s = s.slice(0, -1);
    const cells = [];
    let cur = '';
    for (let i = 0; i < s.length; i++) {
      if (s[i] === '\\' && s[i + 1] === '|') {
        cur += '|';
        i++;
      } else if (s[i] === '|') {
        cells.push(cur.trim());
        cur = '';
      } else {
        cur += s[i];
      }
    }
    cells.push(cur.trim());
    return cells;
  }

  function parseTableSeparator(line) {
    const trimmed = String(line || '').trim();
    if (!trimmed.includes('-') || !trimmed.includes('|')) return null;
    if (!/^\|?\s*:?-{2,}:?\s*(?:\|\s*:?-{2,}:?\s*)*\|?$/.test(trimmed)) return null;
    const rawCols = splitTableRow(trimmed);
    if (!rawCols.length) return null;
    const aligns = [];
    for (const c of rawCols) {
      if (!/^:?-{2,}:?$/.test(c)) return null;
      if (c.startsWith(':') && c.endsWith(':')) aligns.push('center');
      else if (c.endsWith(':')) aligns.push('right');
      else aligns.push('left');
    }
    return aligns;
  }

  function matchHeading(line) {
    const m = String(line || '').match(/^(#{1,6})(\s*)([^\s#].*)$/);
    if (!m) return null;
    // Do not treat bare ticket IDs like #2712 or #123 as Markdown H1
    if (!m[2] && /^\d/.test(m[3])) return null;
    return { level: m[1].length, text: m[3].trim() };
  }

  function isHrLine(line) {
    return /^(?:-{3,}|\*{3,}|_{3,})\s*$/.test(String(line || '').trim());
  }

  function matchListLine(line) {
    const m = String(line || '').match(/^(\s*)(?:([-*+])|(\d+)\.)\s+(.*)$/);
    if (!m) return null;
    return {
      indent: m[1].replace(/\t/g, '  ').length,
      ordered: Boolean(m[3]),
      text: m[4],
    };
  }

  function renderListBlock(lines, startIdx) {
    const first = matchListLine(lines[startIdx]);
    const baseIndent = first.indent;
    const ordered = first.ordered;
    const tag = ordered ? 'ol' : 'ul';
    const items = [];
    let i = startIdx;

    while (i < lines.length) {
      const m = matchListLine(lines[i]);
      if (!m || m.indent < baseIndent || (m.indent === baseIndent && m.ordered !== ordered)) {
        break;
      }
      if (m.indent > baseIndent) {
        const sub = renderListBlock(lines, i);
        if (items.length) {
          items[items.length - 1] += sub.html;
        } else {
          items.push(sub.html);
        }
        i = sub.nextIdx;
        continue;
      }

      let bodyText = m.text;
      let prefix = '';
      const taskMatch = bodyText.match(/^\[( |x|X)\]\s+(.*)$/);
      if (taskMatch) {
        const checked = taskMatch[1].toLowerCase() === 'x';
        prefix = `<input type="checkbox" class="md-task-cb" disabled ${checked ? 'checked' : ''} /> `;
        bodyText = taskMatch[2];
      }
      items.push(prefix + renderInline(bodyText));
      i++;
    }

    const html = `<${tag}>${items.map((it) => `<li>${it}</li>`).join('')}</${tag}>`;
    return { html, nextIdx: i };
  }

  function renderBlocks(lines) {
    const out = [];
    let i = 0;

    while (i < lines.length) {
      const line = lines[i];
      if (!line.trim()) {
        i++;
        continue;
      }

      // 1. Heading
      const h = matchHeading(line);
      if (h) {
        out.push(`<h${h.level}>${renderInline(h.text)}</h${h.level}>`);
        i++;
        continue;
      }

      // 2. Horizontal Rule
      if (isHrLine(line)) {
        out.push('<hr />');
        i++;
        continue;
      }

      // 3. GFM Pipe Table (header line + separator line)
      if (line.includes('|') && i + 1 < lines.length) {
        const aligns = parseTableSeparator(lines[i + 1]);
        if (aligns) {
          const headers = splitTableRow(line);
          const colCount = Math.max(aligns.length, headers.length);
          const thCells = Array.from({ length: colCount }, (_, idx) => {
            const align = aligns[idx] ? ` style="text-align:${aligns[idx]}"` : '';
            return `<th${align}>${renderInline(headers[idx] ?? '')}</th>`;
          }).join('');
          i += 2;
          const bodyRows = [];
          while (i < lines.length && lines[i].trim() && lines[i].includes('|')) {
            if (matchHeading(lines[i]) || isHrLine(lines[i])) break;
            const cells = splitTableRow(lines[i]);
            const tds = Array.from({ length: colCount }, (_, idx) => {
              const align = aligns[idx] ? ` style="text-align:${aligns[idx]}"` : '';
              return `<td${align}>${renderInline(cells[idx] ?? '')}</td>`;
            }).join('');
            bodyRows.push(`<tr>${tds}</tr>`);
            i++;
          }
          const tbodyHtml = bodyRows.length ? `<tbody>${bodyRows.join('')}</tbody>` : '';
          out.push(`<div class="md-table-wrap"><table class="md-table"><thead><tr>${thCells}</tr></thead>${tbodyHtml}</table></div>`);
          continue;
        }
      }

      // 4. Blockquote
      if (/^\s*>\s?/.test(line)) {
        const bqLines = [];
        while (i < lines.length && /^\s*>\s?/.test(lines[i])) {
          bqLines.push(lines[i].replace(/^\s*>\s?/, ''));
          i++;
        }
        out.push(`<blockquote>${renderBlocks(bqLines)}</blockquote>`);
        continue;
      }

      // 5. Ordered / Unordered List
      if (matchListLine(line)) {
        const listRes = renderListBlock(lines, i);
        out.push(listRes.html);
        i = listRes.nextIdx;
        continue;
      }

      // 6. Paragraph (absorb consecutive non-block lines)
      const pLines = [];
      while (i < lines.length) {
        const cur = lines[i];
        if (!cur.trim()) break;
        if (matchHeading(cur) || isHrLine(cur) || /^\s*>\s?/.test(cur) || matchListLine(cur)) break;
        if (cur.includes('|') && i + 1 < lines.length && parseTableSeparator(lines[i + 1])) break;
        pLines.push(renderInline(cur));
        i++;
      }
      if (pLines.length) {
        out.push(`<p>${pLines.join('<br />\n')}</p>`);
      } else {
        i++;
      }
    }

    return out.join('\n');
  }

  function renderMarkdown(markdownText) {
    const text = String(markdownText ?? '').replace(/\r\n?/g, '\n');
    if (!text.trim()) return '';

    const rawLines = text.split('\n');
    const htmlChunks = [];
    let bufferLines = [];

    const flushBuffer = () => {
      if (!bufferLines.length) return;
      const rendered = renderBlocks(bufferLines);
      if (rendered) htmlChunks.push(rendered);
      bufferLines = [];
    };

    let i = 0;
    while (i < rawLines.length) {
      const fenceStart = rawLines[i].match(/^\s*```([a-zA-Z0-9_+-]*)\s*$/);
      if (fenceStart) {
        flushBuffer();
        const lang = fenceStart[1] ? ` class="language-${escapeHtml(fenceStart[1])}"` : '';
        i++;
        const codeLines = [];
        while (i < rawLines.length && !/^\s*```\s*$/.test(rawLines[i])) {
          codeLines.push(rawLines[i]);
          i++;
        }
        if (i < rawLines.length && /^\s*```\s*$/.test(rawLines[i])) i++;
        htmlChunks.push(`<pre class="md-code-block"><code${lang}>${escapeHtml(codeLines.join('\n'))}</code></pre>`);
        continue;
      }
      bufferLines.push(rawLines[i]);
      i++;
    }
    flushBuffer();

    return htmlChunks.join('\n');
  }

  return {
    escapeHtml,
    renderMarkdown,
  };
});
