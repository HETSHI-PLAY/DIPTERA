'use strict';

const assert = require('node:assert/strict');
const { renderMarkdown, escapeHtml } = require('../src/services/markdown.js');

const tests = [
  {
    name: 'heading tanpa spasi (#SECURITY...) tetap jadi h1, sedangkan #2712 tetap teks',
    run() {
      const html = renderMarkdown('#SECURITY OPERATIONS CENTER - LEVEL 1 INCIDENT REPORT\n\nTiket #2712 sedang dipantau.');
      assert.match(html, /<h1>SECURITY OPERATIONS CENTER - LEVEL 1 INCIDENT REPORT<\/h1>/);
      assert.match(html, /<p>Tiket #2712 sedang dipantau\.<\/p>/);
    },
  },
  {
    name: 'header tebal, garis hr, dan GFM pipe table seperti IRIS Summary ter-render rapih',
    run() {
      const sample = [
        '#SECURITY OPERATIONS CENTER - LEVEL 1 INCIDENT REPORT',
        '**INFOGUARD ACAD CSIRT | RESTRICTED**',
        '---',
        '| Nomor Tiket | ASOC-2026-10202 | Severity | CRITICAL |',
        '| :--- | :---: | :--- | ---: |',
        '| **Tanggal & Waktu** | 27/11/2026 08:05:13 WIB | **Status** | Closed |',
      ].join('\n');
      const html = renderMarkdown(sample);
      assert.match(html, /<h1>SECURITY OPERATIONS CENTER - LEVEL 1 INCIDENT REPORT<\/h1>/);
      assert.match(html, /<p><strong>INFOGUARD ACAD CSIRT \| RESTRICTED<\/strong><\/p>/);
      assert.match(html, /<hr \/>/);
      assert.match(html, /<div class="md-table-wrap"><table class="md-table"><thead><tr>/);
      assert.match(html, /<th style="text-align:center">ASOC-2026-10202<\/th>/);
      assert.match(html, /<td style="text-align:left"><strong>Tanggal &amp; Waktu<\/strong><\/td>/);
      assert.match(html, /<td style="text-align:right">Closed<\/td>/);
    },
  },
  {
    name: 'unordered, ordered, task list, dan nested list didukung',
    run() {
      const md = [
        '- Item pertama',
        '  - Sub-item',
        '- [x] Selesai verifikasi',
        '1. Langkah satu',
        '2. Langkah dua',
      ].join('\n');
      const html = renderMarkdown(md);
      assert.match(html, /<ul><li>Item pertama<ul><li>Sub-item<\/li><\/ul><\/li>/);
      assert.match(html, /<input type="checkbox" class="md-task-cb" disabled checked \/> Selesai verifikasi/);
      assert.match(html, /<ol><li>Langkah satu<\/li><li>Langkah dua<\/li><\/ol>/);
    },
  },
  {
    name: 'fenced code block dan inline code melindungi sintaks dan snake_case aman',
    run() {
      const md = [
        'Cek kolom `agent_name_id` dan `**bukan bold**` dengan variable python_requests_v2.',
        '',
        '```json',
        '{"rule": "**keep**", "<tag>": 1}',
        '```',
      ].join('\n');
      const html = renderMarkdown(md);
      assert.match(html, /<code>agent_name_id<\/code>/);
      assert.match(html, /<code>\*\*bukan bold\*\*<\/code>/);
      assert.match(html, /python_requests_v2/);
      assert.doesNotMatch(html, /<em>requests<\/em>/);
      assert.match(html, /<pre class="md-code-block"><code class="language-json">\{&quot;rule&quot;: &quot;\*\*keep\*\*&quot;, &quot;&lt;tag&gt;&quot;: 1\}<\/code><\/pre>/);
    },
  },
  {
    name: 'proteksi XSS: tag script/img di-escape dan skema javascript: diblokir',
    run() {
      const md = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '[Klik bahaya](javascript:alert(1))',
        '[Link aman](https://iris.example.org/case?id=12&tab=summary)',
      ].join('\n');
      const html = renderMarkdown(md);
      assert.doesNotMatch(html, /<script>/i);
      assert.doesNotMatch(html, /<img\b/i);
      assert.doesNotMatch(html, /javascript:/i);
      assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
      assert.match(html, /<a href="https:\/\/iris\.example\.org\/case\?id=12&amp;tab=summary" target="_blank" rel="noopener noreferrer">Link aman<\/a>/);
      assert.equal(escapeHtml('a&<b>'), 'a&amp;&lt;b&gt;');
    },
  },
];

let failed = 0;
for (const t of tests) {
  try {
    t.run();
    console.log(`  ✓ ${t.name}`);
  } catch (err) {
    failed++;
    console.error(`  ✗ ${t.name}`);
    console.error(err);
  }
}

console.log(`\nmarkdown.js: ${tests.length - failed} lulus, ${failed} gagal`);
if (failed > 0) process.exit(1);
