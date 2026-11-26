/* Unit test untuk extract.js — jalankan dengan: node test/extract.test.js */
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const X = require('../src/services/extract.js');

const fixtures = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log('  ✓ ' + name);
  } catch (err) {
    failed++;
    console.log('  ✕ ' + name);
    console.log('    ' + String(err.message).split('\n').join('\n    '));
  }
}

console.log('extract.js');

test('halaman hasil nyata (dari n8n 2.40.7) — tanpa case name', () => {
  const r = X.parse(fixtures('completion-mid.html'));
  assert.equal(r.found, true);
  assert.equal(r.severity, 'LOW');
  assert.match(r.markdown, /# Mid structure markdown/);
  assert.equal(r.caseName, null);
  assert.match(r.fragmentHtml, /Informasi Case IRIS/);
  assert.doesNotMatch(r.fragmentHtml, /<script/i);
});

test('halaman hasil nyata — dengan case name + markdown newline', () => {
  const r = X.parse(fixtures('completion-with-casename.html'));
  assert.equal(r.found, true);
  assert.equal(r.caseName, '[HIGH] Touch Test Case');
  assert.equal(r.severity, 'HIGH');
  assert.match(r.markdown, /# Touch Test/);
  assert.match(r.markdown, /Hello \*markdown\*\./);
  assert.match(r.markdown, /\n/);
  assert.equal(r.statusLine, 'Siap disalin ke IRIS.');
});

test('halaman hasil setelah eksekusi di-resume (status success)', () => {
  const r = X.parse(fixtures('completion-after-success.html'));
  assert.equal(r.found, true);
  assert.match(r.markdown, /# Mid structure markdown/);
});

test('respons POST n8n berisi formWaitingUrl', () => {
  const json = JSON.parse(fixtures('submit-response.json'));
  assert.match(json.formWaitingUrl, /\/form-waiting\/\d+\?signature=/);
});

test('fallback: responseText ter-escape (&lt;h2&gt;…)', () => {
  const html =
    '<!DOCTYPE html><html><body><div>&lt;h2&gt;Informasi Case IRIS&lt;/h2&gt;' +
    '&lt;p&gt;&lt;strong&gt;Case Name&lt;/strong&gt;&lt;/p&gt;&lt;pre&gt;&lt;code&gt;[CRITICAL] Foo Bar&lt;/code&gt;&lt;/pre&gt;' +
    '&lt;p&gt;&lt;strong&gt;Severity:&lt;/strong&gt; CRITICAL&lt;/p&gt;' +
    '&lt;pre&gt;&lt;code&gt;# Judul&#10;isi markdown&lt;/code&gt;&lt;/pre&gt;</div></body></html>';
  const r = X.parse(html);
  assert.equal(r.found, true);
  assert.equal(r.severity, 'CRITICAL');
  assert.equal(r.caseName, '[CRITICAL] Foo Bar');
  assert.match(r.markdown, /# Judul\nisi markdown/);
});

test('halaman error n8n terdeteksi', () => {
  const page =
    '<!DOCTYPE html><html><head><title>Error</title></head><body>' +
    '<pre>The execution "42" has finished with error.</pre></body></html>';
  const r = X.parse(page);
  assert.equal(r.found, false);
  assert.equal(X.looksLikeError(r.pageText), true);
});

test('halaman spinner / tidak dikenal tidak dianggap hasil', () => {
  const page = '<!DOCTYPE html><html><head><title>Form</title></head><body><p>Form is loading…</p></body></html>';
  const r = X.parse(page);
  assert.equal(r.found, false);
  assert.equal(X.looksLikeError(r.pageText), false);
});

test('sanitizeFragment membuang script & event handler', () => {
  const dirty = '<h2 class="x" onclick="alert(1)">Hi</h2><script>steal()</script><img src="javascript:evil()">';
  const clean = X.sanitizeFragment(dirty);
  assert.doesNotMatch(clean, /<script/i);
  assert.doesNotMatch(clean, /onclick/i);
  assert.doesNotMatch(clean, /javascript:/i);
  assert.match(clean, /<h2[^>]*>Hi<\/h2>/);
});

test('resolveResultUrl menyesuaikan host bila diminta', () => {
  const url = 'http://localhost:5678/form-waiting/3?signature=abc';
  assert.equal(
    X.resolveResultUrl(url, 'http://localhost:8080', true),
    'http://localhost:8080/form-waiting/3?signature=abc',
  );
  assert.equal(X.resolveResultUrl(url, 'http://localhost:8080', false), url);
  assert.equal(X.resolveResultUrl(url, 'http://localhost:5678', true), url);
  assert.equal(X.resolveResultUrl('bukan-url', 'http://x', true), 'bukan-url');
});

test('execIdFromWaitingUrl mengambil id eksekusi', () => {
  assert.equal(X.execIdFromWaitingUrl('http://localhost:5678/form-waiting/123?signature=zz'), '123');
  assert.equal(X.execIdFromWaitingUrl('http://localhost:5678/form-waiting/abc-def'), 'abc-def');
  assert.equal(X.execIdFromWaitingUrl('nope'), null);
});

test('decodeEntities aman (tidak dobel decode)', () => {
  assert.equal(X.decodeEntities('&lt;h2&gt;x&lt;/h2&gt;'), '<h2>x</h2>');
  assert.equal(X.decodeEntities('&amp;lt;b&amp;gt;'), '&lt;b&gt;');
  assert.equal(X.decodeEntities('&#10;'), '\n');
  assert.equal(X.decodeEntities('&#x41;'), 'A');
});

test('stripTags menghasilkan teks bersih', () => {
  const text = X.stripTags('<div>Halo <b>dunia</b><script>x()</script></div>');
  assert.equal(text, 'Halo dunia');
});

console.log('\n' + passed + ' lulus, ' + failed + ' gagal');
process.exit(failed ? 1 : 0);
