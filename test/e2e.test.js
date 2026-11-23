/* E2E test: menjalankan index.html + app.js yang asli di dalam jsdom,
 * dengan server n8n tiruan (mock) yang meniru protokol n8n 2.x:
 *
 *   POST /form/<path>                          -> { formWaitingUrl }
 *   GET  /form-waiting/<id>/n8n-execution-status -> running | form-waiting
 *   GET  /form-waiting/<id>?signature=…        -> halaman hasil (HTML responseHtml)
 *   POST /form-waiting/<id>?signature=…        -> tanda eksekusi di-resume
 *
 * Jalankan:
 *   node test/e2e.test.js
 *   NODE_PATH=/tmp/opencode/e2e/node_modules node test/e2e.test.js
 *
 * Kalau container uji n8n asli (127.0.0.1:5679) hidup, satu skenario
 * tambahan dijalankan terhadap n8n asli (dilewati kalau tidak ada).
 * Matikan dengan IRIS_E2E_SKIP_REAL=1, ganti alamat dengan IRIS_E2E_REAL_BASE.
 */
'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM, VirtualConsole } = (() => {
  try {
    return require('jsdom');
  } catch {
    console.error(
      'Uji e2e butuh paket "jsdom".\n' +
        '  npm install                                  (sekali saja)\n' +
        '  NODE_PATH=/path/ke/node_modules node test/e2e.test.js',
    );
    process.exit(2);
  }
})();

const APP_DIR = path.join(__dirname, '..');
const STORAGE_KEY = 'iris-multi-form.v1';
const REAL_BASE = process.env.IRIS_E2E_REAL_BASE || 'http://127.0.0.1:5679';
const MOCK_FORM_PATH = 'e2e-mock-9f2'; // sengaja tidak ada di n8n asli

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(pred, { timeout = 25000, interval = 50, desc = 'kondisi' } = {}) {
  const t0 = Date.now();
  let last = null;
  for (;;) {
    try {
      const v = pred();
      if (v) return v;
    } catch (e) {
      last = e;
    }
    if (Date.now() - t0 > timeout) {
      throw new Error('Timeout menunggu ' + desc + (last ? ' — ' + last.message : ''));
    }
    await sleep(interval);
  }
}

/* ---------------- DOM helpers ---------------- */

const q = (win, sel) => win.document.querySelector(sel);
const qa = (win, sel) => Array.from(win.document.querySelectorAll(sel));
const cardEls = (win) => qa(win, '#cards .card');
const cardById = (win, id) => q(win, '#cards .card[data-id="' + id + '"]');
const chipText = (el) => el.querySelector('.chip-text').textContent.trim();
const summarySub = (el) => el.querySelector('.summary-sub').textContent.trim();
const shown = (el) => el.ownerDocument.defaultView.getComputedStyle(el).display !== 'none';

function click(win, el) {
  assert.ok(el, 'elemen yang diklik tidak ditemukan');
  el.dispatchEvent(new win.MouseEvent('click', { bubbles: true, cancelable: true, view: win }));
}

function setValue(win, el, value) {
  assert.ok(el, 'input tidak ditemukan');
  el.value = value;
  el.dispatchEvent(new win.Event('input', { bubbles: true }));
  if (el.tagName === 'SELECT') el.dispatchEvent(new win.Event('change', { bubbles: true }));
}

function fieldInput(win, cardId, key) {
  return q(win, '#f-' + cardId + '-' + key);
}

/** Teks petunjuk di bawah sebuah field (mis. "otomatis: lanjutan tenant sgu"). */
function noteText(win, cardId, key) {
  const input = fieldInput(win, cardId, key);
  const note = input && input.parentElement.querySelector('.field-note');
  return note ? note.textContent.trim() : '';
}

const fieldValue = (win, cardId, key) => fieldInput(win, cardId, key).value;

/** Isi satu form: caseId (field-2) + raw alert (field-3). */
function fillCard(win, cardId, { caseId, alert }) {
  setValue(win, fieldInput(win, cardId, 'field-2'), caseId);
  setValue(win, fieldInput(win, cardId, 'field-3'), alert);
}

/* ---------------- server statis ---------------- */

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
};

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({ server, port, url: 'http://127.0.0.1:' + port });
    });
  });
}

async function startStaticServer(root) {
  const server = http.createServer((req, res) => {
    const urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    const rel = (urlPath === '/' ? '/index.html' : urlPath).replace(/^\/+/, '');
    const full = path.join(root, rel);
    if (!full.startsWith(root)) {
      res.writeHead(403);
      return res.end('forbidden');
    }
    fs.readFile(full, (err, buf) => {
      if (err) {
        res.writeHead(404, { 'content-type': 'text/plain' });
        return res.end('not found: ' + rel);
      }
      res.writeHead(200, { 'content-type': MIME[path.extname(full).toLowerCase()] || 'application/octet-stream' });
      res.end(buf);
    });
  });
  return listen(server);
}

/* ---------------- mock n8n ---------------- */

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
  });
}

function parseMultipart(raw, contentType) {
  const m = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType || '');
  const boundary = m ? (m[1] || m[2]).trim() : null;
  const fields = {};
  if (!boundary) return fields;
  for (const part of raw.split('--' + boundary)) {
    const i = part.indexOf('\r\n\r\n');
    if (i === -1) continue;
    const nameMatch = /name="([^"]+)"/i.exec(part.slice(0, i));
    if (!nameMatch) continue;
    fields[nameMatch[1]] = part.slice(i + 4).replace(/\r\n$/, '');
  }
  return fields;
}

function resultHtml(caseId, severity) {
  return (
    '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Hasil</title></head><body>' +
    '<div class="wrapper">' +
    '<h2>Informasi Case IRIS</h2>' +
    '<p><strong>Case Name</strong></p>' +
    '<pre><code>[' + severity + '] ' + caseId + '</code></pre>' +
    '<p><strong>Severity:</strong> ' + severity + '</p><hr>' +
    '<h2>Laporan Markdown</h2>' +
    '<p><strong>Siap disalin ke IRIS.</strong></p>' +
    '<pre><code># Laporan ' + caseId + '&#10;&#10;Baris kedua markdown.</code></pre>' +
    '</div></body></html>'
  );
}

const jsonReply = (res, status, obj) => {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
  res.end(body);
};
const textReply = (res, status, text) => {
  res.writeHead(status, { 'content-type': 'text/plain', 'content-length': Buffer.byteLength(text) });
  res.end(text);
};
const htmlReply = (res, status, html) => {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'content-length': Buffer.byteLength(html) });
  res.end(html);
};

/** Port yang sengaja tidak dipakai, untuk membuktikan rewriteHost bekerja. */
async function freePort() {
  const s = http.createServer(() => {});
  const { port, server } = await listen(s);
  await new Promise((r) => server.close(r));
  return port;
}

async function getFreePorts(n) {
  const ports = [];
  for (let i = 0; i < n; i++) ports.push(await freePort());
  return ports;
}

/**
 * @param {number} deadPort port bohongan yang dipakai di formWaitingUrl
 */
async function startMockN8n(deadPort) {
  const mock = {
    subs: new Map(), // id -> fields yang dikirim
    polls: new Map(), // id -> jumlah polling
    posts: [], // { id, fields, time }
    waits: [], // GET halaman hasil
    resumes: [], // POST resume { id, time, bodyLen }
    errors: [], // { path, status }
    plan: () => 0, // id -> berapa kali balas "running" sebelum "form-waiting"
    caseIdOf: (fields) => fields['field-2'] || 'TANPA-CASE-ID',
    /** Daftarkan eksekusi seolah sudah dikirim (untuk uji resume setelah reload). */
    seedSubmission(id, fields) {
      mock.subs.set(String(id), fields);
    },
    doneAt: new Map(), // id -> waktu pertama kali status "form-waiting"
  };

  const server = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://mock');
    const p = u.pathname;

    // ---- kirim form ----
    let m = /^\/form\/(.+)$/.exec(p);
    if (req.method === 'POST' && m) {
      const formPath = decodeURIComponent(m[1]);
      const raw = (await readBody(req)).toString('utf8');
      const fields = parseMultipart(raw, req.headers['content-type']);

      if (formPath === 'missing-path') {
        mock.errors.push({ path: formPath, status: 404 });
        return htmlReply(res, 404, '<!DOCTYPE html><html><body><pre>404 - form not found</pre></body></html>');
      }
      if (formPath === 'classic-ack') {
        mock.errors.push({ path: formPath, status: 200 });
        return jsonReply(res, 200, { status: 200 });
      }
      if (formPath === 'boom-html') {
        mock.errors.push({ path: formPath, status: 200 });
        return htmlReply(
          res,
          200,
          '<!DOCTYPE html><html><body><pre>The execution "9" has finished with error.</pre></body></html>',
        );
      }

      const id = String(mock.nextId++);
      mock.subs.set(id, fields);
      mock.posts.push({ id, fields, time: Date.now() });
      // Host sengaja dibelokkan ke deadPort: app harus menulis ulang ke Base URL.
      return jsonReply(res, 200, {
        formWaitingUrl: 'http://127.0.0.1:' + deadPort + '/form-waiting/' + id + '?signature=sig-' + id,
      });
    }

    // ---- status eksekusi ----
    m = /^\/form-waiting\/([^/]+)\/n8n-execution-status$/.exec(p);
    if (req.method === 'GET' && m) {
      const id = decodeURIComponent(m[1]);
      if (!mock.subs.has(id)) return textReply(res, 404, '');
      const seen = mock.polls.get(id) || 0;
      mock.polls.set(id, seen + 1);
      const stillRunning = seen < Number(mock.plan(id) || 0);
      if (!stillRunning && !mock.doneAt.has(id)) mock.doneAt.set(id, Date.now());
      return textReply(res, 200, stillRunning ? 'running' : 'form-waiting');
    }

    // ---- halaman hasil ----
    m = /^\/form-waiting\/([^/]+)$/.exec(p);
    if (m) {
      const id = decodeURIComponent(m[1]);
      if (!mock.subs.has(id)) return textReply(res, 404, '');
      if (req.method === 'GET') {
        mock.waits.push({ id, time: Date.now() });
        const fields = mock.subs.get(id);
        return htmlReply(res, 200, resultHtml(mock.caseIdOf(fields), 'HIGH'));
      }
      if (req.method === 'POST') {
        const raw = await readBody(req);
        mock.resumes.push({ id, time: Date.now(), bodyLen: raw.length });
        return jsonReply(res, 200, { status: 200 });
      }
    }

    textReply(res, 404, 'mock: rute tidak dikenal ' + req.method + ' ' + p);
  });

  const { port, url } = await listen(server);
  mock.url = url; // http://127.0.0.1:<port>
  mock.nextId = 900001; // id eksekusi palsu (jauh dari id n8n asli)
  mock.stop = () => new Promise((r) => server.close(r));
  return mock;
}

/* ---------------- memuat aplikasi di jsdom ---------------- */

/** fetch tiruan di atas node:http — jsdom tidak punya fetch, dan kita tidak
 *  ingin CORS/undici ikut campur untuk server lokal. */
function createFetch(log) {
  return function fetch(input, init = {}) {
    const url = typeof input === 'string' ? input : String(input && input.url);
    const method = String(init.method || 'GET').toUpperCase();
    const entry = { url, method, time: Date.now() };
    log.push(entry);

    return new Promise((resolve, reject) => {
      const opts = { method, headers: {} };
      let body = null;
      const fd = init.body;
      if (fd && typeof fd.entries === 'function') {
        const boundary = '----irisE2E' + Date.now().toString(16);
        const parts = [];
        const fields = {};
        for (const [k, v] of fd.entries()) {
          fields[k] = String(v);
          parts.push(Buffer.from('--' + boundary + '\r\nContent-Disposition: form-data; name="' + k + '"\r\n\r\n' + v + '\r\n', 'utf8'));
        }
        parts.push(Buffer.from('--' + boundary + '--\r\n', 'utf8'));
        body = Buffer.concat(parts);
        opts.headers['content-type'] = 'multipart/form-data; boundary=' + boundary;
        entry.fields = fields;
      }

      const req = http.request(url, opts, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          entry.status = res.statusCode;
          resolve({
            ok: res.statusCode >= 200 && res.statusCode < 300,
            status: res.statusCode,
            url,
            text: async () => text,
            json: async () => JSON.parse(text),
          });
        });
      });
      req.on('error', (e) => reject(Object.assign(new Error(e.message), { name: e.name, code: e.code })));
      const signal = init.signal;
      if (signal) {
        const onAbort = () => req.destroy(Object.assign(new Error('aborted'), { name: 'AbortError' }));
        if (signal.aborted) onAbort();
        else signal.addEventListener('abort', onAbort, { once: true });
      }
      req.end(body || undefined);
    });
  };
}

async function loadApp(staticUrl, { seed = null } = {}) {
  const pageErrors = [];
  const fetchLog = [];
  const vc = new VirtualConsole();
  vc.on('jsdomError', (e) => {
    const msg = String((e && e.message) || e);
    if (!/Could not parse CSS/i.test(msg)) pageErrors.push(msg);
  });
  vc.on('error', (...args) => pageErrors.push(args.map(String).join(' ')));

  const dom = await JSDOM.fromURL(staticUrl + '/', {
    runScripts: 'dangerously',
    resources: 'usable',
    pretendToBeVisual: true,
    virtualConsole: vc,
    beforeParse(win) {
      win.fetch = createFetch(fetchLog);
      win.Element.prototype.scrollIntoView = function () {};
      win.confirm = () => true;
      win.alert = () => {};
      // Tenant sekarang datang dari environment; sediakan daftar uji di sini.
      win.DIPTERA_CONFIG = { tenantOptions: ['sgu', 'wicida'] };
      if (seed) win.localStorage.setItem(STORAGE_KEY, JSON.stringify(seed));
    },
  });

  const win = dom.window;
  await waitFor(() => win.document.readyState === 'complete' && cardEls(win).length > 0, {
    desc: 'aplikasi selesai init (kartu tampil)',
  });
  await sleep(120); // beri kesempatan bindEvents selesai
  return { dom, win, fetchLog, pageErrors };
}

/** Isi pengaturan lewat panel UI (bukan localStorage) supaya jalur itu ikut teruji. */
function applySettings(win, { baseUrl, formPath, submitMode }) {
  if (q(win, '#settings-panel').hidden) click(win, q(win, '#btn-settings'));
  assert.equal(q(win, '#settings-panel').hidden, false, 'panel pengaturan harus terbuka');
  if (baseUrl != null) setValue(win, q(win, '#set-base-url'), baseUrl);
  if (formPath != null) setValue(win, q(win, '#set-form-path'), formPath);
  if (submitMode != null) setValue(win, q(win, '#set-submit-mode'), submitMode);
  click(win, q(win, '#btn-save-settings'));

  const expected =
    (baseUrl || q(win, '#set-base-url').value).replace(/\/+$/, '') +
    '/form/' +
    encodeURIComponent(formPath || q(win, '#set-form-path').value);
  assert.equal(q(win, '#link-form').getAttribute('href'), expected, 'pengaturan belum terpakai (link form)');
}

function addCard(win) {
  click(win, q(win, '#btn-add'));
  return cardEls(win).at(-1);
}

function submitAll(win) {
  click(win, q(win, '#btn-submit-all'));
}

const postIdsFor = (mock, caseId) => mock.posts.filter((p) => p.fields && p.fields['field-2'] === caseId);

/* ---------------- test runner ---------------- */

let passed = 0;
let failed = 0;
const failures = [];

async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log('  \u2713 ' + name);
  } catch (err) {
    failed++;
    failures.push(name);
    console.log('  \u2715 ' + name);
    console.log(
      String(err && err.stack ? err.stack : err)
        .split('\n')
        .map((l) => '    ' + l)
        .join('\n'),
    );
  }
}

/* ---------------- skenario ---------------- */

async function main() {
  const staticSrv = await startStaticServer(APP_DIR);
  const [deadPort] = await getFreePorts(1);
  const mock = await startMockN8n(deadPort);
  const opened = [];

  const openApp = async (opts) => {
    const app = await loadApp(staticSrv.url, opts);
    opened.push(app);
    return app;
  };

  console.log('e2e.test.js  (mock n8n: ' + mock.url + ', app: ' + staticSrv.url + ')');

  /* ---------- 1. banyak form, berurutan, validasi, notifikasi ---------- */
  await test('2 form: tambah/hapus, kirim berurutan, hasil per kartu', async () => {
    const { win } = await openApp();

    // mulai dengan 1 form
    assert.equal(cardEls(win).length, 1, 'harus mulai dengan 1 form');
    assert.equal(shown(q(win, '#settings-panel')), false, 'panel pengaturan tertutup saat awal');
    assert.equal(shown(q(win, '#btn-cancel')), false, 'tombol Batalkan tersembunyi saat tidak ada pengiriman');
    assert.equal(shown(cardEls(win)[0].querySelector('.result')), false, 'panel hasil tersembunyi sebelum ada hasil');

    // pengaturan -> mock, bukan n8n asli
    applySettings(win, { baseUrl: mock.url, formPath: MOCK_FORM_PATH });

    const el1 = cardEls(win)[0];
    const id1 = el1.dataset.id;
    const el2 = addCard(win);
    assert.equal(cardEls(win).length, 2, 'tambah form -> 2 kartu');
    const id2 = el2.dataset.id;

    // isi kedua form (valid)
    fillCard(win, id1, { caseId: 'CASE-A', alert: '{"severity":"high","title":"A"}' });
    fillCard(win, id2, { caseId: 'CASE-B', alert: '{"severity":"low","title":"B"}' });

    // kartu 1 dilatih untuk butuh 2x polling "running" (uji mode berurutan)
    mock.plan = (id) => (mock.subs.get(id)?.['field-2'] === 'CASE-A' ? 2 : 0);

    // kirim semua: kartu 2 baru mulai setelah kartu 1 selesai
    submitAll(win);
    await waitFor(() => chipText(cardById(win, id1)) === 'Done', { desc: 'card 1 done' });
    await waitFor(() => mock.posts.length === 2, { desc: '2 POSTs sent' });
    await waitFor(() => chipText(cardById(win, id2)) === 'Done', { desc: 'card 2 done' });

    // urutan & sifat berurutan
    const pA = postIdsFor(mock, 'CASE-A')[0];
    const pB = postIdsFor(mock, 'CASE-B')[0];
    assert.ok(pA && pB, 'kedua form terkirim dengan payload masing-masing');
    assert.equal(mock.posts[0].fields['field-3'], '{"severity":"high","title":"A"}', 'payload kartu 1 utuh');
    assert.equal(mock.posts[1].fields['field-3'], '{"severity":"low","title":"B"}', 'payload kartu 2 utuh');
    assert.ok(
      pB.time >= mock.doneAt.get(pA.id),
      'mode berurutan: form 2 mulai setelah form 1 selesai (' + (pB.time - mock.doneAt.get(pA.id)) + 'ms)',
    );

    // rewriteHost: URL hasil menunjuk ke deadPort, harus ditulis ulang ke Base URL
    assert.ok(
      mock.waits.some((w) => w.id === pA.id),
      'halaman hasil diambil dari Base URL yang benar, bukan host dari n8n',
    );

    // autoResume: POST ke form-waiting untuk menandai eksekusi selesai
    assert.deepEqual(
      mock.resumes.map((r) => r.id).sort(),
      [pA.id, pB.id].sort(),
      'autoResume menandai kedua eksekusi selesai',
    );
    assert.ok(
      mock.resumes.every((r) => r.bodyLen === 0),
      'body resume harus kosong',
    );

    // kartu tertutup + notifikasi di kartu yang tertutup
    const elA = cardById(win, id1);
    assert.ok(elA.classList.contains('collapsed'), 'kartu otomatis tertutup setelah dikirim');
    assert.equal(chipText(elA), 'Done');
    assert.equal(summarySub(elA), '[HIGH] CASE-A', 'ringkasan kartu tertutup memuat case name');
    const elB = cardById(win, id2);
    assert.equal(summarySub(elB), '[HIGH] CASE-B', 'ringkasan kartu 2 sesuai inputnya sendiri');
    await waitFor(() => qa(win, '#toasts .toast.success').some((t) => /Form #1 done · HIGH/.test(t.textContent)), {
      desc: 'toast sukses kartu 1',
    });

    // statistik
    assert.equal(q(win, '#stats .stat[data-stat="done"] b').textContent, '2');
    assert.equal(q(win, '#stats .stat[data-stat="error"] b').textContent, '0');

    // buka kartu 1 -> input + hasil (case name, severity, markdown)
    click(win, elA.querySelector('.card-head'));
    assert.equal(elA.classList.contains('collapsed'), false, 'kartu terbuka saat di-klik');
    const result = elA.querySelector('.result');
    assert.equal(result.hidden, false, 'panel hasil tampil');
    assert.equal(shown(result), true, 'panel hasil benar-benar terlihat (CSS)');
    assert.equal(shown(elA.querySelector('.error-panel')), false, 'panel error tidak ikut tampil');
    assert.match(result.textContent, /Informasi Case IRIS/);
    assert.match(result.textContent, /Laporan CASE-A/);
    assert.match(result.querySelector('.chip.sev').textContent.trim(), /HIGH/);
    assert.equal(shown(elA.querySelector('.fields')), false, 'isian form disembunyikan setelah selesai');
    assert.equal(fieldInput(win, id1, 'field-3').value, '', 'textarea log dilepas dari DOM setelah selesai');
    assert.equal(result.querySelector('[data-action="copy-md"]').disabled, false);

    // hapus 1 kartu langsung dari header (tanpa membuka kartu)
    click(win, elB.querySelector('.card-head [data-action="remove"]'));
    assert.equal(cardEls(win).length, 1, 'hapus dari header -> 1 kartu');

    // tersimpan di localStorage
    await sleep(1100);
    const saved = JSON.parse(win.localStorage.getItem(STORAGE_KEY));
    assert.equal(saved.cards.length, 1);
    assert.equal(saved.cards[0].status, 'done');
    assert.equal(saved.cards[0].result.caseName, '[HIGH] CASE-A');
    assert.equal(saved.settings.baseUrl, mock.url);
  });

  /* ---------- 1b. JSON panjang / NDJSON / teks bebas ---------- */
  await test('JSON panjang, NDJSON, dan teks bebas tidak diblokir; terkirim utuh', async () => {
    mock.plan = () => 0;
    const before = mock.posts.length;
    const { win } = await openApp();
    applySettings(win, { baseUrl: mock.url, formPath: MOCK_FORM_PATH });

    const idLong = cardEls(win)[0].dataset.id;
    const longLog = JSON.stringify({
      message: 'x'.repeat(300000),
      events: Array.from({ length: 200 }, (_, i) => ({ i, line: 'log line ' + i })),
    });
    fillCard(win, idLong, { caseId: 'CASE-LONG', alert: longLog });

    const idLines = addCard(win).dataset.id;
    const linesLog = '{"n":1,"message":"baris satu"}\n{"n":2,"message":"baris dua"}';
    fillCard(win, idLines, { caseId: 'CASE-LINES', alert: linesLog });

    const idFree = addCard(win).dataset.id;
    const freeLog = '2026-10-20 10:00:00 INFO raw log bebas, bukan JSON';
    fillCard(win, idFree, { caseId: 'CASE-FREE', alert: freeLog });

    const idNewline = addCard(win).dataset.id;
    const newlineLog = '{"message":"baris satu\nbaris dua","level":"INFO"}';
    fillCard(win, idNewline, { caseId: 'CASE-NEWLINE', alert: newlineLog });

    const idEmpty = addCard(win).dataset.id;
    setValue(win, fieldInput(win, idEmpty, 'field-2'), 'CASE-EMPTY');

    submitAll(win);
    await waitFor(() => chipText(cardById(win, idLong)) === 'Done', { desc: 'long JSON card done' });
    await waitFor(() => chipText(cardById(win, idLines)) === 'Done', { desc: 'NDJSON card done' });
    await waitFor(() => chipText(cardById(win, idFree)) === 'Done', { desc: 'free text card done' });
    await waitFor(() => chipText(cardById(win, idNewline)) === 'Done', { desc: 'newline card done' });
    assert.equal(chipText(cardById(win, idEmpty)), 'Waiting', 'empty alert not sent');
    assert.equal(mock.posts.length - before, 4, 'empat kartu terkirim, satu kosong tidak');

    assert.equal(postIdsFor(mock, 'CASE-LONG')[0].fields['field-3'], longLog, 'JSON panjang terkirim utuh');
    assert.equal(postIdsFor(mock, 'CASE-LINES')[0].fields['field-3'], linesLog, 'NDJSON terkirim utuh');
    assert.equal(postIdsFor(mock, 'CASE-FREE')[0].fields['field-3'], freeLog, 'teks bebas terkirim utuh');
    assert.equal(postIdsFor(mock, 'CASE-NEWLINE')[0].fields['field-3'], newlineLog, 'baris baru mentah terkirim utuh');

    const freeInput = fieldInput(win, idFree, 'field-3');
    assert.ok(!freeInput.classList.contains('invalid'), 'teks bebas tidak diberi bingkai merah');
    assert.match(
      freeInput.parentElement.querySelector('.field-msg').textContent,
      /sent as-is/,
      'JSON warning appears as info, not block',
    );
    assert.match(
      fieldInput(win, idNewline, 'field-3').parentElement.querySelector('.field-msg').textContent,
      /JSON parsed/,
      'raw newline inside string recognized',
    );

    // kartu selesai: isian tidak diisi lagi saat dibuka, hanya hasilnya
    const longCard = cardById(win, idLong);
    assert.ok(longCard.classList.contains('collapsed'), 'kartu panjang tertutup otomatis');
    click(win, longCard.querySelector('.card-head'));
    assert.equal(shown(longCard.querySelector('.fields')), false, 'isian tetap tersembunyi setelah selesai');
    assert.equal(
      fieldInput(win, idLong, 'field-3').value,
      '',
      'textarea log tidak diisi lagi setelah selesai',
    );

    // isi asli tetap aman di state: duplikat membawa log panjang utuh
    const beforeCopy = cardEls(win).map((el) => el.dataset.id);
    click(win, longCard.querySelector('[data-action="duplicate"]'));
    const afterCopy = cardEls(win).map((el) => el.dataset.id);
    assert.equal(afterCopy.length, beforeCopy.length + 1, 'duplikat case selesai menambah kartu');
    assert.equal(
      fieldValue(win, afterCopy[afterCopy.indexOf(idLong) + 1], 'field-3'),
      longLog,
      'duplikat tetap membawa isi log walau textarea sudah dilepas',
    );
  });

  /* ---------- 1c. duplikat & tutup/buka semua ---------- */
  await test('duplikat dan tutup/buka semua menjaga urutan & isi textarea', async () => {
    const { win } = await openApp();
    const id1 = cardEls(win)[0].dataset.id;
    fillCard(win, id1, { caseId: '#D1', alert: '{"dup":true}' });
    const id2 = addCard(win).dataset.id;
    fillCard(win, id2, { caseId: '#D2', alert: '{"dup":false}' });

    click(win, cardById(win, id1).querySelector('[data-action="duplicate"]'));
    const ids = cardEls(win).map((el) => el.dataset.id);
    assert.equal(ids.length, 3, 'duplikat menambah satu kartu');
    assert.equal(ids[0], id1, 'kartu asal tetap di posisi pertama');
    assert.equal(ids[2], id2, 'duplikat disisipkan tepat setelah kartu asal');
    const copyId = ids[1];
    assert.equal(fieldValue(win, copyId, 'field-3'), '{"dup":true}', 'isi kartu ikut tersalin');
    assert.equal(cardEls(win)[1].querySelector('.num').textContent, '2', 'nomor kartu duplikat benar');
    assert.equal(cardEls(win)[2].querySelector('.num').textContent, '3', 'nomor kartu setelahnya diperbarui');

    click(win, q(win, '#btn-toggle-all'));
    assert.ok(cardEls(win).every((el) => el.classList.contains('collapsed')), 'semua kartu tertutup');
    assert.equal(fieldInput(win, copyId, 'field-3').value, '', 'textarea dilepas dari DOM saat tertutup');

    click(win, q(win, '#btn-toggle-all'));
    assert.ok(cardEls(win).every((el) => !el.classList.contains('collapsed')), 'semua kartu terbuka');
    assert.equal(fieldInput(win, copyId, 'field-3').value, '{"dup":true}', 'textarea diisi lagi saat dibuka');
  });

  /* ---------- 2. penomoran otomatis ---------- */
  await test('penomoran otomatis: tiket per tenant & IRIS Case ID berurutan (tetap bisa diedit)', async () => {
    const { win } = await openApp();
    applySettings(win, { baseUrl: mock.url, formPath: MOCK_FORM_PATH });

    const id1 = cardEls(win)[0].dataset.id;
    const id2 = addCard(win).dataset.id;
    const id3 = addCard(win).dataset.id;

    // kartu 1: tenant sgu, tiket 10010, case id #1001
    setValue(win, fieldInput(win, id1, 'field-1'), 'sgu');
    setValue(win, fieldInput(win, id1, 'field-0'), '10010');
    setValue(win, fieldInput(win, id1, 'field-2'), '#1001');

    // kartu 2: pilih tenant yang sama -> tiket & case id lanjut otomatis
    setValue(win, fieldInput(win, id2, 'field-1'), 'sgu');
    await waitFor(() => fieldValue(win, id2, 'field-0') === '10011', { desc: 'tiket kartu 2 = 10011' });
    await waitFor(() => fieldValue(win, id2, 'field-2') === '#1002', { desc: 'case id kartu 2 = #1002' });
    assert.match(noteText(win, id2, 'field-0'), /auto: continues tenant sgu/);

    // kartu 3: tenant wicida -> urutan terpisah, nomor pertama diketik sendiri
    setValue(win, fieldInput(win, id3, 'field-1'), 'wicida');
    await waitFor(() => fieldValue(win, id3, 'field-2') === '#1003', { desc: 'case id kartu 3 = #1003' });
    assert.equal(fieldValue(win, id3, 'field-0'), '', 'tenant baru belum punya acuan tiket');
    setValue(win, fieldInput(win, id3, 'field-0'), '20021');

    // kartu 4: wicida -> 20022, case id #1004
    const id4 = addCard(win).dataset.id;
    setValue(win, fieldInput(win, id4, 'field-1'), 'wicida');
    await waitFor(() => fieldValue(win, id4, 'field-0') === '20022', { desc: 'tiket kartu 4 = 20022 (wicida)' });
    await waitFor(() => fieldValue(win, id4, 'field-2') === '#1004', { desc: 'case id kartu 4 = #1004' });

    // failsafe: isian manual tidak ditimpa dan menjadi acuan berikutnya
    setValue(win, fieldInput(win, id2, 'field-0'), '77777');
    await sleep(600);
    assert.equal(fieldValue(win, id2, 'field-0'), '77777', 'isian manual tidak ditimpa');
    assert.equal(noteText(win, id2, 'field-0'), '', 'tanda otomatis hilang setelah diedit');

    const id5 = addCard(win).dataset.id;
    setValue(win, fieldInput(win, id5, 'field-1'), 'sgu');
    await waitFor(() => fieldValue(win, id5, 'field-0') === '77778', { desc: 'sgu lanjut dari isian manual' });
    await waitFor(() => fieldValue(win, id5, 'field-2') === '#1005', { desc: 'case id kartu 5 = #1005' });

    const id6 = addCard(win).dataset.id;
    setValue(win, fieldInput(win, id6, 'field-1'), 'sgu');
    await waitFor(() => fieldValue(win, id6, 'field-0') === '77779', { desc: 'sgu berikutnya = 77779' });
    await waitFor(() => fieldValue(win, id6, 'field-2') === '#1006', { desc: 'case id kartu 6 = #1006' });

    // nomor otomatis benar-benar ikut terkirim ke n8n
    const ids = [id1, id2, id3, id4, id5, id6];
    ids.forEach((id, i) => setValue(win, fieldInput(win, id, 'field-3'), '{"card":' + (i + 1) + '}'));
    submitAll(win);
    await waitFor(() => cardEls(win).every((el) => chipText(el) === 'Done'), { desc: 'all 6 cards done' });

    const expected = [
      { ticket: '10010', tenant: 'sgu', caseId: '#1001' },
      { ticket: '77777', tenant: 'sgu', caseId: '#1002' },
      { ticket: '20021', tenant: 'wicida', caseId: '#1003' },
      { ticket: '20022', tenant: 'wicida', caseId: '#1004' },
      { ticket: '77778', tenant: 'sgu', caseId: '#1005' },
      { ticket: '77779', tenant: 'sgu', caseId: '#1006' },
    ];
    expected.forEach((exp, i) => {
      const post = mock.posts.find((p) => p.fields && p.fields['field-3'] === '{"card":' + (i + 1) + '}');
      assert.ok(post, 'form #' + (i + 1) + ' terkirim');
      assert.equal(post.fields['field-0'], exp.ticket, 'tiket form #' + (i + 1) + ' ke n8n');
      assert.equal(post.fields['field-1'], exp.tenant, 'tenant form #' + (i + 1) + ' ke n8n');
      assert.equal(post.fields['field-2'], exp.caseId, 'case id form #' + (i + 1) + ' ke n8n');
    });

    // panel pengaturan menampilkan nomor berikutnya
    if (q(win, '#settings-panel').hidden) click(win, q(win, '#btn-settings'));
    const info = q(win, '#numbering-info').textContent;
    assert.match(info, /Next Case ID:.*#1007/, 'info next case id');
    assert.match(info, /sgu → 77780/, 'info next sgu ticket');
    assert.match(info, /wicida → 20023/, 'info next wicida ticket');

    // reset acuan nomor
    click(win, q(win, '#btn-reset-numbering'));
    const id7 = addCard(win).dataset.id;
    assert.equal(fieldValue(win, id7, 'field-2'), '', 'setelah reset, case id tidak diisi otomatis');
    setValue(win, fieldInput(win, id7, 'field-1'), 'sgu');
    assert.equal(fieldValue(win, id7, 'field-0'), '', 'setelah reset, tiket sgu mulai dari kosong lagi');
  });

  /* ---------- 3. gagal HTTP + coba lagi ---------- */
  await test('form path salah -> kartu gagal (HTTP 404), lalu "Coba Lagi" berhasil', async () => {
    const { win } = await openApp();
    applySettings(win, { baseUrl: mock.url, formPath: 'missing-path' });
    const el = cardEls(win)[0];
    const id = el.dataset.id;
    fillCard(win, id, { caseId: 'CASE-404', alert: '{"ok":false}' });

    submitAll(win);
    await waitFor(() => chipText(cardById(win, id)) === 'Failed', { desc: 'card failed' });
    const errPanel = cardById(win, id).querySelector('.error-panel');
    assert.equal(errPanel.hidden, false, 'panel error tampil');
    assert.equal(shown(errPanel), true, 'panel error benar-benar terlihat (CSS)');
    assert.match(errPanel.textContent, /HTTP 404/);
    assert.match(errPanel.textContent, /404 - form not found/, 'detail respons ditampilkan');
    assert.equal(shown(cardById(win, id).querySelector('.fields')), true, 'isian tetap tampil saat gagal');
    assert.equal(cardById(win, id).querySelector('[data-action="retry"]').disabled, false);

    // perbaiki path lalu coba lagi
    applySettings(win, { formPath: MOCK_FORM_PATH });
    click(win, cardById(win, id).querySelector('[data-action="retry"]'));
    await waitFor(() => chipText(cardById(win, id)) === 'Done', { desc: 'card done after retry' });
    assert.equal(cardById(win, id).querySelector('.error-panel').hidden, true, 'panel error disembunyikan');
    assert.equal(summarySub(cardById(win, id)), '[HIGH] CASE-404');
  });

  /* ---------- 3. workflow tanpa halaman hasil ({"status":200}) ---------- */
  await test('respons klasik {"status":200} -> selesai tanpa output', async () => {
    const { win } = await openApp();
    applySettings(win, { baseUrl: mock.url, formPath: 'classic-ack' });
    const el = cardEls(win)[0];
    const id = el.dataset.id;
    fillCard(win, id, { caseId: 'CASE-ACK', alert: '{"ok":true}' });

    submitAll(win);
    await waitFor(() => chipText(cardById(win, id)) === 'Done', { desc: 'card done' });
    const result = cardById(win, id).querySelector('.result');
    assert.match(result.textContent, /no result page/i);
    assert.equal(summarySub(cardById(win, id)), 'Sent to n8n');
  });

  /* ---------- 4. workflow error -> pesan dari n8n ---------- */
  await test('halaman error dari n8n -> kartu gagal dengan detail', async () => {
    const { win } = await openApp();
    applySettings(win, { baseUrl: mock.url, formPath: 'boom-html' });
    const el = cardEls(win)[0];
    const id = el.dataset.id;
    fillCard(win, id, { caseId: 'CASE-ERR', alert: '{"ok":true}' });

    submitAll(win);
    await waitFor(() => chipText(cardById(win, id)) === 'Failed', { desc: 'card failed' });
    const errPanel = cardById(win, id).querySelector('.error-panel');
    assert.match(errPanel.textContent, /Workflow failed in n8n/);
    assert.match(errPanel.textContent, /finished with error/);
  });

  /* ---------- 5. mode paralel ---------- */
  await test('mode paralel: dua form dikirim hampir bersamaan', async () => {
    const before = mock.posts.length;
    const { win } = await openApp();
    applySettings(win, { baseUrl: mock.url, formPath: MOCK_FORM_PATH, submitMode: 'parallel' });
    const id1 = cardEls(win)[0].dataset.id;
    const id2 = addCard(win).dataset.id;
    fillCard(win, id1, { caseId: 'CASE-P1', alert: '{"n":1}' });
    fillCard(win, id2, { caseId: 'CASE-P2', alert: '{"n":2}' });

    submitAll(win);
    await waitFor(() => mock.posts.length === before + 2, { desc: '2 POST paralel' });
    const [a, b] = mock.posts.slice(before);
    assert.ok(Math.abs(b.time - a.time) < 800, 'paralel: selisih kirim ' + Math.abs(b.time - a.time) + 'ms');
    await waitFor(
      () => cardEls(win).every((el) => chipText(el) === 'Done'),
      { desc: 'both cards done' },
    );
  });

  /* ---------- 5b. hapus case yang masih antre ---------- */
  await test('hapus case yang masih antre -> tidak ikut terkirim', async () => {
    const before = mock.posts.length;
    mock.plan = () => 2; // kartu pertama bertahan beberapa detik supaya kartu kedua masih antre
    const { win } = await openApp();
    applySettings(win, { baseUrl: mock.url, formPath: MOCK_FORM_PATH, submitMode: 'sequential' });
    const id1 = cardEls(win)[0].dataset.id;
    const el2 = addCard(win);
    const id2 = el2.dataset.id;
    fillCard(win, id1, { caseId: 'CASE-KEEP', alert: '{"n":1}' });
    fillCard(win, id2, { caseId: 'CASE-DELETE-QUEUE', alert: '{"n":2}' });

    submitAll(win);
    // kartu kedua masih menunggu giliran; hapus lewat tombol di header.
    click(win, el2.querySelector('.card-head [data-action="remove"]'));
    assert.equal(cardById(win, id2), null, 'kartu antre langsung hilang');
    await waitFor(() => chipText(cardById(win, id1)) === 'Done', { desc: 'first card done' });

    assert.equal(mock.posts.length - before, 1, 'hanya kartu pertama yang terkirim');
    assert.equal(postIdsFor(mock, 'CASE-DELETE-QUEUE').length, 0, 'kartu yang dihapus tidak dikirim');
    mock.plan = () => 0;
  });

  /* ---------- 6. lanjut memantau setelah halaman di-reload ---------- */
  await test('reload halaman saat memantau -> polling dilanjutkan ke hasil', async () => {
    const idRun = '900101';
    mock.seedSubmission(idRun, { 'field-2': 'CASE-RELOAD' });
    mock.plan = (id) => (id === idRun ? 1 : 0);

    const seed = {
      v: 1,
      settings: { baseUrl: mock.url, formPath: MOCK_FORM_PATH, submitMode: 'sequential' },
      cards: [
        {
          id: 'seeded-1',
          values: { 'field-2': 'CASE-RELOAD', 'field-3': '{"reload":true}' },
          collapsed: true,
          status: 'running',
          waitingUrl: mock.url + '/form-waiting/' + idRun + '?signature=sig-' + idRun,
          execId: idRun,
          nsStatus: 'running',
          startedAt: Date.now() - 5000,
        },
      ],
    };
    const { win, fetchLog, pageErrors } = await openApp({ seed });
    const el = cardById(win, 'seeded-1');
    assert.match(chipText(el), /^Processing/, 'card recovered in processing status');

    try {
      await waitFor(() => chipText(cardById(win, 'seeded-1')) === 'Done', {
        timeout: 20000,
        desc: 'kartu selesai dipantau ulang',
      });
    } catch (e) {
      const card = cardById(win, 'seeded-1');
      throw new Error(
        e.message +
          '\n  diagnostik: ' +
          JSON.stringify(
            {
              chip: chipText(card),
              sub: summarySub(card),
              errorPanel: card.querySelector('.error-panel').textContent.slice(0, 300),
              polls: Array.from(mock.polls),
              waits: mock.waits,
              resumes: mock.resumes,
              fetch: fetchLog.map((f) => f.method + ' ' + f.url + ' -> ' + (f.status ?? 'ERR')),
              pageErrors,
            },
            null,
            1,
          ),
      );
    }
    assert.equal(summarySub(cardById(win, 'seeded-1')), '[HIGH] CASE-RELOAD');
    await waitFor(() => mock.resumes.some((r) => r.id === idRun), {
      desc: 'eksekusi hasil reload di-resume',
    });
  });

  /* ---------- 7. n8n asli (opsional) ---------- */
  if (process.env.IRIS_E2E_SKIP_REAL !== '1') {
    const alive = await probe(REAL_BASE + '/form/touch-test');
    if (!alive) {
      console.log('  \u2022 dilewati: n8n asli di ' + REAL_BASE + ' tidak aktif (uji manual)');
    } else {
      await test('n8n asli ' + REAL_BASE + ': form touch-test end-to-end', async () => {
        const { win } = await openApp();
        applySettings(win, { baseUrl: REAL_BASE, formPath: 'touch-test' });
        const el = cardEls(win)[0];
        const id = el.dataset.id;
        fillCard(win, id, { caseId: 'CASE-REAL', alert: '{"hello":"real"}' });

        submitAll(win);
        await waitFor(() => chipText(cardById(win, id)) === 'Done', {
          timeout: 90000,
          desc: 'card done (real n8n)',
        });
        const card = cardById(win, id);
        assert.equal(summarySub(card), '[HIGH] Touch Test Case', 'case name dari responsHtml asli');
        const result = card.querySelector('.result');
        assert.match(result.textContent, /# Touch Test/, 'markdown asli tampil');
        assert.match(result.textContent, /Hello \*markdown\*\./);
        assert.match(card.querySelector('.elapsed').textContent, /\ds/, 'durasi tercatat');
      });
    }
  }

  /* ---------- bersih-bersih ---------- */
  for (const app of opened) {
    if (app.pageErrors.length) {
      console.log('  \u2022 error halaman (jsdom): ' + app.pageErrors.slice(0, 3).join(' | '));
    }
    try {
      app.dom.window.close();
    } catch {
      /* ignore */
    }
  }
  await mock.stop();
  await new Promise((r) => staticSrv.server.close(r));

  console.log('\n' + passed + ' lulus, ' + failed + ' gagal');
  if (failed) console.log('gagal: ' + failures.join(', '));
  process.exit(failed ? 1 : 0);
}

function probe(url) {
  return new Promise((resolve) => {
    const req = http.get(url, { timeout: 3000 }, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(false));
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
