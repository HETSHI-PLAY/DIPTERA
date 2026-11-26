/* Uji server statis (server.js): binding, whitelist file, /healthz, config.js. */
'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const { createServer, lanUrls, isLocalHostname, isVirtualInterface } = require('../src/server.js');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function request(port, pathname, method = 'GET') {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, path: pathname, method, timeout: 5000 },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
      },
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });
}

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log('  \u2713 ' + name);
  } catch (err) {
    failed++;
    console.log('  \u2715 ' + name);
    console.log(String(err && err.stack ? err.stack : err).replace(/^/gm, '    '));
  }
}

async function main() {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  console.log('server.test.js  (port ' + port + ')');

  try {
    await test('halaman utama & aset aplikasi dilayani', async () => {
      const root = await request(port, '/');
      assert.equal(root.status, 200);
      assert.match(root.headers['content-type'] || '', /text\/html/);
      assert.match(root.body, /Diptera/);
      assert.match(root.body, /config\.js/);

      const app = await request(port, '/js/app.js');
      assert.equal(app.status, 200);
      assert.match(app.headers['content-type'] || '', /javascript/);
      assert.match(app.body, /Diptera/);

      const triageUi = await request(port, '/js/triage-ui.js');
      assert.equal(triageUi.status, 200);
      assert.match(triageUi.headers['content-type'] || '', /javascript/);

      const extractJs = await request(port, '/js/extract.js');
      assert.equal(extractJs.status, 200);
      assert.match(extractJs.headers['content-type'] || '', /javascript/);

      const numberingJs = await request(port, '/js/numbering.js');
      assert.equal(numberingJs.status, 200);
      assert.match(numberingJs.headers['content-type'] || '', /javascript/);

      const css = await request(port, '/css/styles.css');
      assert.equal(css.status, 200);
      assert.match(css.headers['content-type'] || '', /text\/css/);

      const tenantsCss = await request(port, '/css/tenants.css');
      assert.equal(tenantsCss.status, 200);
      assert.match(tenantsCss.headers['content-type'] || '', /text\/css/);

      const favicon = await request(port, '/favicon.svg');
      assert.equal(favicon.status, 200);
      assert.match(favicon.headers['content-type'] || '', /svg/);
    });

    await test('/healthz membalas ok', async () => {
      const res = await request(port, '/healthz');
      assert.equal(res.status, 200);
      assert.equal(res.body.trim(), 'ok');
    });

    await test('/config.js default bisa dibaca', async () => {
      const res = await request(port, '/config.js');
      assert.equal(res.status, 200);
      assert.match(res.headers['content-type'] || '', /javascript/);
      assert.match(res.body, /DIPTERA_CONFIG/);
    });

    await test('N8N_BASE_URL mengisi config.js container', async () => {
      const old = process.env.N8N_BASE_URL;
      process.env.N8N_BASE_URL = 'http://10.0.0.5:5678/';
      try {
        const res = await request(port, '/config.js');
        assert.equal(res.status, 200);
        assert.match(res.body, /10\.0\.0\.5:5678/);
        assert.doesNotMatch(res.body, /10\.0\.0\.5:5678\/"/);
      } finally {
        if (old == null) delete process.env.N8N_BASE_URL;
        else process.env.N8N_BASE_URL = old;
      }
    });

    await test('file di luar whitelist & path traversal ditolak', async () => {
      for (const p of ['/package.json', '/src/server.js', '/node_modules/jsdom/package.json', '/../package.json', '/test/e2e.test.js']) {
        const res = await request(port, p);
        assert.equal(res.status, 404, p + ' harus 404');
      }
    });

    await test('method selain GET/HEAD ditolak, HEAD tanpa body', async () => {
      const post = await request(port, '/', 'POST');
      assert.equal(post.status, 405);
      const head = await request(port, '/', 'HEAD');
      assert.equal(head.status, 200);
      assert.equal(head.body, '');
    });

    await test('alamat LAN mengabaikan interface virtual', async () => {
      assert.equal(isVirtualInterface('docker0'), true);
      assert.equal(isVirtualInterface('br-3d9564262230'), true);
      assert.equal(isVirtualInterface('veth123'), true);
      assert.equal(isVirtualInterface('wlan0'), false);
      assert.equal(isVirtualInterface('enp2s0'), false);

      const urls = lanUrls(8787, {
        lo: [{ address: '127.0.0.1', family: 'IPv4', internal: true }],
        docker0: [{ address: '172.17.0.1', family: 'IPv4', internal: false }],
        'veth123@if2': [{ address: 'fe80::1', family: 'IPv6', internal: false }],
        tailscale0: [{ address: '100.64.0.2', family: 'IPv4', internal: false }],
        wlan0: [{ address: '192.168.1.10', family: 4, internal: false }],
      });
      assert.deepEqual(urls, ['http://192.168.1.10:8787', 'http://100.64.0.2:8787']);
      assert.equal(isLocalHostname('localhost'), true);
      assert.equal(isLocalHostname('192.168.1.10'), false);
    });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }

  await sleep(10);
  console.log('\n' + passed + ' lulus, ' + failed + ' gagal');
  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
