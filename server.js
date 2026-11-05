/* Server statis kecil untuk Diptera.
 *
 * Kenapa bukan `python3 -m http.server` saja:
 *   - host/port eksplisit (default 0.0.0.0 supaya bisa diakses lewat IP LAN),
 *   - hanya file aplikasi yang dilayani (node_modules/test tidak ikut terbuka),
 *   - alamat LAN dicetak saat start supaya tidak salah pakai localhost,
 *   - /healthz untuk healthcheck container,
 *   - /config.js bisa diisi N8N_BASE_URL dari environment container.
 *
 * Jalankan:
 *   npm start
 *   PORT=9000 N8N_BASE_URL=http://192.168.1.10:5678 npm start
 */
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const ROOT = __dirname;

// Muat .env (opsional) supaya `npm start` bisa membaca konfigurasi dari file.
// Kalau .env tidak ada, environment proses dipakai apa adanya.
try {
  process.loadEnvFile(path.join(ROOT, '.env'));
} catch {
  // .env tidak ada — tidak apa-apa.
}

const HOST = process.env.HOST || '0.0.0.0';
const PORT = Number(process.env.PORT) || 8787;

const APP_FILES = {
  '/': 'index.html',
  '/index.html': 'index.html',
  '/styles.css': 'styles.css',
  '/tenants.css': 'tenants.css',
  '/app.js': 'app.js',
  '/extract.js': 'extract.js',
  '/numbering.js': 'numbering.js',
  '/config.js': 'config.js',
};

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function isLocalHostname(hostname) {
  const h = String(hostname || '').toLowerCase();
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '[::1]' || h === '0.0.0.0';
}

/** Interface virtual (docker/bridge/VPN) tidak bisa dihubungi dari LAN. */
function isVirtualInterface(name) {
  return /^(lo|docker|br-|veth|virbr|vmnet|vboxnet|tun|tap)/i.test(String(name || ''));
}

/** URL aplikasi ini dari sudut pandang PC/HP lain di jaringan yang sama. */
function lanUrls(port, interfaces) {
  const candidates = [];
  for (const [name, addrs] of Object.entries(interfaces || os.networkInterfaces())) {
    if (isVirtualInterface(name)) continue;
    for (const addr of addrs || []) {
      const family = typeof addr.family === 'string' ? addr.family : addr.family === 4 ? 'IPv4' : 'IPv6';
      if (family !== 'IPv4' || addr.internal) continue;
      candidates.push({ name, url: 'http://' + addr.address + ':' + port });
    }
  }
  // Wi-Fi/Ethernet didahulukan; Tailscale dan interface lain menyusul.
  candidates.sort((a, b) => Number(!/^(wl|en|eth)/i.test(a.name)) - Number(!/^(wl|en|eth)/i.test(b.name)));
  return candidates.map((c) => c.url);
}

/** Di dalam container, IP yang terlihat adalah IP internal Docker (tidak bisa diakses dari LAN). */
function inContainer() {
  return process.env.IRIS_IN_CONTAINER === '1' || fs.existsSync('/.dockerenv');
}

function configScript() {
  const configured = String(process.env.N8N_BASE_URL || '').trim();
  const formPath = String(process.env.DIPTERA_FORM_PATH || '').trim();
  const caseId = String(process.env.INITIAL_CASE_ID || '').trim();
  const tenantsRaw = String(process.env.TENANT_OPTIONS || '').trim();
  const ticketsRaw = String(process.env.INITIAL_TICKETS || '').trim();
  const initialTenantsRaw = String(process.env.INITIAL_TENANTS || '').trim();

  const cfg = {};
  if (configured) cfg.baseUrl = configured.replace(/\/+$/, '');
  if (formPath) cfg.formPath = formPath;
  if (caseId) cfg.initialCaseId = caseId;

  let tenants = [];
  let initialTickets = {};

  if (tenantsRaw) {
    try { tenants = JSON.parse(tenantsRaw); } catch {}
  }
  if (ticketsRaw) {
    try { initialTickets = JSON.parse(ticketsRaw); } catch {}
  }
  if (initialTenantsRaw) {
    try {
      const parsedMap = JSON.parse(initialTenantsRaw);
      if (parsedMap && typeof parsedMap === 'object') {
        tenants = Object.keys(parsedMap);
        initialTickets = parsedMap;
      }
    } catch {}
  }

  if (tenants.length > 0) cfg.tenantOptions = tenants;
  if (Object.keys(initialTickets).length > 0) cfg.initialTickets = initialTickets;

  if (Object.keys(cfg).length > 0) {
    return 'window.DIPTERA_CONFIG = ' + JSON.stringify(cfg) + ';\n';
  }
  try {
    return fs.readFileSync(path.join(ROOT, 'config.js'), 'utf8');
  } catch {
    return 'window.DIPTERA_CONFIG = {};\n';
  }
}

function send(res, method, status, type, body) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
  res.writeHead(status, {
    'content-type': type,
    'content-length': buf.length,
    'cache-control': 'no-cache',
    'x-content-type-options': 'nosniff',
  });
  if (method === 'HEAD') res.end();
  else res.end(buf);
}

function createServer() {
  return http.createServer((req, res) => {
    const method = req.method === 'HEAD' ? 'HEAD' : req.method;
    if (method !== 'GET' && method !== 'HEAD') {
      res.setHeader('allow', 'GET, HEAD');
      return send(res, method, 405, 'text/plain; charset=utf-8', 'Method Not Allowed\n');
    }

    let pathname;
    try {
      pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    } catch {
      return send(res, method, 400, 'text/plain; charset=utf-8', 'Bad Request\n');
    }

    if (pathname === '/healthz') {
      return send(res, method, 200, 'text/plain; charset=utf-8', 'ok\n');
    }

    if (pathname === '/config.js') {
      return send(res, method, 200, MIME['.js'], configScript());
    }

    const rel = APP_FILES[pathname];
    if (!rel) {
      return send(
        res,
        method,
        404,
        'text/plain; charset=utf-8',
        '404 — hanya file aplikasi yang dilayani. Buka / untuk halaman utama.\n',
      );
    }

    // Path diambil dari whitelist di atas, jadi tidak ada path traversal.
    const full = path.join(ROOT, rel);
    fs.readFile(full, (err, buf) => {
      if (err) {
        return send(res, method, 500, 'text/plain; charset=utf-8', 'Gagal membaca ' + rel + '\n');
      }
      send(res, method, 200, MIME[path.extname(full).toLowerCase()] || 'application/octet-stream', buf);
    });
  });
}

function printBanner(port, host) {
  const local = 'http://localhost:' + port;
  const container = inContainer();
  const lans = container ? [] : lanUrls(port);
  console.log('');
  console.log('  Diptera');
  console.log('  ' + '-'.repeat(48));
  console.log('  Lokal     : ' + local);
  if (container) {
    console.log('  Jaringan  : http://<IP-PC>:' + port + ' (port host yang dipetakan)');
    console.log('');
    console.log('  Dari PC/HP lain, buka alamat IP PC ini + port yang dipetakan.');
  } else if (lans.length) {
    for (const url of lans) console.log('  Jaringan  : ' + url);
    console.log('');
    console.log('  Dari PC/HP lain, buka alamat "Jaringan" di atas.');
    console.log('  Jangan pakai "localhost" dari perangkat lain.');
  } else if (!isLocalHostname(host)) {
    console.log('  Jaringan  : (tidak terdeteksi — cek koneksi LAN)');
  }
  if (host === '127.0.0.1' || host === 'localhost') {
    console.log('');
    console.log('  PERINGATAN: HOST=' + host + ' hanya bisa diakses dari PC ini.');
    console.log('  Pakai HOST=0.0.0.0 (default) untuk akses lewat IP.');
  }
  if (process.platform === 'linux' && !container) {
    console.log('');
    console.log('  Jika perangkat lain tidak bisa connect, izinkan port ini di firewall:');
    console.log('    sudo ufw allow ' + port + '/tcp');
  }
  console.log('  ' + '-'.repeat(48));
  console.log('  Hentikan  : Ctrl+C');
  console.log('');
}

if (require.main === module) {
  const server = createServer();
  server.listen(PORT, HOST, () => printBanner(PORT, HOST));
  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error('\n  Port ' + PORT + ' sudah dipakai. Jalankan dengan PORT lain, mis. PORT=8788 npm start.\n');
    } else {
      console.error('\n  Gagal menjalankan server:', err.message, '\n');
    }
    process.exit(1);
  });

  const stop = () => server.close(() => process.exit(0));
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

module.exports = { createServer, lanUrls, isLocalHostname, isVirtualInterface, inContainer };
