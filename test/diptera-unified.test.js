'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const { createServer } = require('../server.js');
const extract = require('../extract.js');
const numbering = require('../numbering.js');

function req(port, method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const payload = body !== undefined ? JSON.stringify(body) : null;
    const r = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: urlPath,
        method,
        headers: payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {},
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => resolve({ status: res.statusCode, text: data, json: (() => { try { return JSON.parse(data); } catch { return null; } })() }));
      },
    );
    r.on('error', reject);
    if (payload) r.write(payload);
    r.end();
  });
}

(async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'diptera-unified-test-'));

  // Seed v1 counters.json & legacy history.json to verify zero-loss migration
  fs.writeFileSync(path.join(tmpDir, 'counters.json'), JSON.stringify({
    lastIrisCaseId: '#2670',
    ticketsByTenant: { petra: '30132', sgu: 'ASOC-2026-40022' },
    tenants: ['wicida', 'instikibali', 'petra', 'praditauniversity', 'sgu', 'ikmicirebon'],
  }));
  fs.writeFileSync(path.join(tmpDir, 'history.json'), JSON.stringify([
    { id: 'legacy_job_1', tenant: 'petra', ticketNumber: '30132', irisCaseId: '#2670', status: 'done', caseName: '[HIGH] Legacy Case' }
  ]));

  const server = createServer({
    dataDir: tmpDir,
    env: {
      DEFAULT_WORKSPACE: 'asoc',
      ASOC_N8N_BASE_URL: 'http://10.20.100.65:5678',
      ASOC_FORM_PATH: 'alpha-form',
      ASOC_IRIS_BASE_URL: 'https://10.20.100.66',
      ASOC_CALLBACK_URL: 'http://10.20.100.117:8787/api/n8n-callback',
      SOC_N8N_BASE_URL: 'http://10.20.100.134:5678',
      SOC_FORM_PATH: 'Job-Creator',
      SOC_INITIAL_CASE_ID: '#900',
      SOC_INITIAL_TICKETS: '{"petra":"10100"}',
    },
  });

  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();

  try {
    // 1. Health & static whitelist
    const h = await req(port, 'GET', '/healthz');
    assert.equal(h.status, 200);
    assert.equal(h.text.trim(), 'ok');
    assert.equal((await req(port, 'GET', '/.env')).status, 404);

    // 2. config.js exposes both workspaces with ASOC default
    const cfgRes = await req(port, 'GET', '/config.js');
    assert.equal(cfgRes.status, 200);
    assert.ok(cfgRes.text.includes('"defaultWorkspace":"asoc"'));
    assert.ok(cfgRes.text.includes('"formPath":"alpha-form"'));
    assert.ok(cfgRes.text.includes('"formPath":"Job-Creator"'));

    // 3. v1 -> v2 migration preserved ASOC counters & isolated SOC counters
    const st = await req(port, 'GET', '/api/state');
    assert.equal(st.status, 200);
    assert.equal(st.json.defaultWorkspace, 'asoc');
    assert.equal(st.json.workspaces.asoc.counters.lastIrisCaseId, '#2670');
    assert.equal(st.json.workspaces.asoc.counters.ticketsByTenant.petra, '30132');
    assert.equal(st.json.workspaces.asoc.historyCount, 1);
    assert.equal(st.json.workspaces.soc.counters.lastIrisCaseId, '#900');
    assert.equal(st.json.workspaces.soc.counters.ticketsByTenant.petra, '10100');
    assert.equal(st.json.workspaces.soc.historyCount, 0);

    // 4. Atomic reserve isolated between ASOC & SOC
    const rAsoc = await req(port, 'POST', '/api/counters/reserve', { workspace: 'asoc', tenant: 'petra', reserveTicket: true });
    assert.equal(rAsoc.json.ticketNumber, '30133');
    const rSoc = await req(port, 'POST', '/api/counters/reserve', { workspace: 'soc', tenant: 'petra', reserveTicket: true, reserveCaseId: true });
    assert.equal(rSoc.json.ticketNumber, '10101');
    assert.equal(rSoc.json.irisCaseId, '#901');

    // Verify ASOC counter was NOT affected by SOC reserve
    const stAfter = await req(port, 'GET', '/api/state');
    assert.equal(stAfter.json.workspaces.asoc.counters.lastIrisCaseId, '#2670');
    assert.equal(stAfter.json.workspaces.asoc.counters.ticketsByTenant.petra, '30133');

    // 5. History isolation + rawAlert stripping
    const hcSoc = await req(port, 'POST', '/api/history', {
      id: 'soc_job_1',
      workspace: 'soc',
      mode: 'reporting',
      tenant: 'petra',
      ticketNumber: '10101',
      irisCaseId: '#901',
      rawAlert: '{"secret":"must-not-be-saved"}',
      status: 'done',
      caseName: '[MEDIUM] SOC Case',
      severity: 'MEDIUM',
      markdown: '# SOC MD',
    });
    assert.equal(hcSoc.status, 201);
    assert.equal(hcSoc.json.record.rawAlert, undefined);
    const savedRaw = fs.readFileSync(path.join(tmpDir, 'history.json'), 'utf8');
    assert.ok(!savedRaw.includes('must-not-be-saved'));

    const histAsoc = await req(port, 'GET', '/api/history?workspace=asoc');
    const histSoc = await req(port, 'GET', '/api/history?workspace=soc');
    assert.equal(histAsoc.json.items.length, 1);
    assert.equal(histAsoc.json.items[0].id, 'legacy_job_1');
    assert.equal(histSoc.json.items.length, 1);
    assert.equal(histSoc.json.items[0].id, 'soc_job_1');

    // 6. n8n callback updates ASOC without touching SOC
    const cb1 = await req(port, 'POST', '/api/n8n-callback', {
      event: 'case_created',
      jobId: 'asoc_job_1',
      workspace: 'asoc',
      caseId: 2675,
      reportNumber: 'ASOC-2026-30133',
      tenant: 'petra',
      runMode: 'reporting',
      irisCaseCreated: true,
    });
    assert.equal(cb1.status, 200);
    assert.equal(cb1.json.counters.lastIrisCaseId, '#2675');

    // Repeating callback must NOT bump counters
    const cbRep = await req(port, 'POST', '/api/n8n-callback', {
      event: 'report_ready',
      jobId: 'asoc_rep_1',
      workspace: 'asoc',
      caseId: 9999,
      tenant: 'petra',
      reportNumber: '99999',
      caseName: '[LOW] Repeat',
      runMode: 'repeating',
      runOptions: { createIrisCase: false },
      status: 'done',
    });
    assert.equal(cbRep.status, 200);
    assert.equal(cbRep.json.counters.lastIrisCaseId, '#2675');
    assert.equal(cbRep.json.counters.ticketsByTenant.petra, 'ASOC-2026-30133');

    // 7. Queue auto-increment across idle cards (per-tenant + repeating isolation)
    const qCards = [
      { id: 'c1', mode: 'reporting', status: 'idle', ticketAuto: true, values: { 'field-1': 'petra', 'field-0': '' } },
      { id: 'c2', mode: 'reporting', status: 'idle', ticketAuto: true, values: { 'field-1': 'petra', 'field-0': '' } },
      { id: 'c3', mode: 'reporting', status: 'idle', ticketAuto: true, values: { 'field-1': 'petra', 'field-0': '' } },
      { id: 'c_rep', mode: 'repeating', status: 'idle', ticketAuto: false, values: { 'field-1': 'petra', 'field-0': '99999' } },
    ];
    numbering.computeQueueTickets(qCards, { petra: '10100' });
    assert.equal(qCards[0].values['field-0'], '10101');
    assert.equal(qCards[1].values['field-0'], '10102');
    assert.equal(qCards[2].values['field-0'], '10103');
    assert.equal(qCards[3].values['field-0'], '99999');

    // 8. Extract parser
    const parsedHtml = extract.parse(
      '<h2>Informasi Case IRIS</h2><pre><code>[HIGH] SQLi on web-01</code></pre><p><strong>IRIS Case ID:</strong> #2675</p><p><strong>Severity:</strong> HIGH</p><h2>Laporan Markdown</h2><pre><code># MD BODY</code></pre>',
    );
    assert.equal(parsedHtml.found, true);
    assert.equal(parsedHtml.caseId, '2675');
    assert.equal(parsedHtml.severity, 'HIGH');

    console.log('ALL_UNIFIED_DIPTERA_TESTS_PASSED (8/8)');
  } finally {
    server.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
})();
