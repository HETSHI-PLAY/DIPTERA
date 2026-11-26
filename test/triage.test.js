/* Comprehensive test suite for Autonomous Wazuh Polling, Live Feed (1:1 Parity),
 * Tenant-Isolated 2-Stage Semantic Grouping, Ollama Pre-Triage & Case Audit History.
 */
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { createServer } = require('../src/server.js');
const { evaluateExclusions, deriveExclusionRuleFromAlerts, deriveExclusionRulesFromAlerts, chunkAlertsForPromote } = require('../src/services/triage.js');

function httpJson(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const bodyStr = opts.body != null ? (typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body)) : null;
    const headers = { ...(opts.headers || {}) };
    if (bodyStr != null) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = Buffer.byteLength(bodyStr, 'utf8');
    }
    const req = http.request(u, { method: opts.method || 'GET', headers, timeout: 8000 }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch {}
        resolve({ status: res.statusCode, headers: res.headers, json, text });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
    if (bodyStr != null) req.write(bodyStr);
    req.end();
  });
}

async function main() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'diptera-triage-test-'));

  // Mock Wazuh hits store (mutable per scenario)
  let mockWazuhHits = [];
  let wazuhQueries = [];
  let clusterHealthForbidden = false;
  let countForbidden = false;

  const mockWazuh = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      let parsed = {};
      try { parsed = body ? JSON.parse(body) : {}; } catch {}

      if (req.url === '/_cluster/health' || req.url === '/') {
        if (clusterHealthForbidden) {
          res.writeHead(403, { 'content-type': 'application/json' });
          return res.end(JSON.stringify({
            error: { reason: 'no permissions for [cluster:monitor/main] and User [name=llm_reader_asoc, backend_roles=[], requestedTenant=null]' },
          }));
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ cluster_name: 'wazuh-mock-cluster', status: 'green' }));
      }
      if (req.url.endsWith('/_count')) {
        if (countForbidden) {
          res.writeHead(403, { 'content-type': 'application/json' });
          return res.end(JSON.stringify({ error: { reason: 'no permissions for [indices:data/read/search/_count]' } }));
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ count: mockWazuhHits.length }));
      }
      if (req.url.endsWith('/_search')) {
        wazuhQueries.push({ url: req.url, auth: req.headers.authorization || '', body: parsed });

        // Handle ID lookup for Case Audit History fetch-wazuh
        const should = parsed?.query?.bool?.should;
        if (Array.isArray(should)) {
          const wantedIds = new Set();
          for (const clause of should) {
            if (clause?.ids?.values) clause.ids.values.forEach((v) => wantedIds.add(String(v)));
          }
          const matched = mockWazuhHits.filter((h) => wantedIds.has(String(h._id)));
          res.writeHead(200, { 'content-type': 'application/json' });
          return res.end(JSON.stringify({ hits: { total: { value: matched.length }, hits: matched } }));
        }

        // Handle severity & watermark/time-range filtering
        const filters = parsed?.query?.bool?.filter || [];
        let minLv = 0;
        let maxLv = 99;
        let sinceMs = null;
        let sinceInclusive = false;
        let untilMs = null;
        for (const f of filters) {
          if (f.range?.['rule.level']) {
            minLv = f.range['rule.level'].gte ?? minLv;
            maxLv = f.range['rule.level'].lte ?? maxLv;
          }
          if (f.range?.['@timestamp']) {
            if (f.range['@timestamp'].gte) {
              sinceMs = Date.parse(f.range['@timestamp'].gte);
              sinceInclusive = true;
            } else if (f.range['@timestamp'].gt) {
              sinceMs = Date.parse(f.range['@timestamp'].gt);
              sinceInclusive = false;
            }
            if (f.range['@timestamp'].lte) {
              untilMs = Date.parse(f.range['@timestamp'].lte);
            }
          }
        }
        const filtered = mockWazuhHits.filter((h) => {
          const lv = Number(h._source?.rule?.level || 0);
          if (lv < minLv || lv > maxLv) return false;
          const tsMs = Date.parse(h._source['@timestamp']);
          if (sinceMs != null && (sinceInclusive ? tsMs < sinceMs : tsMs <= sinceMs)) return false;
          if (untilMs != null && tsMs > untilMs) return false;
          return true;
        });

        const pageHits = parsed?.size === 0
          ? []
          : filtered.slice(0, Number(parsed?.size) > 0 ? Number(parsed.size) : filtered.length);

        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({
          hits: {
            total: { value: filtered.length, relation: 'eq' },
            hits: pageHits,
          },
        }));
      }

      res.writeHead(404);
      res.end('not found');
    });
  });

  // Mock Ollama server tracking single-concurrency & per-tenant isolation
  let ollamaMode = 'smart';
  let activeOllamaCalls = 0;
  let maxConcurrentOllamaCalls = 0;
  let ollamaRequests = [];

  const mockOllama = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      if (req.url === '/api/tags') {
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ models: [{ name: 'hf.co/Triago/NVIDIA-Nemotron-Nano-12B-v2-Q8_0-GGUF:Q8_0' }] }));
      }
      if (req.url === '/api/chat') {
        activeOllamaCalls++;
        maxConcurrentOllamaCalls = Math.max(maxConcurrentOllamaCalls, activeOllamaCalls);
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          ollamaRequests.push(body);
          await new Promise((r) => setTimeout(r, 25));

          if (ollamaMode === 'error') {
            res.writeHead(503, { 'content-type': 'application/json' });
            return res.end(JSON.stringify({ error: 'GPU busy' }));
          }
          if (ollamaMode === 'truncated_once' && typeof body.format === 'object') {
            const uMsg = body.messages.find((m) => m.role === 'user')?.content || '';
            const cIdx = uMsg.indexOf('Kandidat batch:\n');
            const cands = JSON.parse(uMsg.slice(cIdx + 'Kandidat batch:\n'.length));
            const firstObj = JSON.stringify({
              candidate_id: cands[0].candidate_id,
              verdict: 'FALSE_POSITIVE',
              group_key: 'salvaged-first',
              incident_title: 'Salvaged Candidate 1',
              ai_reasoning: 'Salvaged dari JSON terpotong.',
            });
            res.writeHead(200, { 'content-type': 'application/json' });
            return res.end(JSON.stringify({
              done_reason: 'length',
              message: { content: `{"results":[${firstObj},{"candidate_id":"${cands[1]?.candidate_id || 'x'}","verdict":"TRU` },
            }));
          }
          if (ollamaMode === 'bad_schema_json_retry' && typeof body.format === 'object') {
            res.writeHead(200, { 'content-type': 'application/json' });
            return res.end(JSON.stringify({ done_reason: 'stop', message: { content: 'not valid json at all' } }));
          }

          const userMsg = body.messages.find((m) => m.role === 'user')?.content || '';
          const exMarker = 'Sampel alert unik:\n';
          if (userMsg.includes(exMarker)) {
            const samples = JSON.parse(userMsg.slice(userMsg.indexOf(exMarker) + exMarker.length));
            const aiRules = [];
            if (samples[0]?.path) {
              aiRules.push({
                target: 'path',
                mode: 'wildcard',
                pattern: samples[0].path.replace(/\/\d+(?=\/|$)/g, '/*'),
                note: 'AI exclude URL spesifik',
              });
            }
            if (samples[0]?.rule_description) {
              aiRules.push({
                target: 'rule_description',
                mode: 'contains',
                pattern: samples[0].rule_description,
                note: 'AI exclude deskripsi rule',
              });
            }
            res.writeHead(200, { 'content-type': 'application/json' });
            return res.end(JSON.stringify({
              message: { content: JSON.stringify({ reasoning: 'Saran rule spesifik dari sampel alert.', rules: aiRules }) },
            }));
          }

          const batchMarker = 'Kandidat batch:\n';
          const idx = userMsg.indexOf(batchMarker);
          const candidates = JSON.parse(userMsg.slice(idx + batchMarker.length));

          const results = candidates.map((c) => {
            const urlSample = (c.samples?.[0]?.url || '') + ' ' + (c.samples?.[0]?.full_log || '');
            if (/\.env|\.git|sqlmap|l9scan|wp-login/i.test(urlSample)) {
              return {
                candidate_id: c.candidate_id,
                verdict: 'TRUE_POSITIVE',
                group_key: 'web-secret-scanning-' + (c.source_ips?.[0] || 'ext'),
                incident_title: 'Automated Web Vulnerability Scanning',
                ai_reasoning: 'Akses berulang ke file sensitif dengan user-agent scanner.',
              };
            }
            if (/\/apps\/form|typo-legit/i.test(urlSample)) {
              return {
                candidate_id: c.candidate_id,
                verdict: 'FALSE_POSITIVE',
                group_key: 'normal-app-400',
                incident_title: 'Normal Application Client 400',
                ai_reasoning: 'Trafik aplikasi user biasa dengan browser standar.',
              };
            }
            return {
              candidate_id: c.candidate_id,
              verdict: 'NEEDS_REVIEW',
              group_key: 'ssh-bruteforce-' + c.candidate_id,
              incident_title: 'Anomali Perlu Verifikasi (' + (c.agent_names?.[0] || 'agent') + ')',
              ai_reasoning: 'Perlu verifikasi konteks oleh analis SOC.',
            };
          });

          res.writeHead(200, { 'content-type': 'application/json' });
          return res.end(JSON.stringify({ message: { content: JSON.stringify({ results }) } }));
        } finally {
          activeOllamaCalls--;
        }
      }
      res.writeHead(404);
      res.end('not found');
    });
  });

  await Promise.all([
    new Promise((r) => mockWazuh.listen(0, '127.0.0.1', r)),
    new Promise((r) => mockOllama.listen(0, '127.0.0.1', r)),
  ]);

  const wazuhUrl = `http://127.0.0.1:${mockWazuh.address().port}`;
  const ollamaUrl = `http://127.0.0.1:${mockOllama.address().port}`;

  const server = createServer({
    dataDir: tmpDir,
    env: {
      AUTH_ENABLED: 'false',
      ASOC_N8N_BASE_URL: 'http://127.0.0.1:5678',
      SOC_N8N_BASE_URL: 'http://127.0.0.1:5678',
    },
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  try {
    // 1. Credential protection & Config Persistence
    const saveCfgRes = await httpJson(`${baseUrl}/api/triage/config`, {
      method: 'POST',
      body: {
        wazuh: {
          url: wazuhUrl,
          indexPattern: 'wazuh-alerts-*',
          username: 'soc_ro',
          password: 'SuperSecretWazuhPassword!',
          minRuleLevel: 7,
          maxRuleLevel: 15,
          tenantMapping: { 'instiki-*': 'instiki', 'pradita-*': 'pradita' },
        },
        ollama: { baseUrl: ollamaUrl, temperature: 0.1 },
      },
    });
    assert.equal(saveCfgRes.status, 200);
    assert.equal(saveCfgRes.json.config.wazuh.password, undefined);
    assert.equal(saveCfgRes.json.config.wazuh.hasPassword, true);

    const getCfgRes = await httpJson(`${baseUrl}/api/triage/config`);
    assert.equal(getCfgRes.json.config.wazuh.password, undefined);
    assert.equal(getCfgRes.json.config.wazuh.hasPassword, true);

    // /config.js must NOT expose Wazuh credentials
    const publicCfgJs = await httpJson(`${baseUrl}/config.js`);
    assert.equal(publicCfgJs.text.includes('SuperSecretWazuhPassword'), false);
    assert.equal(publicCfgJs.text.includes('soc_ro'), false);

    // Updating without password preserves existing password
    await httpJson(`${baseUrl}/api/triage/config`, {
      method: 'POST',
      body: { wazuh: { url: wazuhUrl, minRuleLevel: 7, maxRuleLevel: 15 } },
    });

    // 2. Test Connection Endpoints (including least-privilege read-only user without cluster:monitor/main)
    const testWazuh = await httpJson(`${baseUrl}/api/triage/test-wazuh`, { method: 'POST', body: {} });
    assert.equal(testWazuh.status, 200);
    assert.equal(testWazuh.json.ok, true);
    assert.equal(testWazuh.json.clusterName, 'wazuh-mock-cluster');

    clusterHealthForbidden = true;
    const testWazuhReadOnly = await httpJson(`${baseUrl}/api/triage/test-wazuh`, { method: 'POST', body: {} });
    assert.equal(testWazuhReadOnly.status, 200);
    assert.equal(testWazuhReadOnly.json.ok, true);
    assert.equal(testWazuhReadOnly.json.status, 'read-only');
    assert.equal(typeof testWazuhReadOnly.json.docCount, 'number');

    countForbidden = true;
    const testWazuhSearchFallback = await httpJson(`${baseUrl}/api/triage/test-wazuh`, { method: 'POST', body: {} });
    assert.equal(testWazuhSearchFallback.status, 200);
    assert.equal(testWazuhSearchFallback.json.ok, true);
    assert.equal(testWazuhSearchFallback.json.status, 'read-only');
    assert.equal(typeof testWazuhSearchFallback.json.docCount, 'number');
    clusterHealthForbidden = false;
    countForbidden = false;
    wazuhQueries = [];

    const testOllama = await httpJson(`${baseUrl}/api/triage/test-ollama`, { method: 'POST', body: {} });
    assert.equal(testOllama.status, 200);
    assert.equal(testOllama.json.modelAvailable, true);

    // 3. Test Exclusion Rules helper (contains, starts_with, regex)
    assert.equal(evaluateExclusions({ data: { url: '/login.php?next=1' } }, [{ enabled: true, target: 'path', mode: 'contains', pattern: '/login.php' }]).excluded, true);
    assert.equal(evaluateExclusions({ full_log: 'GET /assets/app.js HTTP/1.1' }, [{ enabled: true, target: 'path', mode: 'starts_with', pattern: '/assets/' }]).excluded, true);
    assert.equal(evaluateExclusions({ full_log: 'Mozilla HealthCheck/1.0' }, [{ enabled: true, target: 'full_log', mode: 'regex', pattern: 'HealthCheck/\\d' }]).excluded, true);

    // 4. Populate Realistic Wazuh Hits:
    // - 1 noise hit matching /login.php (excluded before Ollama)
    // - 2 attack hits on rule 31151 across 2 agents in tenant "instiki" (must merge into 1 TP group)
    // - 1 legit 400 hit on SAME rule 31151 in tenant "instiki" (must stay separate FP group!)
    // - 1 review hit in tenant "instiki" (to test manual same-tenant merge)
    // - 1 attack hit in tenant "pradita" (must stay strictly isolated in tenant "pradita")
    const rawAttackInstiki1 = {
      '@timestamp': '2026-11-26T01:05:00.000Z',
      rule: { id: '31151', level: 10, description: 'Multiple web server 400 error codes.' },
      agent: { id: '001', name: 'instiki-web-01' },
      data: { srcip: '157.245.36.108', url: '/.env', http_user_agent: 'l9scan/2.0' },
      full_log: '157.245.36.108 "GET /.env HTTP/1.1" 400 "l9scan/2.0"',
      custom_preserved_flag: 'keep-intact-1',
    };
    const rawAttackInstiki2 = {
      '@timestamp': '2026-11-26T01:05:15.000Z',
      rule: { id: '31151', level: 12, description: 'Multiple web server 400 error codes.' },
      agent: { id: '002', name: 'instiki-portal-02' },
      data: { srcip: '157.245.36.108', url: '/.git/config', http_user_agent: 'l9scan/2.0' },
      full_log: '157.245.36.108 "GET /.git/config HTTP/1.1" 400 "l9scan/2.0"',
    };
    const rawLegitInstiki = {
      '@timestamp': '2026-11-26T01:05:25.000Z',
      rule: { id: '31151', level: 8, description: 'Multiple web server 400 error codes.' },
      agent: { id: '001', name: 'instiki-web-01' },
      data: { srcip: '10.10.2.5', url: '/apps/form?typo-legit=1', http_user_agent: 'Mozilla/5.0' },
      full_log: '10.10.2.5 "POST /apps/form?typo-legit=1 HTTP/1.1" 400 "Mozilla/5.0"',
    };
    const rawReviewInstiki = {
      '@timestamp': '2026-11-26T01:05:40.000Z',
      rule: { id: '5710', level: 10, description: 'Attempt to login using a non-existent user' },
      agent: { id: '003', name: 'instiki-ssh-03' },
      data: { srcip: '45.10.20.30' },
      full_log: 'sshd: Invalid user admin from 45.10.20.30',
    };
    const rawExcludedLogin = {
      '@timestamp': '2026-11-26T01:05:45.000Z',
      rule: { id: '31151', level: 7, description: 'Web 400' },
      agent: { id: '001', name: 'instiki-web-01' },
      data: { srcip: '10.10.2.8', url: '/login.php' },
      full_log: '10.10.2.8 "POST /login.php HTTP/1.1" 400',
    };
    const rawAttackPradita = {
      '@timestamp': '2026-11-26T01:06:00.000Z',
      rule: { id: '31151', level: 15, description: 'Multiple web server 400 error codes.' },
      agent: { id: '010', name: 'pradita-web-01' },
      data: { srcip: '157.245.36.108', url: '/.env' },
      full_log: '157.245.36.108 "GET /.env HTTP/1.1" 400 "sqlmap/1.7"',
    };

    mockWazuhHits = [
      { _id: 'w-pradita-1', _source: rawAttackPradita },
      { _id: 'w-excl-login', _source: rawExcludedLogin },
      { _id: 'w-rev-instiki', _source: rawReviewInstiki },
      { _id: 'w-fp-instiki', _source: rawLegitInstiki },
      { _id: 'w-tp-instiki-2', _source: rawAttackInstiki2 },
      { _id: 'w-tp-instiki-1', _source: rawAttackInstiki1 },
    ];

    ollamaRequests = [];
    const pollRes = await httpJson(`${baseUrl}/api/triage/worker`, { method: 'POST', body: { action: 'poll_now' } });
    assert.equal(pollRes.status, 200);
    assert.equal(pollRes.json.ok, true);
    assert.equal(pollRes.json.fetchedCount, 6);
    assert.equal(pollRes.json.excludedCount, 1);
    assert.equal(pollRes.json.analyzedCount, 5);
    // Strict single-concurrency lock & per-tenant micro-batches (2 tenants = 2 Ollama calls)
    assert.equal(maxConcurrentOllamaCalls, 1);
    assert.equal(ollamaRequests.length, 2);
    const firstOllamaReq = ollamaRequests[0];
    assert.equal(firstOllamaReq.think, false);
    assert.equal(firstOllamaReq.keep_alive, '2m');
    assert.equal(typeof firstOllamaReq.format, 'object');
    assert.ok(firstOllamaReq.format?.properties?.results);
    assert.equal(firstOllamaReq.options.num_ctx, 12288);
    assert.equal(firstOllamaReq.options.num_predict, 4096);
    assert.equal(firstOllamaReq.options.top_p, 0.85);
    assert.equal(firstOllamaReq.options.top_k, 20);
    assert.equal(firstOllamaReq.options.repeat_penalty, 1.05);

    const groups = pollRes.json.snapshot.groups;
    assert.equal(groups.length, 4); // instiki TP (2 agents merged), instiki FP, instiki REVIEW, pradita TP

    const instikiTp = groups.find((g) => g.tenant_mapped === 'instiki' && g.verdict === 'TRUE_POSITIVE');
    const instikiFp = groups.find((g) => g.tenant_mapped === 'instiki' && g.verdict === 'FALSE_POSITIVE');
    const instikiRev = groups.find((g) => g.tenant_mapped === 'instiki' && g.verdict === 'NEEDS_REVIEW');
    const praditaTp = groups.find((g) => g.tenant_mapped === 'pradita' && g.verdict === 'TRUE_POSITIVE');

    assert.ok(instikiTp && instikiFp && instikiRev && praditaTp);
    // Multi-agent merge within instiki
    assert.equal(instikiTp.alert_count, 2);
    assert.deepEqual(instikiTp.agents.map((a) => a.name).sort(), ['instiki-portal-02', 'instiki-web-01']);
    // Same rule.id (31151) legit vs attack separated
    assert.notEqual(instikiTp.group_id, instikiFp.group_id);
    // Cross-tenant isolation even with same IP & rule.id
    assert.equal(praditaTp.alert_count, 1);
    // Immutable raw_wazuh_alert preserved untouched
    const rawFromGrp = instikiTp.alerts.find((a) => a.alert_id === 'w-tp-instiki-1').raw_wazuh_alert;
    assert.deepEqual(rawFromGrp, rawAttackInstiki1);

    // 5. Realtime Live Feed 1:1 Parity check
    const liveRes = await httpJson(`${baseUrl}/api/triage/live`);
    assert.equal(liveRes.status, 200);
    assert.equal(liveRes.json.totalHits, 6);
    assert.equal(liveRes.json.displayedCount, 6);
    assert.equal(liveRes.json.parityMatch, true);
    const liveExcluded = liveRes.json.items.find((i) => i.alert_id === 'w-excl-login');
    assert.match(liveExcluded.status_label, /Excluded \(Matched Rule: \/login\.php\)/);

    // 6. Manual Merge validation: cross-tenant rejected (400), same-tenant allowed
    const badMerge = await httpJson(`${baseUrl}/api/triage/merge`, {
      method: 'POST',
      body: { groupIds: [instikiTp.group_id, praditaTp.group_id] },
    });
    assert.equal(badMerge.status, 400);
    assert.match(badMerge.json.error, /tenant yang berbeda/i);

    const goodMerge = await httpJson(`${baseUrl}/api/triage/merge`, {
      method: 'POST',
      body: { groupIds: [instikiTp.group_id, instikiRev.group_id] },
    });
    assert.equal(goodMerge.status, 200);
    assert.equal(goodMerge.json.group.alert_count, 3);
    assert.equal(goodMerge.json.group.tenant_mapped, 'instiki');

    // 7. Chunking helper test (> 1000 alerts split into [1000, 50])
    const fake1050 = Array.from({ length: 1050 }, (_, i) => ({ id: i }));
    const chunked = chunkAlertsForPromote(fake1050);
    assert.deepEqual(chunked.map((c) => c.length), [1000, 50]);

    // 8. Promote ("Buat Case") -> Case Audit History + Watermark Reset + On-demand Wazuh Fetch
    const mergedGroupId = goodMerge.json.group.group_id;
    const promoteRes = await httpJson(`${baseUrl}/api/triage/promote`, {
      method: 'POST',
      body: {
        groupId: mergedGroupId,
        workspace: 'soc',
        irisCaseId: '#2712',
        irisTicketNumber: '30100',
        resetWatermark: true,
      },
    });
    assert.equal(promoteRes.status, 200);
    assert.equal(promoteRes.json.tenant, 'instiki');
    assert.equal(promoteRes.json.chunks.length, 1);
    assert.equal(promoteRes.json.chunks[0].length, 3);
    assert.ok(promoteRes.json.watermarkTimestamp);
    // Pre-promote queue cleared by watermark reset
    assert.equal(promoteRes.json.snapshot.groups.length, 0);

    // Case Audit History recorded lightweight wazuh_alert_ids
    const histRes = await httpJson(`${baseUrl}/api/triage/history?q=w-tp-instiki-1`);
    assert.equal(histRes.status, 200);
    assert.equal(histRes.json.items.length, 1);
    assert.equal(histRes.json.items[0].iris_case_id, '#2712');
    assert.equal(histRes.json.items[0].wazuh_alert_ids.length, 3);
    assert.equal(histRes.json.items[0].raw_wazuh_alert, undefined);

    // Live Feed reflects Case Created status (24h scope sees pre-watermark events)
    const live24h = await httpJson(`${baseUrl}/api/triage/live?scope=24h`);
    const promotedLive = live24h.json.items.find((i) => i.alert_id === 'w-tp-instiki-1');
    assert.match(promotedLive.status_label, /Case Created/);

    // On-demand fetch-wazuh from Case History
    const fetchWazuhRes = await httpJson(`${baseUrl}/api/triage/history/${histRes.json.items[0].history_id}/fetch-wazuh`, {
      method: 'POST',
      body: {},
    });
    assert.equal(fetchWazuhRes.status, 200);
    assert.equal(fetchWazuhRes.json.total, 3);

    // 9. Subsequent poll with Ollama down -> fallback NEEDS_REVIEW + Unanalyzed; permanent dedup ignores old IDs
    ollamaMode = 'error';
    const futureAlert = {
      '@timestamp': '2029-11-26T09:30:00.000Z',
      rule: { id: '550', level: 9, description: 'Integrity checksum changed' },
      agent: { id: '004', name: 'instiki-db-04' },
      full_log: 'ossec: File modified /etc/passwd',
    };
    mockWazuhHits.unshift({ _id: 'w-future-1', _source: futureAlert });

    const fallbackPoll = await httpJson(`${baseUrl}/api/triage/worker`, { method: 'POST', body: { action: 'poll_now' } });
    assert.equal(fallbackPoll.status, 200);
    assert.equal(fallbackPoll.json.analyzedCount, 1);
    const fbGrp = fallbackPoll.json.snapshot.groups[0];
    assert.equal(fbGrp.verdict, 'NEEDS_REVIEW');
    assert.equal(fbGrp.unanalyzed, true);

    // Dismiss does NOT advance watermark
    const wmBeforeDismiss = fallbackPoll.json.snapshot.watermarkTimestamp;
    const dismissRes = await httpJson(`${baseUrl}/api/triage/dismiss`, {
      method: 'POST',
      body: { groupIds: [fbGrp.group_id] },
    });
    assert.equal(dismissRes.json.dismissedGroups, 1);
    assert.equal(dismissRes.json.snapshot.watermarkTimestamp, wmBeforeDismiss);

    // Re-poll after dismiss does not bring back w-future-1 (permanent deduplication)
    const rePoll = await httpJson(`${baseUrl}/api/triage/worker`, { method: 'POST', body: { action: 'poll_now' } });
    assert.equal(rePoll.json.analyzedCount, 0);

    // 10. Burst pre-grouping, micro-batch chunking (>15 candidates), Split Alert, & Remove Alert
    ollamaMode = 'smart';
    ollamaRequests = [];
    const burstHits = [];
    // 6 different source IPs hitting SAME (instiki, rule 31151, /.env) -> must pre-group into 1 candidate with <=3 samples
    for (let i = 1; i <= 6; i++) {
      burstHits.push({
        _id: `w-burst-${i}`,
        _source: {
          '@timestamp': `2029-11-26T10:00:0${i}.000Z`,
          rule: { id: '31151', level: 10, description: 'Multiple web server 400 error codes.' },
          agent: { id: `00${i}`, name: `instiki-edge-0${i}` },
          data: { srcip: `198.51.100.${i}`, url: '/.env', http_status: '404' },
          full_log: `198.51.100.${i} "GET /.env HTTP/1.1" 404 "l9scan/${i}.0"`,
        },
      });
    }
    // 16 distinct normalized paths -> combined with burst = 17 candidates -> must split into 2 Ollama calls (15 + 2)
    for (let i = 1; i <= 16; i++) {
      burstHits.push({
        _id: `w-chunk-${i}`,
        _source: {
          '@timestamp': `2029-11-26T10:01:${String(i).padStart(2, '0')}.000Z`,
          rule: { id: '31151', level: 10, description: 'Multiple web server 400 error codes.' },
          agent: { id: '001', name: 'instiki-web-01' },
          data: { srcip: '203.0.113.50', url: `/apps/form/step-${i}?typo-legit=1`, http_status: '400' },
          full_log: `203.0.113.50 "GET /apps/form/step-${i}?typo-legit=1 HTTP/1.1" 400 "Mozilla/5.0"`,
        },
      });
    }
    mockWazuhHits.push(...burstHits);

    const burstPoll = await httpJson(`${baseUrl}/api/triage/worker`, { method: 'POST', body: { action: 'poll_now' } });
    assert.equal(burstPoll.status, 200);
    assert.equal(burstPoll.json.analyzedCount, 22);
    assert.equal(maxConcurrentOllamaCalls, 1);
    assert.equal(ollamaRequests.length, 3); // chunked 8 + 8 + 1

    const burstReqBody = ollamaRequests[0].messages.find((m) => m.role === 'user').content;
    const burstCands = JSON.parse(burstReqBody.slice(burstReqBody.indexOf('Kandidat batch:\n') + 'Kandidat batch:\n'.length));
    const compressedEnvCand = burstCands.find((c) => c.normalized_path === '/.env');
    assert.ok(compressedEnvCand, 'Burst /.env alerts must compress into 1 candidate');
    assert.equal(compressedEnvCand.alert_count, 6);
    assert.equal(compressedEnvCand.source_ip_count, 6);
    assert.ok(compressedEnvCand.source_ips.length <= 5);
    assert.ok(compressedEnvCand.samples.length <= 3);
    assert.equal(compressedEnvCand.http_statuses['404'], 6);

    const tpBurstGroup = burstPoll.json.snapshot.groups.find((g) => g.verdict === 'TRUE_POSITIVE' && g.tenant_mapped === 'instiki');
    assert.ok(tpBurstGroup && tpBurstGroup.alert_count === 6);

    // Split 2 alerts out into a new group
    const wmBeforeSplit = burstPoll.json.snapshot.watermarkTimestamp;
    const splitRes = await httpJson(`${baseUrl}/api/triage/split`, {
      method: 'POST',
      body: { groupId: tpBurstGroup.group_id, alertIds: ['w-burst-1', 'w-burst-2'], incidentTitle: 'Sub-insiden Terpisah' },
    });
    assert.equal(splitRes.status, 200);
    assert.equal(splitRes.json.sourceGroup.alert_count, 4);
    assert.equal(splitRes.json.newGroup.alert_count, 2);
    assert.equal(splitRes.json.newGroup.tenant_mapped, 'instiki');
    assert.equal(splitRes.json.newGroup.incident_title, 'Sub-insiden Terpisah');
    assert.equal(splitRes.json.snapshot.watermarkTimestamp, wmBeforeSplit);

    // Splitting all remaining alerts in a group must fail with 400
    const badSplit = await httpJson(`${baseUrl}/api/triage/split`, {
      method: 'POST',
      body: { groupId: splitRes.json.newGroup.group_id, alertIds: ['w-burst-1', 'w-burst-2'] },
    });
    assert.equal(badSplit.status, 400);

    // Remove 1 alert from split group -> count becomes 1, live feed shows Dismissed
    const remOne = await httpJson(`${baseUrl}/api/triage/remove-alerts`, {
      method: 'POST',
      body: { groupId: splitRes.json.newGroup.group_id, alertIds: ['w-burst-1'] },
    });
    assert.equal(remOne.status, 200);
    assert.equal(remOne.json.removedCount, 1);
    assert.equal(remOne.json.groupRemoved, false);
    assert.equal(remOne.json.group.alert_count, 1);

    const liveAfterRem = await httpJson(`${baseUrl}/api/triage/live?scope=24h`);
    const remLive = liveAfterRem.json.items.find((i) => i.alert_id === 'w-burst-1');
    assert.match(remLive.status_label, /Dismissed/);

    // Remove last alert -> groupRemoved === true & re-poll does not revive w-burst-1/2
    const remLast = await httpJson(`${baseUrl}/api/triage/remove-alerts`, {
      method: 'POST',
      body: { groupId: splitRes.json.newGroup.group_id, alertIds: ['w-burst-2'] },
    });
    assert.equal(remLast.status, 200);
    assert.equal(remLast.json.groupRemoved, true);

    const postRemovePoll = await httpJson(`${baseUrl}/api/triage/worker`, { method: 'POST', body: { action: 'poll_now' } });
    assert.equal(postRemovePoll.json.analyzedCount, 0);

    // 11. Manual Poll Time-Range & Purge Triage Database
    const badRange = await httpJson(`${baseUrl}/api/triage/worker`, {
      method: 'POST',
      body: { action: 'poll_now', range: 'custom', from: '2029-11-26T10:05:00.000Z', to: '2029-11-26T10:00:00.000Z' },
    });
    assert.equal(badRange.status, 400);

    wazuhQueries = [];
    const presetPoll = await httpJson(`${baseUrl}/api/triage/worker`, {
      method: 'POST',
      body: { action: 'poll_now', range: '1h', size: 50 },
    });
    assert.equal(presetPoll.status, 200);
    assert.ok(wazuhQueries.length >= 1);
    const lastTsFilter = wazuhQueries[wazuhQueries.length - 1].body.query.bool.filter.find((f) => f.range?.['@timestamp']);
    assert.ok(lastTsFilter?.range?.['@timestamp']?.gte, 'Preset range must set gte filter');
    assert.equal(lastTsFilter?.range?.['@timestamp']?.lte, undefined);

    const purgeStateRes = await httpJson(`${baseUrl}/api/triage/purge`, {
      method: 'POST',
      body: { clearState: true, includeHistory: false },
    });
    assert.equal(purgeStateRes.status, 200);
    assert.equal(purgeStateRes.json.ok, true);
    assert.equal(purgeStateRes.json.snapshot.groups.length, 0);
    assert.equal(purgeStateRes.json.snapshot.watermarkTimestamp, null);
    assert.equal(purgeStateRes.json.snapshot.historyCount, 1);

    const cfgAfterPurge = await httpJson(`${baseUrl}/api/triage/config`);
    assert.equal(cfgAfterPurge.json.config.wazuh.url, wazuhUrl);

    // Custom time range re-pulls purged alerts in [10:00:00Z .. 10:00:10Z] (the 6 w-burst-* hits)
    const customRePull = await httpJson(`${baseUrl}/api/triage/worker`, {
      method: 'POST',
      body: {
        action: 'poll_now',
        range: 'custom',
        from: '2029-11-26T10:00:00.000Z',
        to: '2029-11-26T10:00:10.000Z',
        size: 20,
      },
    });
    assert.equal(customRePull.status, 200);
    assert.equal(customRePull.json.fetchedCount, 6);
    assert.equal(customRePull.json.analyzedCount, 6);

    // Purge history only -> keeps active triage groups intact
    const purgeHistRes = await httpJson(`${baseUrl}/api/triage/purge`, {
      method: 'POST',
      body: { clearState: false, includeHistory: true },
    });
    assert.equal(purgeHistRes.status, 200);
    assert.equal(purgeHistRes.json.clearedHistory, 1);
    assert.equal(purgeHistRes.json.snapshot.historyCount, 0);
    assert.ok(purgeHistRes.json.snapshot.groups.length >= 1);

    const histAfterPurge = await httpJson(`${baseUrl}/api/triage/history`);
    assert.equal(histAfterPurge.json.items.length, 0);

    // 12. In-flight poll aborted cleanly when purge or pause occurs
    const slowPollPromise = httpJson(`${baseUrl}/api/triage/worker`, {
      method: 'POST',
      body: {
        action: 'poll_now',
        range: 'custom',
        from: '2029-11-26T10:01:00.000Z',
        to: '2029-11-26T10:01:20.000Z',
        size: 50,
      },
    });
    await new Promise((r) => setTimeout(r, 15));
    const abortPurge = await httpJson(`${baseUrl}/api/triage/purge`, {
      method: 'POST',
      body: { clearState: true, includeHistory: false },
    });
    assert.equal(abortPurge.status, 200);
    const slowPollRes = await slowPollPromise;
    assert.equal(slowPollRes.status, 200);
    const afterAbortQueue = await httpJson(`${baseUrl}/api/triage/queue`);
    assert.equal(afterAbortQueue.json.groups.length, 0, 'Aborted in-flight poll must not write back to purged queue');

    // 13. Isolated 24h Batch Pull with progress bar + split/remove/promote/clear (must NOT pollute main AI Triage queue)
    const run24Res = await httpJson(`${baseUrl}/api/triage/batch24h/run`, {
      method: 'POST',
      body: {
        range: 'custom',
        from: '2029-11-26T10:00:00.000Z',
        to: '2029-11-26T10:01:20.000Z',
        size: 100,
      },
    });
    assert.equal(run24Res.status, 202);
    assert.equal(run24Res.json.started, true);

    let snap24 = null;
    for (let i = 0; i < 40; i++) {
      const r = await httpJson(`${baseUrl}/api/triage/batch24h`);
      snap24 = r.json;
      if (snap24.job && snap24.job.running === false) break;
      await new Promise((rWait) => setTimeout(rWait, 40));
    }
    assert.ok(snap24 && snap24.job.phase === 'done', `Expected batch24h done, got ${snap24?.job?.phase}`);
    assert.equal(snap24.job.percent, 100);
    assert.ok(snap24.groups.length >= 2);
    assert.equal(snap24.job.fetchedCount, 22);

    // Main AI Triage queue MUST stay 0 (strictly isolated)
    const mainQueueCheck = await httpJson(`${baseUrl}/api/triage/queue`);
    assert.equal(mainQueueCheck.json.groups.length, 0);

    const tp24 = snap24.groups.find((g) => g.verdict === 'TRUE_POSITIVE');
    assert.ok(tp24 && tp24.alert_count === 6);

    const split24 = await httpJson(`${baseUrl}/api/triage/batch24h/split`, {
      method: 'POST',
      body: { groupId: tp24.group_id, alertIds: ['w-burst-1', 'w-burst-2'], incidentTitle: '24h Split Case' },
    });
    assert.equal(split24.status, 200);
    assert.equal(split24.json.sourceGroup.alert_count, 4);
    assert.equal(split24.json.newGroup.alert_count, 2);

    const rem24 = await httpJson(`${baseUrl}/api/triage/batch24h/remove-alerts`, {
      method: 'POST',
      body: { groupId: split24.json.newGroup.group_id, alertIds: ['w-burst-1'] },
    });
    assert.equal(rem24.status, 200);
    assert.equal(rem24.json.group.alert_count, 1);

    const promo24 = await httpJson(`${baseUrl}/api/triage/batch24h/promote`, {
      method: 'POST',
      body: {
        groupId: split24.json.newGroup.group_id,
        workspace: 'soc',
        irisCaseId: '#9924',
        irisTicketNumber: '30240',
      },
    });
    assert.equal(promo24.status, 200);
    assert.equal(promo24.json.chunks[0].length, 1);

    // Main queue & watermark still untouched after 24h promote
    const mainAfter24Promo = await httpJson(`${baseUrl}/api/triage/queue`);
    assert.equal(mainAfter24Promo.json.groups.length, 0);
    assert.equal(mainAfter24Promo.json.watermarkTimestamp, null);

    const clear24 = await httpJson(`${baseUrl}/api/triage/batch24h/clear`, { method: 'POST', body: {} });
    assert.equal(clear24.status, 200);
    assert.equal(clear24.json.snapshot.groups.length, 0);

    // 14. Live Feed extended time ranges (1h, 7d, custom from/to + size, and invalid custom 400)
    wazuhQueries = [];
    const live1h = await httpJson(`${baseUrl}/api/triage/live?range=1h&size=25`);
    assert.equal(live1h.status, 200);
    assert.equal(live1h.json.range, '1h');
    assert.ok(wazuhQueries.length >= 1);
    assert.equal(wazuhQueries[wazuhQueries.length - 1].body.size, 25);

    const liveCustom = await httpJson(
      `${baseUrl}/api/triage/live?range=custom&from=${encodeURIComponent('2029-11-26T10:00:00.000Z')}&to=${encodeURIComponent('2029-11-26T10:00:10.000Z')}&size=10`,
    );
    assert.equal(liveCustom.status, 200);
    assert.equal(liveCustom.json.totalHits, 6);
    assert.equal(liveCustom.json.items.length, 6);

    const liveBadRange = await httpJson(
      `${baseUrl}/api/triage/live?range=custom&from=${encodeURIComponent('2029-11-26T10:05:00.000Z')}&to=${encodeURIComponent('2029-11-26T10:00:00.000Z')}`,
    );
    assert.equal(liveBadRange.status, 400);

    // 15. deriveExclusionRuleFromAlerts + ignore-exclude (auto rule creation, dedup, queue & batch24h, + Exclusion CRUD)
    const derivedPath = deriveExclusionRuleFromAlerts([
      { raw_wazuh_alert: { data: { url: '/cdn-cgi/rum?foo=1' }, full_log: 'GET /cdn-cgi/rum?foo=1 HTTP/1.1 404', rule: { description: 'Web 404' } } },
      { raw_wazuh_alert: { data: { url: '/cdn-cgi/rum?foo=2' }, full_log: 'GET /cdn-cgi/rum?foo=2 HTTP/1.1 404', rule: { description: 'Web 404' } } },
    ], 'Noise CDN RUM');
    assert.equal(derivedPath.target, 'path');
    assert.equal(derivedPath.mode, 'contains');
    assert.equal(derivedPath.pattern, '/cdn-cgi/rum');

    const derivedLog = deriveExclusionRuleFromAlerts([
      { raw_wazuh_alert: { full_log: '2029-11-26T10:00:00Z systemd: Started Session c991 of user backup.', rule: { description: 'Systemd noise' } } },
      { raw_wazuh_alert: { full_log: '2029-11-26T10:01:00Z systemd: Started Session c992 of user backup.', rule: { description: 'Systemd noise' } } },
    ], 'Systemd session');
    assert.equal(derivedLog.target, 'full_log');
    assert.match(derivedLog.pattern, /Started Session/);

    // Poll burst /.env alerts into main queue, then click "Abaikan + Exclude"
    const beforeIgnorePoll = await httpJson(`${baseUrl}/api/triage/worker`, {
      method: 'POST',
      body: { action: 'poll_now', range: 'custom', from: '2029-11-26T10:00:00.000Z', to: '2029-11-26T10:00:10.000Z', size: 20 },
    });
    assert.equal(beforeIgnorePoll.json.snapshot.groups.length, 1);
    const ignoreTargetGrp = beforeIgnorePoll.json.snapshot.groups[0];

    const ignoreRes = await httpJson(`${baseUrl}/api/triage/ignore-exclude`, {
      method: 'POST',
      body: { groupIds: [ignoreTargetGrp.group_id] },
    });
    assert.equal(ignoreRes.status, 200);
    assert.equal(ignoreRes.json.removedGroups, 1);
    assert.equal(ignoreRes.json.rulesAdded.length, 1);
    assert.equal(ignoreRes.json.rulesAdded[0].pattern, '/.env');
    assert.equal(ignoreRes.json.rulesAdded[0].source, 'auto_ignore');
    assert.equal(ignoreRes.json.snapshot.groups.length, 0);

    // Purge queue and re-poll SAME /.env hits -> must now be auto-excluded (0 analyzed)
    await httpJson(`${baseUrl}/api/triage/purge`, { method: 'POST', body: { clearState: true } });
    const postAutoExcludePoll = await httpJson(`${baseUrl}/api/triage/worker`, {
      method: 'POST',
      body: { action: 'poll_now', range: 'custom', from: '2029-11-26T10:00:00.000Z', to: '2029-11-26T10:00:10.000Z', size: 20 },
    });
    assert.equal(postAutoExcludePoll.status, 200);
    assert.equal(postAutoExcludePoll.json.excludedCount, 6);
    assert.equal(postAutoExcludePoll.json.analyzedCount, 0);

    // Exclusion Rules CRUD (GET, POST manual, PATCH toggle/edit, DELETE)
    const listExRes = await httpJson(`${baseUrl}/api/triage/exclusions`);
    assert.equal(listExRes.status, 200);
    const autoEnvRule = listExRes.json.rules.find((r) => r.pattern === '/.env' && r.source === 'auto_ignore');
    assert.ok(autoEnvRule);

    const addManualEx = await httpJson(`${baseUrl}/api/triage/exclusions`, {
      method: 'POST',
      body: { target: 'path', mode: 'starts_with', pattern: '/healthz', note: 'Probe k8s' },
    });
    assert.equal(addManualEx.status, 201);
    assert.equal(addManualEx.json.rule.source, 'manual');

    // Duplicate rule returns 200 alreadyExisted without creating a duplicate row
    const addDupEx = await httpJson(`${baseUrl}/api/triage/exclusions`, {
      method: 'POST',
      body: { target: 'path', mode: 'starts_with', pattern: '/healthz' },
    });
    assert.equal(addDupEx.status, 200);
    assert.equal(addDupEx.json.alreadyExisted, true);

    const patchEx = await httpJson(`${baseUrl}/api/triage/exclusions/${encodeURIComponent(addManualEx.json.rule.id)}`, {
      method: 'PATCH',
      body: { enabled: false, note: 'Disabled temporary' },
    });
    assert.equal(patchEx.status, 200);
    assert.equal(patchEx.json.rule.enabled, false);
    assert.equal(patchEx.json.rule.note, 'Disabled temporary');

    const delEx = await httpJson(`${baseUrl}/api/triage/exclusions/${encodeURIComponent(addManualEx.json.rule.id)}`, {
      method: 'DELETE',
    });
    assert.equal(delEx.status, 200);
    assert.equal(delEx.json.deletedId, addManualEx.json.rule.id);

    // 16. Wildcard (*) matching on user's 6-endpoint academic pattern & multi-target exclusions
    const academicAlerts = [
      { raw_wazuh_alert: { data: { url: '//mhs/2602020404/pa' } } },
      { raw_wazuh_alert: { data: { url: '/service/mhs/2602020058/ip-kemarin' } } },
      { raw_wazuh_alert: { data: { url: '//mhs/2502020574/pa' } } },
      { raw_wazuh_alert: { data: { url: '//krs/sp/kelas-detil/2502020574' } } },
      { raw_wazuh_alert: { data: { url: '/service/mhs/cek-matkul-ganda' } } },
      { raw_wazuh_alert: { data: { url: '/service/mhs/2502020167/ip-kemarin' } } },
    ];
    const wildRules = deriveExclusionRulesFromAlerts(academicAlerts, 'Academic service 400');
    assert.equal(wildRules.length, 4);
    assert.equal(wildRules.some((r) => r.mode === 'wildcard' && r.pattern === '/service/mhs/*/ip-kemarin'), true);
    assert.equal(wildRules.some((r) => r.mode === 'wildcard' && r.pattern === '//mhs/*/pa'), true);
    assert.equal(wildRules.some((r) => r.mode === 'wildcard' && r.pattern === '//krs/sp/kelas-detil/*'), true);
    assert.equal(wildRules.some((r) => r.mode === 'contains' && r.pattern === '/service/mhs/cek-matkul-ganda'), true);
    assert.equal(evaluateExclusions({ data: { url: '/service/mhs/999999999/ip-kemarin?t=1' } }, wildRules).excluded, true);
    assert.equal(evaluateExclusions({ data: { url: '//mhs/123456/pa' } }, wildRules).excluded, true);
    assert.equal(evaluateExclusions({ data: { url: '//krs/sp/kelas-detil/777777' } }, wildRules).excluded, true);
    assert.equal(evaluateExclusions({ data: { url: '/service/mhs/a/b/ip-kemarin' } }, wildRules).excluded, false);
    assert.equal(evaluateExclusions({ data: { url: '/service/admin/exec' } }, wildRules).excluded, false);

    // Multi-target exclusions: filename, rule_description, rule_id, src_ip, agent_name, user_agent
    assert.equal(evaluateExclusions({ syscheck: { path: '/var/log/nginx/laravel.log' } }, [{ enabled: true, target: 'filename', mode: 'wildcard', pattern: '*.log' }]).excluded, true);
    assert.equal(evaluateExclusions({ rule: { id: '31151', description: 'Multiple web server 400 error codes.' } }, [{ enabled: true, target: 'rule_description', mode: 'wildcard', pattern: '*400 error*' }]).excluded, true);
    assert.equal(evaluateExclusions({ rule: { id: '31151' } }, [{ enabled: true, target: 'rule_id', mode: 'contains', pattern: '31151' }]).excluded, true);
    assert.equal(evaluateExclusions({ data: { srcip: '10.20.30.40', http_user_agent: 'HealthCheckBot/2.1' }, agent: { name: 'siakad-app-01' } }, [
      { enabled: true, target: 'src_ip', mode: 'wildcard', pattern: '10.20.*' },
    ]).excluded, true);
    assert.equal(evaluateExclusions({ agent: { name: 'siakad-app-01' } }, [{ enabled: true, target: 'agent_name', mode: 'wildcard', pattern: 'siakad-*' }]).excluded, true);
    assert.equal(evaluateExclusions({ data: { http_user_agent: 'HealthCheckBot/2.1' } }, [{ enabled: true, target: 'user_agent', mode: 'contains', pattern: 'HealthCheckBot' }]).excluded, true);

    // 17. Exclude Preview Suggest, AI Analyze Suggest & Explicit Rules Confirm Flow
    await httpJson(`${baseUrl}/api/triage/purge`, { method: 'POST', body: { clearState: true } });
    mockWazuhHits.push({
      _id: 'w-wild-1',
      _source: {
        '@timestamp': '2029-11-26T10:15:00.000Z',
        rule: { id: '31151', level: 8, description: 'Academic 404 probe' },
        agent: { id: '009', name: 'instiki-web-09' },
        data: { srcip: '10.10.2.5', url: '/service/mhs/2602020058/ip-kemarin', http_status: '400' },
        full_log: '10.10.2.5 "GET /service/mhs/2602020058/ip-kemarin HTTP/1.1" 400 "typo-legit"',
      },
    });
    const wildPoll = await httpJson(`${baseUrl}/api/triage/worker`, {
      method: 'POST',
      body: { action: 'poll_now', range: 'custom', from: '2029-11-26T10:14:00.000Z', to: '2029-11-26T10:16:00.000Z', size: 10 },
    });
    assert.equal(wildPoll.json.snapshot.groups.length, 1);
    const wildGrp = wildPoll.json.snapshot.groups[0];

    const suggestRes = await httpJson(`${baseUrl}/api/triage/exclusions/suggest`, {
      method: 'POST',
      body: { source: 'queue', groupIds: [wildGrp.group_id] },
    });
    assert.equal(suggestRes.status, 200);
    assert.equal(suggestRes.json.rules[0].mode, 'wildcard');
    assert.equal(suggestRes.json.rules[0].pattern, '/service/mhs/*/ip-kemarin');

    const aiSuggestRes = await httpJson(`${baseUrl}/api/triage/exclusions/ai-suggest`, {
      method: 'POST',
      body: { source: 'queue', groupIds: [wildGrp.group_id] },
    });
    assert.equal(aiSuggestRes.status, 200);
    assert.ok(aiSuggestRes.json.reasoning);
    assert.equal(aiSuggestRes.json.rules.some((r) => r.target === 'rule_description'), true);

    const confirmExplicit = await httpJson(`${baseUrl}/api/triage/ignore-exclude`, {
      method: 'POST',
      body: {
        groupIds: [wildGrp.group_id],
        rules: [{ target: 'path', mode: 'wildcard', pattern: '/service/mhs/*/ip-kemarin', note: 'Disetujui analis' }],
      },
    });
    assert.equal(confirmExplicit.status, 200);
    assert.equal(confirmExplicit.json.rulesAdded[0].pattern, '/service/mhs/*/ip-kemarin');
    assert.equal(confirmExplicit.json.rulesAdded[0].mode, 'wildcard');

    // 18. Truncated JSON salvage & auto-retry fallback from strict schema to format:"json" (0 Unanalyzed)
    await httpJson(`${baseUrl}/api/triage/purge`, { method: 'POST', body: { clearState: true } });
    mockWazuhHits.push(
      {
        _id: 'w-trunc-1',
        _source: {
          '@timestamp': '2029-11-26T10:20:00.000Z',
          rule: { id: '31151', level: 8, description: 'Truncated test 1' },
          agent: { id: '011', name: 'instiki-web-11' },
          data: { srcip: '10.10.2.9', url: '/apps/form/ok-1' },
          full_log: 'GET /apps/form/ok-1 HTTP/1.1 400 typo-legit',
        },
      },
      {
        _id: 'w-trunc-2',
        _source: {
          '@timestamp': '2029-11-26T10:20:05.000Z',
          rule: { id: '31151', level: 9, description: 'Truncated test 2' },
          agent: { id: '011', name: 'instiki-web-11' },
          data: { srcip: '10.10.2.9', url: '/apps/form/ok-2' },
          full_log: 'GET /apps/form/ok-2 HTTP/1.1 400 typo-legit',
        },
      },
    );
    ollamaMode = 'truncated_once';
    const truncRes = await httpJson(`${baseUrl}/api/triage/worker`, {
      method: 'POST',
      body: { action: 'poll_now', range: 'custom', from: '2029-11-26T10:19:50.000Z', to: '2029-11-26T10:20:20.000Z', size: 10 },
    });
    assert.equal(truncRes.status, 200);
    assert.equal(truncRes.json.analyzedCount, 2);
    assert.equal(truncRes.json.snapshot.groups.some((g) => g.unanalyzed), false);

    await httpJson(`${baseUrl}/api/triage/purge`, { method: 'POST', body: { clearState: true } });
    ollamaMode = 'bad_schema_json_retry';
    const retryRes = await httpJson(`${baseUrl}/api/triage/worker`, {
      method: 'POST',
      body: { action: 'poll_now', range: 'custom', from: '2029-11-26T10:19:50.000Z', to: '2029-11-26T10:20:20.000Z', size: 10 },
    });
    assert.equal(retryRes.status, 200);
    assert.equal(retryRes.json.analyzedCount, 2);
    assert.equal(retryRes.json.snapshot.groups.some((g) => g.unanalyzed), false);

    // 19. Separate Ollama settings update preserves Wazuh/Exclusions & forwards custom inference params
    const saveOllamaOnly = await httpJson(`${baseUrl}/api/triage/config`, {
      method: 'POST',
      body: {
        ollama: {
          numCtx: 16384,
          numPredict: 3072,
          topP: 0.9,
          topK: 40,
          repeatPenalty: 1.1,
          microBatchSize: 4,
          timeoutSec: 120,
          keepAlive: '5m',
          think: true,
          useJsonSchema: false,
        },
      },
    });
    assert.equal(saveOllamaOnly.status, 200);
    assert.equal(saveOllamaOnly.json.config.wazuh.url, wazuhUrl);
    assert.ok(saveOllamaOnly.json.config.exclusionRules.length >= 1);
    assert.equal(saveOllamaOnly.json.config.ollama.numCtx, 16384);
    assert.equal(saveOllamaOnly.json.config.ollama.numPredict, 3072);
    assert.equal(saveOllamaOnly.json.config.ollama.useJsonSchema, false);

    await httpJson(`${baseUrl}/api/triage/purge`, { method: 'POST', body: { clearState: true } });
    ollamaMode = 'smart';
    ollamaRequests = [];
    const customParamPoll = await httpJson(`${baseUrl}/api/triage/worker`, {
      method: 'POST',
      body: { action: 'poll_now', range: 'custom', from: '2029-11-26T10:19:50.000Z', to: '2029-11-26T10:20:20.000Z', size: 10 },
    });
    assert.equal(customParamPoll.status, 200);
    assert.equal(ollamaRequests.length, 1);
    const customReq = ollamaRequests[0];
    assert.equal(customReq.options.num_ctx, 16384);
    assert.equal(customReq.options.num_predict, 3072);
    assert.equal(customReq.options.top_p, 0.9);
    assert.equal(customReq.options.top_k, 40);
    assert.equal(customReq.options.repeat_penalty, 1.1);
    assert.equal(customReq.keep_alive, '5m');
    assert.equal(customReq.think, true);
    assert.equal(customReq.format, 'json');

    // 20) Official Wazuh severity scale, tenant-scoped exclusions & IKMI multi-condition AND-lock regression
    await httpJson(`${baseUrl}/api/triage/purge`, { method: 'POST', body: { clearState: true } });
    ollamaMode = 'smart';
    ollamaRequests = [];
    mockWazuhHits.push(
      {
        _id: 'ikmi-sev10',
        _source: {
          '@timestamp': '2029-11-26T10:25:01.000Z',
          agent: { id: '201', name: 'srv-indigoes', labels: { tenant: 'ikmicirebon' } },
          rule: { id: '31151', level: 10, description: 'Multiple web server 400 error codes from same source ip.' },
          data: { srcip: '203.0.113.55', id: '404', url: '/tentang-kampus' },
          full_log: '203.0.113.55 - - [26/Nov/2029:10:25:01] "GET /tentang-kampus HTTP/1.1" 404 512 "-" "Mozilla/5.0"',
        },
      },
    );
    const sevPoll = await httpJson(`${baseUrl}/api/triage/worker`, {
      method: 'POST',
      body: { action: 'poll_now', range: 'custom', from: '2029-11-26T10:24:50.000Z', to: '2029-11-26T10:25:10.000Z', size: 10 },
    });
    assert.equal(sevPoll.status, 200);
    const sevWs = sevPoll.json?.snapshot?.workerStatus || {};
    assert.equal(sevWs.running, false);
    assert.equal(sevWs.phase, 'done');
    assert.equal(sevWs.aiActive, false);
    assert.ok(sevWs.lastBatchCount >= 1);
    assert.ok(sevWs.lastAnalyzedCount >= 1);
    assert.equal(typeof sevWs.lastDurationMs, 'number');
    assert.ok(String(sevWs.aiModel || '').length > 0);
    assert.equal(ollamaRequests.length, 1);
    const sevSys = ollamaRequests[0].messages.find((m) => m.role === 'system')?.content || '';
    const sevUser = ollamaRequests[0].messages.find((m) => m.role === 'user')?.content || '';
    assert.ok(sevSys.includes('Level 7–11: Medium'), 'System prompt must state Level 7-11 is Medium');
    assert.ok(sevUser.includes('"severity_label":"Medium"'), 'Candidate payload must tag level 10 as Medium');

    // Auto-derive IKMI /mod/quiz/edit.php exclusion scoped to ikmicirebon with AND locks
    const quizSuggest = await httpJson(`${baseUrl}/api/triage/exclusions/suggest`, {
      method: 'POST',
      body: {
        source: 'live',
        title: 'High amount of POST requests',
        rawAlerts: [
          {
            _id: 'ikmi-quiz-1',
            agent: { name: 'srv-indigoes', labels: { tenant: 'ikmicirebon' } },
            rule: { id: '31154', level: 10, description: 'High amount of POST requests in a small period of time.' },
            data: { srcip: '36.70.1.9', id: '303', url: '/mod/quiz/edit.php?cmid=442' },
            full_log: '36.70.1.9 - - [26/Nov/2029:10:26:00] "POST /mod/quiz/edit.php?cmid=442 HTTP/1.1" 303 0 "https://indigoes.ikmi.ac.id/mod/quiz/view.php" "Mozilla/5.0"',
          },
        ],
      },
    });
    assert.equal(quizSuggest.status, 200);
    assert.equal(quizSuggest.json.tenant, 'ikmicirebon');
    const quizRule = quizSuggest.json.rules[0];
    assert.equal(quizRule.tenant, 'ikmicirebon');
    assert.deepEqual(quizRule.ruleIds, ['31154']);
    assert.deepEqual(quizRule.httpStatuses, ['303']);
    assert.equal(quizRule.referer, 'indigoes.ikmi.ac.id');

    // Create IKMI locked exclusion rules and test against live Wazuh feed
    const ikmiRulesToAdd = [
      quizRule,
      {
        tenant: 'ikmicirebon',
        target: 'path',
        mode: 'wildcard',
        pattern: '/cms/login*',
        ruleIds: ['31151'],
        httpStatuses: ['419'],
        note: 'IKMI CSRF expired only',
      },
      {
        tenant: 'ikmicirebon',
        target: 'path',
        mode: 'wildcard',
        pattern: '/webservice/rest/server.php*wsfunction=core_course_view_course*',
        ruleIds: ['31153', '31154'],
        httpStatuses: ['200'],
        userAgent: 'MoodleMobile',
        note: 'IKMI MoodleMobile REST API',
      },
      {
        tenant: 'ikmicirebon',
        target: 'path',
        mode: 'wildcard',
        pattern: '/cms/apicms_ikmi_v2.php*',
        ruleIds: ['31153', '31154'],
        httpStatuses: ['200'],
        srcIps: ['123.253.78.156'],
        note: 'IKMI internal gateway SIAKAD sync',
      },
    ];
    for (const r of ikmiRulesToAdd) {
      const addRes = await httpJson(`${baseUrl}/api/triage/exclusions`, { method: 'POST', body: r });
      assert.ok(addRes.status === 200 || addRes.status === 201);
    }

    mockWazuhHits.push(
      // Excluded: IKMI MoodleMobile 200 OK rate rule
      {
        _id: 'ikmi-mob-ok',
        _source: {
          '@timestamp': '2029-11-26T10:26:10.000Z',
          agent: { name: 'srv-indigoes', labels: { tenant: 'ikmicirebon' } },
          rule: { id: '31153', level: 10, description: 'High amount of POST requests.' },
          data: { srcip: '114.5.10.2', id: '200', url: '/webservice/rest/server.php?wsfunction=core_course_view_course' },
          full_log: '114.5.10.2 - - [26/Nov/2029:10:26:10] "POST /webservice/rest/server.php?wsfunction=core_course_view_course HTTP/1.1" 200 900 "-" "MoodleMobile/4.3"',
        },
      },
      // NOT Excluded: Same path & MoodleMobile UA & HTTP 200, but SQLi signature rule 31103!
      {
        _id: 'ikmi-sqli-blindspot-check',
        _source: {
          '@timestamp': '2029-11-26T10:26:11.000Z',
          agent: { name: 'srv-indigoes', labels: { tenant: 'ikmicirebon' } },
          rule: { id: '31103', level: 12, description: 'SQL injection attempt.' },
          data: { srcip: '185.10.1.9', id: '200', url: '/webservice/rest/server.php?wsfunction=core_course_view_course' },
          full_log: '185.10.1.9 - - [26/Nov/2029:10:26:11] "POST /webservice/rest/server.php?wsfunction=core_course_view_course HTTP/1.1" 200 900 "-" "MoodleMobile/4.3"',
        },
      },
      // NOT Excluded: Same path & rule 31153 & HTTP 200, but python-requests bot UA!
      {
        _id: 'ikmi-bot-ua',
        _source: {
          '@timestamp': '2029-11-26T10:26:12.000Z',
          agent: { name: 'srv-indigoes', labels: { tenant: 'ikmicirebon' } },
          rule: { id: '31153', level: 10, description: 'High amount of POST requests.' },
          data: { srcip: '185.10.1.9', id: '200', url: '/webservice/rest/server.php?wsfunction=core_course_view_course' },
          full_log: '185.10.1.9 - - [26/Nov/2029:10:26:12] "POST /webservice/rest/server.php?wsfunction=core_course_view_course HTTP/1.1" 200 900 "-" "python-requests/2.31"',
        },
      },
      // Excluded: IKMI /cms/login 419 CSRF
      {
        _id: 'ikmi-login-419',
        _source: {
          '@timestamp': '2029-11-26T10:26:13.000Z',
          agent: { name: 'srv-indigoes', labels: { tenant: 'ikmicirebon' } },
          rule: { id: '31151', level: 10, description: 'Multiple web server 400 error codes.' },
          data: { srcip: '36.70.1.9', id: '419', url: '/cms/login' },
          full_log: '36.70.1.9 - - [26/Nov/2029:10:26:13] "POST /cms/login HTTP/1.1" 419 420 "-" "Mozilla/5.0"',
        },
      },
      // NOT Excluded: IKMI /cms/login 401 Brute Force
      {
        _id: 'ikmi-login-401',
        _source: {
          '@timestamp': '2029-11-26T10:26:14.000Z',
          agent: { name: 'srv-indigoes', labels: { tenant: 'ikmicirebon' } },
          rule: { id: '31151', level: 10, description: 'Multiple web server 400 error codes.' },
          data: { srcip: '45.10.20.30', id: '401', url: '/cms/login' },
          full_log: '45.10.20.30 - - [26/Nov/2029:10:26:14] "POST /cms/login HTTP/1.1" 401 420 "-" "Mozilla/5.0"',
        },
      },
      // NOT Excluded: Different tenant (instiki) with exact same /cms/login + 419!
      {
        _id: 'instiki-login-419',
        _source: {
          '@timestamp': '2029-11-26T10:26:15.000Z',
          agent: { name: 'srv-instiki', labels: { tenant: 'instiki' } },
          rule: { id: '31151', level: 10, description: 'Multiple web server 400 error codes.' },
          data: { srcip: '36.70.1.9', id: '419', url: '/cms/login' },
          full_log: '36.70.1.9 - - [26/Nov/2029:10:26:15] "POST /cms/login HTTP/1.1" 419 420 "-" "Mozilla/5.0"',
        },
      },
      // Excluded: IKMI internal gateway /cms/apicms_ikmi_v2.php
      {
        _id: 'ikmi-apicms-gw',
        _source: {
          '@timestamp': '2029-11-26T10:26:16.000Z',
          agent: { name: 'srv-indigoes', labels: { tenant: 'ikmicirebon' } },
          rule: { id: '31153', level: 10, description: 'High amount of POST requests.' },
          data: { srcip: '123.253.78.156', id: '200', url: '/cms/apicms_ikmi_v2.php?sync=1' },
          full_log: '123.253.78.156 - - [26/Nov/2029:10:26:16] "POST /cms/apicms_ikmi_v2.php?sync=1 HTTP/1.1" 200 120 "-" "curl/8.0"',
        },
      },
      // NOT Excluded: External scraper IP on /cms/apicms_ikmi_v2.php
      {
        _id: 'ikmi-apicms-ext',
        _source: {
          '@timestamp': '2029-11-26T10:26:17.000Z',
          agent: { name: 'srv-indigoes', labels: { tenant: 'ikmicirebon' } },
          rule: { id: '31153', level: 10, description: 'High amount of POST requests.' },
          data: { srcip: '45.10.20.30', id: '200', url: '/cms/apicms_ikmi_v2.php?sync=1' },
          full_log: '45.10.20.30 - - [26/Nov/2029:10:26:17] "POST /cms/apicms_ikmi_v2.php?sync=1 HTTP/1.1" 200 120 "-" "curl/8.0"',
        },
      },
    );

    const feedRes = await httpJson(
      `${baseUrl}/api/triage/live?range=custom&from=2029-11-26T10:26:05.000Z&to=2029-11-26T10:26:25.000Z&size=50`,
    );
    assert.equal(feedRes.status, 200);
    const byId = new Map(feedRes.json.items.map((it) => [it.alert_id, it]));
    assert.equal(byId.get('ikmi-mob-ok').status_code, 'excluded');
    assert.notEqual(byId.get('ikmi-sqli-blindspot-check').status_code, 'excluded', 'SQLi signature rule must NEVER be excluded');
    assert.notEqual(byId.get('ikmi-bot-ua').status_code, 'excluded', 'External bot UA must NOT match MoodleMobile lock');
    assert.equal(byId.get('ikmi-login-419').status_code, 'excluded');
    assert.notEqual(byId.get('ikmi-login-401').status_code, 'excluded', '401 brute force on /cms/login must NOT be excluded');
    assert.notEqual(byId.get('instiki-login-419').status_code, 'excluded', 'ikmicirebon rule must NOT exclude instiki tenant');
    assert.equal(byId.get('ikmi-apicms-gw').status_code, 'excluded');
    assert.notEqual(byId.get('ikmi-apicms-ext').status_code, 'excluded', 'External IP on apicms must NOT match gateway IP lock');

    // Poll one excluded hit so excludedAlertMap & topExcludedRules are populated for stats verification
    const statPoll = await httpJson(`${baseUrl}/api/triage/worker`, {
      method: 'POST',
      body: { action: 'poll_now', range: 'custom', from: '2029-11-26T10:26:05.000Z', to: '2029-11-26T10:26:25.000Z', size: 50 },
    });
    assert.equal(statPoll.status, 200);

    const statsRes = await httpJson(`${baseUrl}/api/triage/stats`);
    assert.equal(statsRes.status, 200);
    assert.equal(statsRes.json.ok, true);
    assert.ok(statsRes.json.summary.aiTriagedAlerts >= 1);
    assert.ok(statsRes.json.summary.casesCreated >= 1);
    assert.ok(statsRes.json.summary.caseAlerts >= 1);
    assert.ok(statsRes.json.summary.excludedAlerts >= 1);
    assert.ok(Array.isArray(statsRes.json.perTenant));
    assert.ok(Array.isArray(statsRes.json.topExcludedRules) && statsRes.json.topExcludedRules.length >= 1);

    console.log('ALL_TRIAGE_TESTS_PASSED (20/20)');
  } finally {
    await new Promise((r) => server.close(r));
    await new Promise((r) => mockWazuh.close(r));
    await new Promise((r) => mockOllama.close(r));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

