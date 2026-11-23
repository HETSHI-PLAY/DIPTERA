'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const { createServer } = require('../server.js');

function req(port, method, urlPath, body, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const payload = body !== undefined ? JSON.stringify(body) : null;
    const headers = payload
      ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload), ...extraHeaders }
      : { ...extraHeaders };
    const r = http.request({ hostname: '127.0.0.1', port, path: urlPath, method, headers }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch {}
        resolve({ status: res.statusCode, headers: res.headers, text: data, json });
      });
    });
    r.on('error', reject);
    if (payload) r.write(payload);
    r.end();
  });
}

(async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'diptera-approvals-test-'));
  const mockWebhookCalls = [];
  let mockBehavior = { status: 200, body: { resumed: true } };

  // Mock n8n webhook-waiting server
  const mockN8n = http.createServer((mReq, mRes) => {
    const chunks = [];
    mReq.on('data', (c) => chunks.push(c));
    mReq.on('end', () => {
      const rawBody = Buffer.concat(chunks).toString('utf8');
      let parsedBody = null;
      try { parsedBody = rawBody ? JSON.parse(rawBody) : null; } catch {}
      const u = new URL(mReq.url, 'http://127.0.0.1');
      mockWebhookCalls.push({
        method: mReq.method,
        pathname: u.pathname,
        query: Object.fromEntries(u.searchParams.entries()),
        body: parsedBody,
      });
      const respStr = JSON.stringify(mockBehavior.body);
      mRes.writeHead(mockBehavior.status, {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(respStr),
      });
      mRes.end(respStr);
    });
  });

  await new Promise((r) => mockN8n.listen(0, '127.0.0.1', r));
  const mockPort = mockN8n.address().port;
  const mockBase = `http://127.0.0.1:${mockPort}`;

  const server = createServer({
    dataDir: tmpDir,
    env: {
      DEFAULT_WORKSPACE: 'asoc',
      ASOC_N8N_BASE_URL: mockBase,
      ASOC_FORM_PATH: 'alpha-form',
      ASOC_IRIS_BASE_URL: 'https://10.20.100.66',
    },
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  // Separate server with security flags enabled (secret + allowed hosts)
  const secTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'diptera-approvals-sec-'));
  const secServer = createServer({
    dataDir: secTmpDir,
    env: {
      APPROVAL_API_SECRET: 'super-secret-token',
      APPROVAL_ALLOWED_HOSTS: `127.0.0.1:${mockPort}`,
    },
  });
  await new Promise((r) => secServer.listen(0, '127.0.0.1', r));
  const secPort = secServer.address().port;

  try {
    // 1. Intake validation, persistence, history linkage, and retry deduplication
    const badMissing = await req(port, 'POST', '/api/approvals', { caseName: 'No Resume URL' });
    assert.equal(badMissing.status, 400);

    const badScheme = await req(port, 'POST', '/api/approvals', { resumeUrl: 'ftp://example.com/hook' });
    assert.equal(badScheme.status, 400);

    const jobRes = await req(port, 'POST', '/api/history', {
      id: 'job_appr_test_1',
      workspace: 'asoc',
      mode: 'reporting',
      tenant: 'petra',
      ticketNumber: '30140',
      irisCaseId: '#412',
      status: 'running',
    });
    assert.equal(jobRes.status, 201);

    const resumeUrl1 = `${mockBase}/webhook-waiting/exec-101`;
    const created1 = await req(port, 'POST', '/api/approvals', {
      resumeUrl: resumeUrl1,
      workspace: 'asoc',
      workflowName: 'Alpha Reporter v2',
      execId: '101',
      jobId: 'job_appr_test_1',
      caseId: 412,
      caseName: '[HIGH] SQL Injection on Portal',
      tenant: 'petra',
      clientName: 'Petra University',
      ticketNumber: '30140',
      severity: 'HIGH',
      classification: 'True Positive',
      summary: 'Terdeteksi SQL Injection ke endpoint login.',
      markdown: '## 1. RINGKASAN INSIDEN\nTerdeteksi SQL Injection.',
      deadlineAt: new Date(Date.now() + 3600 * 1000).toISOString(),
    });
    assert.equal(created1.status, 201);
    assert.equal(created1.json.ok, true);
    assert.equal(created1.json.deduplicated, false);
    const apr1Id = created1.json.approval.id;
    assert.equal(created1.json.approval.irisCaseId, '#412');
    assert.equal(created1.json.approval.status, 'pending');
    assert.equal(created1.json.approval.attempt, 1);

    // Verify approvals.json persisted & /api/state reflects pending count & history linked
    const approvalsFile = JSON.parse(fs.readFileSync(path.join(tmpDir, 'approvals.json'), 'utf8'));
    assert.equal(approvalsFile.length, 1);
    assert.equal(approvalsFile[0].id, apr1Id);

    const st1 = await req(port, 'GET', '/api/state');
    assert.equal(st1.status, 200);
    assert.equal(st1.json.approvals.pending, 1);

    const hist1 = await req(port, 'GET', '/api/history/job_appr_test_1');
    assert.equal(hist1.json.record.approvalId, apr1Id);
    assert.equal(hist1.json.record.approvalStatus, 'pending');

    // Deduplicate retry on identical pending resumeUrl
    const dedup = await req(port, 'POST', '/api/approvals', {
      resumeUrl: resumeUrl1,
      summary: 'Ringkasan diperbarui',
    });
    assert.equal(dedup.status, 200);
    assert.equal(dedup.json.deduplicated, true);
    assert.equal(dedup.json.approval.id, apr1Id);
    assert.equal(dedup.json.approval.summary, 'Ringkasan diperbarui');

    // 2. Approve decision proxies POST to n8n resumeUrl, updates status/history, blocks double decide
    const approveRes = await req(port, 'POST', `/api/approvals/${apr1Id}/decide`, {
      decision: 'approve',
      reason: 'Sudah diverifikasi oleh tim',
      decidedBy: 'Budi',
    });
    assert.equal(approveRes.status, 200);
    assert.equal(approveRes.json.ok, true);
    assert.equal(approveRes.json.approval.status, 'approved');
    assert.equal(approveRes.json.approval.decidedBy, 'Budi');
    assert.equal(approveRes.json.n8nStatus, 200);

    assert.equal(mockWebhookCalls.length, 1);
    assert.equal(mockWebhookCalls[0].method, 'POST');
    assert.equal(mockWebhookCalls[0].pathname, '/webhook-waiting/exec-101');
    assert.equal(mockWebhookCalls[0].body.approvalId, apr1Id);
    assert.equal(mockWebhookCalls[0].body.decision, 'approve');
    assert.equal(mockWebhookCalls[0].body.approved, true);
    assert.equal(mockWebhookCalls[0].body['Approval Status'], '✅ Approve');
    assert.equal(mockWebhookCalls[0].body.reason, 'Sudah diverifikasi oleh tim');
    assert.equal(mockWebhookCalls[0].body.decidedBy, 'Budi');

    const histAfterApprove = await req(port, 'GET', '/api/history/job_appr_test_1');
    assert.equal(histAfterApprove.json.record.approvalStatus, 'approved');

    // Double decide returns 409 Conflict and does NOT call n8n again
    const doubleRes = await req(port, 'POST', `/api/approvals/${apr1Id}/decide`, { decision: 'deny' });
    assert.equal(doubleRes.status, 409);
    assert.equal(mockWebhookCalls.length, 1);

    // 3. Deny + Rejection notification + Re-approval loop creates attempt #2 and auto-resolves open rejections
    const rejJobRes = await req(port, 'POST', '/api/history', {
      id: 'job_rej_test_1',
      workspace: 'asoc',
      mode: 'reporting',
      tenant: 'sgu',
      ticketNumber: '40030',
      irisCaseId: '#413',
      status: 'running',
    });
    assert.equal(rejJobRes.status, 201);

    const resumeUrl2 = `${mockBase}/webhook-waiting/exec-202`;
    const created2 = await req(port, 'POST', '/api/approvals', {
      resumeUrl: resumeUrl2,
      execId: '202',
      jobId: 'job_rej_test_1',
      caseId: 413,
      caseName: '[MEDIUM] Suspicious PowerShell',
      tenant: 'sgu',
      severity: 'MEDIUM',
    });
    assert.equal(created2.status, 201);
    const apr2Id = created2.json.approval.id;

    const denyRes = await req(port, 'POST', `/api/approvals/${apr2Id}/decide`, {
      decision: 'deny',
      reason: 'Perlu lengkapi bagian rekomendasi',
      decidedBy: 'Ani',
    });
    assert.equal(denyRes.status, 200);
    assert.equal(denyRes.json.approval.status, 'denied');
    assert.equal(mockWebhookCalls[1].body.decision, 'deny');
    assert.equal(mockWebhookCalls[1].body.approved, false);
    assert.equal(mockWebhookCalls[1].body['Approval Status'], '❌ Decline');

    // Diptera - Inform Rejection webhook call -> POST /api/rejections
    const rejCreate1 = await req(port, 'POST', '/api/rejections', {
      workspace: 'asoc',
      approvalId: apr2Id,
      jobId: 'job_rej_test_1',
      execId: '202',
      caseId: 413,
      caseName: '[MEDIUM] Suspicious PowerShell',
      caseUrl: 'https://10.20.100.66/case?cid=413',
      tenant: 'sgu',
      clientName: 'SGU',
      ticketNumber: '40030',
      severity: 'MEDIUM',
      classification: 'True Positive',
      reason: 'Perlu lengkapi bagian rekomendasi',
      decidedBy: 'Ani',
      retryInMinutes: 10,
    });
    assert.equal(rejCreate1.status, 201);
    assert.equal(rejCreate1.json.ok, true);
    assert.equal(rejCreate1.json.case_id, '413');
    const rej1Id = rejCreate1.json.rejection.id;
    assert.equal(rejCreate1.json.rejection.status, 'open');

    const rejectionsFile = JSON.parse(fs.readFileSync(path.join(tmpDir, 'rejections.json'), 'utf8'));
    assert.equal(rejectionsFile.length, 1);
    assert.equal(rejectionsFile[0].id, rej1Id);

    const stRej1 = await req(port, 'GET', '/api/state');
    assert.equal(stRej1.json.rejections.open, 1);
    assert.equal(stRej1.json.rejections.openItems[0].id, rej1Id);

    const apr2Linked = await req(port, 'GET', `/api/approvals/${apr2Id}`);
    assert.equal(apr2Linked.json.approval.rejectionId, rej1Id);
    assert.equal(apr2Linked.json.approval.rejectionStatus, 'open');

    const histRejLinked = await req(port, 'GET', '/api/history/job_rej_test_1');
    assert.equal(histRejLinked.json.record.rejectionId, rej1Id);
    assert.equal(histRejLinked.json.record.rejectionReason, 'Perlu lengkapi bagian rekomendasi');

    // Acknowledge rejection
    const ackRes = await req(port, 'PATCH', `/api/rejections/${rej1Id}`, {
      status: 'acknowledged',
      acknowledgedBy: 'Analis-1',
    });
    assert.equal(ackRes.status, 200);
    assert.equal(ackRes.json.rejection.status, 'acknowledged');
    assert.equal(ackRes.json.rejection.acknowledgedBy, 'Analis-1');
    const stRejAfterAck = await req(port, 'GET', '/api/state');
    assert.equal(stRejAfterAck.json.rejections.open, 0);
    const apr2AfterAck = await req(port, 'GET', `/api/approvals/${apr2Id}`);
    assert.equal(apr2AfterAck.json.approval.rejectionStatus, 'acknowledged');

    // Second open rejection should auto-resolve when re-approval request arrives
    const rejCreate2 = await req(port, 'POST', '/api/rejections', {
      workspace: 'asoc',
      approvalId: apr2Id,
      jobId: 'job_rej_test_1',
      execId: '202',
      caseId: 413,
      reason: 'Masih ada bagian yang perlu dicek ulang',
    });
    assert.equal(rejCreate2.status, 201);
    const rej2Id = rejCreate2.json.rejection.id;
    assert.equal((await req(port, 'GET', '/api/state')).json.rejections.open, 1);

    // Re-approval request after Wait 10 Minutes with same execId & resumeUrl
    const reapproval = await req(port, 'POST', '/api/approvals', {
      resumeUrl: resumeUrl2,
      execId: '202',
      jobId: 'job_rej_test_1',
      caseId: 413,
      caseName: '[MEDIUM] Suspicious PowerShell (Revisi)',
      tenant: 'sgu',
      severity: 'MEDIUM',
    });
    assert.equal(reapproval.status, 201);
    assert.equal(reapproval.json.deduplicated, false);
    assert.notEqual(reapproval.json.approval.id, apr2Id);
    assert.equal(reapproval.json.approval.attempt, 2);
    assert.equal(reapproval.json.approval.status, 'pending');

    const rej2Resolved = await req(port, 'GET', `/api/rejections/${rej2Id}`);
    assert.equal(rej2Resolved.json.rejection.status, 'resolved');
    assert.equal(rej2Resolved.json.rejection.resolvedReason, 'reapproval_requested');
    assert.equal((await req(port, 'GET', '/api/state')).json.rejections.open, 0);

    // 4. GET resume method appends query parameters
    const createdGet = await req(port, 'POST', '/api/approvals', {
      resumeUrl: `${mockBase}/webhook-waiting/exec-get-303`,
      resumeMethod: 'GET',
      workspace: 'soc',
      caseName: '[LOW] GET Method Check',
      severity: 'LOW',
    });
    assert.equal(createdGet.status, 201);
    const aprGetId = createdGet.json.approval.id;
    const decideGet = await req(port, 'POST', `/api/approvals/${aprGetId}/decide`, {
      decision: 'approve',
      reason: 'LGTM',
      decidedBy: 'Citra',
    });
    assert.equal(decideGet.status, 200);
    const getCall = mockWebhookCalls[mockWebhookCalls.length - 1];
    assert.equal(getCall.method, 'GET');
    assert.equal(getCall.pathname, '/webhook-waiting/exec-get-303');
    assert.equal(getCall.query.decision, 'approve');
    assert.equal(getCall.query.approved, 'true');
    assert.equal(getCall.query.reason, 'LGTM');
    assert.equal(getCall.query.decidedBy, 'Citra');

    // 5. Auto-expire past deadline & n8n 404 expiredHint + manual PATCH expired
    const pastDeadline = await req(port, 'POST', '/api/approvals', {
      resumeUrl: `${mockBase}/webhook-waiting/exec-past-404`,
      caseName: 'Already Expired Case',
      deadlineAt: new Date(Date.now() - 5000).toISOString(),
    });
    assert.equal(pastDeadline.status, 201);
    const pastId = pastDeadline.json.approval.id;
    const pastList = await req(port, 'GET', `/api/approvals?status=expired`);
    assert.ok(pastList.json.items.some((x) => x.id === pastId));
    const decideExpired = await req(port, 'POST', `/api/approvals/${pastId}/decide`, { decision: 'approve' });
    assert.equal(decideExpired.status, 409);

    // n8n returns 404 on resume -> Diptera returns 502 with expiredHint: true
    mockBehavior = { status: 404, body: { message: 'Execution not found' } };
    const staleCreate = await req(port, 'POST', '/api/approvals', {
      resumeUrl: `${mockBase}/webhook-waiting/exec-gone-505`,
      caseName: 'Stale Execution Case',
    });
    const staleId = staleCreate.json.approval.id;
    const staleDecide = await req(port, 'POST', `/api/approvals/${staleId}/decide`, { decision: 'approve' });
    assert.equal(staleDecide.status, 502);
    assert.equal(staleDecide.json.expiredHint, true);
    assert.equal(staleDecide.json.n8nStatus, 404);

    const markExp = await req(port, 'PATCH', `/api/approvals/${staleId}`, { status: 'expired' });
    assert.equal(markExp.status, 200);
    assert.equal(markExp.json.approval.status, 'expired');
    mockBehavior = { status: 200, body: { resumed: true } };

    // 6. Security controls: APPROVAL_API_SECRET & APPROVAL_ALLOWED_HOSTS
    const unauth = await req(secPort, 'POST', '/api/approvals', { resumeUrl: `${mockBase}/webhook-waiting/sec-1` });
    assert.equal(unauth.status, 401);

    const wrongSec = await req(secPort, 'POST', '/api/approvals', { resumeUrl: `${mockBase}/webhook-waiting/sec-1` }, { 'X-Diptera-Secret': 'wrong' });
    assert.equal(wrongSec.status, 401);

    const badHost = await req(secPort, 'POST', '/api/approvals', { resumeUrl: 'http://evil.example.com/hook' }, { 'X-Diptera-Secret': 'super-secret-token' });
    assert.equal(badHost.status, 403);

    const secOk = await req(secPort, 'POST', '/api/approvals', { resumeUrl: `${mockBase}/webhook-waiting/sec-1` }, { 'X-Diptera-Secret': 'super-secret-token' });
    assert.equal(secOk.status, 201);

    const rejUnauth = await req(secPort, 'POST', '/api/rejections', { caseName: 'Unauth Rejection' });
    assert.equal(rejUnauth.status, 401);
    const rejSecOk = await req(secPort, 'POST', '/api/rejections', { caseName: 'Auth Rejection' }, { 'X-Diptera-Secret': 'super-secret-token' });
    assert.equal(rejSecOk.status, 201);

    // 7. UI assets contain Approval menu, Global Rejection Banner, and handlers
    const htmlRes = await req(port, 'GET', '/');
    assert.equal(htmlRes.status, 200);
    assert.ok(htmlRes.text.includes('id="tab-approvals"'));
    assert.ok(htmlRes.text.includes('id="view-approvals"'));
    assert.ok(htmlRes.text.includes('id="approvals-list"'));
    assert.ok(htmlRes.text.includes('id="rejection-banner"'));

    const jsRes = await req(port, 'GET', '/app.js');
    assert.equal(jsRes.status, 200);
    assert.ok(jsRes.text.includes('submitApprovalDecision'));
    assert.ok(jsRes.text.includes('renderApprovalsList'));
    assert.ok(jsRes.text.includes('renderRejectionBanner'));
    assert.ok(jsRes.text.includes('acknowledgeRejection'));

    const cssRes = await req(port, 'GET', '/styles.css');
    assert.equal(cssRes.status, 200);
    assert.ok(cssRes.text.includes('.approval-card'));
    assert.ok(cssRes.text.includes('.rejection-banner'));

    // 8. Validate Alpha Reporter v2 (1).json structure and IF expressions (if present locally)
    const wfPath = path.join(__dirname, '..', 'Alpha Reporter v2 (1).json');
    if (fs.existsSync(wfPath)) {
      const wf = JSON.parse(fs.readFileSync(wfPath, 'utf8'));
      const byName = new Map(wf.nodes.map((n) => [n.name, n]));
      assert.equal(byName.has('Telegram - Ask Approval'), false, 'Telegram - Ask Approval must be removed');
      assert.equal(byName.has('Telegram - Inform Rejection'), false, 'Telegram - Inform Rejection must be removed');
      assert.equal(byName.has('Diptera - Send Approval Request'), true);
      assert.equal(byName.has('Diptera - Wait Approval'), true);
      assert.equal(byName.has('Diptera - Inform Rejection'), true);

      const sendNode = byName.get('Diptera - Send Approval Request');
      const waitNode = byName.get('Diptera - Wait Approval');
      const rejNode = byName.get('Diptera - Inform Rejection');
      const getDetailsNode = byName.get('Get Case Details');
      assert.equal(sendNode.type, 'n8n-nodes-base.httpRequest');
      assert.equal(sendNode.parameters.method, 'POST');
      assert.ok(String(sendNode.parameters.jsonBody).includes('$execution.resumeUrl'));

      assert.equal(waitNode.type, 'n8n-nodes-base.wait');
      assert.equal(waitNode.parameters.resume, 'webhook');
      assert.equal(waitNode.parameters.httpMethod, 'POST');

      assert.equal(rejNode.type, 'n8n-nodes-base.httpRequest');
      assert.equal(rejNode.parameters.method, 'POST');
      assert.ok(String(rejNode.parameters.url).includes('/api/rejections'));

      assert.ok(String(getDetailsNode.parameters.url).includes("$('Set Approval Deadline').first().json.case_id"));

      assert.equal(wf.connections['If Summary Exists'].main[0][0].node, 'Diptera - Send Approval Request');
      assert.equal(wf.connections['Diptera - Send Approval Request'].main[0][0].node, 'Diptera - Wait Approval');
      assert.equal(wf.connections['Diptera - Wait Approval'].main[0][0].node, 'If Approval Timed Out');
      assert.equal(wf.connections['If Case Approved'].main[1][0].node, 'Diptera - Inform Rejection');
      assert.equal(wf.connections['Diptera - Inform Rejection'].main[0][0].node, 'Wait 10 Minutes');
      assert.equal(wf.connections['Telegram - Ask Approval'], undefined);
      assert.equal(wf.connections['Telegram - Inform Rejection'], undefined);

      for (const [src, val] of Object.entries(wf.connections)) {
        assert.ok(byName.has(src), `Missing source node: ${src}`);
        for (const branch of (val.main || [])) {
          for (const edge of branch) {
            assert.ok(byName.has(edge.node), `Missing target node: ${edge.node}`);
          }
        }
      }

      // Evaluate If Approval Timed Out & If Case Approved expressions against Wait node output shapes
      const timedOutExpr = byName.get('If Approval Timed Out').parameters.conditions.conditions[0].leftValue
        .replace(/^=\{\{\s*/, '').replace(/\s*\}\}$/, '');
      const approvedExpr = byName.get('If Case Approved').parameters.conditions.conditions[0].leftValue
        .replace(/^=\{\{\s*/, '').replace(/\s*\}\}$/, '');

      const evalExpr = (expr, $json) => Function('$json', `return (${expr});`)($json);

      const waitApprove = { body: { decision: 'approve', approved: true, 'Approval Status': '✅ Approve', reason: 'OK' } };
      const waitDeny = { body: { decision: 'deny', approved: false, 'Approval Status': '❌ Decline', reason: 'Fix summary' } };
      const waitTimeout = { ok: true, approval: { id: 'apr_1', status: 'pending' }, counts: { pending: 1 } };

      assert.equal(evalExpr(timedOutExpr, waitApprove) === '', false);
      assert.equal(evalExpr(timedOutExpr, waitDeny) === '', false);
      assert.equal(evalExpr(timedOutExpr, waitTimeout) === '', true);

      assert.equal(evalExpr(approvedExpr, waitApprove), true);
      assert.equal(evalExpr(approvedExpr, waitDeny), false);
    }

    console.log('ALL_APPROVAL_TESTS_PASSED (8/8)');
  } finally {
    server.close();
    secServer.close();
    mockN8n.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
    fs.rmSync(secTmpDir, { recursive: true, force: true });
  }
})();

