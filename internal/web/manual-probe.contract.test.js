const fs = require('fs');
const path = require('path');
const assert = require('assert/strict');
eval(fs.readFileSync(path.join(__dirname, 'static/app.js'), 'utf8'));

(async () => {
  const shell = app();
  let requests = 0;
  shell.api = async (method, resource) => {
    assert.equal(method, 'POST'); assert.equal(resource, '/routes/7/probe'); requests++;
    return {execution_id: 'one-execution', ok: false, execution: {RouteID: 7, Endpoint: 'messages', StatusCode: 200,
      Success: false, ErrorClass: 'partial_failure', Capability: 'transient_error', Reachable: true,
      SemanticSeen: true, NormalEndSeen: false, SentAtMS: 1000, FirstSemanticAtMS: 1012, DoneAtMS: 1040,
      RedactedDetail: 'upstream_closed'}};
  };
  shell.loadHealth = async () => {};
  await shell.probe(7);
  assert.equal(requests, 1, 'manual action sends one model attempt');
  const result = shell.manualProbeResult();
  assert.equal(result.routeId, 7); assert.equal(result.endpoint, 'messages');
  assert.equal(result.success, false); assert.equal(result.errorClass, 'partial_failure');
  assert.equal(result.semanticMS, '12ms'); assert.equal(result.totalMS, '40ms');
  assert.equal(result.normalEndSeen, false);
  shell.probeResult = {execution: {route_id: 8, endpoint: 'responses', sent_at_ms: 0, first_semantic_at_ms: 0, done_at_ms: 3}};
  assert.equal(shell.manualProbeResult().semanticMS, '—', 'unsent execution must not invent timing');
  assert.equal(shell.manualProbeResult().totalMS, '—');
  shell.probeResult = {l1: {verdict: 'ok'}, l2: {verdict: 'ok'}};
  assert.equal(shell.manualProbeResult(), null, 'retired Outcome pair is not an execution');
  const page = fs.readFileSync(path.join(__dirname, 'static/index.html'), 'utf8');
  assert.doesNotMatch(page, /probeResult\.(l1|l2|route_id)/);
  assert.match(page, /hdrExport\.candidate/);
  assert.doesNotMatch(page, /建议的 probe_headers|填入该上游的表单/);
  console.log('manual execution and safe sample draft contracts passed');
})().catch(error => {console.error(error);process.exitCode=1;});
