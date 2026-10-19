import assert from 'node:assert/strict';
import {test} from 'node:test';

let metadataModule = {};
try { metadataModule = await import('./static/js/attempt_metadata.mjs'); }
catch (error) { if (error.code !== 'ERR_MODULE_NOT_FOUND') throw error; }

const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return {resolve, promise}; };
const row = () => ({id: 7, req_id: 'fixture-request', attempt: 1, attempts: 2, ts_recv: 90, ts_sent: 100, ts_first_byte: 115, ts_done: 150, bytes_written: 0,
  route_id: 3, upstream_id: 4, model_name_id: 5, resp_status: 503, outcome: 'upstream_error', metadata: {
    version: 1, attempt: 1, attempts: 2, config_generation: 7, settings_revision: 8, endpoint_id: 9, endpoint_revision: 10, auth_profile_revision: 11,
    upstream_network_revision: 12, upstream_credential_revision: 13, route_revision: 14, route_capability_revision: 15, model_revision: 16, model_capability_revision: 17,
    transform_version_id: 18, request_transform_revision: 19, response_header_at_ms: 110, first_event_at_ms: 120, first_semantic_at_ms: 135,
    retry_policy: 'balanced', retry_reason: 'policy_retry_after_possible_upstream_accept', request_write_state: 'possibly_written', capability_effect: 'applied', error_class: 'transient_error',
    retried: true, half_open: false, duplicate_risk: true, synthetic_completion: false, execution_id: 'exact-one', execution_stored: true,
    request_input_hash: 'a'.repeat(64), request_output_hash: 'b'.repeat(64), request_body_changed: true, request_headers_changed: false, request_diff_reason: 'recorded',
    response_input_hash: '', response_output_hash: '', response_body_changed: false, response_headers_changed: false, response_diff_reason: 'secret_taint',
  }});

function setup(get = async () => ({})) {
  assert.equal(typeof metadataModule.createAttemptMetadataFeature, 'function', '逐 Attempt 安全元数据功能尚未接入');
  const calls = [];
  const shell = {err: '', sample: null, hdrExport: null, reset() {}, _lockModal() {}, _unlockModal() {}};
  metadataModule.createAttemptMetadataFeature(shell, {get(path) { calls.push(path); return get(path); }});
  return {shell, calls};
}

test('the fixed view exposes captured revisions and real stage differences without treating zero bytes as missing', () => {
  const {shell} = setup(); shell.openAttemptMetadata(row());
  const attempt = shell.attemptMetadata.attempts[0];
  assert.equal(attempt.version, '1');
  assert.equal(attempt.timings.find(value => value.label === '响应头（发送起）').value, '10ms');
  assert.equal(attempt.timings.find(value => value.label === '首字节（发送起）').value, '15ms');
  assert.equal(attempt.timings.find(value => value.label === '首事件（发送起）').value, '20ms');
  assert.equal(attempt.timings.find(value => value.label === '首语义（发送起）').value, '35ms');
  assert.equal(attempt.timings.find(value => value.label === '客户端写出').value, '0 B');
  assert.ok(attempt.revisions.some(value => value.label === 'Settings 修订' && value.value === '8'));
  assert.equal(attempt.executionID, 'exact-one'); assert.equal(attempt.canOpenExecution, true);
});

test('historical unknown cannot inherit plausible current versions or invent negative boolean facts', () => {
  const {shell} = setup(); const old = row(); old.metadata.version = 0; old.metadata.settings_revision = 999;
  shell.openAttemptMetadata(old);
  const attempt = shell.attemptMetadata.attempts[0];
  assert.match(attempt.notice, /历史.*未知/);
  assert.equal(attempt.canOpenExecution, false);
  assert.equal(attempt.revisions.some(value => value.value === '999'), false);
  assert.equal(attempt.decisions.find(value => value.label === '潜在重复执行').value, '未知');
});

test('omitted comparisons stay omitted and the view drops arbitrary extra body/error fields', () => {
  const {shell} = setup(); const value = row();
  value.in_body = 'private-extra-body'; value.metadata.private_error = 'private-extra-error';
  value.metadata.response_input_hash = 'c'.repeat(64); value.metadata.response_body_changed = true;
  shell.openAttemptMetadata(value);
  const attempt = shell.attemptMetadata.attempts[0];
  assert.match(attempt.diffs[1].reason, /Secret.*省略/);
  assert.equal(attempt.diffs[1].inputHash, '未记录');
  assert.equal(JSON.stringify(shell.attemptMetadata).includes('private-extra'), false);
  assert.equal(JSON.stringify(shell.attemptMetadata).includes('c'.repeat(64)), false);
});

test('response view explains client bytes and discarded upstream prefixes without claiming original wire', () => {
  const {shell} = setup(); const value = row(); value.metadata.response_view = 'client_response';
  shell.openAttemptMetadata(value);
  assert.match(shell.attemptMetadata.attempts[0].responseView, /客户端.*视图/);
  value.metadata.response_view = 'upstream_attempt_prefix'; shell.openAttemptMetadata(value);
  assert.match(shell.attemptMetadata.attempts[0].responseView, /前缀/);
  value.metadata.version = 0; shell.openAttemptMetadata(value);
  assert.equal(shell.attemptMetadata.attempts[0].responseView, '未知');
});

test('schema 15 persisted original and omitted views have explicit labels while historical rows remain unknown',()=>{
 const {shell}=setup();const value=row();
 for(const [view,label] of Object.entries({upstream_response:/原始上游响应/,no_response:/未收到上游/,omitted_secret:/Secret.*省略/,omitted_unverified:/无法.*安全.*省略/})){
  value.metadata.response_view=view;shell.openAttemptMetadata(value);
  assert.match(shell.attemptMetadata.attempts[0].responseView,label);
 }
 value.metadata.version=0;value.metadata.response_view='upstream_response';shell.openAttemptMetadata(value);
 assert.equal(shell.attemptMetadata.attempts[0].responseView,'未知');
});

test('sample metadata exposes recorded response truncation without loading any body',async()=>{
 const value=row();value.truncated=4;value.metadata.response_view='upstream_response';
 const {shell,calls}=setup(async()=>({id:42,attempt_count:1,attempts:[value]}));
 await shell.openSampleMetadata(42);
 assert.deepEqual(calls,['/samples/42/metadata']);
 assert.equal(shell.attemptMetadata.attempts[0].decisions.find(f=>f.label==='样本响应正文截断')?.value,'是');
});

test('missing exact detail distinguishes pending observation from unavailable retained disposition', () => {
  const {shell} = setup(); const value = row(); value.metadata.execution_stored = false; value.metadata.capability_effect = 'pending';
  shell.openAttemptMetadata(value); assert.match(shell.attemptMetadata.attempts[0].executionState, /待.*持久化/);
  value.metadata.capability_effect = 'applied'; shell.openAttemptMetadata(value);
  assert.match(shell.attemptMetadata.attempts[0].executionState, /详情.*不可用|已淘汰/);
  assert.equal(shell.attemptMetadata.attempts[0].canOpenExecution, false);
});

test('sample metadata uses only its body-free endpoint and makes old login results unable to refill the drawer', async () => {
  const old = deferred(), newer = deferred(); let reads = 0;
  const {shell, calls} = setup(() => ++reads === 1 ? old.promise : newer.promise);
  const first = shell.openSampleMetadata(42); shell.reset();
  const second = shell.openSampleMetadata(43);
  old.resolve({id: 42, attempts: [row()], body: 'old-private'}); await first;
  assert.equal(shell.attemptMetadata.loading, true); assert.equal(shell.attemptMetadata.attempts.length, 0);
  newer.resolve({id: 43, req_id: 'new-request', attempt_count: 1, attempts: [row()], body: 'unexpected-private'}); await second;
  assert.deepEqual(calls, ['/samples/42/metadata', '/samples/43/metadata']);
  assert.equal(shell.attemptMetadata.sampleID, 43);
  assert.equal(JSON.stringify(shell.attemptMetadata).includes('private'), false);
  assert.equal(shell.attemptMetadata.attempts[0].timings.find(value => value.label === '客户端写出').value, '未记录');
});

test('Execution navigation uses the exact captured ID and never queries related Route records', async () => {
  const {shell, calls} = setup(async () => ({ID: 'exact-one'})); shell.openAttemptMetadata(row());
  await shell.openMetadataExecution();
  assert.deepEqual(calls, ['/probe-executions/exact-one']); assert.equal(shell.executionDrawer.ID, 'exact-one');
  const missing = row(); missing.metadata.execution_stored = false; shell.openAttemptMetadata(missing);
  await shell.openMetadataExecution(); assert.equal(calls.length, 1);
});

test('a retained-row link that has since been pruned stays honest and never falls back to a nearby execution', async () => {
  const error = Object.assign(new Error('not found'), {status: 404});
  const {shell, calls} = setup(async () => { throw error; }); shell.openAttemptMetadata(row());
  await shell.openMetadataExecution();
  assert.equal(shell.attemptMetadata.attempts[0].canOpenExecution, false);
  assert.match(shell.attemptMetadata.error, /已淘汰|不可用/); assert.equal(calls.length, 1);
});

test('changing the selected Attempt invalidates an older exact-detail read without unlocking the new read', async () => {
  const old = deferred(), newer = deferred(); let reads = 0;
  const {shell} = setup(() => ++reads === 1 ? old.promise : newer.promise);
  shell.openAttemptMetadata(row());
  const secondAttempt = structuredClone(shell.attemptMetadata.attempts[0]); secondAttempt.executionID = 'exact-two'; secondAttempt.key = 'log-8';
  shell.attemptMetadata.attempts.push(secondAttempt);
  const first = shell.openMetadataExecution();
  shell.attemptMetadata.selected = 1; shell.selectMetadataAttempt();
  const second = shell.openMetadataExecution();
  old.resolve({ID: 'exact-one'}); await first;
  assert.equal(shell.executionDrawer, null); assert.equal(shell.attemptMetadata.executionLoading, true);
  newer.resolve({ID: 'exact-two'}); await second;
  assert.equal(shell.executionDrawer.ID, 'exact-two');
});

test('opening sample body from metadata delegates to the existing password prompt without reading it', async () => {
  const {shell, calls} = setup(async () => ({id: 42, req_id: 'fixture', attempt_count: 1, attempts: [row()]}));
  let requested; shell.openSample = async id => { requested = id; };
  await shell.openSampleMetadata(42); await shell.openMetadataSampleBody();
  assert.equal(requested, 42); assert.deepEqual(calls, ['/samples/42/metadata']);
});
