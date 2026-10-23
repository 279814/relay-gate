import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createSecurityFeature} from './static/js/security.mjs';

function fixture(api) {
  const shell = {authed: true, err: '', msg: '', reset() { this.authed = false; }};
  createSecurityFeature(shell, api);
  return shell;
}
function pending() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return {promise, resolve, reject}; }

test('finding filters execute on the server and next page replaces rather than accumulates evidence', async () => {
  const paths = [];
  const shell = fixture({async get(path) { paths.push(path); return {findings: [{id: paths.length === 1 ? 'first' : 'second'}], total: 7, next_cursor: paths.length === 1 ? 'opaque-next' : ''}; }});
  Object.assign(shell.security, {severity: 'high', routeID: '7', category: 'prompt_injection', fromTime: '2026-10-19T13:00', toTime: '2026-10-19T14:00'});
  await shell.loadSecurityFindings();
  let query = new URL('http://local' + paths[0]).searchParams;
  assert.equal(query.get('limit'), '25');
  assert.equal(query.get('severity'), 'high');
  assert.equal(query.get('route_id'), '7');
  assert.equal(query.get('category'), 'prompt_injection');
  assert.equal(query.get('from_ms'), String(new Date('2026-10-19T13:00').getTime()));
  assert.equal(query.get('to_ms'), String(new Date('2026-10-19T14:00').getTime()));
  assert.equal(shell.security.total, 7);
  await shell.nextSecurityFindings();
  query = new URL('http://local' + paths[1]).searchParams;
  assert.equal(query.get('cursor'), 'opaque-next');
  assert.deepEqual(shell.security.findings.map(row => row.id), ['second']);
  assert.equal(shell.security.nextCursor, '');
  await shell.loadSecurityFindings();
  assert.equal(new URL('http://local' + paths[2]).searchParams.has('cursor'), false, 'explicit filter refresh returns to the first page');
});

test('a later filter owns its result, busy state and errors even when the old page finishes last', async () => {
  const first = pending(), second = pending(); let calls = 0;
  const shell = fixture({get() { return ++calls === 1 ? first.promise : second.promise; }});
  const oldRead = shell.loadSecurityFindings();
  shell.security.severity = 'critical';
  const newRead = shell.loadSecurityFindings();
  first.reject(new Error('obsolete error'));
  await oldRead;
  assert.equal(shell.err, '');
  assert.equal(shell.security.loading, true);
  second.resolve({findings: [{id: 'new'}], total: 1, next_cursor: ''});
  await newRead;
  assert.deepEqual(shell.security.findings.map(row => row.id), ['new']);
  assert.equal(shell.security.loading, false);
});

test('logout and invalid filters cannot restore a former page or silently submit an incomplete filter', async () => {
  const old = pending(); let calls = 0;
  const shell = fixture({get() { calls++; return old.promise; }});
  const read = shell.loadSecurityFindings();
  shell.reset();
  old.resolve({findings: [{id: 'old-private-evidence'}], total: 1, next_cursor: 'old-cursor'});
  await read;
  assert.deepEqual(shell.security.findings, []);
  assert.equal(shell.security.nextCursor, '');
  shell.security.routeID = '-1';
  await shell.loadSecurityFindings();
  assert.equal(calls, 1);
  assert.match(shell.security.findingsError, /筛选|Route/);
});

test('duplicate next-page actions are bounded and a failed page is distinct from no findings', async () => {
  const next = pending(); let calls = 0;
  const shell = fixture({get() { calls++; return next.promise; }});
  shell.security.nextCursor = 'one-page';
  const read = shell.nextSecurityFindings();
  await shell.nextSecurityFindings();
  assert.equal(calls, 1);
  next.reject(new Error('persistent findings unavailable'));
  await read;
  assert.match(shell.security.findingsError, /unavailable/);
  assert.equal(shell.security.loading, false);
  assert.deepEqual(shell.security.findings, []);
});
