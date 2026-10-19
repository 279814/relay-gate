import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createApiClient} from './static/js/api.mjs';
import {createCredentialsFeature} from './static/js/credentials.mjs';

test('a completed mutation with pending audit stays successful and exposes its confirmation status', async t => {
  let notices = 0;
  t.mock.method(globalThis, 'fetch', async () => new Response(JSON.stringify({relay_key: 'synthetic-new-key'}), {
    status: 200, headers: {'X-Audit-Status': 'pending', 'X-Audit-Event-ID': '42'},
  }));
  const data = await createApiClient({onAuditPending: () => notices++}).post('/credentials/rotate-relay', {});
  assert.equal(data.relay_key, 'synthetic-new-key');
  assert.equal(data.audit_pending, true);
  assert.equal(data.audit_event_id, '42');
  assert.equal(notices, 1);
});

test('credential audit reads bounded persistent pages and resets the cursor when filters change', async t => {
  const calls = [];
  t.mock.method(globalThis, 'fetch', async url => {
    calls.push(url);
    const page = calls.length === 1 ? {items: [{id: 2, action: 'route_disable'}], next_cursor: 'next-page'} :
      {items: [{id: 1, action: 'relay_rotate'}], next_cursor: ''};
    return new Response(JSON.stringify(page), {status: 200});
  });
  const shell = {};
  createCredentialsFeature(shell, createApiClient());
  await shell.loadAuditEvents(true);
  await shell.loadAuditEvents(false);
  assert.deepEqual(shell.credentials.audit.items.map(event => event.id), [2, 1]);
  assert.match(calls[0], /audit-events\?limit=25/);
  assert.match(calls[1], /cursor=next-page/);
  shell.credentials.audit.filter.category = 'credential';
  await shell.loadAuditEvents(false);
  assert.match(calls[2], /category=credential/);
  assert.doesNotMatch(calls[2], /cursor=/);
  assert.deepEqual(shell.credentials.audit.items.map(event => event.id), [1]);
  shell.reset();
  assert.deepEqual(shell.credentials.audit.items, []);
});

test('credential rotation retains the delivered key and warns against repeating an already completed operation', async t => {
  t.mock.method(globalThis, 'fetch', async url => new Response(JSON.stringify(url.endsWith('/rotate-relay') ?
    {relay_key: 'synthetic-active-key', grace_seconds: 0} : {}), {
    status: 200, headers: url.endsWith('/rotate-relay') ? {'X-Audit-Status': 'pending', 'X-Audit-Event-ID': '7'} : {},
  }));
  const shell = {displayState: 'running', msg: '', err: ''};
  createCredentialsFeature(shell, createApiClient());
  await shell.rotateRelayKey();
  assert.equal(shell.credentials.relay_key, 'synthetic-active-key');
  assert.match(shell.auditWarning, /已完成.*审计.*确认.*勿重复/);
  assert.equal(shell.err, '', 'a pending terminal audit must not turn a completed rotation into a failed mutation');
  shell.reset();
});
