import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createApiClient} from './static/js/api.mjs';
import {createCredentialsFeature} from './static/js/credentials.mjs';

const deferred = () => {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return {promise, resolve};
};
const response = data => ({status: 200, ok: true, text: async () => JSON.stringify(data)});

function feature(t, handle) {
  t.mock.timers.enable({apis: ['setTimeout', 'Date'], now: 1000000});
  const callbacks = [];
  const schedule = globalThis.setTimeout;
  t.mock.method(globalThis, 'setTimeout', (callback, delay) => {
    callbacks.push(callback);
    return schedule(callback, delay);
  });
  const calls = [];
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    const path = url.replace('/admin/api', '');
    calls.push({path, method: options.method, body: options.body && JSON.parse(options.body)});
    const result = await handle(path, calls.at(-1));
    return response(result);
  });
  const shell = {authed: true, displayState: 'running', err: '', msg: ''};
  const api = createApiClient({onUnauthorized: () => shell.reset()});
  shell.reset = function () { api.invalidatePendingRequests(); this.authed = false; };
  createCredentialsFeature(shell, api);
  shell.credentials.password = 'synthetic-admin-password';
  t.after(() => shell.reset());
  return {shell, calls, callbacks};
}

const status = left => ({rotation_allowed: true, relay_grace_seconds_left: left});

test('Master plaintext expires at the API TTL even when the status refresh fails', async t => {
  const {shell} = feature(t, path => {
    if (path === '/credentials/reveal-master') return {master_key: 'synthetic-master', ttl_sec: 7};
    throw new Error('status refresh unavailable');
  });
  await shell.revealMasterKey();
  assert.equal(shell.credentials.master_key, 'synthetic-master');
  t.mock.timers.tick(6999);
  assert.equal(shell.credentials.master_key, 'synthetic-master');
  t.mock.timers.tick(1);
  assert.equal(shell.credentials.master_key, '', 'API ttl_sec must clear the actual plaintext');
});

test('Master reveal fails closed when the response has no usable TTL', async t => {
  const {shell} = feature(t, path => path === '/credentials' ? status(0) : {master_key: 'synthetic-master'});
  await shell.revealMasterKey();
  assert.equal(shell.credentials.master_key, '');
  assert.ok(shell.err, 'an invalid expiry must not silently display a key indefinitely');
});

test('a renewed reveal survives an already queued old expiration callback', async t => {
  let reveals = 0;
  const {shell, callbacks} = feature(t, path => path === '/credentials' ? status(0) :
    {master_key: ++reveals === 1 ? 'synthetic-first' : 'synthetic-second', ttl_sec: 30});
  await shell.revealMasterKey();
  assert.ok(callbacks.length > 0, 'the first reveal must have an expiry');
  const oldExpiry = callbacks[0];
  t.mock.timers.tick(10000);
  await shell.revealMasterKey();
  oldExpiry();
  assert.equal(shell.credentials.master_key, 'synthetic-second');
  t.mock.timers.tick(29999);
  assert.equal(shell.credentials.master_key, 'synthetic-second');
  t.mock.timers.tick(1);
  assert.equal(shell.credentials.master_key, '');
});

test('a late same-session reveal cannot replace a newer revealed key', async t => {
  const old = deferred(); let reveals = 0;
  const {shell} = feature(t, path => path === '/credentials' ? status(0) :
    ++reveals === 1 ? old.promise : {master_key: 'synthetic-current', ttl_sec: 30});
  const first = shell.revealMasterKey();
  await shell.revealMasterKey();
  old.resolve({master_key: 'synthetic-obsolete', ttl_sec: 30});
  await first;
  assert.equal(shell.credentials.master_key, 'synthetic-current');
});

test('Master rotation clears a visible reveal before waiting for the API', async t => {
  const rotation = deferred();
  const {shell, callbacks} = feature(t, path => {
    if (path === '/credentials') return status(0);
    if (path === '/credentials/reveal-master') return {master_key: 'synthetic-master', ttl_sec: 30};
    if (path === '/credentials/rotate-master') return rotation.promise;
    return {};
  });
  await shell.revealMasterKey();
  shell.credentials.new_master = 'synthetic-next-master';
  const rotating = shell.rotateMasterKey();
  assert.equal(shell.credentials.master_key, '', 'old plaintext must disappear as rotation starts');
  callbacks[0]();
  rotation.resolve({new_key_id: 'new-id', phase: 'cleaned'});
  await rotating;
  assert.equal(shell.credentials.master_key, '');
});

test('a reveal begun before Master rotation cannot restore the retired key', async t => {
  const old = deferred();
  const {shell} = feature(t, path => {
    if (path === '/credentials') return status(0);
    if (path === '/credentials/reveal-master') return old.promise;
    return {new_key_id: 'new-id', phase: 'cleaned'};
  });
  await shell.loadCredentials();
  const revealing = shell.revealMasterKey();
  shell.credentials.new_master = 'synthetic-next-master';
  await shell.rotateMasterKey();
  old.resolve({master_key: 'synthetic-retired', ttl_sec: 30});
  await revealing;
  assert.equal(shell.credentials.master_key, '');
});

test('a reveal during Master rotation cannot show the key being retired', async t => {
  const rotation = deferred();
  t.after(() => rotation.resolve({new_key_id: 'new-id', phase: 'cleaned'}));
  const {shell, calls} = feature(t, path => {
    if (path === '/credentials') return status(0);
    if (path === '/credentials/rotate-master') return rotation.promise;
    if (path === '/credentials/reveal-master') return {master_key: 'synthetic-retiring', ttl_sec: 30};
    return {};
  });
  await shell.loadCredentials();
  const rotating = shell.rotateMasterKey();
  await shell.revealMasterKey();
  assert.equal(shell.credentials.master_key, '');
  assert.equal(calls.filter(call => call.path === '/credentials/reveal-master').length, 0);
  rotation.resolve({new_key_id: 'new-id', phase: 'cleaned'});
  await rotating;
});

test('logout cancels timers and queued old callbacks cannot clear a new login reveal', async t => {
  let reveals = 0;
  const {shell, callbacks} = feature(t, path => path === '/credentials' ? status(0) :
    {master_key: ++reveals === 1 ? 'synthetic-old-session' : 'synthetic-new-session', ttl_sec: 30});
  await shell.revealMasterKey();
  assert.ok(callbacks.length > 0);
  const oldExpiry = callbacks[0];
  shell.reset(); shell.authed = true;
  await shell.revealMasterKey();
  oldExpiry();
  assert.equal(shell.credentials.master_key, 'synthetic-new-session');
  t.mock.timers.tick(30000);
  assert.equal(shell.credentials.master_key, '');
});

test('Relay grace counts down without requests and catches up after a delayed timer', async t => {
  const {shell, calls} = feature(t, () => status(5));
  await shell.loadCredentials();
  assert.equal(shell.credentials.status.relay_grace_seconds_left, 5);
  t.mock.timers.tick(1000);
  assert.equal(shell.credentials.status.relay_grace_seconds_left, 4);
  t.mock.timers.setTime(1020000);
  t.mock.timers.tick(1);
  assert.equal(shell.credentials.status.relay_grace_seconds_left, 0, 'background tab delay must not extend grace');
  assert.equal(calls.length, 1, 'display ticks must not poll or extend server grace');
});

test('a newer status replaces the old countdown and an old callback cannot alter it', async t => {
  let reads = 0;
  const {shell, callbacks} = feature(t, () => status(++reads === 1 ? 5 : 20));
  await shell.loadCredentials();
  assert.ok(callbacks.length > 0);
  const oldTick = callbacks[0];
  await shell.loadCredentials();
  oldTick();
  assert.equal(shell.credentials.status.relay_grace_seconds_left, 20);
  t.mock.timers.tick(1000);
  assert.equal(shell.credentials.status.relay_grace_seconds_left, 19);
});

test('a stale status cannot restore revoked Relay grace', async t => {
  const old = deferred(); let reads = 0;
  const {shell} = feature(t, path => path === '/credentials' ? (++reads === 1 ? old.promise : status(0)) : {ok: true});
  const first = shell.loadCredentials();
  await shell.revokeRelayGrace();
  old.resolve(status(600));
  await first;
  assert.equal(shell.credentials.status.relay_grace_seconds_left, 0);
});

test('Relay rotation replaces the countdown even when its status refresh fails', async t => {
  let reads = 0;
  const {shell, callbacks} = feature(t, path => {
    if (path === '/credentials/rotate-relay') return {relay_key: 'synthetic-relay', grace_seconds: 600};
    if (++reads === 1) return status(5);
    throw new Error('status refresh unavailable');
  });
  await shell.loadCredentials();
  const oldTick = callbacks[0];
  await shell.rotateRelayKey();
  oldTick();
  assert.equal(shell.credentials.relay_key, 'synthetic-relay');
  assert.equal(shell.credentials.status.relay_grace_seconds_left, 600);
  t.mock.timers.tick(1000);
  assert.equal(shell.credentials.status.relay_grace_seconds_left, 599);
});

test('an old Relay rotation response cannot replace the latest key and grace', async t => {
  const old = deferred(); let rotations = 0;
  const {shell} = feature(t, path => path === '/credentials' ? status(600) :
    ++rotations === 1 ? old.promise : {relay_key: 'synthetic-current', grace_seconds: 600});
  const first = shell.rotateRelayKey();
  await shell.rotateRelayKey();
  old.resolve({relay_key: 'synthetic-obsolete', grace_seconds: 5});
  await first;
  assert.equal(shell.credentials.relay_key, 'synthetic-current');
  assert.equal(shell.credentials.status.relay_grace_seconds_left, 600);
});

test('a queued grace callback after logout cannot mutate the new session status', async t => {
  let reads = 0;
  const {shell, callbacks} = feature(t, () => status(++reads === 1 ? 5 : 20));
  await shell.loadCredentials();
  const oldTick = callbacks[0];
  shell.reset(); shell.authed = true;
  await shell.loadCredentials();
  oldTick();
  assert.equal(shell.credentials.status.relay_grace_seconds_left, 20);
  t.mock.timers.tick(1000);
  assert.equal(shell.credentials.status.relay_grace_seconds_left, 19);
});
