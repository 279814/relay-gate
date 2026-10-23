/* modules.contract.test.mjs — P0-15 module contracts.
 *
 * Run: node internal/web/modules.contract.test.mjs
 * No package.json / bundler / experimental flags.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import vm from 'node:vm';

const here = path.dirname(fileURLToPath(import.meta.url));
const staticDir = path.join(here, 'static');
const jsDir = path.join(staticDir, 'js');

const { createApiClient, parseProbeHeadersJSON, field } = await import(pathToFileURL(path.join(jsDir, 'api.mjs')).href);
const { createProbeFeature, mergeProbeTabs, probeTabIds } = await import(pathToFileURL(path.join(jsDir, 'probes.mjs')).href);
const modal = await import(pathToFileURL(path.join(jsDir, 'modal.mjs')).href);
const { createCountTokensFeature, summarizeCountTokens, countTokensClass } = await import(pathToFileURL(path.join(jsDir, 'count_tokens.mjs')).href);
const { createCredentialsFeature } = await import(pathToFileURL(path.join(jsDir, 'credentials.mjs')).href);

let failed = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log('ok  ' + name);
  } catch (e) {
    failed++;
    console.error('FAIL ' + name + ': ' + (e && e.message ? e.message : e));
  }
}

await check('script order in index.html', () => {
  const html = fs.readFileSync(path.join(staticDir, 'index.html'), 'utf8');
  const appAt = html.indexOf('src="/admin/app.js"');
  const bootAt = html.indexOf('src="/admin/js/boot.mjs"');
  const alpineAt = html.indexOf('src="/admin/alpine.min.js"');
  assert.ok(appAt >= 0 && bootAt > appAt && alpineAt > bootAt);
  assert.ok(html.includes('type="module" src="/admin/js/boot.mjs"'));
});

await check('no x-html / innerHTML / storage in business modules', () => {
  for (const name of ['api.mjs', 'probes.mjs', 'probe_statistics.mjs', 'modal.mjs', 'boot.mjs', 'errors.mjs', 'migration.mjs', 'credentials.mjs', 'security.mjs', 'canary.mjs', 'transforms.mjs', 'runtime.mjs', 'count_tokens.mjs']) {
    const src = fs.readFileSync(path.join(jsDir, name), 'utf8');
    assert.ok(!/x-html/.test(src), name + ' x-html');
    assert.ok(!/\binnerHTML\b/.test(src), name + ' innerHTML');
    assert.ok(!/localStorage|sessionStorage/.test(src), name + ' storage');
  }
  const html = fs.readFileSync(path.join(staticDir, 'index.html'), 'utf8');
  assert.ok(!/x-html/.test(html));
});

await check('network exit only in api.mjs among modules', () => {
  for (const name of fs.readdirSync(jsDir)) {
    if (!name.endsWith('.mjs')) continue;
    if (name === 'api.mjs') continue;
    const src = fs.readFileSync(path.join(jsDir, name), 'utf8');
    assert.ok(!/\bfetch\s*\(/.test(src), name + ' fetch');
    assert.ok(!/XMLHttpRequest/.test(src), name + ' xhr');
    assert.ok(!/EventSource/.test(src), name + ' EventSource');
    assert.ok(!/WebSocket/.test(src), name + ' WebSocket');
  }
  const apiSrc = fs.readFileSync(path.join(jsDir, 'api.mjs'), 'utf8');
  assert.ok(/\bfetch\s*\(/.test(apiSrc));
});

await check('parseProbeHeadersJSON position hint', () => {
  const bad = '{\n"a": "line1\nline2"\n}';
  assert.throws(() => parseProbeHeadersJSON(bad), (err) => {
    const msg = String(err.message);
    assert.ok(msg.includes('JSON') || msg.includes('json') || /探活头/.test(msg));
    assert.ok(/position|附近|near/i.test(msg));
    return true;
  });
  assert.deepEqual(parseProbeHeadersJSON(''), {});
  assert.deepEqual(parseProbeHeadersJSON('{"x":"1"}'), { x: '1' });
});

await check('field() prefers first present key', () => {
  assert.equal(field({ State: 'up', state: 'down' }, 'state', 'State'), 'down');
  assert.equal(field({ State: 'up' }, 'state', 'State'), 'up');
  assert.equal(field(null, 'a'), undefined);
});

await check('createApiClient 401 reset + session shape', async () => {
  let unauthorized = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes('/session-unauth')) {
      return { status: 401, ok: false, text: async () => '' };
    }
    if (String(url).includes('/ok')) {
      return { status: 200, ok: true, text: async () => '{"items":[],"next_cursor":""}' };
    }
    return { status: 204, ok: true, text: async () => '' };
  };
  try {
    const api = createApiClient({ onUnauthorized: () => { unauthorized++; } });
    await assert.rejects(() => api.get('/session-unauth'), (err) => {
      assert.equal(err.status, 401);
      return true;
    });
    assert.equal(unauthorized, 1);
    const page = await api.get('/ok');
    assert.deepEqual(page.items, []);
    assert.equal(page.next_cursor, '');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

await check('probe feature lists + filter reset + load more + bad cursor', async () => {
  const pages = {
    '/capabilities?limit=50': { items: [{ State: 'ok', ScopeType: 'route', ScopeID: 1, Endpoint: 'messages' }], next_cursor: 'c1' },
    '/capabilities?limit=50&cursor=c1': { items: [{ State: 'dead', ScopeType: 'route', ScopeID: 2, Endpoint: 'messages' }], next_cursor: '' },
  };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const u = String(url).replace(/^.*\/admin\/api/, '');
    if (u.includes('cursor=bad')) {
      return { status: 400, ok: false, text: async () => '{"error":"bad cursor"}' };
    }
    const body = pages[u];
    if (!body) return { status: 404, ok: false, text: async () => 'missing ' + u };
    return { status: 200, ok: true, text: async () => JSON.stringify(body) };
  };
  try {
    const shell = {
      err: '',
      tabs: [],
      async run(fn) { await fn(); return { ok: true }; },
    };
    const api = createApiClient();
    createProbeFeature(shell, api);
    mergeProbeTabs(shell);
    assert.ok(probeTabIds().includes('capabilities'));
    assert.ok(shell.tabs.some((t) => t.id === 'capabilities'));

    await shell.loadCapabilities(true);
    assert.equal(shell.capabilities.items.length, 1);
    assert.equal(shell.capabilities.next_cursor, 'c1');
    await shell.loadCapabilities(false);
    assert.equal(shell.capabilities.items.length, 2);
    assert.equal(shell.capabilities.next_cursor, '');

    shell.capabilities.next_cursor = 'bad';
    await shell.loadCapabilities(false);
    assert.ok(shell.err.includes('bad cursor') || /400|cursor|游标/i.test(shell.err));
    assert.equal(shell.capabilities.items.length, 0);

    shell.onProbeFilterChange('capabilities');
    assert.equal(shell.capabilities.next_cursor, '');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

await check('Probe list filters expose the typed HTTP fields and reset cursors', async () => {
  const expected = {
    endpoints: ['upstream_id', 'endpoint', 'needs_review'], secrets: ['name_prefix'],
    executions: ['upstream_id', 'route_id', 'endpoint', 'error_class', 'trigger', 'capability_state'],
    capabilities: ['upstream_id', 'route_id', 'endpoint', 'state', 'expired'],
    reachability: ['upstream_id', 'state', 'current'], calibrations: ['route_id', 'endpoint', 'state'],
    probeCostDaily: ['day_from', 'day_to', 'trigger', 'origin', 'endpoint', 'route_id', 'upstream_id'],
  };
  const paths = { endpoints: '/upstream-endpoints', secrets: '/probe-secrets', executions: '/probe-executions', capabilities: '/capabilities', reachability: '/reachability', calibrations: '/calibrations', probeCostDaily: '/probe-costs' };
  const seen = [];
  const shell = { err: '' };
  createProbeFeature(shell, { get: async url => { seen.push(new URL(url, 'http://fixture')); return { items: [], next_cursor: '' }; } });
  const html = fs.readFileSync(path.join(staticDir, 'index.html'), 'utf8');
  for (const [list, keys] of Object.entries(expected)) {
    assert.deepEqual(Object.keys(shell[list].filter), keys, list + ' typed fields');
    assert.deepEqual(shell.probeFilterFields[list].map(field => field.key), keys, list + ' controls');
    assert.ok(html.includes('probeFilterFields.' + list), list + ' visible filters');
    shell[list].next_cursor = 'old-filter-cursor';
    shell[list].items = [{ id: 'old-filter-row' }];
    shell[list].filter[keys[0]] = 'fixture-selected';
    shell.onProbeFilterChange(list);
    assert.equal(shell[list].next_cursor, '');
    assert.deepEqual(shell[list].items, []);
    await shell.loadPaged(list, paths[list], true);
    const request = seen.at(-1);
    assert.equal(request.searchParams.get(keys[0]), 'fixture-selected');
    assert.equal(request.searchParams.has('cursor'), false);
  }
});

await check('Probe cost rows preserve the complete SQL identity across origins and endpoints', () => {
  const html = fs.readFileSync(path.join(staticDir, 'index.html'), 'utf8');
  const expression = html.match(/x-for="c in probeCostDaily.items" :key="([^"]+)"/)[1];
  const key = new Function('c', 'f', 'return ' + expression);
  const first = { DayUTC: '2099-01-01', Trigger: 'manual', Origin: 'manual', Endpoint: 'messages', RouteID: 1, UpstreamID: 1 };
  for (const changed of [{ Origin: 'learned' }, { Endpoint: 'count_tokens' }, { UpstreamID: 2 }]) {
    assert.notEqual(key(first, field), key({ ...first, ...changed }, field));
  }
});

await check('capabilityBadge expired is derived stale', () => {
  const shell = {};
  createProbeFeature(shell, createApiClient());
  const badge = shell.capabilityBadge({ State: 'ok', ExpiresAt: Date.now() - 1000 });
  assert.equal(badge.text, 'expired');
  assert.equal(badge.stale, true);
});

await check('lazyProbeWarning', () => {
  const shell = {};
  createProbeFeature(shell, createApiClient());
  const msg = shell.lazyProbeWarning({ probe_mode: 'lazy' });
  assert.ok(msg.length > 0);
  assert.ok(/lazy|周期|模型/i.test(msg));
  assert.equal(shell.lazyProbeWarning({ probe_mode: 'active' }), '');
});

await check('runtimeDropWarn uses API limits not constants', () => {
  const shell = {};
  createProbeFeature(shell, createApiClient());
  shell.probeRuntime = { DroppedByCapacity: 1, FullObserverLimit: 32 };
  const warn = shell.runtimeDropWarn();
  assert.ok(warn.includes('capacity=1'));
  const src = fs.readFileSync(path.join(jsDir, 'probes.mjs'), 'utf8');
  assert.ok(!src.includes('16 * 1024 * 1024'));
});

await check('modal helpers export', () => {
  assert.equal(typeof modal.openModalLock, 'function');
  assert.equal(typeof modal.bindEscape, 'function');
  assert.equal(typeof modal.focusFirst, 'function');
});

await check('boot wraps window.app without requiring committed app.js edits', () => {
  const boot = fs.readFileSync(path.join(jsDir, 'boot.mjs'), 'utf8');
  assert.match(boot, /createProbeFeature/);
  assert.match(boot, /__relayProbeBooted/);
  const appSrc = fs.readFileSync(path.join(staticDir, 'app.js'), 'utf8');
  assert.match(appSrc, /function app\s*\(/);
  const sandbox = { window: {}, console };
  vm.runInNewContext(appSrc + '\nwindow.app = app;', sandbox);
  assert.equal(typeof sandbox.window.app, 'function');
});

await check('boot wrappers call originals with the reactive this, not bind(shell)', () => {
  const boot = fs.readFileSync(path.join(jsDir, 'boot.mjs'), 'utf8');
  for (const name of ['boot', 'loadAll', 'loadHealth', 'go', 'editUp']) {
    assert.ok(!new RegExp(`shell\\.${name}\\.bind\\(shell\\)`).test(boot), name + ' bound to raw shell');
  }
});

await check('Upstream save uses the explicit classic DTO without intercepting API calls', () => {
  const boot = fs.readFileSync(path.join(jsDir, 'boot.mjs'), 'utf8');
  const classic = fs.readFileSync(path.join(staticDir, 'app.js'), 'utf8');
  assert.ok(!boot.includes('origSaveUp'));
  assert.ok(!boot.includes('shell.saveUp ='));
  for (const field of ['probe_mode: f.probe_mode', 'host_override: f.host_override', 'tls_server_name: f.tls_server_name', 'body.initial_endpoints']) assert.ok(classic.includes(field), field);
});

await check('Secret clear sends empty value', async () => {
  let putBody;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, opt) => {
    if (opt && opt.method === 'PUT') putBody = JSON.parse(opt.body);
    return { status: 200, ok: true, text: async () => '{"id":1,"revision":2}' };
  };
  try {
    const shell = {
      err: '', msg: '',
      async run(fn, msg) { await fn(); if (msg) this.msg = msg; return { ok: true }; },
      async loadSecrets() {},
    };
    createProbeFeature(shell, createApiClient());
    globalThis.confirm = () => true;
    await shell.clearSecret(1, 3);
    assert.equal(putBody.value, '');
    assert.equal(putBody.expected_revision, 3);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

await check('count_tokens station posture: uniform, mixed, not wired', () => {
  const routes = [
    { route_id: 1, upstream_id: 10, model_name: 'a', count_tokens: 'supported' },
    { route_id: 2, upstream_id: 10, model_name: 'b', count_tokens: 'supported' },
    { route_id: 3, upstream_id: 20, model_name: 'a', count_tokens: 'unsupported' },
    { route_id: 4, upstream_id: 30, model_name: 'a', count_tokens: 'unknown' },
    { route_id: 5, upstream_id: 40, model_name: 'a', count_tokens: 'config_error' },
    { route_id: 6, upstream_id: 50, model_name: 'a', count_tokens: 'unknown' },
    { route_id: 7, upstream_id: 50, model_name: 'b', count_tokens: 'supported' },
    { route_id: 8, upstream_id: 50, model_name: 'c', count_tokens: 'unsupported' },
    { route_id: 9, upstream_id: 60, model_name: 'a' },
  ];
  assert.equal(summarizeCountTokens(routes, 10).state, 'supported');
  assert.equal(summarizeCountTokens(routes, 20).state, 'unsupported');
  assert.equal(summarizeCountTokens(routes, 30).state, 'unknown');
  assert.equal(summarizeCountTokens(routes, 40).state, 'config_error');
  const mixed = summarizeCountTokens(routes, 50);
  assert.equal(mixed.state, 'mixed');
  assert.equal(mixed.text, 'mixed: 1 supported / 1 unsupported / 1 unknown');
  assert.equal(mixed.routes.length, 3);
  assert.equal(summarizeCountTokens(routes, 60).state, 'na');
  assert.equal(summarizeCountTokens(routes, 99).state, 'none');
  assert.equal(countTokensClass('supported'), 'ok');
  assert.equal(countTokensClass('unsupported'), 'err');
  assert.equal(countTokensClass('config_error'), 'err');
  assert.equal(countTokensClass('mixed'), 'warn');
  assert.equal(countTokensClass('unknown'), 'unknown');

  const shell = { health: { routes: [] }, routes: [{ id: 3, upstream_id: 20 }] };
  createCountTokensFeature(shell);
  assert.equal(shell.countTokensPosture(20).state, 'na', 'configured routes but no /health rows');
  assert.equal(shell.countTokensPosture(99).state, 'none');
  shell.health.routes = routes;
  assert.equal(shell.countTokensPosture(50).state, 'mixed');
});

await check('count_tokens posture identifies a partial health page without inventing no-routes', () => {
  const shell = {health: {routes: [{route_id: 1, upstream_id: 10, count_tokens: 'supported'}], next_cursor: 'next'}, configPages: {health: {cursor: ''}}, routes: []};
  createCountTokensFeature(shell);
  assert.equal(shell.countTokensPosture(10).text, '本页 supported');
  assert.equal(shell.countTokensPosture(20).state, 'na');
  assert.equal(shell.countTokensPosture(20).text, '未在本页');
  shell.health.next_cursor = '';
  shell.configPages.health.cursor = 'last-page';
  assert.equal(shell.countTokensPosture(20).state, 'na');
});

await check('Master rotation never sends requests while environment override or status is unknown', async () => {
  for (const status of [null, { rotation_allowed: false, blocked_reason: 'Run credentials migrate and restart without ENCRYPTION_KEY' }]) {
    const sent = [];
    const shell = { displayState: 'running', err: '', msg: '' };
    createCredentialsFeature(shell, {
      get: async () => status,
      post: async (url, body) => { sent.push({ url, body }); return {}; },
    });
    shell.credentials.status = status;
    shell.credentials.new_master = 'fixture-master-input';
    await shell.rotateMasterKey();
    assert.equal(sent.length, 0, 'blocked rotation must not send the new master to the API');
    assert.equal(shell.credentials.new_master, 'fixture-master-input', 'blocked input should remain editable');
    assert.ok(shell.err.length > 0);
    if (status) assert.equal(shell.err, status.blocked_reason);
  }
});

await check('Master rotation is enabled only by explicit backend allowance', async () => {
  const sent = [];
  const shell = { displayState: 'running', err: '', msg: '' };
  createCredentialsFeature(shell, {
    get: async () => ({ rotation_allowed: true }),
    post: async (url, body) => { sent.push({ url, body }); return { phase: 'cleaned', new_key_id: 'fixture-key-id' }; },
  });
  await shell.loadCredentials();
  shell.credentials.new_master = 'fixture-new-master';
  shell.credentials.password = 'fixture-admin';
  await shell.rotateMasterKey();
  assert.deepEqual(sent, [{ url: '/credentials/rotate-master', body: { password: 'fixture-admin', new_master: 'fixture-new-master' } }]);
  assert.equal(shell.credentials.new_master, '');
  assert.match(shell.msg, /fixture-key-id/);
});

if (failed) {
  console.error(`\n${failed} check(s) failed`);
  process.exit(1);
}
console.log('\nall modules.contract checks passed');
