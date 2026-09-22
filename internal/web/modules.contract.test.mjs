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
  for (const name of ['api.mjs', 'probes.mjs', 'modal.mjs', 'boot.mjs', 'errors.mjs', 'migration.mjs', 'credentials.mjs', 'security.mjs', 'transforms.mjs', 'runtime.mjs']) {
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

if (failed) {
  console.error(`\n${failed} check(s) failed`);
  process.exit(1);
}
console.log('\nall modules.contract checks passed');
