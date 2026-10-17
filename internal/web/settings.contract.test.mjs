import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';
import { createApiClient } from './static/js/api.mjs';
import { createSettingsFeature } from './static/js/settings.mjs';
import { createRuntimeStateFeature } from './static/js/runtime.mjs';

const moduleFile = new URL('./static/js/settings.mjs', import.meta.url);
const snapshot = revision => ({ settings: { real_connect_sec: 30, real_response_header_sec: 1200, real_first_byte_sec: 1200, real_first_semantic_sec: 1200, real_idle_sec: 600, real_total_sec: 1800, count_tokens_connect_sec: 30, count_tokens_total_sec: 180 }, revision, limits: { min_real_first_semantic_sec: 300 } });

async function fixture(api) {
  assert.ok(fs.existsSync(moduleFile), 'revision-aware Settings module is missing');
  const { createSettingsFeature } = await import(moduleFile);
  const shell = { authed: true, settings: null, err: '', msg: '', reset() { this.authed = false; } };
  createSettingsFeature(shell, api);
  return shell;
}

test('Settings save submits the displayed revision and independent current stages', async () => {
  let reads = 0;
  const writes = [];
  const shell = await fixture({ async get() { reads++; return snapshot(4); }, async put(path, body) { writes.push({ path, body }); return { settings: { ...snapshot(4).settings, count_tokens_connect_sec: 2 }, revision: 5 }; } });
  await shell.loadSettings();
  shell.settings.count_tokens_connect_sec = 2;
  await shell.saveSettings();
  assert.equal(reads, 1, 'save must never fetch a newer revision behind the editor');
  assert.equal(writes.length, 1);
  assert.equal(writes[0].path, '/settings');
  assert.equal(writes[0].body.expected_revision, 4);
  assert.equal(writes[0].body.count_tokens_connect_sec, 2);
  assert.equal(writes[0].body.count_tokens_total_sec, undefined, 'unchanged fields stay out of a partial PUT');
  assert.equal(shell.settingsState.revision, 5);
  assert.equal(shell.settingsDirty(), false);
});

test('409 keeps the draft and revision and requires explicit reload before retry', async t => {
  let reads = 0, writes = 0;
  const shell = await fixture({ async get() { reads++; return snapshot(reads === 1 ? 4 : 5); }, async put() { writes++; throw Object.assign(new Error('revision conflict'), { status: 409 }); } });
  await shell.loadSettings();
  shell.settings.real_first_semantic_sec = 1250;
  await shell.saveSettings();
  await shell.saveSettings();
  await shell.loadSettings();
  assert.equal(shell.settings.real_first_semantic_sec, 1250);
  assert.equal(shell.settingsState.revision, 4);
  assert.equal(shell.settingsState.conflict, true);
  assert.equal(writes, 1);
  assert.equal(reads, 1, 'background refresh must not discard the conflicted draft');
  const originalConfirm = globalThis.confirm;
  globalThis.confirm = () => true;
  t.after(() => { globalThis.confirm = originalConfirm; });
  await shell.reloadSettings();
  assert.equal(shell.settingsState.revision, 5);
  assert.equal(shell.settingsState.conflict, false);
  assert.equal(shell.settingsDirty(), false);
});

test('activation-pending means persisted and preserves edits without replaying', async () => {
  let writes = 0;
  const shell = await fixture({ async get() { return snapshot(7); }, async put() { writes++; throw Object.assign(new Error('activation pending'), { status: 503, data: { code: 'config_activation_pending', persisted: true, new_revision: 8 } }); } });
  await shell.loadSettings();
  shell.settings.real_first_semantic_sec = 1300;
  await shell.saveSettings();
  await shell.saveSettings();
  assert.equal(shell.settings.real_first_semantic_sec, 1300);
  assert.equal(shell.settingsState.pending, true);
  assert.equal(shell.settingsState.revision, 7);
  assert.equal(shell.settingsState.persistedRevision, 8);
  assert.match(shell.err + shell.msg, /已保存/);
  assert.equal(writes, 1);
});

test('background loads preserve unsaved edits and logout clears the versioned draft', async () => {
  let reads = 0;
  const shell = await fixture({ async get() { reads++; return snapshot(3); } });
  await shell.loadSettings();
  shell.settings.count_tokens_total_sec = 200;
  await shell.loadSettings();
  assert.equal(reads, 1);
  assert.equal(shell.settings.count_tokens_total_sec, 200);
  shell.reset();
  assert.equal(shell.settings, null);
  assert.equal(shell.settingsState.revision, 0);
  assert.equal(shell.settingsState.conflict, false);
});

test('Settings markup binds every new stage and exposes no legacy controls', () => {
  const html = fs.readFileSync(new URL('./static/index.html', import.meta.url), 'utf8');
  for (const key of ['real_first_token_sec', 'l2_first_token_sec', 'count_tokens_sec']) assert.ok(!html.includes('settings.' + key), key);
  for (const key of ['real_response_header_sec', 'real_first_byte_sec', 'real_first_semantic_sec', 'l2_response_header_sec', 'l2_first_byte_sec', 'l2_first_event_sec', 'l2_first_semantic_sec', 'l2_idle_sec', 'count_tokens_connect_sec', 'count_tokens_total_sec']) assert.ok(html.includes('settings.' + key), key);
  assert.ok(html.includes('reloadSettings()'));
  assert.ok(html.includes('settingsState.conflict'));
});

test('late Settings reads cannot overwrite a new login or unlock its pending read', async () => {
  let finishOldRead, finishNewRead;
  let reads = 0;
  const oldRead = new Promise(resolve => { finishOldRead = resolve; });
  const newRead = new Promise(resolve => { finishNewRead = resolve; });
  const shell = await fixture({ get() { return ++reads === 1 ? oldRead : newRead; } });
  const loading = shell.loadSettings();
  shell.reset(); shell.authed = true;
  const newLoading = shell.loadSettings();
  finishOldRead(snapshot(4));
  await loading;
  assert.equal(shell.settings, null);
  assert.equal(shell.settingsState.revision, 0);
  assert.equal(shell.settingsState.loading, true);
  finishNewRead(snapshot(8));
  await newLoading;
  assert.equal(shell.settingsState.revision, 8);
});

test('late Settings write errors do not mark the new login conflicted or unlock its save', async () => {
  let failOldSave, finishNewSave;
  let writes = 0, reads = 0;
  const oldSave = new Promise((resolve, reject) => { failOldSave = reject; });
  const newSave = new Promise(resolve => { finishNewSave = resolve; });
  const shell = await fixture({ get() { return Promise.resolve(snapshot(++reads === 1 ? 4 : 8)); }, put() { return ++writes === 1 ? oldSave : newSave; } });
  await shell.loadSettings();
  shell.settings.count_tokens_total_sec = 200;
  const oldSaving = shell.saveSettings();
  shell.reset(); shell.authed = true;
  await shell.loadSettings();
  shell.settings.count_tokens_total_sec = 210;
  const saving = shell.saveSettings();
  shell.err = 'new login message';
  failOldSave(Object.assign(new Error('old conflict'), {status:409}));
  await oldSaving;
  assert.equal(shell.settingsState.revision, 8);
  assert.equal(shell.settingsState.busy, true);
  assert.equal(shell.settingsState.conflict, false);
  assert.equal(shell.err, 'new login message');
  finishNewSave({settings: {...snapshot(8).settings, count_tokens_total_sec:210}, revision:9});
  await saving;
});

// Exercise the actual boot -> shared client -> feature boundary. The proxy
// records reactive writes, rather than substituting an API that skips 401 hooks.
async function bootClientFixture(t, fetchResponse) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = fetchResponse;
  t.after(() => { globalThis.fetch = originalFetch; });
  let resets = 0;
  const base = { authed:true, settings:null, err:'', msg:'', tabs:[],
    async boot() {}, reset() { resets++; this.authed = false; } };
  const source = fs.readFileSync(new URL('./static/js/boot.mjs', import.meta.url), 'utf8');
  const imports = [...source.matchAll(/^import \{ ([^}]+) \} from .+;$/gm)].flatMap(match => match[1].split(',').map(name => name.trim()));
  const context = { window:{app:()=>base}, console, createApiClient, createSettingsFeature, createRuntimeStateFeature };
  for (const name of imports) if (!(name in context)) context[name] = () => {};
  vm.runInNewContext(source.replace(/^import .+;$/gm, ''), context);
  const raw = context.window.app();
  const writes = [];
  const shell = new Proxy(raw, {set(target,key,value) { writes.push([key,value]); return Reflect.set(target,key,value); }});
  await shell.boot();
  return {shell,writes,resets:()=>resets};
}

const httpJSON = (status, data) => ({status,ok:status>=200&&status<300,text:async()=>JSON.stringify(data)});

test('real client old 401 preserves the new login draft and its pending save', async t => {
  let finishOld, finishSave;
  let reads = 0;
  const oldResponse = new Promise(resolve => {finishOld=resolve;});
  const saveResponse = new Promise(resolve => {finishSave=resolve;});
  const {shell} = await bootClientFixture(t, (url,opt) => {
    if (opt.method==='PUT') return saveResponse;
    return ++reads===1 ? oldResponse : Promise.resolve(httpJSON(200,snapshot(8)));
  });
  const oldLoad=shell.loadSettings();
  shell.reset();shell.authed=true;
  await shell.loadSettings();
  shell.settings.count_tokens_total_sec=210;
  const saving=shell.saveSettings();
  finishOld(httpJSON(401,{error:'old login expired'}));await oldLoad;
  assert.equal(shell.authed,true);
  assert.equal(shell.settings.count_tokens_total_sec,210);
  assert.equal(shell.settingsState.revision,8);
  assert.equal(shell.settingsState.busy,true);
  finishSave(httpJSON(200,{settings:{...snapshot(8).settings,count_tokens_total_sec:210},revision:9}));
  await saving;
  assert.equal(shell.settingsState.revision,9);
});

test('real client current 401 clears state through the reactive receiver', async t => {
  const {shell,writes,resets} = await bootClientFixture(t,async()=>httpJSON(401,{error:'expired'}));
  shell.applyStatePayload({state:'running',revision:4});
  writes.length=0;
  await shell.loadSettings();
  assert.equal(shell.authed,false);
  assert.equal(shell.settings,null);
  assert.equal(shell.stateRevision,0);
  assert.equal(resets(),1);
  assert.ok(writes.some(([key,value])=>key==='authed'&&value===false),'reset must write through the Alpine receiver');
});

test('concurrent old 401s cannot clear a relogin and current 401 still resets it', async t => {
  const responses=[];
  const {shell,resets} = await bootClientFixture(t,()=>new Promise(resolve=>responses.push(resolve)));
  const first=shell.loadSettings();
  const second=shell.refreshState();
  responses[0](httpJSON(401,{}));await first;
  assert.equal(resets(),1);
  shell.authed=true;
  const current=shell.loadSettings();
  responses[2](httpJSON(200,snapshot(8)));await current;
  shell.settings.count_tokens_total_sec=220;
  responses[1](httpJSON(401,{}));await second;
  assert.equal(resets(),1);
  assert.equal(shell.authed,true);
  assert.equal(shell.settings.count_tokens_total_sec,220);
  const current401=shell.refreshState();
  responses[3](httpJSON(401,{}));await current401;
  assert.equal(resets(),2);
  assert.equal(shell.authed,false);
});
