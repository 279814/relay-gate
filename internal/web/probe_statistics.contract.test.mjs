import assert from 'node:assert/strict';
import test from 'node:test';
import { createProbeFeature, mergeProbeTabs } from './static/js/probes.mjs';

function shellFor(api) {
  return createProbeFeature({ authed: true, tabs: [], reset() { this.authed = false; } }, api);
}

test('statistics feature calls the bounded endpoint and replaces each page', async () => {
  const calls = [];
  const responses = [
    { items: [{ template_id: 'builtin:a' }], total_rows: 2, next_cursor: 'next', previous_cursor: '', coverage: {} },
    { items: [{ template_id: 'builtin:b' }], total_rows: 2, next_cursor: '', previous_cursor: 'previous', coverage: {} },
    { items: [{ template_id: 'builtin:a' }], total_rows: 2, next_cursor: 'next', previous_cursor: '', coverage: {} },
  ];
  const shell = shellFor({ async get(path) { calls.push(path); return responses.shift(); } });
  assert.equal(typeof shell.loadProbeStatistics, 'function');
  mergeProbeTabs(shell);
  assert.ok(shell.tabs.some(tab => tab.id === 'probe-statistics'));
  shell.probeStatistics.filter.day_from = '2026-10-18';
  shell.probeStatistics.filter.day_to = '2026-10-19';
  shell.probeStatistics.filter.endpoint = 'messages';
  await shell.loadProbeStatistics();
  const first = new URL(calls[0], 'http://localhost');
  assert.equal(first.pathname, '/probe-statistics');
  assert.equal(first.searchParams.get('basis'), 'executions');
  assert.equal(first.searchParams.get('limit'), '50');
  assert.equal(first.searchParams.get('day_from'), '2026-10-18');
  assert.equal(first.searchParams.get('endpoint'), 'messages');
  await shell.loadProbeStatistics('next');
  assert.deepEqual(shell.probeStatistics.items.map(row => row.template_id), ['builtin:b']);
  assert.equal(new URL(calls[1], 'http://localhost').searchParams.get('cursor'), 'next');
  await shell.loadProbeStatistics('previous');
  assert.deepEqual(shell.probeStatistics.items.map(row => row.template_id), ['builtin:a']);
  assert.equal(new URL(calls[2], 'http://localhost').searchParams.get('cursor'), 'previous');
});

test('changed filters and logout prevent stale statistics responses from returning', async () => {
  const pending = [];
  const shell = shellFor({ get() { return new Promise((resolve, reject) => pending.push({ resolve, reject })); } });
  assert.equal(typeof shell.loadProbeStatistics, 'function');
  const old = shell.loadProbeStatistics();
  shell.probeStatistics.filter.endpoint = 'models';
  shell.onStatisticsFilterChange();
  const fresh = shell.loadProbeStatistics();
  pending[1].resolve({ items: [{ endpoint: 'models' }], total_rows: 1, coverage: {} });
  await fresh;
  pending[0].resolve({ items: [{ endpoint: 'messages' }], total_rows: 900, next_cursor: 'stale', coverage: {} });
  await old;
  assert.deepEqual(shell.probeStatistics.items, [{ endpoint: 'models' }]);
  const beforeLogout = shell.loadProbeStatistics();
  shell.reset();
  pending[2].resolve({ items: [{ endpoint: 'private-synthetic' }], total_rows: 1, coverage: {} });
  await beforeLogout;
  assert.equal(shell.authed, false);
  assert.deepEqual(shell.probeStatistics.items, []);
});

test('editing a filter before its change event also rejects the old response', async () => {
  let resolve;
  const shell = shellFor({ get() { return new Promise(done => { resolve = done; }); } });
  const pending = shell.loadProbeStatistics();
  shell.probeStatistics.filter.endpoint = 'models';
  resolve({ items: [{ endpoint: 'messages' }], total_rows: 1, coverage: {} });
  await pending;
  assert.deepEqual(shell.probeStatistics.items, []);
  assert.equal(shell.probeStatistics.loading, false);
});

test('unknown usage and real context are never rendered as zero cost or a Recipe rate', () => {
  const shell = shellFor({ async get() {} });
  assert.equal(typeof shell.statisticsTokenText, 'function');
  assert.equal(shell.statisticsTokenText(null, 3), 'unknown');
  assert.match(shell.statisticsTokenText(12, null), /12.*unknown/);
  assert.match(shell.statisticsTokenText(12, 3), /12.*3.*unknown/);
  assert.equal(shell.statisticsRateText(null), 'unknown');
  assert.equal(shell.statisticsRateText(0.5), '50.0%');
  assert.match(shell.statisticsRecipeText({ binding_use: 'real_traffic_context' }), /非 Recipe/);
  shell.probeStatistics.basis = 'daily';
  assert.match(shell.statisticsRecipeText({}), /未记录/);
  assert.match(shell.statisticsTriggerText('manual'), /canary/);
});

test('Canary basis uses recorded sources and clears unrelated Recipe filters', async () => {
  const calls = [];
  const shell = shellFor({ async get(path) { calls.push(path); return { items: [], total_rows: 0, coverage: {} }; } });
  const state = shell.probeStatistics;
  state.filter.recipe_id = '12'; state.filter.version_id = '5'; state.filter.origin = 'manual';
  state.filter.endpoint = 'models'; state.filter.trigger = 'recovery';
  state.basis = 'canary';
  shell.onStatisticsFilterChange();
  assert.equal(state.filter.recipe_id, '');
  assert.equal(state.filter.version_id, '');
  assert.equal(state.filter.origin, '');
  assert.equal(state.filter.endpoint, '');
  assert.equal(state.filter.trigger, '');
  const fields = shell.statisticsFilterFields();
  assert.deepEqual(fields.find(field => field.key === 'canary_source').options, ['manual', 'periodic']);
  assert.ok(!fields.some(field => field.key === 'recipe_id' || field.key === 'origin'));
  state.filter.canary_source = 'periodic';
  await shell.loadProbeStatistics();
  const query = new URL(calls[0], 'http://localhost').searchParams;
  assert.equal(query.get('basis'), 'canary');
  assert.equal(query.get('canary_source'), 'periodic');
  assert.equal(query.has('recipe_id'), false);
  assert.match(shell.statisticsRecipeText({ canary_source: 'periodic' }), /Canary.*非 Recipe/);
  assert.equal(shell.statisticsTriggerText('scheduled', 'periodic'), 'Canary · 周期');
  state.basis = 'executions';
  shell.onStatisticsFilterChange();
  assert.equal(state.filter.canary_source, '');
});
