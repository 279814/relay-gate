import assert from 'node:assert/strict';
import fs from 'node:fs';
import { test } from 'node:test';

test('recipe editor keeps a conflicted draft and never silently retries a write', async () => {
  const file = new URL('./static/js/recipe_admin.mjs', import.meta.url);
  assert.ok(fs.existsSync(file), 'Recipe/Profile editor module is missing');
  const { createRecipeAdminFeature } = await import(file);
  const calls = [];
  const api = {
    async get(path) {
      if (path.endsWith('/versions?limit=25')) return { items: [{ id: 9, recipe_id: 2, version: 1, method: 'GET', headers: [], body_text: '', timeout_profile: 'l1' }], next_cursor: '' };
      return { ID: 2, ScopeType: 'upstream', ScopeID: 3, Endpoint: 'models', Revision: 4, DraftVersionID: 9 };
    },
    async post(path, body) { calls.push({ path, body }); throw Object.assign(new Error('revision conflict'), { status: 409 }); },
  };
  const shell = { tabs: [], err: '', _lockModal() {}, _unlockModal() {}, async loadRecipes() {} };
  createRecipeAdminFeature(shell, api);
  await shell.openRecipe(2);
  shell.recipeEditor.draft.body = 'preserve this edit';
  await shell.saveRecipeVersion();
  assert.equal(shell.recipeEditor.draft.body, 'preserve this edit');
  assert.equal(shell.recipeEditor.conflict, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].body.expected_revision, 4);
  assert.equal(calls[0].path, '/probe-recipes/2/versions');
  await shell.saveRecipeVersion();
  assert.equal(calls.length, 1, 'conflict must require explicit reload before any retry');
});

test('Force never sends without a failed completed test and explicit acknowledgement', async () => {
  const file = new URL('./static/js/recipe_admin.mjs', import.meta.url);
  assert.ok(fs.existsSync(file), 'Recipe/Profile editor module is missing');
  const { createRecipeAdminFeature } = await import(file);
  const calls = [];
  const shell = { tabs: [], err: '' };
  createRecipeAdminFeature(shell, { async post(path, body) { calls.push({ path, body }); } });
  shell.recipeEditor = { recipe: { ID: 1, Revision: 5 }, selected: { id: 7 }, execution: { ID: 'success', Success: true, Final: true, SentAtMS: 1 }, forceAcknowledged: true, busy: false, conflict: false };
  assert.equal(shell.canForceRecipe(), false);
  await shell.publishRecipe(true);
  assert.equal(calls.length, 0);
});

test('safe sample import starts an explicit draft without any probe or publish', async () => {
  const { createRecipeAdminFeature } = await import('./static/js/recipe_admin.mjs');
  const shell = { tabs: [] };
  let calls = 0;
  createRecipeAdminFeature(shell, { async post() { calls++; } });
  assert.equal(typeof shell.openSampleRecipeCandidate, 'function', 'sample candidate bridge is missing');
  shell.openSampleRecipeCandidate({ upstream_id: 3, endpoint: 'messages', method: 'POST', body_text: '{"model":"{{UPSTREAM_MODEL}}"}', headers: [], timeout_profile: 'l2_standard', origin: 'legacy_migration' });
  assert.equal(shell.recipeForm.scope, 'upstream');
  assert.equal(shell.recipeForm.scope_id, 3);
  assert.equal(shell.recipeForm.endpoint, 'messages');
  assert.equal(calls, 0);
});

test('logout clears recipe/profile data and releases modal state', async () => {
  const { createRecipeAdminFeature } = await import('./static/js/recipe_admin.mjs');
  let originalReset = 0, unlocked = 0;
  const shell = { tabs: [], reset() { originalReset++; }, _unlockModal() { unlocked++; } };
  createRecipeAdminFeature(shell, {});
  shell.recipeEditor = { draft: { body: 'private manual template' } };
  shell.profileView = { profile: { id: 1 } };
  shell.recipeCandidateSeed = { body_text: 'candidate' };
  shell.profiles.items.push({ id: 1 });
  shell.reset();
  assert.equal(shell.recipeEditor, null);
  assert.equal(shell.profileView, null);
  assert.equal(shell.recipeCandidateSeed, null);
  assert.deepEqual(shell.profiles.items, []);
  assert.equal(originalReset, 1);
  assert.equal(unlocked, 1);
});
