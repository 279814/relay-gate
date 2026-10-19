import test from 'node:test';
import assert from 'node:assert/strict';
import { createTransformsFeature } from './static/js/transforms.mjs';

const plain = { kind: 'replace_bytes', from: 'old', to: 'new' };

test('published draft exposes explicit request reencoding separately from rules text', () => {
  const shell = {};
  createTransformsFeature(shell, {});
  shell.selectTransformSet({ id: 7, draft: { rules: [{ kind: 'request_reencode' }, plain] } });
  assert.equal(shell.transforms.requestReencode, true);
  assert.deepEqual(JSON.parse(shell.transforms.draftRulesJSON), [plain]);
  shell.selectTransformSet({ id: 8, draft: { rules: [plain] } });
  assert.equal(shell.transforms.requestReencode, false);
  shell.reset();
  assert.equal(shell.transforms.requestReencode, false);
});

test('saving uses the explicit opt-in once, and clearing it removes authorization', async () => {
  const sent = [];
  const shell = {};
  createTransformsFeature(shell, {
    async put(path, body) { sent.push({ path, body }); return { id:7, revision:sent.length+1, state:'active', draft: { revision: sent.length+1, rules:body.rules } }; },
  });
  shell.loadTransforms = async () => {};
  shell.selectTransformSet({ id: 7, revision:1, state:'active', draft: { rules: [plain] } });
  shell.transforms.requestReencode = true;
  await shell.saveTransformDraft();
  assert.deepEqual(sent[0].body.rules, [{ kind: 'request_reencode' }, plain]);
  shell.transforms.draftRulesJSON = JSON.stringify([{ kind: 'request_reencode' }, plain]);
  await shell.saveTransformDraft();
  assert.deepEqual(sent[1].body.rules, [{ kind: 'request_reencode' }, plain]);
  shell.transforms.requestReencode = false;
  await shell.saveTransformDraft();
  assert.deepEqual(sent[2].body.rules, [plain]);
  assert.deepEqual(sent.map(call=>call.body.expected_revision),[1,2,3]);
});
