const fs = require('fs');
const path = require('path');
const assert = require('assert/strict');
eval(fs.readFileSync(path.join(__dirname, 'static/app.js'), 'utf8'));

(async () => {
  const shell = app();
  shell.loadHealth = async () => {};
  let calls = [];
  shell.api = async (method, resource, body) => { calls.push({method, resource, body}); return {items: [], next_cursor: ''}; };
  shell.editMn({id: 1, revision: 7, name: 'edited', protocol: 'anthropic'});
  await shell.saveMn();
  assert.equal(calls[0].body.expected_revision, 7, 'save must send the editing revision');

  shell.editMn({id: 1, revision: 7, name: 'keep my draft', protocol: 'anthropic'});
  calls = [];
  shell.api = async (...args) => { calls.push(args); const e = new Error('revision conflict'); e.status = 409; throw e; };
  await shell.saveMn();
  assert.equal(shell.mnForm.name, 'keep my draft');
  assert.equal(shell.mnForm.revision, 7);
  assert.equal(calls.length, 1, 'conflict must not silently fetch and adopt a newer revision');
  assert.match(shell.err, /刷新|最新/);

  calls = [];
  shell.api = async (method, resource) => { calls.push(resource); return resource.includes('cursor=') ? {items: [{id: 2}], next_cursor: ''} : {items: [{id: 1}], next_cursor: 'opaque-next'}; };
  await shell.loadConfigPage('upstreams', 'reset');
  assert.deepEqual(shell.upstreams.map(row => row.id), [1]);
  await shell.loadConfigPage('upstreams', 'next');
  assert.deepEqual(shell.upstreams.map(row => row.id), [2]);
  assert.match(calls[1], /cursor=opaque-next/);

  shell.editUp(null);
  assert.equal(shell.upForm.initial_endpoints.length, 5);
  assert.equal(new Set(shell.upForm.initial_endpoints.map(ep => ep.endpoint)).size, 5);
  calls = [];
  shell.upForm.name = 'new'; shell.upForm.base_url = 'https://example.test'; shell.upForm.api_key = 'fixture-private-key';
  shell.api = async (method, resource, body) => { calls.push({method, resource, body}); return {items: [], next_cursor: ''}; };
  await shell.saveUp();
  assert.equal(calls[0].body.initial_endpoints.length, 5);
  assert.ok(calls[0].body.initial_endpoints.every(ep => ep.auth_profile.mode && ep.auth_profile.secret_ref));
	for (const field of ['auth_style','l1_path','full_url_mode','probe_headers']) assert.ok(!(field in calls[0].body), 'legacy global field was sent: '+field);

  let releaseOld;
  const oldResponse = new Promise(resolve => { releaseOld = resolve; });
  let ordinal = 0;
  shell.api = async () => ++ordinal === 1 ? oldResponse : {items: [{id: 99}], next_cursor: ''};
  const oldLoad = shell.loadConfigPage('upstreams', 'reset');
  shell.configPages.upstreams.enabled = 'false';
  await shell.loadConfigPage('upstreams', 'reset');
  releaseOld({items: [{id: 1}], next_cursor: ''});
  await oldLoad;
  assert.deepEqual(shell.upstreams.map(row => row.id), [99], 'late page response must not replace the selected filter');

  for (const [edit, save, field] of [['editUp','saveUp','upForm'], ['editMn','saveMn','mnForm'], ['editRt','saveRt','rtForm']]) {
    shell[edit](null);
    calls = [];
    shell.api = async (method, resource, body) => {
      calls.push({method, resource, body});
      const error = new Error('activation pending'); error.status = 503;
      error.data = {persisted: true, resource_id: 44, revision: 1};
      throw error;
    };
    await shell[save]();
    assert.equal(shell[field].id, 44, field + ' must retain the already committed create ID');
    assert.equal(shell[field].revision, 1);
    assert.equal(calls.length, 1, 'pending create must not automatically fetch/adopt another version');
    await shell[save]();
    assert.equal(calls[1].method, 'PUT', 'retry must not duplicate the already committed resource');
    assert.equal(calls[1].body.expected_revision, 1);
  }
	for (const method of ['delUp','delMn']) {
	  let prompt;
	  global.confirm = message => { prompt = message; return false; };
	  await shell[method]({id: 7, revision: 2, name: 'referenced'});
	  assert.match(prompt, /禁止硬删除|不能删除/);
	  assert.match(prompt, /历史不会/);
	  assert.ok(!prompt.includes('一并删除'));
	}
  console.log('ok configadmin client revision, conflict draft, cursor and explicit bundle');
})().catch(error => { console.error(error); process.exitCode = 1; });
