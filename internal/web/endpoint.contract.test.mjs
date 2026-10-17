import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createProbeFeature} from './static/js/probes.mjs';

function fixture(overrides={}){
  const writes=[];
  const shell={authed:true,err:'',msg:''};
  createProbeFeature(shell,{async post(path,body){writes.push({method:'POST',path,body});},async put(path,body){writes.push({method:'PUT',path,body});},...overrides});
  shell.loadEndpoints=async()=>{};
  return {shell,writes};
}

test('ordinary Endpoint editor sends only editable auth and mutation fields',async()=>{
  const {shell,writes}=fixture();
  shell.endpointForm={id:7,upstream_id:3,endpoint:'messages',url_mode:'canonical',url_override:'',fixed_query_template:'',revision:8,auth_profile:{mode:'auto_calibrated',calibrated_mode:'x_api_key',secret_ref:'upstream_api_key',revision:4}};
  await shell.saveEndpoint();
  assert.equal(writes.length,1);
  assert.deepEqual(Object.keys(writes[0].body).sort(),['upstream_id','endpoint','url_override','fixed_query_template','auth_profile','expected_revision'].sort());
  assert.equal(writes[0].body.expected_revision,8);
  assert.equal(writes[0].body.auth_profile.calibrated_mode,undefined);
  assert.equal(writes[0].body.auth_profile.revision,undefined);
  assert.equal(writes[0].body.auth_profile.mode,'auto_calibrated');
});

test('new Endpoint POST carries no server revision or compatibility state',async()=>{
  const {shell,writes}=fixture();
  shell.endpointForm={upstream_id:3,endpoint:'messages',auth_profile:{mode:'x_api_key',secret_ref:'upstream_api_key'}};
  await shell.saveEndpoint();
  assert.equal(writes.length,1);
  assert.equal(writes[0].method,'POST');
  assert.equal(writes[0].body.expected_revision,undefined);
  assert.equal(writes[0].body.url_mode,undefined);
});

test('new Endpoint editor initializes a boolean idle state for Alpine button binding',()=>{
  const {shell}=fixture();
  shell.editEndpoint();
  assert.equal(shell.endpointForm.saving,false);
  assert.equal(shell.endpointForm.auth_profile.secret_ref,'upstream_api_key');
});

test('migration Endpoint editor fails closed and leaves review/calibration as explicit actions',async()=>{
  const {shell,writes}=fixture();
  shell.endpointForm={id:7,upstream_id:3,endpoint:'messages',revision:8,legacy_compat_real_only:true,auth_profile:{mode:'legacy_auto_real_only',secret_ref:'upstream_api_key'}};
  await shell.saveEndpoint();
  assert.equal(writes.length,0);
  assert.ok(shell.endpointForm);
  assert.match(shell.err,/审核|校准/);
});

test('late Endpoint failure preserves a new login draft, error and save ownership',async()=>{
  let reject;
  const pending=new Promise((resolve,rejectRequest)=>{reject=rejectRequest;});
  const {shell}=fixture({post:async()=>pending});
  shell.editEndpoint();
  shell.endpointForm.upstream_id=3;
  const previous=shell.endpointForm;
  const save=shell.saveEndpoint();
  shell.authed=false;shell.endpointForm=null;
  shell.authed=true;shell.editEndpoint();shell.endpointForm.saving=true;shell.err='new-login-error';
  const current=shell.endpointForm;
  reject(Object.assign(new Error('old-login-error'),{status:409}));
  await save;
  assert.equal(shell.endpointForm,current);
  assert.equal(shell.err,'new-login-error');
  assert.equal(current.saving,true);
  assert.equal(previous.saving,false);
});

test('persisted Endpoint create keeps the draft and blocks replay until explicit reload',async t=>{
  let writes=0,reads=0;
  const saved={id:19,upstream_id:3,endpoint:'messages',revision:1,url_mode:'canonical',auth_profile:{mode:'x_api_key',secret_ref:'upstream_api_key'}};
  const {shell}=fixture({post:async()=>{writes++;throw Object.assign(new Error('pending'),{status:503,data:{code:'config_activation_pending',persisted:true,resource:'endpoint',id:19,new_revision:1}});},get:async()=>{reads++;return saved;}});
  shell.editEndpoint();shell.endpointForm.upstream_id=3;
  const draft=shell.endpointForm;
  await shell.saveEndpoint();await shell.saveEndpoint();
  assert.equal(writes,1);
  assert.equal(reads,0);
  assert.equal(shell.endpointForm,draft);
  assert.equal(draft.pending,true);
  assert.match(shell.err,/已保存/);
  const original=globalThis.confirm;globalThis.confirm=()=>true;t.after(()=>{globalThis.confirm=original;});
  await shell.reloadEndpoint();
  assert.equal(reads,1);
  assert.equal(shell.endpointForm.id,19);
  assert.equal(shell.endpointForm.revision,1);
  assert.equal(shell.endpointForm.pending,false);
});

test('persisted Endpoint deletion displays pending activation without replaying DELETE',async t=>{
  let deletes=0,reloads=0;
  const {shell}=fixture({del:async path=>{deletes++;assert.equal(path,'/upstream-endpoints/19?expected_revision=4');throw Object.assign(new Error('pending'),{status:503,data:{code:'config_activation_pending',persisted:true,resource_id:19,revision:4}});}});
  const endpoint={id:19,revision:4,endpoint:'messages',url_mode:'canonical',auth_profile:{mode:'header_bearer',secret_ref:'upstream_api_key'}};
  shell.endpoints.items=[endpoint];
  shell.loadEndpoints=async()=>{reloads++;shell.endpoints.items=[];};
  const original=globalThis.confirm;globalThis.confirm=()=>true;t.after(()=>{globalThis.confirm=original;});
  await shell.deleteEndpoint(endpoint);await shell.deleteEndpoint(endpoint);
  assert.equal(deletes,1);
  assert.equal(reloads,0);
  assert.equal(endpoint.delete_pending,true);
  assert.match(shell.msg,/已删除.*待激活/);
  await shell.loadEndpoints(true);
  assert.equal(reloads,1);
  assert.equal(deletes,1);
});
