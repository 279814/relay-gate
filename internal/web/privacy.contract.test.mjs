import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {test} from 'node:test';
import * as apiModule from './static/js/api.mjs';
import * as probesModule from './static/js/probes.mjs';
import * as errorsModule from './static/js/errors.mjs';
import * as migrationModule from './static/js/migration.mjs';
import * as credentialsModule from './static/js/credentials.mjs';
import * as securityModule from './static/js/security.mjs';
import * as transformsModule from './static/js/transforms.mjs';
import * as runtimeModule from './static/js/runtime.mjs';
import * as countModule from './static/js/count_tokens.mjs';
import * as recipeModule from './static/js/recipe_admin.mjs';
import * as settingsModule from './static/js/settings.mjs';
import * as attemptMetadataModule from './static/js/attempt_metadata.mjs';

const deferred=()=>{let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};};
const httpJSON=(status,data)=>({status,ok:status>=200&&status<300,text:async()=>JSON.stringify(data)});

async function fullBoot(t,fetchResponse,configure=()=>{}) {
  const before=globalThis.fetch;
  globalThis.fetch=fetchResponse;
  t.after(()=>{globalThis.fetch=before;});
  const context={window:{},console,URLSearchParams,setTimeout,clearTimeout,setInterval,clearInterval};
  for(const module of [apiModule,probesModule,errorsModule,migrationModule,credentialsModule,securityModule,transformsModule,runtimeModule,countModule,recipeModule,settingsModule,attemptMetadataModule])Object.assign(context,module);
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(new URL('./static/app.js',import.meta.url),'utf8'),context);
  const base=context.app();base.boot=async()=>{};base.authed=true;
  configure(base);
  context.window.app=()=>base;
  const boot=fs.readFileSync(new URL('./static/js/boot.mjs',import.meta.url),'utf8');
  vm.runInContext(boot.replace(/^import .+;$/gm,''),context);
  const shell=context.window.app();await shell.boot();return shell;
}

test('full boot logout clears credentials, evidence, drafts, probe data and modal resources',async t=>{
  const shell=await fullBoot(t,async()=>httpJSON(200,{}));
  for(const key of ['master_key','relay_key','admin_password','password','new_master'])shell.credentials[key]='synthetic-private';
  shell.security.findings=[{detail:'synthetic-private'}];shell.security.smtpPassword='synthetic-private';shell.security.scanText='synthetic-private';shell.security.smtp={password:'synthetic-private'};
  shell.recentErrors.latest={error:'synthetic-private'};shell.recentErrors.logs=[{error:'synthetic-private'}];shell.recentErrors.open=true;
  shell.transforms.draftRulesJSON='synthetic-private';shell.transforms.previewBody='synthetic-private';shell.transforms.previewResult='synthetic-private';shell.transforms.executions=[{note:'synthetic-private'}];
  for(const key of ['endpoints','secrets','recipes','executions','capabilities','reachability','calibrations','probeCostDaily'])shell[key].items=[{value:'synthetic-private'}];
  shell.executionDrawer={detail:'synthetic-private'};shell.endpointForm={fixed_query_template:'synthetic-private'};shell.secretForm={value:'synthetic-private'};shell.recipeForm={note:'synthetic-private'};
  shell.profileFilters.client_family='synthetic-private';shell.profileView={profile:{body:'synthetic-private'}};
  shell.attemptMetadata.open=true;shell.attemptMetadata.reqID='synthetic-private';shell.attemptMetadata.attempts=[{executionID:'synthetic-private'}];
  let modalReleased=0; shell._modalUnlock=()=>{modalReleased++;};
  shell.reset();
  assert.equal(shell.authed,false);
  assert.equal(JSON.stringify(shell).includes('synthetic-private'),false);
  assert.equal(shell.credentials.master_key,'');assert.equal(shell.security.findings.length,0);
  assert.equal(modalReleased,1);assert.equal(shell._modalUnlock,null);
  assert.equal(shell.probeModuleReady,true,'logout must not disable installed modules');
});

test('old successful security response cannot refill data or unlock the new login request',async t=>{
  const old=deferred(),current=deferred();let requests=0;
  const shell=await fullBoot(t,()=>++requests===1?old.promise:current.promise);
  const oldLoad=shell.loadSecurityFindings();shell.reset();shell.authed=true;
  const newLoad=shell.loadSecurityFindings();shell.err='new login message';
  old.resolve(httpJSON(200,{findings:[{detail:'old-private'}],total:1}));await oldLoad;
  assert.equal(shell.security.findings.length,0);assert.equal(shell.security.loading,true);assert.equal(shell.err,'new login message');
  current.resolve(httpJSON(200,{findings:[{detail:'current'}],total:1}));await newLoad;
  assert.equal(shell.security.findings[0].detail,'current');
});

test('a body text completed after reset never returns credential data to its caller',async t=>{
  const text=deferred();let began=false;
  const before=globalThis.fetch;t.after(()=>{globalThis.fetch=before;});
  globalThis.fetch=async()=>({status:200,ok:true,text(){began=true;return text.promise;}});
  const api=apiModule.createApiClient();const response=api.get('/credentials/reveal-master').then(data=>({data}),error=>({error}));
  await Promise.resolve();await Promise.resolve();assert.equal(began,true);
  api.invalidatePendingRequests();text.resolve('{"master_key":"old-private"}');
  const result=await response;
  assert.equal(result.data,undefined);assert.equal(result.error?.stale,true);assert.equal(result.error?.data,undefined);
});

test('old run catch and finally cannot replace a new session message or unlock its action',async t=>{
  const old=deferred(),current=deferred();let requests=0;
  const shell=await fullBoot(t,()=>++requests===1?old.promise:current.promise);
  const first=shell.run(()=>shell.api('POST','/fixture-old'));
  shell.reset();shell.authed=true;
  const second=shell.run(()=>shell.api('POST','/fixture-new'));shell.err='new login message';
  old.resolve(httpJSON(200,{private:'old'}));await first;
  assert.equal(shell.busy,true);assert.equal(shell.err,'new login message');
  current.resolve(httpJSON(200,{}));await second;assert.equal(shell.busy,false);
});

test('a stale budget preflight cannot issue a write in the new login',async t=>{
  const old=deferred();const requests=[];
  const shell=await fullBoot(t,(url,opt)=>{requests.push([url,opt.method]);return requests.length===1?old.promise:Promise.resolve(httpJSON(200,{budgets:{request_ms:50,sse_event_ms:10}}));});
  const saving=shell.saveTransformBudgets();shell.reset();shell.authed=true;shell.msg='new login';
  old.resolve(httpJSON(500,{error:'old request failed'}));await saving;
  assert.equal(requests.length,1,'an expired preflight must not continue with a new authenticated PUT');
  assert.equal(shell.msg,'new login');
});

test('old probe page and finally cannot replace or unlock a newer filter page',async t=>{
  const old=deferred(),current=deferred();let requests=0;
  const shell=await fullBoot(t,()=>++requests===1?old.promise:current.promise);
  const first=shell.loadExecutions(true);
  shell.executions.filter.route_id='2';shell.onProbeFilterChange('executions');
  const second=shell.loadExecutions(true);
  old.resolve(httpJSON(200,{items:[{id:'old-filter'}],next_cursor:'old'}));await first;
  assert.equal(shell.executions.items.length,0);assert.equal(shell.executions.loading,true);
  current.resolve(httpJSON(200,{items:[{id:'new-filter'}],next_cursor:''}));await second;
  assert.equal(shell.executions.items[0].id,'new-filter');
});

test('old probe completion cannot clear a new login probe or replace its message',async t=>{
  const old=deferred(),current=deferred();let requests=0;
  const shell=await fullBoot(t,()=>++requests===1?old.promise:current.promise);
  shell.loadHealth=async()=>{};
  const first=shell.probe(1);shell.reset();shell.authed=true;
  const second=shell.probe(2);shell.err='current probe';
  old.resolve(httpJSON(200,{execution_id:'old'}));await first;
  assert.equal(shell.probing,2);assert.equal(shell.err,'current probe');assert.equal(shell.probeResult,null);
  current.resolve(httpJSON(200,{execution_id:'current'}));await second;
  assert.equal(shell.probeResult.execution_id,'current');
});

test('old profile list finally cannot unlock a new login profile read',async t=>{
  const old=deferred(),current=deferred();let requests=0;
  const shell=await fullBoot(t,()=>++requests===1?old.promise:current.promise);
  const first=shell.loadProfiles(true);shell.reset();shell.authed=true;
  const second=shell.loadProfiles(true);shell.err='current profiles';
  old.resolve(httpJSON(200,{items:[{private:'old'}],next_cursor:''}));await first;
  assert.equal(shell.profiles.loading,true);assert.equal(shell.profiles.items.length,0);assert.equal(shell.err,'current profiles');
  current.resolve(httpJSON(200,{items:[],next_cursor:''}));await second;
});

test('all obsolete status responses are rejected before reading their body',async t=>{
  const before=globalThis.fetch;t.after(()=>{globalThis.fetch=before;});
  for(const status of [200,204,400,503]){
    const old=deferred();let bodyReads=0;
    globalThis.fetch=()=>old.promise;
    const api=apiModule.createApiClient();
    const result=api.get('/private').then(data=>({data}),error=>({error}));
    api.invalidatePendingRequests();
    old.resolve({status,ok:status<300,text(){bodyReads++;return Promise.resolve('{"private":"old"}');}});
    const settled=await result;
    assert.equal(settled.data,undefined);assert.equal(settled.error?.stale,true);assert.equal(bodyReads,0);
  }
});

test('Upstream saves keep explicit current fields across logout and relogin',async t=>{
  const old=deferred(),current=deferred();const requests=[];
  const shell=await fullBoot(t,(url,opt)=>{requests.push(JSON.parse(opt.body));return requests.length===1?old.promise:current.promise;});
  shell.loadConfigPage=async()=>{};shell.loadHealth=async()=>{};
  const form=host=>({id:1,revision:1,name:'fixture',base_url:'https://fixture.invalid',proxy_url:'',enabled:true,probe_mode:'active',host_override:host,tls_server_name:''});
  shell.upForm=form('old-private');
  const first=shell.saveUp();shell.reset();shell.authed=true;
  shell.upForm=form('new-public');
  const second=shell.saveUp();
  assert.equal(requests[1].host_override,'new-public');
  shell.err='new message';old.resolve(httpJSON(200,{}));await first;
  assert.equal(shell.err,'new message');
  assert.equal(shell.upForm.host_override,'new-public');
  current.resolve(httpJSON(200,{}));await second;
});

test('an obsolete loadAll cannot start fresh authenticated reads after logout',async t=>{
  const old=deferred();const requests=[];
  const shell=await fullBoot(t,(url)=>{requests.push(url);return requests.length<=4?old.promise:Promise.resolve(httpJSON(401,{}));});
  const loading=shell.loadAll();
  assert.equal(requests.length,4);
  shell.reset();
  old.resolve(httpJSON(200,{items:[],next_cursor:'',state:'running',revision:1}));
  await loading;
  assert.equal(requests.length,4,'old continuations must not create a new request cohort while logged out');
});
