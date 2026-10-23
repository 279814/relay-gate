import test from 'node:test';
import assert from 'node:assert/strict';
import {createTransformsFeature} from './static/js/transforms.mjs';

const set = () => ({id:7,revision:3,state:'active',draft:{rules:[],revision:2}});
test('draft uses the displayed revision and keeps unsaved input on conflict', async()=>{
 const calls=[];const shell={};
 createTransformsFeature(shell,{put:async(path,body)=>{calls.push({path,body});throw new Error('revision conflict');}});
 shell.selectTransformSet(set());shell.transforms.draftRulesJSON='[{"kind":"replace_bytes","from":"a","to":"b"}]';
 await shell.saveTransformDraft();
 assert.equal(calls[0].body.expected_revision,3);
 assert.match(shell.transforms.draftRulesJSON,/replace_bytes/);assert.equal(shell.transforms.selected.revision,3);
});
test('budget save never refreshes away the client revision', async()=>{
 const calls=[];const shell={};
 createTransformsFeature(shell,{get:async()=>{throw new Error('unexpected read');},put:async(path,body)=>{calls.push(body);return {revision:5,budgets:{request_ms:20,sse_event_ms:5}};}});
 Object.assign(shell.transforms,{budgetRevision:4,budgetRequestMs:20,budgetSSEMs:5,budgetBaselineRequestMs:50,budgetBaselineSSEMs:10});
 await shell.saveTransformBudgets();assert.equal(calls[0].expected_revision,4);assert.equal(shell.transforms.budgetRevision,5);
});
test('publish requires an explicitly loaded exact binding',async()=>{
 const calls=[];const shell={};createTransformsFeature(shell,{post:async(...args)=>{calls.push(args);}});
 shell.selectTransformSet(set());Object.assign(shell.transforms,{routeId:'10',endpointId:'20'});
 await shell.publishTransform();assert.equal(calls.length,0);assert.match(shell.err,/绑定/);
});

test('binding lookup is exact and stale target cannot authorize publishing',async()=>{
 const calls=[];const shell={};createTransformsFeature(shell,{get:async path=>{calls.push(path);return {bindings:[]};},post:async()=>{throw new Error('must not publish');}});
 shell.selectTransformSet(set());Object.assign(shell.transforms,{routeId:'10',endpointId:'20'});
 await shell.loadTransformBinding();assert.equal(calls[0],'/transform-bindings?route_id=10&endpoint_id=20&limit=1');assert.equal(shell.transforms.bindingRevision,0);
 shell.transforms.endpointId='21';await shell.publishTransform();assert.match(shell.err,/绑定/);
});

test('lifecycle action uses displayed set revision',async()=>{
 let sent;const shell={};createTransformsFeature(shell,{post:async(path,body)=>{sent={path,body};return {...set(),revision:4,state:'disabled'};}});
 shell.selectTransformSet(set());shell.loadTransforms=async()=>{};
 await shell.changeTransformLifecycle('disable');assert.equal(sent.path,'/transforms/7/disable');assert.equal(sent.body.expected_revision,3);assert.equal(shell.transforms.selected.state,'disabled');
});

test('late draft save cannot replace a newly selected set',async()=>{
 let finish;const shell={};createTransformsFeature(shell,{put:()=>new Promise(resolve=>{finish=resolve;})});
 shell.selectTransformSet(set());const save=shell.saveTransformDraft();
 shell.selectTransformSet({...set(),id:8});finish({...set(),revision:4});await save;
 assert.equal(shell.transforms.selectedId,8);
});

test('concurrent write is suppressed and persisted failure blocks every replay',async()=>{
 let finish;const calls=[];const shell={};createTransformsFeature(shell,{post:(path,body)=>{calls.push({path,body});if(calls.length===1)return new Promise((resolve,reject)=>{finish=reject;});return {};}});
 shell.selectTransformSet(set());Object.assign(shell.transforms,{routeId:'10',endpointId:'20',bindingTarget:'10:20',bindingRevision:0});
 const first=shell.publishTransform();await shell.shadowTransform();assert.equal(calls.length,1);
 finish(Object.assign(new Error('activation pending'),{data:{persisted:true}}));await first;
 assert.equal(shell.transforms.activationPending,true);await shell.publishTransform();await shell.shadowTransform();await shell.changeTransformLifecycle('disable');assert.equal(calls.length,1);
});

test('late list and budget reload cannot overwrite newer reads',async()=>{
 const pending=[];const shell={};createTransformsFeature(shell,{get:path=>new Promise(resolve=>pending.push({path,resolve}))});
 const older=shell.loadTransforms(), newer=shell.loadTransforms();
 for(const item of pending.slice(4))item.resolve(item.path==='/transforms'?{sets:[{id:2}]}:{});
 await newer;for(const item of pending.slice(0,4))item.resolve(item.path==='/transforms'?{sets:[{id:1}]}:{});await older;
 assert.equal(shell.transforms.sets[0].id,2);
 const a=shell.reloadTransformBudgets(),b=shell.reloadTransformBudgets();const response=n=>({revision:n,budgets:{request_ms:n,sse_event_ms:1}});
 pending.at(-1).resolve(response(5));await b;pending.at(-2).resolve(response(4));await a;assert.equal(shell.transforms.budgetRevision,5);
});

test('late publication does not attribute the old binding to edited target',async()=>{
 let finish;const shell={};createTransformsFeature(shell,{post:()=>new Promise(resolve=>{finish=resolve;})});shell.loadTransforms=async()=>{};
 shell.selectTransformSet(set());Object.assign(shell.transforms,{routeId:'10',endpointId:'20',bindingTarget:'10:20',bindingRevision:0});
 const pending=shell.publishTransform();shell.transforms.endpointId='21';await shell.loadTransformBinding();
 finish({set_revision:4,binding:{revision:1},version:{id:9}});await pending;
 assert.notEqual(shell.transforms.bindingTarget,'10:21');assert.equal(shell.transforms.bindingRevision,null);assert.equal(shell.transforms.selected.revision,4);
});

test('execution page binds filter, replaces page, and ignores late selection',async()=>{
 const pending=[];const shell={};createTransformsFeature(shell,{get:path=>new Promise(resolve=>pending.push({path,resolve}))});
 shell.transforms.executionFilter.route_id='7';const old=shell.loadTransformExecutions();shell.transforms.executionFilter.route_id='8';const current=shell.loadTransformExecutions();
 pending[1].resolve({executions:[{id:'current'}],next_cursor:'c',total:3});await current;pending[0].resolve({executions:[{id:'stale'}]});await old;
 assert.equal(shell.transforms.executions[0].id,'current');assert.match(pending[1].path,/route_id=8/);
 const next=shell.loadTransformExecutions(true);assert.match(pending[2].path,/cursor=c/);pending[2].resolve({executions:[{id:'next'}],total:3});await next;assert.deepEqual(shell.transforms.executions,[{id:'next'}]);
});

test('budget write supersedes an earlier reload and cannot be double submitted',async()=>{
 let read,write;let writes=0;const shell={};createTransformsFeature(shell,{get:()=>new Promise(resolve=>{read=resolve;}),put:()=>{writes++;if(writes>1)return {};return new Promise(resolve=>{write=resolve;});}});
 Object.assign(shell.transforms,{budgetRevision:4,budgetRequestMs:20,budgetSSEMs:5});const reload=shell.reloadTransformBudgets(),save=shell.saveTransformBudgets();await shell.saveTransformBudgets();assert.equal(writes,1);
 write({revision:5,budgets:{request_ms:20,sse_event_ms:5}});await save;read({revision:4,budgets:{request_ms:50,sse_event_ms:10}});await reload;assert.equal(shell.transforms.budgetRevision,5);
});

test('selection read started before a write cannot move the editor mid-write',async()=>{
 let read,write;const shell={};createTransformsFeature(shell,{get:()=>new Promise(resolve=>{read=resolve;}),post:()=>new Promise(resolve=>{write=resolve;})});shell.loadTransforms=async()=>{};
 shell.selectTransformSet(set());Object.assign(shell.transforms,{routeId:'10',endpointId:'20',bindingTarget:'10:20',bindingRevision:0});
 const selection=shell.selectTransformSet({id:8}),publish=shell.publishTransform();read({...set(),id:8,revision:20});await selection;
 write({set_revision:4,binding:{revision:1},version:{id:9}});await publish;assert.equal(shell.transforms.selectedId,7);assert.equal(shell.transforms.selected.revision,4);
});
