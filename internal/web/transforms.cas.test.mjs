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
