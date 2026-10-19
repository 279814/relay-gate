import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createRecentErrorsFeature} from './static/js/errors.mjs';
import {createProbeFeature} from './static/js/probes.mjs';

const deferred=()=>{let resolve;const promise=new Promise(done=>{resolve=done;});return {promise,resolve};};
const setup=handler=>{
  const calls=[];
  const api={get:async path=>{calls.push(path);return handler(path);}};
  const shell={err:'',msg:'',tab:'health',logFilter:{outcome:'timeout'},reset(){},$nextTick(){}};
  createProbeFeature(shell,api);createRecentErrorsFeature(shell,api);
  return {shell,calls};
};

test('recent error filters and cursor are sent to the API and filter changes restart the page',async()=>{
  const {shell,calls}=setup(path=>({failed_count:205,logs:[{id:calls.length,error:'plain'}],next_cursor:calls.length===1?'stable-cursor':''}));
  Object.assign(shell.recentErrors,{upstream_id:'20',route_id:'10',protocol:'anthropic',outcome:'timeout',from_time:'2026-10-18T01:00',to_time:'2026-10-18T02:00'});
  await shell.openRecentErrors();
  let query=new URL(calls[0],'http://fixture').searchParams;
  for(const [key,value] of Object.entries({limit:'50',upstream_id:'20',route_id:'10',protocol:'anthropic',outcome:'timeout'}))assert.equal(query.get(key),value);
  assert.equal(Number(query.get('from_ms')),new Date('2026-10-18T01:00').getTime());
  assert.equal(Number(query.get('to_ms')),new Date('2026-10-18T02:00').getTime());
  await shell.loadMoreRecentErrors();
  query=new URL(calls[1],'http://fixture').searchParams;
  assert.equal(query.get('cursor'),'stable-cursor');assert.equal(query.has('before_id'),false);
  assert.equal(shell.recentErrors.logs.length,2);
  shell.recentErrors.route_id='11';await shell.applyRecentErrorFilters();
  query=new URL(calls.at(-1),'http://fixture').searchParams;
  assert.equal(query.get('route_id'),'11');assert.equal(query.has('cursor'),false);assert.equal(shell.recentErrors.logs.length,1);
});

test('an old filter page or duplicate load-more cannot overwrite the selected page',async()=>{
  const old=deferred();let n=0;
  const {shell,calls}=setup(()=>++n===1?old.promise:{failed_count:1,logs:[{id:2}],next_cursor:''});
  const first=shell.openRecentErrors();
  shell.recentErrors.route_id='2';await shell.applyRecentErrorFilters();
  old.resolve({failed_count:1,logs:[{id:1}],next_cursor:'old'});await first;
  assert.deepEqual(shell.recentErrors.logs,[{id:2}]);assert.equal(shell.recentErrors.next_cursor,'');
  const count=calls.length;await shell.loadMoreRecentErrors();await shell.loadMoreRecentErrors();assert.equal(calls.length,count,'no cursor must mean no duplicate last-page request');
});

test('background home refresh leaves an open modal pagination position intact',async()=>{
  let n=0;const {shell,calls}=setup(()=>({failed_count:2,logs:[{id:++n}],next_cursor:'next'}));
  await shell.openRecentErrors();await shell.loadMoreRecentErrors();
  const ids=shell.recentErrors.logs.map(row=>row.id),before=calls.length;
  await shell.refreshRecentErrors();
  assert.deepEqual(shell.recentErrors.logs.map(row=>row.id),ids);assert.equal(calls.length,before);
});

test('Capability and related Execution links execute the real target list filters',async()=>{
  const {shell,calls}=setup(()=>({items:[],next_cursor:''}));
  shell.capabilities.filter.state='unsupported';shell.executions.filter.error_class='auth';
  const row={route_id:10,upstream_id:20,endpoint_kind:'messages'};
  await shell.openRecentErrorCapabilities(row);
  let url=new URL(calls.find(path=>path.startsWith('/capabilities?')),'http://fixture');
  assert.equal(shell.tab,'capabilities');assert.equal(url.searchParams.get('route_id'),'10');assert.equal(url.searchParams.get('upstream_id'),'20');assert.equal(url.searchParams.get('endpoint'),'messages');assert.equal(url.searchParams.has('state'),false);
  await shell.openRecentErrorExecutions(row);
  url=new URL(calls.find(path=>path.startsWith('/probe-executions?')),'http://fixture');
  assert.equal(shell.tab,'executions');assert.equal(url.searchParams.get('route_id'),'10');assert.equal(url.searchParams.get('upstream_id'),'20');assert.equal(url.searchParams.get('endpoint'),'messages');assert.equal(url.searchParams.has('error_class'),false);
});

test('RequestLog links query the exact ReqID group and Sample links only open reauthentication',async()=>{
  const {shell,calls}=setup(()=>({logs:[{id:8,req_id:'exact-group'}],total:300}));
  await shell.openRecentErrorRequestLogs({req_id:'exact-group'});
  assert.equal(shell.tab,'reqlogs');assert.equal(shell.reqLogs[0].id,8);
  const query=new URL(calls[0],'http://fixture').searchParams;assert.equal(query.get('req_id'),'exact-group');assert.equal(query.get('limit'),'200');
  let sampleID;shell.openSample=async id=>{sampleID=id;};
  await shell.openRecentErrorSample({sample_id:42});
  assert.equal(sampleID,42);assert.equal(calls.length,1,'opening a sample must not GET its unredacted body');
});

test('logout makes an old recent-error response unable to restore its text',async()=>{
  const old=deferred();const {shell}=setup(()=>old.promise);
  const loading=shell.openRecentErrors();shell.reset();
  old.resolve({failed_count:1,logs:[{id:1,error:'old-private'}],next_cursor:'old'});await loading;
  assert.equal(shell.recentErrors.logs.length,0);assert.equal(shell.recentErrors.next_cursor,'');assert.equal(shell.recentErrors.loading,false);
});

test('a delayed RequestLog link cannot navigate away from a newly selected error filter',async()=>{
  const old=deferred();const {shell}=setup(path=>path.startsWith('/request-logs?')?old.promise:{failed_count:1,logs:[{id:2}],next_cursor:''});
  await shell.openRecentErrors();
  const linking=shell.openRecentErrorRequestLogs({req_id:'old-group'});
  shell.recentErrors.route_id='2';await shell.applyRecentErrorFilters();
  old.resolve({logs:[{id:1,req_id:'old-group'}]});await linking;
  assert.equal(shell.tab,'health');assert.equal(shell.recentErrors.open,true);assert.equal(shell.recentErrors.logs[0].id,2);
});
