import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createRuntimeStateFeature} from './static/js/runtime.mjs';

function fixture(api) {
  const shell = {authed:true, busy:false, err:'', msg:'', reset(){this.authed=false;}, api, loadHealth(){}};
  createRuntimeStateFeature(shell);
  shell.applyStatePayload({state:'running', revision:4});
  return shell;
}

test('state CAS holds displayed revision and preserves conflict until explicit reload', async () => {
  const sent=[];
  const shell=fixture(async (method,path,body) => {sent.push({method,path,body}); if(method==='GET')return {state:'paused',revision:5}; throw Object.assign(new Error('conflict'),{status:409});});
  await shell.toggleState();
  await shell.toggleState();
  shell.applyStatePayload({state:'paused',revision:5});
  assert.equal(shell.stateRevision,4);
  assert.equal(shell.stateBlocked,true);
  assert.deepEqual(sent,[{method:'POST',path:'/state',body:{state:'paused',expected_revision:4}}]);
  await shell.reloadState();
  assert.equal(shell.stateRevision,5);
  assert.equal(shell.running,false);
  assert.equal(shell.stateBlocked,false);
});

test('pending state keeps the captured revision, blocks replay, and logout clears it', async () => {
  let writes=0;
  const shell=fixture(async()=>{writes++;throw Object.assign(new Error('pending'),{status:503,data:{code:'pause_drain_pending',persisted:true,state:'paused',new_revision:5}});});
  await shell.toggleState();
  await shell.toggleState();
  assert.equal(writes,1);
  assert.equal(shell.stateRevision,4);
  assert.equal(shell.stateBlocked,true);
  assert.match(shell.err,/已保存|已持久化/);
  shell.reset();
  assert.equal(shell.stateRevision,0);
  assert.equal(shell.stateBlocked,false);
});

test('successful state change adopts server revision and describes gradual recovery',async()=>{
  const shell=fixture(async()=>({state:'running',revision:6}));
  shell.applyStatePayload({state:'paused',revision:5});
  await shell.toggleState();
  assert.equal(shell.stateRevision,6);
  assert.equal(shell.running,true);
  assert.match(shell.msg,/渐进/);
  assert.ok(!shell.msg.includes('全部 Route 置 unknown'));
});
