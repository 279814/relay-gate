import assert from 'node:assert/strict';
import test from 'node:test';
import { createSecurityFeature } from './static/js/security.mjs';

function feature(api) {
 const shell={authed:true,msg:'',err:'',reset(){this.authed=false;}};
 createSecurityFeature(shell,api);
 shell.loadSecurityFindings=async()=>{};
 return shell;
}
const result = id => ({ execution_id:id,success:true,canary:{execution_id:id,source:'manual',verdict:'passed',nonce_matched:true,tool_matched:true} });

test('explicit manual Canary calls the real route endpoint and retains typed result', async()=>{
 const calls=[];
 const shell=feature({async post(path,body){calls.push([path,body]);return result('canary-one');}});
 assert.ok(shell.canary, 'Canary feature state missing');
 shell.security.canaryRouteId='7';
 await shell.runSecurityCanary();
 assert.deepEqual(calls,[['/security/canary',{route_id:7}]]);
 assert.equal(shell.canary.result.execution_id,'canary-one');
 assert.equal(shell.canary.running,false);
 assert.equal(shell.canaryFlagText(null),'unknown');
 assert.equal(shell.canaryFlagText(false),'不匹配');
 assert.equal(shell.canaryVerdictText('not_sent'),'未发送');
});

test('Canary policy uses current server revision and preserves conflict draft until reload', async()=>{
 const calls=[];
 let revision=2;
 const shell=feature({
 async get(path){calls.push(['GET',path]);return {upstream_id:3,route_id:7,enabled:false,interval_sec:900,revision};},
 async put(path,body){calls.push(['PUT',path,body]);throw Object.assign(new Error('conflict'),{status:409});}
 });
 assert.ok(shell.canary, 'Canary policy state missing');
 shell.canary.upstreamId='3';
 await shell.loadCanaryPolicy();
 shell.canary.draft.enabled=true;
 shell.canary.draft.revision=900;
 await shell.saveCanaryPolicy();
 assert.deepEqual(calls[1],['PUT','/security/canary-policy/3',{route_id:7,enabled:true,interval_sec:900,revision:2}]);
 assert.equal(shell.canary.conflict,true);
 assert.equal(shell.canary.draft.enabled,true);
 await shell.saveCanaryPolicy();
 assert.equal(calls.length,2);
 revision=3;
 await shell.loadCanaryPolicy();
 assert.equal(shell.canary.conflict,false);
 assert.equal(shell.canary.policy.revision,3);
 assert.equal(shell.canary.draft.enabled,false);
});

test('late Canary results cannot replace edited routes or a new login', async()=>{
 const pending=[];
 const shell=feature({post(){return new Promise(resolve=>pending.push(resolve));}});
 assert.ok(shell.canary);
 shell.security.canaryRouteId='7';
 const old=shell.runSecurityCanary();
 shell.security.canaryRouteId='8';
 pending[0](result('old-route'));
 await old;
 assert.equal(shell.canary.result,null);
 assert.equal(shell.canary.running,false);
 const logout=shell.runSecurityCanary();
 shell.reset();
 shell.authed=true;
 pending[1](result('old-login'));
 await logout;
 assert.equal(shell.canary.result,null);
});

test('late Canary policy reads cannot replace a different Upstream draft', async()=>{
 let resolve;
 const shell=feature({get(){return new Promise(done=>{resolve=done;});}});
 assert.ok(shell.canary);
 shell.canary.upstreamId='3';
 const old=shell.loadCanaryPolicy();
 shell.canary.upstreamId='4';
 resolve({upstream_id:3,route_id:7,enabled:true,interval_sec:900,revision:2});
 await old;
 assert.equal(shell.canary.policy,null);
 assert.equal(shell.canary.loading,false);
});

