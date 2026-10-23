import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createSecurityFeature} from './static/js/security.mjs';
function fixture(api){const shell={err:'',msg:'',reset(){}};createSecurityFeature(shell,api);return shell;}
test('review uses displayed revision, preserves conflict draft and never retries',async()=>{
 const calls=[];const shell=fixture({async put(path,body){calls.push({path,body});throw Object.assign(new Error('conflict'),{status:409});}});
 shell.editSecurityReview({id:'finding/a',review:{revision:3,status:'open'}});
 shell.security.management.review.status='false_positive';await shell.saveSecurityReview();await shell.saveSecurityReview();
 assert.equal(calls.length,1);assert.equal(calls[0].body.expected_revision,3);assert.equal(calls[0].body.status,'false_positive');assert.match(calls[0].path,/finding%2Fa/);
 assert.equal(shell.security.management.review.status,'false_positive');assert.equal(shell.security.management.conflict,true);
});
test('ignore drafts default to 24h, submit explicit permanence and CAS only held revision',async()=>{
 const calls=[];const shell=fixture({async post(path,body){calls.push({path,body});return {id:1,...body,revision:1};},async get(){return {rules:[],total:0};}});
 const before=Date.now();shell.newSecurityIgnore({rule_id:'custom:a',route_id:7},'rule');
 assert.equal(shell.security.management.ignoreDraft.permanent,false);assert.ok(new Date(shell.security.management.ignoreDraft.expires).getTime()>before+23*3600000);
 shell.security.management.ignoreDraft.permanent=true;await shell.saveSecurityIgnore();
 assert.equal(calls[0].body.expires_at_ms,0);assert.equal(calls[0].body.rule_id,'custom:a');assert.equal(calls[0].body.route_id,0);
});
test('raw opens metadata only; password is cleared per call and close/reset defeats late evidence',async()=>{
 let finish;const paths=[];const shell=fixture({async get(path){paths.push(path);return {available:true,reason:'original_upstream_response'};},post(path,body){paths.push(path);assert.equal(body.password,'temporary-password');return new Promise(resolve=>{finish=resolve});}});
 await shell.openSecurityEvidence({id:'trusted'});assert.equal(paths.length,1);assert.match(paths[0],/evidence-metadata$/);
 shell.security.management.evidence.password='temporary-password';const pending=shell.readSecurityEvidence();assert.equal(shell.security.management.evidence.password,'');
 shell.closeSecurityEvidence();finish({available:true,body:Buffer.from('<script>plain text only</script>').toString('base64')});await pending;assert.equal(shell.security.management.evidence,null);
 shell.reset();assert.equal(shell.security.management.evidence,null);
});
test('manual route disable uses previously displayed current Route revision without refetch/retry',async()=>{
 const calls=[];const shell=fixture({async get(path){calls.push(path);return {id:7,upstream_id:42,revision:8,enabled:true};},async put(path,body){calls.push({path,body});throw Object.assign(new Error('conflict'),{status:409});}});
 await shell.inspectSecurityRoute({route_id:7,upstream_id:42});await shell.disableSecurityRoute();await shell.disableSecurityRoute();
 assert.equal(calls.length,2);assert.deepEqual(calls[1],{path:'/routes/7',body:{expected_revision:8,enabled:false}});assert.equal(shell.security.management.routeTarget.revision,8);
});
