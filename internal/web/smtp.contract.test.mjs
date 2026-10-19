import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createSecurityFeature} from './static/js/security.mjs';

function fixture() {
  const writes=[];
  const shell={authed:true,err:'',msg:''};
  createSecurityFeature(shell,{async put(path,body){writes.push({path,body});return body;}});
  shell.security.smtp={enabled:true,host:'smtp.example.test',port:587,use_starttls:true,use_smtps:false,
    from:'relay@example.test',recipients:'ops@example.test',username:'',min_severity:'critical',aggregation_window_sec:7,rate_limit_window_sec:13,revision:4,has_password:true,updated_at:1};
  return {shell,writes};
}

test('SMTP editor explicitly switches the existing TLS flags and preserves a custom port',()=>{
  const {shell}=fixture();
  assert.equal(typeof shell.setSMTPMode,'function','editor needs an explicit TLS mode action');
  shell.setSMTPMode('smtps');
  assert.equal(shell.security.smtp.use_smtps,true);
  assert.equal(shell.security.smtp.use_starttls,false);
  assert.equal(shell.security.smtp.port,465);
  shell.security.smtp.port=2465;
  shell.setSMTPMode('starttls');
  assert.equal(shell.security.smtp.use_starttls,true);
  assert.equal(shell.security.smtp.use_smtps,false);
  assert.equal(shell.security.smtp.port,2465);
});

test('enabled SMTP cannot save missing or conflicting TLS modes',async()=>{
  for (const flags of [[false,false],[true,true]]) {
    const {shell,writes}=fixture();
    [shell.security.smtp.use_starttls,shell.security.smtp.use_smtps]=flags;
    await shell.saveSMTP();
    assert.equal(writes.length,0,'invalid TLS mode reached the network');
    assert.match(shell.err,/STARTTLS|SMTPS|加密/);
  }
});

test('SMTP save sends editable fields and keeps the TLS selection without server metadata',async()=>{
  const {shell,writes}=fixture();
  await shell.saveSMTP();
  assert.equal(writes.length,1);
  assert.equal(writes[0].body.use_starttls,true);
  assert.equal(writes[0].body.use_smtps,false);
  assert.equal(writes[0].body.has_password,undefined);
  assert.equal(writes[0].body.updated_at,undefined);
  assert.equal(shell.security.smtpPassword,'');
});


test('SMTP save includes independent windows and an explicit expected revision',async()=>{
 const {shell,writes}=fixture();
 await shell.saveSMTP();
 assert.equal(writes[0].body.aggregation_window_sec,7);
 assert.equal(writes[0].body.rate_limit_window_sec,13);
 assert.equal(writes[0].body.expected_revision,4);
 assert.equal(writes[0].body.revision,undefined);
});

test('SMTP conflict keeps draft and password, blocks replay until explicit reload',async()=>{
 const {shell}=fixture();
 let writes=0;
 createSecurityFeature(shell,{
  async put(){writes++;throw Object.assign(new Error('conflict'),{status:409});},
  async get(){return {revision:5,aggregation_window_sec:20,rate_limit_window_sec:30};},
 });
 shell.security.smtp={enabled:false,host:'draft.example.test',revision:4,aggregation_window_sec:7,rate_limit_window_sec:13};
 shell.security.smtpPassword='draft-fixture-password';
 await shell.saveSMTP();
 assert.equal(writes,1);
 assert.equal(shell.security.smtp.host,'draft.example.test');
 assert.equal(shell.security.smtpPassword,'draft-fixture-password');
 assert.equal(shell.security.smtpConflict,true);
 await shell.saveSMTP();
 assert.equal(writes,1,'conflicted form must require explicit reload');
 await shell.loadSMTP();
 assert.equal(shell.security.smtpPassword,'draft-fixture-password','background load must retain conflict draft');
 await shell.loadSMTP(true);
 assert.equal(shell.security.smtp.revision,5);
 assert.equal(shell.security.smtpConflict,false);
 assert.equal(shell.security.smtpPassword,'');
});

test('SMTP invalid windows never send, and loading after logout cannot replace the new session',async()=>{
 for (const value of [0,-1,86401,1.5,'not-an-integer']) {
  const {shell,writes}=fixture();
  shell.security.smtp.aggregation_window_sec=value;
  await shell.saveSMTP();
  assert.equal(writes.length,0);
 }
 const shell={authed:true};
 let resolve;
 createSecurityFeature(shell,{get(){return new Promise(r=>resolve=r);}});
 const loading=shell.loadSMTP();
 shell.reset();
 resolve({revision:99});
 await loading;
 assert.equal(shell.security.smtp,null);
});

test('SMTP committed but activation-pending response preserves draft and blocks repeat',async()=>{
 const {shell}=fixture();
 const draft=shell.security.smtp;
 createSecurityFeature(shell,{async put(){return {config_activation_pending:true};}});
 shell.security.smtp=draft;
 shell.security.smtpPassword='fixture-password';
 await shell.saveSMTP();
 assert.equal(shell.security.smtp,draft);
 assert.equal(shell.security.smtpConflict,true);
 assert.equal(shell.security.smtpPassword,'');
 assert.match(shell.msg,/已保存|已提交/);
});


test('SMTP old-session save failure cannot mark a new login conflicted or clear its password',async()=>{
 const {shell}=fixture();
 const draft=shell.security.smtp;
 let reject;
 createSecurityFeature(shell,{put(){return new Promise((_,r)=>reject=r);}});
 shell.security.smtp=draft;
 const saving=shell.saveSMTP();
 shell.reset();
 shell.security.smtpPassword='new-session-fixture';
 shell.security.smtpSaving=true;
 reject(Object.assign(new Error('conflict'),{status:409}));
 await saving;
 assert.equal(shell.security.smtpConflict,false);
 assert.equal(shell.security.smtpPassword,'new-session-fixture');
 assert.equal(shell.security.smtpSaving,true);
});
