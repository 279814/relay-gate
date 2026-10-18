import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createSecurityFeature} from './static/js/security.mjs';

function fixture() {
  const writes=[];
  const shell={authed:true,err:'',msg:''};
  createSecurityFeature(shell,{async put(path,body){writes.push({path,body});return body;}});
  shell.security.smtp={enabled:true,host:'smtp.example.test',port:587,use_starttls:true,use_smtps:false,
    from:'relay@example.test',recipients:'ops@example.test',username:'',min_severity:'critical',has_password:true,updated_at:1};
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
