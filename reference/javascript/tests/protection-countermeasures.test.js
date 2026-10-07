import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync,readFileSync,writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { sealData,openData } from '../src/data-protection.js';
import { secureChannel,channelConfig } from '../src/secure-channel.js';
import { Journal,readJournal,appendEmergency } from '../src/journal.js';
import { readArtifact,writeProtectedArtifact } from '../src/protected-artifacts.js';
import { generateDataset } from '../src/guardian-learning.js';
import { seal,teacherKeys } from '../src/learning-crypto.js';
import { developCountermeasures,validateCountermeasure,countermeasureProposal } from '../src/countermeasures.js';
import { createLab } from '../src/lab.js';
import { createSentryWorker } from '../src/worker-client.js';
const temp=()=>mkdtempSync(join(tmpdir(),'sentry-protection-'));
const fixture=()=>{const keys=teacherKeys(),data=generateDataset([],{trainCampaigns:3,validationCampaigns:2,testCampaigns:2});return {keys,data,envelope:seal(data,keys.privateKey,'guardian-dataset')};};

test('authenticated encryption protects data, context, keys and tampering',()=>{
  const key=randomBytes(32),value={secret:'PRIVATE_SESSION_DATA'},a=sealData(value,key,'log'),b=sealData(value,key,'log');
  assert.notEqual(a.nonce,b.nonce);assert.equal(JSON.stringify(a).includes(value.secret),false);assert.deepEqual(openData(a,key,'log'),value);
  assert.throws(()=>openData(a,key,'training'),/authentication/);assert.throws(()=>openData(a,randomBytes(32),'log'),/authentication/);
  for(const field of ['tag','nonce','ciphertext']){const altered={...a,[field]:(a[field][0]==='a'?'b':'a')+a[field].slice(1)};assert.throws(()=>openData(altered,key,'log'),/authentication/);}
  const large={blob:'x'.repeat(2*1024*1024)};assert.equal(openData(sealData(large,key,'dataset'),key,'dataset').blob.length,large.blob.length);
});

test('encrypted journal retains delta reconstruction and rejects truncation and plaintext downgrade',()=>{
  const key=randomBytes(32).toString('hex'),path=join(temp(),'evidence.jsonl'),j=new Journal(path,key,{encrypted:true});
  for(let i=0;i<40;i++)j.append({time:i,type:'signal',data:{private:'PRIVATE_LOG_DATA',blob:'x'.repeat(2000),counter:i}});
  assert.equal(readFileSync(path,'utf8').includes('PRIVATE_LOG_DATA'),false);assert.equal(j.check().count,40);assert.ok(j.stats().deltaRecords>0);
  const rows=readJournal(path,key);assert.equal(rows.at(-1).payload.data.counter,39);assert.throws(()=>readJournal(path,'wrong'),/authentication/);
  const bytes=readFileSync(path,'utf8');writeFileSync(path,bytes.trim().split('\n').slice(0,-1).join('\n')+'\n');assert.throws(()=>j.check(),/truncation/);
  writeFileSync(path,rows.map(r=>JSON.stringify(r.encoded)).join('\n')+'\n');assert.throws(()=>j.check(),/plaintext_downgrade/);
});

test('emergency receipts are encrypted and authenticated independently',()=>{
  const path=join(temp(),'emergency'),key=randomBytes(32);appendEmergency(path,{private:'PRIVATE_EMERGENCY'},key);
  const bytes=readFileSync(path,'utf8');assert.equal(bytes.includes('PRIVATE_EMERGENCY'),false);
  assert.equal(openData(JSON.parse(bytes),key,'emergency-record').private,'PRIVATE_EMERGENCY');
});

test('transport rejects replay, reflection, cross-session, forged and out-of-order packets',()=>{
  const config=channelConfig(),parent=secureChannel(config,'parent'),child=secureChannel(config,'child');
  const packet=parent.encode({private:'PRIVATE_TRANSPORT'});assert.equal(JSON.stringify(packet).includes('PRIVATE_TRANSPORT'),false);
  assert.deepEqual(child.decode(packet),{private:'PRIVATE_TRANSPORT'});assert.throws(()=>child.decode(packet),/replay/);assert.throws(()=>child.decode(parent.encode({})),/closed/);
  assert.throws(()=>secureChannel(config,'parent').decode(packet),/authentication/);
  assert.throws(()=>secureChannel(channelConfig(),'child').decode(packet),/authentication/);
  const second=parent.encode({});assert.throws(()=>secureChannel(config,'child').decode(second),/replay/);
  assert.throws(()=>secureChannel(config,'child').decode({payload:'plaintext'}),/authentication/);
});

test('user-wrapped artifact keys preserve local recovery without plaintext or bundled keys',()=>{
  const path=join(temp(),'training.json'),value={private:'PRIVATE_TRAINING_DATA'};writeProtectedArtifact(path,value);
  const bytes=readFileSync(path,'utf8');assert.equal(bytes.includes(value.private),false);assert.deepEqual(readArtifact(path),value);
  const envelope=JSON.parse(bytes);envelope.envelope.tag='0'.repeat(32);writeFileSync(path,JSON.stringify(envelope));assert.throws(()=>readArtifact(path),/authentication/);
});

test('countermeasure development derives constrained proposals with held-out evaluation',()=>{
  const {keys,envelope}=fixture(),result=developCountermeasures(envelope,keys.publicKey);
  assert.equal(result.installed,false);assert.equal(result.authorityChange,false);assert.equal(result.candidates.length,3);
  for(const row of result.candidates){assert.equal(row.validation.wrongLabel,0);assert.equal(row.test.legitimateAffected,0);assert.equal(validateCountermeasure(row.candidate).status,'review_required');}
  envelope.payload.batches[0].poisoned=1;assert.throws(()=>developCountermeasures(envelope,keys.publicKey),/untrusted_countermeasure/);
});

test('countermeasure rules cannot carry code, new powers or target protected control',()=>{
  const {keys,envelope}=fixture(),candidate=developCountermeasures(envelope,keys.publicKey).candidates.find(r=>r.candidate.rule.button==='CONTAIN').candidate;
  const observed={evidence:'case',deviceMismatch:1,missingProof:1,protectedControl:false};
  assert.equal(countermeasureProposal(candidate,observed).button,'CONTAIN');assert.equal(countermeasureProposal(candidate,{...observed,protectedControl:true}),null);
  assert.throws(()=>validateCountermeasure({...candidate,script:'disable safeguards'}),/invalid_fields/);
  assert.throws(()=>validateCountermeasure({...candidate,rule:{...candidate.rule,button:'REVOKE'}}),/invalid_countermeasure/);
  assert.throws(()=>validateCountermeasure({...candidate,rule:{...candidate.rule,missingProof:0}}),/invalid_countermeasure/);
});

test('a countermeasure cannot forge trusted signals, expand authority or bypass quarantine',async()=>{
  const {keys,envelope}=fixture(),candidate=developCountermeasures(envelope,keys.publicKey).candidates.find(r=>r.candidate.rule.button==='CONTAIN').candidate;
  const l=await createLab(),worker=await createSentryWorker(l);
  const observation={evidence:'countermeasure-case',deviceMismatch:1,missingProof:1,protectedControl:false};
  try {
    assert.equal((await worker.tryCountermeasure(candidate,observation)).error,'trusted_evidence_required');
    await l.observe('countermeasure-case','session-alice','suspicious');
    assert.equal((await worker.tryCountermeasure(candidate,observation)).error,'proposal_denied');
    await l.observe('real-case','session-bob','credential_misuse');
    assert.equal((await worker.tryCountermeasure(candidate,{...observation,evidence:'real-case'})).ok,true);
    assert.ok(l.rows().some(r=>r.payload.type==='reconciliation' && r.payload.data.cause.trigger==='proposal'));
    await l.advance(31000);assert.equal((await worker.tryCountermeasure(candidate,{...observation,evidence:'real-case'})).ok,false);
    assert.equal(readFileSync(l.journalPath,'utf8').includes('session-alice'),false);
    assert.equal((await l.status()).data.policyHash,l.ready.policyHash);
  }finally{await worker.close();await l.close();}
});
