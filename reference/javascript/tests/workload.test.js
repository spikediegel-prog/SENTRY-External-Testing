import test from 'node:test';
import assert from 'node:assert/strict';
import { WorkloadPool, validateWorkload } from '../src/workload-pool.js';
import { createLab } from '../src/lab.js';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Controller } from '../src/controller.js';
import { sign, validatePolicy } from '../src/protocol.js';

const config={processes:2,threadsPerProcess:2,maxPending:4,reservedPending:2,taskTimeoutMs:3000,maxRestarts:1};
test('multiple processes and threads analyze in parallel but return admission order',async()=>{
  const pool=await new WorkloadPool(config).start();
  try {
    const completed=[];
    const jobs=Array.from({length:4},(_,i)=>pool.submit({lane:'worker',body:{id:i,text:'x'.repeat(12000)}}).then(r=>{completed.push(i);return r;}));
    const results=await Promise.all(jobs);assert.ok(results.every(r=>r.analysis?.inputHash.length===64));assert.deepEqual(completed,[0,1,2,3]);
    assert.equal(pool.stats().analysisThreads,4);assert.equal(new Set(pool.processes.map(p=>p.child.pid)).size,2);assert.equal(pool.stats().maxOutstanding,4);
  } finally {await pool.close();}
});

test('bounded queues reserve capacity for signal without silently accepting overload',async()=>{
  const pool=await new WorkloadPool(config).start();
  try {
    const jobs=Array.from({length:10},(_,i)=>pool.submit({lane:'worker',body:{i}}));
    const signal=pool.submit({lane:'observer',body:{signal:true}},{signal:true});
    const results=await Promise.all(jobs);assert.equal(results.filter(r=>r.error==='workload_overloaded').length,6);assert.ok((await signal).analysis);
    assert.equal(pool.stats().maxOutstanding,5);assert.equal(pool.stats().outstanding,0);
  } finally {await pool.close();}
});

test('analysis process crash fails unfinished work and recovers only bounded compute resources',async()=>{
  const pool=await new WorkloadPool({...config,processes:1,threadsPerProcess:1}).start();
  try {
    const job=pool.submit({lane:'worker',body:{text:'x'.repeat(10000)}});
    pool.failProcess(pool.processes[0],'analysis_unavailable');
    assert.equal((await job).error,'analysis_unavailable');
    const replacement=await pool.submit({lane:'worker',body:{text:'retry'}});assert.ok(replacement.analysis);assert.equal(pool.stats().restarts,1);assert.equal(pool.stats().analysisThreads,1);
  } finally {await pool.close();}
});

test('hung analysis has a deadline and cannot pin later admissions indefinitely',async()=>{
  const pool=await new WorkloadPool({...config,processes:1,threadsPerProcess:1,taskTimeoutMs:100,maxRestarts:0}).start();
  try {
    pool.processes[0].child.send=()=>true; // trusted fault fixture: no worker response
    const result=await pool.submit({lane:'worker',body:{command:'status'}});
    assert.equal(result.error,'analysis_timeout');assert.equal(pool.stats().outstanding,0);assert.equal(pool.stats().restarts,0);
    await Promise.all([pool.submit({lane:'worker',body:{}}),pool.submit({lane:'worker',body:{}})]);
    assert.equal(pool.normal.length,0);assert.equal(pool.signal.length,0);
  } finally {await pool.close();}
});

test('compute configuration cannot silently expand resource bounds',()=>{
  assert.throws(()=>validateWorkload({...config,processes:4,threadsPerProcess:4}),/too_many/);
  assert.throws(()=>validateWorkload({...config,maxPending:999999}),/invalid_workload/);
  assert.throws(()=>validateWorkload({...config,authority:['REVOKE']}),/invalid_fields/);
});

test('heavy concurrent noise preserves signed control, signal, dead-man and observer sequence order',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'barriers-workload-')),workloadPath=join(dir,'workload.json');writeFileSync(workloadPath,JSON.stringify(config));
  const l=await createLab({workloadPath});
  try {
    const flood=Array.from({length:40},(_,i)=>l.observe('flood-'+i,'session-bob','junk'));
    const intrusion=l.sessionUse('intrusion','session-alice','attacker-device','missing');
    const control=l.observe('control','control-health','control');
    const renew=l.attest('sentry-1',1);
    assert.equal((await control).ok,true);assert.equal((await renew).ok,true);
    const attack=await intrusion;assert.equal(attack.ok,true,attack.error);assert.equal(attack.data.sessions['session-alice'].route,'sandbox');
    const results=await Promise.all(flood);assert.ok(results.every(r=>r.ok || r.error==='workload_overloaded'));
    assert.equal((await l.advance(30001)).ok,true);
    const s=(await l.status()).data;assert.equal(s.state,'RECOVERY_REQUIRED');assert.equal(s.severed,true);assert.equal(s.policyHash,l.ready.policyHash);assert.ok(s.workload.maxOutstanding<=6);assert.equal(s.metrics.dropped,results.filter(r=>r.ok).length);
    assert.equal((await l.propose('CONTAIN','intrusion')).error,'authority_expired');
  } finally {await l.close();}
});

test('parallel queued proposals recheck authority after independent self-containment',async()=>{
  const policy=validatePolicy(JSON.parse(readFileSync(new URL('../policy.json',import.meta.url),'utf8')));
  const c=new Controller(policy,{supervisor:'s',observer:'o',human:'h',journal:'j'},join(mkdtempSync(join(tmpdir(),'barriers-queued-')),'evidence.jsonl'));
  c.handle({lane:'supervisor',body:sign('s','supervisor',{seq:1,command:'recover',instance:'sentry-1',generation:1,policyHash:c.hash,integrity:true})});
  c.handle({lane:'observer',body:sign('o','observer',{seq:1,event:{id:'known',session:'session-alice',kind:'credential_misuse'}})});
  const pool=await new WorkloadPool(config).start();
  try {
    const request={lane:'worker',body:{command:'propose',action:'CONTAIN',evidence:'known',uncertainty:0,token:c.workerToken}};
    const result=pool.submit(request).then(()=>c.handle(request));
    c.panic('integrity_failure');
    assert.equal((await result).error,'authority_expired');assert.equal(c.severed,true);
  }finally{await pool.close();}
});

test('protected priority lane has separate replay state and cannot expand scope',async()=>{
  const l=await createLab();
  try {
    const bad=await l.trusted('control',{event:{id:'fake-protected',session:'session-alice',kind:'control'}});
    assert.equal(bad.error,'protected_traffic_mismatch');
    const envelope=sign(l.keys.control,'control',{seq:2,event:{id:'health',session:'control-health',kind:'control'}});
    assert.equal((await l.request('control',envelope)).ok,true);assert.equal((await l.request('control',envelope)).error,'replay');
    assert.equal((await l.observe('noise','session-bob','junk')).ok,true);
    const forged={payload:{seq:3,event:{id:'forged',session:'control-health',kind:'control'}},mac:'0'.repeat(64)};
    assert.equal((await l.request('control',forged)).error,'authentication_failed');
    assert.equal((await l.status()).data.policyHash,l.ready.policyHash);
  }finally{await l.close();}
});
