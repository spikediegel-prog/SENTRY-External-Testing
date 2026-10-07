import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync,writeFileSync,readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLab } from '../src/lab.js';
import { sign,validatePolicy } from '../src/protocol.js';
import { validateEndpointPolicy,SimulatedEndpointAdapter } from '../src/endpoint-adapter.js';
import { Controller } from '../src/controller.js';

const policy=()=>validatePolicy(JSON.parse(readFileSync(new URL('../policy.json',import.meta.url),'utf8')));
const config=()=>({version:1,mode:'simulate',bindings:[
  {session:'session-alice',provider:'microsoft-defender',deviceId:'simulated-device-a',allowIsolation:true},
  {session:'session-bob',provider:'crowdstrike-falcon',deviceId:'simulated-device-b',allowIsolation:true},
  {session:'control-health',provider:'microsoft-defender',deviceId:'simulated-control-device',allowIsolation:false}
]});
async function lab(cfg=config()){
  const directory=mkdtempSync(join(tmpdir(),'sentry-endpoint-')),path=join(directory,'endpoint.json');writeFileSync(path,JSON.stringify(cfg));
  return createLab({directory,endpointPolicyPath:path});
}
const alert=(l,{seq=1,provider='microsoft-defender',deviceId='simulated-device-a',alertId='alert-a',finding='suspected_exfiltration'}={})=>sign(l.keys.endpoint[provider],'endpoint-alert/'+provider,{seq,provider,deviceId,alertId,finding});

test('endpoint integration is disabled by default and direct worker commands are rejected',async()=>{
  const l=await createLab();try{
    assert.equal((await l.endpointAlert(alert(l))).error,'endpoint_integration_disabled');
    for(const command of ['endpoint_alert','isolate_endpoint','lift_containment','set_endpoint_policy'])assert.equal((await l.worker({command})).error,'unknown_worker_command');
  }finally{await l.close();}
});
test('endpoint scope is boot-only, protected, unique and never accepts live mode',()=>{
  assert.throws(()=>validateEndpointPolicy({...config(),mode:'live'},policy()),/invalid_endpoint_policy/);
  const protectedConfig=config();protectedConfig.bindings[2].allowIsolation=true;assert.throws(()=>validateEndpointPolicy(protectedConfig,policy()),/invalid_endpoint_binding/);
  const duplicate=config();duplicate.bindings[1]={...duplicate.bindings[1],provider:duplicate.bindings[0].provider,deviceId:duplicate.bindings[0].deviceId};assert.throws(()=>validateEndpointPolicy(duplicate,policy()),/invalid_endpoint_binding/);
  assert.throws(()=>validateEndpointPolicy({...config(),emergency:true},policy()),/invalid_fields/);
});
test('authenticated endpoint alerts cause only a local challenge, not confirmed exfiltration or host isolation',async()=>{
  const l=await lab();try{
    assert.equal((await l.endpointAlert(alert(l))).ok,true);const state=(await l.status()).data;
    assert.equal(state.sessions['session-alice'].challenged,true);assert.equal(state.sessions['session-alice'].route,'production');
    assert.equal(state.pending.length,0);assert.ok(state.endpoint.devices.every(d=>d.state==='connected'));
    assert.equal((await l.endpointAlert(alert(l))).error,'endpoint_alert_replay');
  }finally{await l.close();}
});
test('forged, unmapped, cross-provider and protected-control endpoint alerts fail closed',async()=>{
  const l=await lab();try{
    const forged=alert(l);forged.mac='0'.repeat(64);assert.equal((await l.endpointAlert(forged)).error,'endpoint_alert_authentication');
    assert.equal((await l.endpointAlert(alert(l,{deviceId:'other-host'}))).error,'endpoint_device_out_of_scope');
    assert.equal((await l.endpointAlert(alert(l,{deviceId:'simulated-control-device'}))).error,'protected_endpoint_alert_requires_human_review');
    const wrong=sign(l.keys.endpoint['crowdstrike-falcon'],'endpoint-alert/crowdstrike-falcon',{seq:2,provider:'microsoft-defender',deviceId:'simulated-device-a',alertId:'x',finding:'suspected_poisoning'});
    assert.equal((await l.endpointAlert(wrong)).error,'endpoint_alert_authentication');
  }finally{await l.close();}
});
test('both simulated vendors isolate only after the existing intervention window and preserve receipts',async()=>{
  const l=await lab();try{
    for(const [id,session] of [['a','session-alice'],['b','session-bob']])await l.observe(id,session,'credential_misuse');
    assert.ok((await l.status()).data.endpoint.devices.every(d=>d.state==='connected'));
    await l.advance(5001);const state=(await l.status()).data;
    assert.equal(state.endpoint.devices.filter(d=>d.state==='simulated_isolated').length,2);
    assert.equal(state.endpoint.devices.find(d=>d.binding.endsWith('simulated-control-device')).state,'connected');
    const rows=l.rows(),intents=rows.filter(r=>r.payload.type==='endpoint_intent'),receipts=rows.filter(r=>r.payload.type==='endpoint_reconciliation');
    assert.equal(intents.length,2);assert.equal(receipts.length,2);
    assert.deepEqual(intents.map(r=>r.payload.data.requestId).sort(),receipts.map(r=>r.payload.data.requestId).sort());
  }finally{await l.close();}
});
test('human override cancels endpoint escalation and a denied grant cannot inherit session authority',async()=>{
  const cfg=config();cfg.bindings[1].allowIsolation=false;const l=await lab(cfg);try{
    await l.observe('human-case','session-alice','credential_misuse');await l.trusted('human',{command:'cancel',caseId:'human-case'});
    await l.observe('denied-case','session-bob','credential_misuse');await l.advance(5001);
    const state=(await l.status()).data;assert.ok(state.endpoint.devices.every(d=>d.state==='connected'));
    assert.equal(state.sessions['session-bob'].route,'isolated');assert.ok(l.rows().some(r=>r.payload.type==='endpoint_response_denied'));
  }finally{await l.close();}
});
test('expiry and clean recovery do not isolate or automatically release endpoint devices',async()=>{
  const l=await lab();try{
    await l.observe('case','session-alice','credential_misuse');await l.advance(5001);await l.advance(30001);
    const count=(await l.status()).data.endpoint.receiptCount;
    assert.equal((await l.endpointAlert(alert(l))).error,'authority_expired');
    await l.recover('clean-instance',2);const state=(await l.status()).data;
    assert.equal(state.endpoint.receiptCount,count);assert.equal(state.endpoint.devices[0].state,'simulated_isolated');
    assert.equal((await l.worker({command:'lift_containment'})).ok,false);
  }finally{await l.close();}
});
test('endpoint audit failure revokes controller authority and does not report successful recovery',()=>{
  const keys={supervisor:'s',observer:'o',human:'h',journal:'j'},directory=mkdtempSync(join(tmpdir(),'sentry-endpoint-fault-'));
  const c=new Controller(policy(),keys,join(directory,'evidence.jsonl'),config());
  c.handle({lane:'supervisor',body:sign('s','supervisor',{seq:1,command:'recover',instance:'one',generation:1,policyHash:c.hash,integrity:true})});
  const original=c.record.bind(c);let fail=true;c.record=(type,data)=>{if(type==='endpoint_reconciliation' && fail){fail=false;throw new Error('ENOSPC injected');}return original(type,data);};
  c.handle({lane:'observer',body:sign('o','observer',{seq:1,event:{id:'case',session:'session-alice',kind:'credential_misuse'}})});
  const result=c.handle({lane:'supervisor',body:sign('s','supervisor',{seq:2,command:'advance',ms:5001})});
  assert.equal(result.ok,false);assert.equal(c.severed,true);assert.equal(c.endpoint.snapshot().devices[0].state,'simulated_isolated');
});

test('pending endpoint isolation is abandoned on authority expiry',async()=>{
  const l=await lab();try{
    await l.observe('pending','session-alice','credential_misuse');await l.advance(31000);
    const state=(await l.status()).data;assert.equal(state.severed,true);assert.equal(state.pending.length,0);
    assert.ok(state.endpoint.devices.every(d=>d.state==='connected'));assert.equal(state.endpoint.receiptCount,0);
  }finally{await l.close();}
});
test('simulated response retries reconcile once and scope cannot mutate after construction',()=>{
  const events=[],cfg=config(),adapter=new SimulatedEndpointAdapter(cfg,policy(),{},(type,data)=>events.push({type,data}),()=>{});
  cfg.bindings[0].deviceId='attacker-choice';
  const first=adapter.isolate('session-alice',{evidence:'same-case'}),second=adapter.isolate('session-alice',{evidence:'same-case'});
  assert.deepEqual(second,first);assert.equal(events.filter(e=>e.type==='endpoint_intent').length,1);
  assert.equal(events.filter(e=>e.type==='endpoint_reconciliation').length,1);
  assert.ok(adapter.snapshot().devices[0].binding.endsWith('simulated-device-a'));
});
