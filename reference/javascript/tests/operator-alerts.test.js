import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync,mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Controller } from '../src/controller.js';
import { validatePolicy,sign } from '../src/protocol.js';
import { readJournal } from '../src/journal.js';
import { OperatorAlerts } from '../src/operator-alerts.js';

function fixture(){
  const keys={supervisor:'s',observer:'o',human:'h',journal:'j'};
  const c=new Controller(validatePolicy(JSON.parse(readFileSync(new URL('../policy.json',import.meta.url),'utf8'))),keys,join(mkdtempSync(join(tmpdir(),'sentry-operator-')),'evidence.jsonl'));
  let supervisor=0,observer=0,human=0;
  const trusted=(lane,payload)=>c.handle({lane,body:sign(keys[lane],lane,{seq:lane==='supervisor'?++supervisor:lane==='observer'?++observer:++human,...payload})});
  assert.equal(trusted('supervisor',{command:'recover',instance:'one',generation:1,policyHash:c.hash,integrity:true}).ok,true);
  return {c,keys,trusted};
}
test('a failed containment postcondition alerts the operator and blocks affected local access',()=>{
  const {c,keys,trusted}=fixture();
  Object.defineProperty(c.sessions['session-alice'],'route',{get:()=> 'production',set:()=>{},enumerable:true}); // trusted actuator-failure fixture
  const result=trusted('observer',{event:{id:'case',session:'session-alice',kind:'credential_misuse'}});
  assert.equal(result.error,'barrier_containment_failure');assert.equal(c.severed,true);
  const alert=c.snapshot().operatorAlerts.recent[0];assert.equal(alert.kind,'CONTAINMENT_FAILURE');assert.equal(alert.authorityStatus,'revoked');
  assert.equal(alert.containmentStatus,'not_verified');assert.equal(alert.sacrificialCoreStatus,'not_implemented');assert.equal(alert.automaticAccessRestoration,false);
  assert.deepEqual(alert.affectedSessions,['session-alice']);
  const blocked=trusted('observer',{event:{id:'legit-after-failure',session:'session-alice',kind:'legitimate'}});assert.equal(blocked.ok,true);
  const rows=readJournal(c.journal.path,keys.journal);
  assert.equal(rows.find(r=>r.payload.type==='admission' && r.payload.data.event.id==='legit-after-failure').payload.data.route,'denied');
  assert.ok(rows.some(r=>r.payload.type==='access_hold_reconciliation'));assert.ok(rows.some(r=>r.payload.type==='operator_alert'));
});
test('acknowledgment and clean instance recovery never restore held access or endpoint authority',()=>{
  const {c,trusted}=fixture();c.panic('endpoint_response_failure',{session:'session-alice'});
  const id=c.snapshot().operatorAlerts.recent[0].id;
  assert.equal(c.handle({lane:'worker',body:{command:'acknowledge_alert',alertId:id}}).error,'unknown_worker_command');
  assert.equal(trusted('human',{command:'acknowledge_alert',alertId:id}).ok,true);assert.equal(c.severed,true);assert.equal(c.accessHolds.has('session-alice'),true);
  assert.equal(trusted('human',{command:'acknowledge_alert',alertId:id}).error,'operator_alert_already_acknowledged');
  assert.equal(trusted('supervisor',{command:'recover',instance:'two',generation:2,policyHash:c.hash,integrity:true}).ok,true);
  assert.equal(c.accessHolds.has('session-alice'),true);assert.equal(c.snapshot().operatorAlerts.recent[0].acknowledged,true);
  assert.equal(c.handle({lane:'worker',body:{command:'clear_access_hold'}}).error,'unknown_worker_command');
});
test('repeated panic creates one alert and protected control is never held',()=>{
  const {c}=fixture();c.panic('endpoint_response_failure',{session:'control-health'});c.panic('endpoint_response_failure',{session:'control-health'});
  assert.equal(c.snapshot().operatorAlerts.totalRaised,1);assert.equal(c.accessHolds.size,0);
});
test('an alert write failure cannot keep authority alive or claim external delivery',()=>{
  const {c}=fixture(),original=c.record.bind(c);
  c.record=(type,data)=>{if(type==='operator_alert')throw new Error('ENOSPC injected');return original(type,data);};
  c.panic('integrity_failure');assert.equal(c.severed,true);assert.equal(c.snapshot().operatorAlerts.recent[0].delivery,'local_status_only');
  assert.equal(readFileSync(c.fallback,'utf8').includes('operatorMessage'),false);
});
test('operator alert history is bounded while monotonically counting every raised event',()=>{
  const alerts=new OperatorAlerts();for(let i=0;i<100;i++)alerts.raise({reason:'lease_expired',instance:'one',generation:i,sessions:[],anchor:String(i)});
  assert.equal(alerts.snapshot().recent.length,64);assert.equal(alerts.snapshot().totalRaised,100);
});
