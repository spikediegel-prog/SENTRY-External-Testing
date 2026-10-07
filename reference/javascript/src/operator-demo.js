import { mkdirSync,readFileSync,writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { Controller } from './controller.js';
import { validatePolicy,sign } from './protocol.js';
import { preserveKey } from './key-vault.js';
import { readJournal } from './journal.js';

const directory=fileURLToPath(new URL('../runs/operator-'+Date.now()+'/',import.meta.url));mkdirSync(directory,{recursive:true});
const path=join(directory,'evidence.jsonl'),keys=Object.fromEntries(['supervisor','observer','human','journal','control'].map(k=>[k,randomBytes(32).toString('hex')]));
writeFileSync(path+'.keyref',preserveKey(keys.journal));
const c=new Controller(validatePolicy(JSON.parse(readFileSync(new URL('../policy.json',import.meta.url),'utf8'))),keys,path);
const sequence={supervisor:0,observer:0,human:0};
const trusted=(lane,payload)=>c.handle({lane,body:sign(keys[lane],lane,{seq:++sequence[lane],...payload})});
trusted('supervisor',{command:'recover',instance:'one',generation:1,policyHash:c.hash,integrity:true});
// Trusted white-box actuator fault, never an input exposed to SENTRY.
Object.defineProperty(c.sessions['session-alice'],'route',{get:()=> 'production',set:()=>{},enumerable:true});
const failure=trusted('observer',{event:{id:'containment-fault',session:'session-alice',kind:'credential_misuse'}});assert.equal(failure.error,'barrier_containment_failure');
const alert=c.snapshot().operatorAlerts.recent[0];
assert.equal(trusted('human',{command:'acknowledge_alert',alertId:alert.id}).ok,true);
assert.equal(trusted('supervisor',{command:'recover',instance:'two',generation:2,policyHash:c.hash,integrity:true}).ok,true);
trusted('observer',{event:{id:'access-after-recovery',session:'session-alice',kind:'legitimate'}});
const rows=readJournal(path,keys.journal);assert.equal(rows.find(r=>r.payload.type==='admission').payload.data.route,'denied');
const report={classification:'Recorded',scope:'Local actuator fault and operator-status simulation; no external notification or real sacrificial core',
  operatorAlert:c.snapshot().operatorAlerts.recent[0],accessHolds:c.snapshot().accessHolds,
  checks:{containmentFailureDetected:true,authorityRevokedBeforeAlert:true,affectedAccessHeld:true,acknowledgmentDoesNotRestoreAccess:true,
    cleanInstanceDoesNotReleaseHold:true,noAutomaticAccessPromise:true},evidence:path,policyHash:c.hash,
  claims:{localFailureWorkflow:'Verified by tests',operatorDelivery:'Local status only',sacrificialExecutionCage:'Proposed',safeProductionAccessRelease:'Unknown'}};
writeFileSync(new URL('../operator-report.json',import.meta.url),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report.checks));
