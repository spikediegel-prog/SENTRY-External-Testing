import { mkdirSync,writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { createLab } from './lab.js';
import { sign } from './protocol.js';

const directory=fileURLToPath(new URL('../runs/endpoints-'+Date.now()+'/',import.meta.url));mkdirSync(directory,{recursive:true});
const config={version:1,mode:'simulate',bindings:[
  {session:'session-alice',provider:'microsoft-defender',deviceId:'simulated-defender-device',allowIsolation:true},
  {session:'session-bob',provider:'crowdstrike-falcon',deviceId:'simulated-falcon-device',allowIsolation:true}
]};
const path=join(directory,'endpoint-policy.json');writeFileSync(path,JSON.stringify(config,null,2));
const l=await createLab({directory,endpointPolicyPath:path});
try{
  for(const binding of config.bindings){
    const envelope=sign(l.keys.endpoint[binding.provider],'endpoint-alert/'+binding.provider,
      {seq:1,provider:binding.provider,deviceId:binding.deviceId,alertId:'alert-'+binding.session,finding:'suspected_exfiltration'});
    const accepted=await l.endpointAlert(envelope);assert.equal(accepted.ok,true);
    assert.equal((await l.endpointAlert(envelope)).error,'endpoint_alert_replay');
  }
  const alertsOnly=(await l.status()).data;assert.ok(alertsOnly.endpoint.devices.every(d=>d.state==='connected'));
  await l.sessionUse('independent-alice','session-alice','unexpected-device','missing');
  await l.sessionUse('independent-bob','session-bob','unexpected-device','missing');
  const beforeWindow=(await l.status()).data;assert.ok(beforeWindow.endpoint.devices.every(d=>d.state==='connected'));
  await l.advance(5001);const isolated=(await l.status()).data;assert.ok(isolated.endpoint.devices.every(d=>d.state==='simulated_isolated'));
  await l.advance(30001);const expired=(await l.status()).data;assert.equal(expired.severed,true);
  assert.equal((await l.worker({command:'lift_containment'})).ok,false);
  const receipts=l.rows().filter(r=>['endpoint_intent','endpoint_reconciliation'].includes(r.payload.type));
  const report={classification:'Recorded',scope:'Synthetic normalized alerts and in-memory endpoint responses only; no vendor connection or actual device isolation',
    providers:config.bindings.map(b=>b.provider),checks:{alertsOnlyChallenge:true,replayDenied:true,windowPreserved:true,explicitHostScopeRequired:true,
      simulatedIsolationReconciled:true,expirySeversAuthority:true,workerCannotRestoreEndpoints:true},
    alertsOnly:alertsOnly.endpoint,afterIsolation:isolated.endpoint,afterExpiry:expired.endpoint,receipts:receipts.map(r=>r.payload),evidence:l.journalPath,
    policyHash:l.ready.policyHash,claims:{localScopeAndGateChecks:'Verified by endpoint tests',vendorInteroperability:'Proposed',realDeviceEffects:'Unknown',credentialedApiCalls:'Not implemented'}};
  writeFileSync(new URL('../endpoint-report.json',import.meta.url),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({classification:report.classification,providers:report.providers,checks:report.checks}));
}finally{await l.close();}
