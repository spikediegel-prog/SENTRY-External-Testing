import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import assert from 'node:assert/strict';
import { createLab } from './lab.js';

const directory=fileURLToPath(new URL('../runs/load-'+Date.now()+'/',import.meta.url));mkdirSync(directory,{recursive:true});
const l=await createLab({directory});
try {
  const start=performance.now();
  const noise=Array.from({length:160},(_,i)=>l.observe('burst-'+i,'session-bob','junk'));
  const intrusion=l.sessionUse('intrusion','session-alice','attacker-device','missing');
  const controlStart=performance.now();const control=await l.observe('protected','control-health','control');const controlResponseMs=performance.now()-controlStart;
  assert.equal(control.ok,true);
  const attack=await intrusion;assert.equal(attack.ok,true,attack.error);
  const results=await Promise.all(noise);
  assert.ok(results.every(r=>r.ok || r.error==='workload_overloaded'));
  await l.advance(5001);const isolated=(await l.status()).data;
  assert.equal(isolated.sessions['session-alice'].route,'isolated');assert.equal(isolated.sessions['session-alice'].credential,false);
  await l.advance(30001);const revoked=(await l.status()).data;assert.equal(revoked.severed,true);
  const report={classification:'Recorded',scope:'Finite local concurrent burst; no production DoS or speedup claim',noiseSubmitted:160,noiseProcessed:results.filter(r=>r.ok).length,backpressure:results.filter(r=>r.error==='workload_overloaded').length,controlResponseMs,elapsedMs:performance.now()-start,isolated,revoked,evidence:l.journalPath};
  writeFileSync(new URL('../load-report.json',import.meta.url),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));
}finally{await l.close();}
