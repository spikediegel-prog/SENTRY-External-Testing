import { readFileSync,writeFileSync,mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { readArtifact } from './protected-artifacts.js';
import { createBackgroundLearner } from './background-learning.js';
import { createLab } from './lab.js';
import { createSentryWorker } from './worker-client.js';
const saved=JSON.parse(readFileSync(new URL('../learning-report.json',import.meta.url),'utf8')).artifactDirectory;
const result=await createBackgroundLearner().run(readArtifact(join(saved,'guardian-dataset.json')),readFileSync(join(saved,'teacher-public-key.pem'),'utf8'));
const directory=fileURLToPath(new URL('../runs/security-'+Date.now()+'/',import.meta.url));mkdirSync(directory,{recursive:true});
const l=await createLab({directory}),worker=await createSentryWorker(l);
try{
  const candidate=result.countermeasures.candidates.find(r=>r.candidate.rule.button==='CONTAIN').candidate;
  const observation={evidence:'security-demo-case',deviceMismatch:1,missingProof:1,protectedControl:false};
  const forged=await worker.tryCountermeasure(candidate,observation);assert.equal(forged.error,'trusted_evidence_required');
  await l.sessionUse(observation.evidence,'session-alice','unexpected-device','missing');
  const accepted=await worker.tryCountermeasure(candidate,observation);assert.equal(accepted.ok,true);
  const protectedResult=await worker.tryCountermeasure(candidate,{...observation,protectedControl:true});assert.equal(protectedResult.ok,true);
  await l.advance(31000);const expired=await worker.tryCountermeasure(candidate,observation);assert.equal(expired.ok,false);
  const final=(await l.status()).data;
  assert.equal(final.policyHash,l.ready.policyHash);
  assert.equal(readFileSync(l.journalPath,'utf8').includes('unexpected-device'),false);
  const report={classification:'Recorded',scope:'Local simulation; no production cryptographic boundary or novel exploit defense proof',
    countermeasures:result.countermeasures,checks:{forgedEvidenceDenied:true,preauthorizedProposalAccepted:true,protectedControlSkipped:true,expiredAuthorityDenied:true,policyHashUnchanged:true,encryptedEvidence:true},
    evidence:l.journalPath,anchor:final.journal,privateKeyCustody:'Windows CurrentUser DPAPI vault outside distributable outputs; same-user compromise not isolated'};
  writeFileSync(new URL('../security-report.json',import.meta.url),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify(report.checks));
}finally{await worker.close();await l.close();}
