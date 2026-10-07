import { mkdirSync,writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { createLab } from './lab.js';
import { createSentryWorker } from './worker-client.js';
import { loadLibrary } from './cve-library.js';
import { teacherKeys,seal } from './learning-crypto.js';
import { acceptTrainingExport } from './training-export.js';
import { generateDataset } from './guardian-learning.js';
import { trainDetector,joinConfirmedLabels,attachVerifiedSeed } from './learning-pipeline.js';
import { digest } from './protocol.js';
import { runCveScenarios } from './cve-scenarios.js';
import { writeProtectedArtifact } from './protected-artifacts.js';

const knowledgeDirectory=fileURLToPath(new URL('../knowledge/',import.meta.url));
const library=loadLibrary(knowledgeDirectory),keys=teacherKeys();
const directory=fileURLToPath(new URL('../runs/learning-'+Date.now()+'/',import.meta.url));mkdirSync(directory,{recursive:true});
const cveScenarios=await runCveScenarios(library,join(directory,'cve-scenarios'));
const write=(name,value)=>writeProtectedArtifact(join(directory,name),value);
const l=await createLab({directory});let worker;
try{
  const labels=[];
  for(let i=0;i<24;i++){
    const eventId='training-observation-'+i,deviceMismatch=i%2,missingProof=Math.floor(i/2)%2;
    const result=await l.sessionUse(eventId,'session-bob',deviceMismatch?'unexpected-device':'bound-device-session-bob',missingProof?'missing':'valid');assert.equal(result.ok,true,result.error);
    const confirmedKind=deviceMismatch && missingProof?'credential_misuse':deviceMismatch || missingProof?'suspicious':'legitimate';
    labels.push({sourceRef:digest({eventId}),confirmedKind,origin:'independent_guardian_simulator'});
  }
  const exportResult=await l.exportTraining();assert.equal(exportResult.ok,true,exportResult.error);
  const exported=acceptTrainingExport(exportResult.trainingExport,l.keys.journal,l.ready.policyHash);
  const signedLabels=seal({anchorHead:exported.anchor.head,labels},keys.privateKey,'confirmed-telemetry-labels');
  const confirmed=joinConfirmedLabels(exported,signedLabels,keys.publicKey);
  write('telemetry-export.json',exportResult.trainingExport);write('confirmed-labels.json',signedLabels);write('telemetry-dataset.json',confirmed);
  write('export-verification-receipt.json',seal({classification:'Recorded',verifiedDuringLiveRun:true,sourceExportHash:digest(exportResult.trainingExport),anchor:exported.anchor,policyHash:l.ready.policyHash},keys.privateKey,'export-verification-receipt'));
  const dataset=seal(attachVerifiedSeed(generateDataset(library.entries.map(e=>e.id)),confirmed,digest(exportResult.trainingExport)),keys.privateKey,'guardian-dataset');write('guardian-dataset.json',dataset);
  const trained=trainDetector(dataset,keys.publicKey,keys.privateKey);write('shadow-model.json',trained.model);write('evaluation.json',trained.report);writeFileSync(join(directory,'teacher-public-key.pem'),keys.publicKey);
  worker=await createSentryWorker(l,{shadowModelPath:join(directory,'shadow-model.json'),teacherPublicKey:keys.publicKey,knowledgeDirectory});
  const shadow=[];
  for(const family of ['clean_normal','instruction_injection','camouflaged_poison']){const batch=dataset.payload.batches.find(b=>b.split==='test' && b.family===family);shadow.push({family,result:await worker.screenTraining({rows:batch.rows})});}
  const references=await worker.searchCves('CVE-2023-4966');
  const state=(await l.status()).data;assert.equal(state.policyHash,l.ready.policyHash);assert.ok(shadow.every(s=>s.result.mode==='shadow_only' && s.result.authorityChange===false));assert.equal(references[0].authority,'none');
  const report={classification:'Recorded',scope:'Local synthetic poisoning detector and reference retrieval; no LLM fine-tuning or production admission',cves:library.entries.map(e=>({id:e.id,source:e.source,sha256:e.rawSha256})),cveScenarios,verifiedTelemetrySamples:confirmed.length,datasetHash:digest(dataset.payload),evaluation:trained.report,shadow,policyHashUnchanged:true,artifactDirectory:directory,teacherKeyCustody:'private_key_discarded_after_run; public_key_bundled_for_integrity_not_external_trust',claims:{liveExportAuthentication:'Verified during this run',heldoutSimulationMetrics:'Recorded',realWorldPoisoningResistance:'Unknown',productionModelDeployment:'Proposed'}};
  writeFileSync(new URL('../learning-report.json',import.meta.url),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));
}finally{if(worker)await worker.close();await l.close();}
