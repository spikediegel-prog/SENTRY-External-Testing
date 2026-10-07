import { mkdirSync,readFileSync,writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { generatePermutationDataset,featureCollisionProbes } from './guardian-permutations.js';
import { teacherKeys,seal,verifySealed } from './learning-crypto.js';
import { features,baselineRisk } from './poison-features.js';
import { probability,metrics } from './poison-model.js';
import { createBackgroundLearner } from './background-learning.js';
import { readArtifact,writeProtectedArtifact } from './protected-artifacts.js';
import { createLab } from './lab.js';
import { createSentryWorker } from './worker-client.js';

const directory=fileURLToPath(new URL('../runs/permutations-'+Date.now()+'/',import.meta.url));mkdirSync(directory,{recursive:true});
const keys=teacherKeys(),dataset=generatePermutationDataset(),envelope=seal(dataset,keys.privateKey,'guardian-dataset');
writeProtectedArtifact(join(directory,'guardian-dataset.json'),envelope);writeFileSync(join(directory,'teacher-public-key.pem'),keys.publicKey);
const fitted=await createBackgroundLearner().run(envelope,keys.publicKey);
writeProtectedArtifact(join(directory,'candidate.json'),fitted);
const saved=JSON.parse(readFileSync(new URL('../learning-report.json',import.meta.url),'utf8')).artifactDirectory;
const original=readArtifact(join(saved,'shadow-model.json')),oldKey=readFileSync(join(saved,'teacher-public-key.pem'),'utf8');
assert.ok(verifySealed(original,oldKey,'shadow-model'));
const test=dataset.batches.filter(b=>b.split==='test').map(batch=>({batch,x:features(batch),y:batch.poisoned}));
const predicted=(model,e)=>probability(model,e.x)>=model.threshold;
const byPermutation=Object.fromEntries([...new Set(test.map(e=>e.batch.permutationKey))].map(key=>{
  const selected=test.filter(e=>e.batch.permutationKey===key);
  return [key,{axes:selected[0].batch.permutationAxes,original:metrics(selected,e=>predicted(original.payload,e)),
    augmented:metrics(selected,e=>predicted(fitted.candidate,e)),baseline:metrics(selected,e=>baselineRisk(e.x))}];
}));
const collisionProbes=featureCollisionProbes(dataset).map(probe=>{
  const cleanFeatures=features(probe.clean),attackFeatures=features(probe.adversarial);assert.deepEqual(cleanFeatures,attackFeatures);
  const risk=probability(fitted.candidate,attackFeatures);
  return {name:probe.name,classification:probe.classification,scope:probe.scope,featuresIdentical:true,risk,
    flagged:risk>=fitted.candidate.threshold,distinguishableByCurrentModel:false};
});
mkdirSync(join(directory,'authority-proof'),{recursive:true});
const l=await createLab({directory:join(directory,'authority-proof')});
let worker;
try{
  worker=await createSentryWorker(l);const before=(await l.status()).data;
  const c=fitted.countermeasures.candidates.find(r=>r.candidate.rule.button==='CONTAIN')?.candidate;
  assert.ok(c);
  await l.observe('permutation-real-case','session-alice','credential_misuse');
  const observed={evidence:'permutation-real-case',deviceMismatch:1,missingProof:1,protectedControl:false};
  assert.equal((await worker.tryCountermeasure(c,observed)).ok,true);
  assert.equal((await worker.tryCountermeasure(c,{...observed,evidence:'invented-evidence'})).ok,false);
  await l.advance(31000);assert.equal((await worker.tryCountermeasure(c,observed)).ok,false);
  const after=(await l.status()).data;assert.equal(after.policyHash,before.policyHash);
  const report={classification:'Recorded',scope:'Finite synthetic permutations; no adaptive attack or production generalization proof',
    seed:dataset.seed,splitCounts:fitted.evaluation.splits,combinationCounts:{train:5,validation:4,test:5},
    evaluation:fitted.evaluation,originalOnSameTest:metrics(test,e=>predicted(original.payload,e)),byPermutation,collisionProbes,
    featureLimits:['Current batch features are invariant to row order','No sequence model or direct temporal feature is implemented','Low-volume poisoning may evade aggregate signals'],
    authorityChecks:{policyUnchanged:true,forgedEvidenceDenied:true,expiredAuthorityDenied:true,activeModelChanged:false,automaticPromotion:false},
    candidateStatus:'unsigned_review_required',artifactDirectory:directory,evidence:l.journalPath,
    claims:{partitionChecks:'Verified locally',metrics:'Recorded',temporalAttackDetection:'Unknown',productionGeneralization:'Unknown'}};
  writeFileSync(new URL('../permutation-report.json',import.meta.url),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({test:report.evaluation.test,unfamiliarFamilies:report.evaluation.heldOutFamilies,activeModelChanged:false}));
}finally{if(worker)await worker.close();await l.close();}
