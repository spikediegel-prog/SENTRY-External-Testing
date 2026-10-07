import { digest } from './protocol.js';
import { features,FEATURE_NAMES,baselineRisk } from './poison-features.js';
import { fitLogistic,probability,metrics,chooseThreshold,validateModel } from './poison-model.js';
import { verifySealed,seal } from './learning-crypto.js';
import { HELD_OUT_FAMILIES,random } from './guardian-learning.js';
import { validatePermutationPartition } from './guardian-permutations.js';

export function validateDataset(dataset) {
  if(dataset.version!==1 || dataset.origin!=='guardian_synthetic_not_real_attacks' || !Array.isArray(dataset.batches) || dataset.batches.length<24 || dataset.batches.length>2000)throw new Error('invalid_dataset');
  const campaigns=new Map(),ids=new Set();
  for(const batch of dataset.batches){
    if(!['guardian_synthetic','verified_simulation_export'].includes(batch.origin) || !['train','validation','test'].includes(batch.split) || ![0,1].includes(batch.poisoned) || typeof batch.campaign!=='string' || typeof batch.family!=='string' || ids.has(batch.id))throw new Error('invalid_dataset_batch');
    if(batch.origin==='verified_simulation_export' && (batch.split!=='train' || batch.poisoned!==0 || !/^[a-f0-9]{64}$/.test(batch.sourceExportHash)))throw new Error('invalid_verified_seed');
    ids.add(batch.id);if(campaigns.has(batch.campaign) && campaigns.get(batch.campaign)!==batch.split)throw new Error('campaign_leakage');campaigns.set(batch.campaign,batch.split);
    if(HELD_OUT_FAMILIES.includes(batch.family) && batch.split!=='test')throw new Error('heldout_family_leakage');
    features(batch);
  }
  if(['train','validation','test'].some(split=>!dataset.batches.some(b=>b.split===split && b.poisoned===0) || !dataset.batches.some(b=>b.split===split && b.poisoned===1)))throw new Error('missing_split_classes');
  validatePermutationPartition(dataset);
}
export function attachVerifiedSeed(dataset,samples,sourceExportHash) {
  if(!/^[a-f0-9]{64}$/.test(sourceExportHash) || !Array.isArray(samples) || samples.length<4 || samples.length>128 || new Set(samples.map(s=>s.sampleId)).size!==samples.length || samples.some(s=>s.provenance!=='authenticated_simulated_observer' || s.labelSource!=='independent_guardian_simulator' || !['legitimate','suspicious','credential_misuse'].includes(s.label)))throw new Error('unconfirmed_training_seed');
  const result=structuredClone(dataset);
  result.batches.push({id:digest({sourceExportHash,ids:samples.map(s=>s.sampleId)}),campaign:'verified-delta-'+sourceExportHash,split:'train',family:'clean_verified_export',origin:'verified_simulation_export',sourceExportHash,cveReferences:[],poisoned:0,rows:samples.map(s=>({id:s.sampleId,source:'authenticated-simulation-observer',signals:s.features,claimedLabel:s.label,independentLabel:s.label,provenanceVerified:true,note:'Independent simulator-confirmed delta-log observation.',trigger:''}))});
  result.verifiedSeedSamples=samples.length;validateDataset(result);return result;
}
export function trainDetector(envelope,publicKey,privateKey) {
  if(!verifySealed(envelope,publicKey,'guardian-dataset'))throw new Error('untrusted_dataset');
  const dataset=envelope.payload;validateDataset(dataset);
  const examples=dataset.batches.map(b=>({x:features(b),y:b.poisoned,batch:b}));
  const train=examples.filter(e=>e.batch.split==='train'),validation=examples.filter(e=>e.batch.split==='validation'),test=examples.filter(e=>e.batch.split==='test');
  const fitted=fitLogistic(train),threshold=chooseThreshold(fitted,validation);
  const model=validateModel({version:1,purpose:'poisoning_risk_advisory',status:'shadow_candidate',featureNames:FEATURE_NAMES,weights:fitted.weights,bias:fitted.bias,threshold,trainingDigest:digest({train:train.map(e=>e.batch.id),validation:validation.map(e=>e.batch.id)})});
  const predict=e=>probability(model,e.x)>=model.threshold;
  const byFamily=Object.fromEntries([...new Set(test.map(e=>e.batch.family))].map(family=>[family,metrics(test.filter(e=>e.batch.family===family),predict)]));
  const report={classification:'Recorded',scope:'Synthetic Guardian campaigns only; no real-world poisoning guarantee',splits:{train:train.length,validation:validation.length,test:test.length},validation:metrics(validation,predict),test:metrics(test,predict),heldOutFamilies:metrics(test.filter(e=>HELD_OUT_FAMILIES.includes(e.batch.family)),predict),baseline:metrics(test,e=>baselineRisk(e.x)),byFamily,threshold,downstream:downstreamExperiment(model,dataset),qualification:{eligibleForAutomaticTrainingAdmission:false,reasons:['synthetic_evaluation_only','shadow_candidate_only','no_promotion_mechanism','unfamiliar_attack_coverage_not_established']},claims:{modelTraining:'Verified by pipeline tests',realWorldDetection:'Unknown',llmFineTuning:'Not implemented',productionAdmission:'Not implemented'}};
  return {model:privateKey?seal(model,privateKey,'shadow-model'):{payload:model,replay:true},report};
}
function downstreamExperiment(model,dataset) {
  const rng=random(77439);
  const fresh=n=>Array.from({length:n},()=>{const a=Number(rng()>0.5),b=Number(rng()>0.5);return {x:[a,b],y:Number(a&&b)};});
  const seed=fresh(64),test=fresh(256);
  const batches=dataset.batches.filter(b=>b.split==='test');
  const candidateRows=selected=>selected.flatMap(b=>b.rows.map(r=>({x:[r.signals.deviceMismatch,r.signals.missingProof],y:Number(r.claimedLabel==='credential_misuse')})));
  const selected=batches.filter(b=>probability(model,features(b))<model.threshold);
  const measured=rows=>{const m=fitLogistic([...seed,...rows]);return metrics(test,e=>probability(m,e.x)>=0.5);};
  return {classification:'Recorded',scope:'Toy session classifier; deliberately unsafe baseline accepts claimed labels without independent verification',trustedSeedOnly:measured([]),unscreenedCandidates:measured(candidateRows(batches)),shadowScreenedCandidates:measured(candidateRows(selected)),candidates:batches.length,retained:selected.length,rejected:batches.length-selected.length,productionTrainingChanged:false};
}
export function joinConfirmedLabels(exportPayload,labelsEnvelope,publicKey) {
  if(!verifySealed(labelsEnvelope,publicKey,'confirmed-telemetry-labels') || labelsEnvelope.payload.anchorHead!==exportPayload.anchor.head)throw new Error('untrusted_labels');
  const labels=labelsEnvelope.payload.labels,refs=new Set(exportPayload.samples.map(s=>s.sourceRef));
  if(!Array.isArray(labels) || labels.length>256 || new Set(labels.map(l=>l.sourceRef)).size!==labels.length || labels.some(l=>l.origin!=='independent_guardian_simulator' || !refs.has(l.sourceRef) || !['legitimate','suspicious','credential_misuse'].includes(l.confirmedKind)))throw new Error('invalid_confirmed_labels');
  return exportPayload.samples.map(sample=>({...sample,label:labels.find(l=>l.sourceRef===sample.sourceRef)?.confirmedKind??null,labelSource:'independent_guardian_simulator'}));
}
