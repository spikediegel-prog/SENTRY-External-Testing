import { validateDataset } from './learning-pipeline.js';
import { verifySealed } from './learning-crypto.js';
import { digest,exact } from './protocol.js';

export function validateCountermeasure(candidate) {
  exact(candidate,['version','classification','status','trainingDigest','rule']);
  exact(candidate.rule,['deviceMismatch','missingProof','button','uncertainty']);
  const r=candidate.rule;
  if(candidate.version!==1 || candidate.classification!=='Proposed' || candidate.status!=='review_required' ||
    !/^[a-f0-9]{64}$/.test(candidate.trainingDigest) || ![0,1].includes(r.deviceMismatch) || ![0,1].includes(r.missingProof) ||
    !(r.deviceMismatch || r.missingProof) || !['CHALLENGE','CONTAIN'].includes(r.button) ||
    r.uncertainty!==(r.button==='CONTAIN'?0.1:0.8) ||
    r.button==='CONTAIN' && !(r.deviceMismatch && r.missingProof))throw new Error('invalid_countermeasure');
  return structuredClone(candidate);
}
export function countermeasureProposal(candidate,observation) {
  const c=validateCountermeasure(candidate);
  exact(observation,['evidence','deviceMismatch','missingProof','protectedControl']);
  if(typeof observation.evidence!=='string' || observation.evidence.length<1 || observation.evidence.length>100 ||
    ![0,1].includes(observation.deviceMismatch) || ![0,1].includes(observation.missingProof) || typeof observation.protectedControl!=='boolean')throw new Error('invalid_countermeasure_observation');
  if(observation.protectedControl || c.rule.deviceMismatch!==observation.deviceMismatch || c.rule.missingProof!==observation.missingProof)return null;
  return {button:c.rule.button,evidence:observation.evidence,uncertainty:c.rule.uncertainty};
}
export function developCountermeasures(envelope,publicKey) {
  if(!verifySealed(envelope,publicKey,'guardian-dataset'))throw new Error('untrusted_countermeasure_dataset');
  const dataset=envelope.payload;validateDataset(dataset);
  // This teacher-signed simulation fixture explicitly labels which batches are clean.
  // Never infer training trust from the poisoning model's risk score.
  const trustedRows=split=>dataset.batches.filter(b=>b.split===split && b.poisoned===0).flatMap(b=>b.rows)
    .filter(r=>r.provenanceVerified===true && r.independentLabel!==null && r.claimedLabel===r.independentLabel);
  const train=trustedRows('train'),validation=trustedRows('validation'),test=trustedRows('test');
  const trainingDigest=digest(train.map(r=>({id:r.id,signals:r.signals,label:r.independentLabel}))),candidates=[];
  for(const [deviceMismatch,missingProof] of [[1,0],[0,1],[1,1]]) {
    const matching=train.filter(r=>r.signals.deviceMismatch===deviceMismatch && r.signals.missingProof===missingProof);
    const expected=deviceMismatch && missingProof?'credential_misuse':'suspicious';
    if(matching.length<8 || matching.filter(r=>r.independentLabel===expected).length/matching.length<0.95)continue;
    const candidate=validateCountermeasure({version:1,classification:'Proposed',status:'review_required',trainingDigest,
      rule:{deviceMismatch,missingProof,button:expected==='credential_misuse'?'CONTAIN':'CHALLENGE',uncertainty:expected==='credential_misuse'?0.1:0.8}});
    const evaluate=rows=>{
      const fired=rows.filter(r=>r.signals.deviceMismatch===deviceMismatch && r.signals.missingProof===missingProof);
      return {matchingRows:fired.length,legitimateAffected:fired.filter(r=>r.independentLabel==='legitimate').length,
        wrongLabel:fired.filter(r=>r.independentLabel!==expected).length};
    };
    const validationResult=evaluate(validation);
    // Qualification is for human review only. Failed validation cannot become a candidate.
    if(validationResult.matchingRows<1 || validationResult.wrongLabel>0)continue;
    candidates.push({candidate,trainingSupport:matching.length,validation:validationResult,test:evaluate(test)});
  }
  return {classification:'Proposed',scope:'Finite template synthesis from independently labeled simulated clean batches only',
    candidates,authorityChange:false,installed:false,automaticPromotion:false,
    limitations:['not_novel_exploit_defense','not_real_world_efficacy','teacher_trust_required','controller_rechecks_original_evidence']};
}
