import { readVerifiedJournal } from './journal.js';
import { digest,sign,verify } from './protocol.js';

export function exportTraining(journal,policyHash) {
  const checked=readVerifiedJournal(journal.path,journal.key,{head:journal.head,count:journal.count,encrypted:journal.encrypted});
  let lastTime=null;
  const samples=checked.entries.filter(r=>r.payload.type==='signal_classification').map(({payload})=>{
    const raw=payload.data.raw;
    if(raw?.kind!=='session_use' || typeof raw.id!=='string' || typeof raw.session!=='string' || typeof raw.device!=='string' || !['valid','missing'].includes(raw.proof))throw new Error('invalid_training_observation');
    const cadence=lastTime===null?0:Math.min(1,Math.max(0,Math.round((payload.time-lastTime)/10)/100));lastTime=payload.time;
    return {sampleId:digest({anchor:checked.anchor.head,seq:payload.n}),sourceRef:digest({eventId:raw.id}),recordSequence:payload.n,features:{deviceMismatch:Number(raw.device!=='bound-device-'+raw.session),missingProof:Number(raw.proof!=='valid'),cadence},label:null,provenance:'authenticated_simulated_observer'};
  });
  if(samples.length>256)throw new Error('training_export_bound');
  if(new Set(samples.map(s=>s.sourceRef)).size!==samples.length)throw new Error('ambiguous_training_event_ids');
  return sign(journal.key,'training-export',{version:1,classification:'Recorded',policyHash,anchor:checked.anchor,samples,privacy:'raw_ids_devices_text_excluded',labels:'independent_confirmation_required'});
}
export function acceptTrainingExport(envelope,key,expectedPolicyHash) {
  if(!verify(key,'training-export',envelope) || envelope.payload.version!==1 || envelope.payload.policyHash!==expectedPolicyHash || !Array.isArray(envelope.payload.samples) || envelope.payload.samples.length>256)throw new Error('unverified_training_export');
  for(const sample of envelope.payload.samples)if(sample.label!==null || !/^[a-f0-9]{64}$/.test(sample.sourceRef) || ![0,1].includes(sample.features?.deviceMismatch) || ![0,1].includes(sample.features?.missingProof) || !Number.isFinite(sample.features?.cadence) || sample.features.cadence<0 || sample.features.cadence>1)throw new Error('invalid_export_sample');
  return structuredClone(envelope.payload);
}
