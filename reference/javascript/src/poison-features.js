export const FEATURE_NAMES=Object.freeze(['duplicateRate','sourceConcentration','labelMismatchRate','distributionShift','instructionPressure','triggerConcentration','unverifiedLabelRate','missingProvenanceRate']);
const kinds=['legitimate','suspicious','credential_misuse'];
export function features(batch) {
  if(!batch || !Array.isArray(batch.rows) || batch.rows.length<4 || batch.rows.length>128)throw new Error('invalid_training_batch');
  const sources=new Map(),patterns=new Set(),triggers=new Map();let mismatches=0,instructions=0,unknown=0,missing=0,maliciousPatterns=0;
  for(const row of batch.rows){
    if(!row || typeof row.source!=='string' || row.source.length>100 || !row.signals || ![0,1].includes(row.signals.deviceMismatch) || ![0,1].includes(row.signals.missingProof) || typeof row.signals.cadence!=='number' || !Number.isFinite(row.signals.cadence) || row.signals.cadence<0 || row.signals.cadence>1 || !kinds.includes(row.claimedLabel) || row.independentLabel!==null && !kinds.includes(row.independentLabel) || typeof row.note!=='string' || row.note.length>1000 || typeof row.trigger!=='string' || row.trigger.length>100)throw new Error('invalid_training_row');
    sources.set(row.source,(sources.get(row.source)??0)+1);
    patterns.add(JSON.stringify([row.signals,row.claimedLabel,row.trigger]));
    if(row.independentLabel===null)unknown++;else if(row.independentLabel!==row.claimedLabel)mismatches++;
    if(row.provenanceVerified!==true)missing++;
    if(/ignore\s+(previous|prior)|disable\s+(sentry|dead.?man)|grant\s+.*authority|override\s+.*policy/i.test(row.note))instructions++;
    if(row.trigger)triggers.set(row.trigger,(triggers.get(row.trigger)??0)+1);
    if(row.signals.deviceMismatch && row.signals.missingProof)maliciousPatterns++;
  }
  const n=batch.rows.length;
  return [1-patterns.size/n,Math.max(...sources.values())/n,mismatches/n,Math.abs(maliciousPatterns/n-0.25),instructions/n,triggers.size?Math.max(...triggers.values())/n:0,unknown/n,missing/n];
}
export const baselineRisk=x=>x[2]>0.05 || x[4]>0.05 || x[7]>0.05;
