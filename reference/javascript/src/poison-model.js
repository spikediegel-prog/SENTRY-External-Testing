import { FEATURE_NAMES,features } from './poison-features.js';
import { exact } from './protocol.js';

const sigmoid=x=>1/(1+Math.exp(-Math.max(-40,Math.min(40,x))));
export function fitLogistic(examples,{epochs=600,rate=0.4,penalty=0.01}={}) {
  if(!Array.isArray(examples) || examples.length<8 || examples.length>10000)throw new Error('invalid_training_size');
  const width=examples[0].x.length,w=Array(width).fill(0);let bias=0;
  for(const e of examples)if(e.x.length!==width || e.x.some(v=>!Number.isFinite(v) || v<0 || v>1) || ![0,1].includes(e.y))throw new Error('invalid_training_features');
  for(let epoch=0;epoch<epochs;epoch++){
    const gradient=Array(width).fill(0);let gb=0;
    for(const e of examples){const error=sigmoid(bias+w.reduce((s,v,i)=>s+v*e.x[i],0))-e.y;gb+=error;for(let i=0;i<width;i++)gradient[i]+=error*e.x[i];}
    for(let i=0;i<width;i++)w[i]-=rate*(gradient[i]/examples.length+penalty*w[i]);bias-=rate*gb/examples.length;
  }
  return {weights:w,bias};
}
export const probability=(model,x)=>sigmoid(model.bias+model.weights.reduce((s,v,i)=>s+v*x[i],0));
export function metrics(examples,predict) {
  let tp=0,tn=0,fp=0,fn=0;
  for(const e of examples){const yes=predict(e);if(e.y){if(yes)tp++;else fn++;}else if(yes)fp++;else tn++;}
  return {count:examples.length,tp,tn,fp,fn,precision:tp+fp?tp/(tp+fp):null,recall:tp+fn?tp/(tp+fn):null,falsePositiveRate:fp+tn?fp/(fp+tn):null,accuracy:examples.length?(tp+tn)/examples.length:null};
}
export function chooseThreshold(model,validation,targetFpr=0.05) {
  let selected={threshold:1,recall:-1};
  for(let t=0.05;t<=1;t+=0.01){const m=metrics(validation,e=>probability(model,e.x)>=t);if(m.falsePositiveRate<=targetFpr && m.recall>selected.recall)selected={threshold:Number(t.toFixed(2)),recall:m.recall};}
  return selected.threshold;
}
export function validateModel(model) {
  exact(model,['version','purpose','status','featureNames','weights','bias','threshold','trainingDigest']);
  if(model.version!==1 || model.purpose!=='poisoning_risk_advisory' || model.status!=='shadow_candidate' || JSON.stringify(model.featureNames)!==JSON.stringify(FEATURE_NAMES) || !Array.isArray(model.weights) || model.weights.length!==8 || model.weights.some(w=>!Number.isFinite(w) || Math.abs(w)>20) || !Number.isFinite(model.bias) || Math.abs(model.bias)>20 || !Number.isFinite(model.threshold) || model.threshold<0 || model.threshold>1 || !/^[a-f0-9]{64}$/.test(model.trainingDigest))throw new Error('invalid_shadow_model');
  return Object.freeze({...model,weights:Object.freeze([...model.weights]),featureNames:FEATURE_NAMES});
}
export function screenBatch(model,batch) {
  model=validateModel(model);const x=features(batch),risk=probability(model,x);
  const verdict=risk>=model.threshold?'review_for_quarantine':risk>=model.threshold*0.6?'uncertain':'lower_observed_risk';
  return {classification:'Proposed',mode:'shadow_only',risk,verdict,features:Object.fromEntries(FEATURE_NAMES.map((k,i)=>[k,x[i]])),authorityChange:false,trainingAdmission:false};
}
