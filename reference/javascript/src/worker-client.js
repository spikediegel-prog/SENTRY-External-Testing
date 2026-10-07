import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { loadLibrary } from './cve-library.js';
import { verifySealed } from './learning-crypto.js';
import { validateModel } from './poison-model.js';
import { channelConfig,secureChannel } from './secure-channel.js';
import { readArtifact } from './protected-artifacts.js';

// Trusted supervisor forwards every worker request ONLY to the untrusted lane.
export async function createSentryWorker(lab,{shadowModelPath=null,teacherPublicKey=null,knowledgeDirectory=null}={}) {
  let shadowModel=null;
  if(shadowModelPath){const envelope=readArtifact(shadowModelPath);if(!teacherPublicKey || !verifySealed(envelope,teacherPublicKey,'shadow-model'))throw new Error('untrusted_shadow_model');shadowModel=validateModel(envelope.payload);}
  const library=knowledgeDirectory?loadLibrary(knowledgeDirectory):null;
  const env={ ...process.env }; delete env.BARRIERS_TRUSTED_KEYS;
  const ipcConfig=channelConfig(),channel=secureChannel(ipcConfig,'parent');env.BARRIERS_IPC_SECURITY=JSON.stringify(ipcConfig);
  const child=fork(fileURLToPath(new URL('./sentry-host.js',import.meta.url)),[],{ env,stdio:['ignore','ignore','ignore','ipc'] });
  let id=0; const pending=new Map();
  child.on('message',wire=>{try{child.emit('secure-message',channel.decode(wire));}catch{child.kill();}});
  child.on('secure-message',async m=>{
    if (m.type==='proposal') {
      const result=await lab.worker(m.body);
      if (child.connected) child.send(channel.encode({ type:'result',id:m.id,result }));
    } else if (m.type==='review-result') { const p=pending.get(m.id); pending.delete(m.id); p?.(m.result); }
  });
  await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(new Error('worker_start_timeout')),5000);
    child.on('secure-message',m=>{ if (m.type==='ready') { clearTimeout(timer); resolve(); } });
    child.send(channel.encode({ type:'init',token:lab.token,shadowModel,library }));
  });
  const request=(type,payload)=>new Promise((resolve,reject)=>{
    const n=++id; const timer=setTimeout(()=>{pending.delete(n);reject(new Error('worker_timeout'));},5000);
    pending.set(n,r=>{clearTimeout(timer);resolve(r);}); child.send(channel.encode({ type,id:n,...payload }));
  });
  return {
    review:event=>request('review',{ event }),
    raw:body=>request('raw',{ body }),
    screenTraining:batch=>request('screen_training',{batch}),
    pressButton:proposal=>request('advisory_button',{request:proposal}),
    tryCountermeasure:(candidate,observation)=>request('countermeasure',{candidate,observation}),
    searchCves:query=>request('reference_query',{query}),
    close:()=>new Promise(resolve=>{ child.once('exit',resolve); child.kill(); })
  };
}
