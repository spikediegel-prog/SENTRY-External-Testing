import { Sentry } from './sentry.js';
import { childChannel } from './secure-channel.js';
const channel=childChannel();
const emit=message=>process.send(channel.encode(message));

let sentry, next=0; const pending=new Map();
const send=body=>new Promise(resolve=>{ const id=++next; pending.set(id,resolve); emit({ type:'proposal',id,body }); });
process.on('message',async wire=>{
  let m;try{m=channel.decode(wire);}catch{process.exit(1);return;}
  if (m.type==='init') { sentry=new Sentry(send,m.token,{shadowModel:m.shadowModel??null,library:m.library??null}); emit({ type:'ready' }); }
  else if (m.type==='result') { const resolve=pending.get(m.id); pending.delete(m.id); resolve?.(m.result); }
  else if (m.type==='review') {
    try { const result=await sentry.review(m.event); emit({ type:'review-result',id:m.id,result }); }
    catch (e) { emit({ type:'review-result',id:m.id,result:{ ok:false,error:e.message } }); }
  }
  else if (m.type==='raw') { const result=await send(m.body); emit({ type:'review-result',id:m.id,result }); }
  else if(m.type==='countermeasure' || m.type==='screen_training' || m.type==='reference_query' || m.type==='advisory_button'){
    try{const result=m.type==='countermeasure'?await sentry.tryCountermeasure(m.candidate,m.observation):m.type==='advisory_button'?await sentry.pressButton(m.request):m.type==='screen_training'?await sentry.reviewTrainingBatch(m.batch):sentry.lookupCves(m.query);emit({type:'review-result',id:m.id,result});}
    catch(e){emit({type:'review-result',id:m.id,result:{ok:false,error:e.message}});}
  }
});
