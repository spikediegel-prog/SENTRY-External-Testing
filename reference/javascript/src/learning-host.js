import { trainDetector } from './learning-pipeline.js';
import { childChannel } from './secure-channel.js';
import { developCountermeasures } from './countermeasures.js';
const channel=childChannel(),emit=m=>process.send(channel.encode(m));
process.once('message',wire=>{
  try {
    const m=channel.decode(wire);
    const fitted=trainDetector(m.envelope,m.publicKey,null);
    emit({ok:true,result:{classification:'Proposed',mode:'offline_candidate',
      candidate:fitted.model.payload,evaluation:fitted.report,countermeasures:developCountermeasures(m.envelope,m.publicKey),authorityChange:false,
      activeModelChanged:false,trainingAdmission:false}});
  }catch(error){try{emit({ok:false,error:error.message});}catch{process.exit(1);}}
});
