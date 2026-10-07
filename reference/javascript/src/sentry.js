// Deliberately low-authority intelligence prototype: bounded counters + proposals.
// No signing keys, policy writer, clock controller, execution adapter or lease minting.
import { screenBatch,validateModel } from './poison-model.js';
import { searchCves } from './cve-library.js';
import { countermeasureProposal } from './countermeasures.js';
export class Sentry {
  constructor(workerTransport, token, {shadowModel=null,library=null}={}) {
    this.send = workerTransport; this.token = token;
    this.counts = new Map(); this.reviews = 0;
    this.shadowModel=shadowModel?validateModel(shadowModel):null;this.library=library;
  }
  async reviewTrainingBatch(batch) {
    if(!this.shadowModel)throw new Error('shadow_model_not_loaded');
    if(JSON.stringify(batch).length>65536)throw new Error('shadow_input_bound');
    const result=screenBatch(this.shadowModel,batch);
    await this.send({command:'learn',recommendation:'Shadow poisoning review: '+JSON.stringify({risk:result.risk,verdict:result.verdict,authorityChange:false,trainingAdmission:false})});
    return result;
  }
  lookupCves(query) {if(!this.library)throw new Error('reference_library_not_loaded');return searchCves(this.library,query);}
  async tryCountermeasure(candidate,observation) {
    const proposal=countermeasureProposal(candidate,observation);
    if(!proposal)return {ok:true,classification:'Recorded',reason:'Countermeasure did not match or protected control'};
    return this.pressButton(proposal);
  }
  async pressButton(request) {
    if(!request || Object.keys(request).sort().join(',')!=='button,evidence,uncertainty' ||
      !['CHALLENGE','CONTAIN'].includes(request.button) || typeof request.evidence!=='string' ||
      request.evidence.length<1 || request.evidence.length>100 || !Number.isFinite(request.uncertainty) ||
      request.uncertainty<0 || request.uncertainty>1)throw new Error('invalid_advisory_button');
    // A button is a proposal. Only the controller can validate evidence and execute.
    return this.send({command:'propose',action:request.button,evidence:request.evidence,
      uncertainty:request.uncertainty,token:this.token});
  }
  async review(observation) {
    this.reviews++;
    const kind = String(observation.kind).slice(0,100);
    if (this.counts.size < 32 || this.counts.has(kind)) this.counts.set(kind,(this.counts.get(kind)??0)+1);
    if (kind === 'credential_misuse') {
      return this.send({ command:'propose',action:'CONTAIN',evidence:observation.id,uncertainty:0.1,token:this.token });
    }
    if (kind === 'suspicious') {
      const result=await this.send({ command:'propose',action:'CHALLENGE',evidence:observation.id,uncertainty:0.8,token:this.token });
      if (this.counts.get(kind)%3===0) await this.send({ command:'learn',recommendation:'Repeated suspicious observations: recommend an administrator-reviewed signature. No new authority requested or granted.' });
      return result;
    }
    return { ok:true, classification:'Recorded', reason:'No consequential proposal' };
  }
}
