import { exact,freeze,digest,verify } from './protocol.js';
const PROVIDERS=['microsoft-defender','crowdstrike-falcon'];

export function validateEndpointPolicy(value,policy) {
  exact(value,['version','mode','bindings']);
  if(value.version!==1 || !['disabled','simulate'].includes(value.mode) || !Array.isArray(value.bindings) || value.bindings.length>16 || value.mode==='disabled' && value.bindings.length)throw new Error('invalid_endpoint_policy');
  const sessions=new Set(),devices=new Set();
  for(const b of value.bindings){
    exact(b,['session','provider','deviceId','allowIsolation']);
    const device=b.provider+'/'+b.deviceId;
    if(!policy.sessions.includes(b.session) || !PROVIDERS.includes(b.provider) || typeof b.deviceId!=='string' || !/^[A-Za-z0-9_-]{1,100}$/.test(b.deviceId) ||
      typeof b.allowIsolation!=='boolean' || sessions.has(b.session) || devices.has(device) || policy.protectedSessions.includes(b.session) && b.allowIsolation)throw new Error('invalid_endpoint_binding');
    sessions.add(b.session);devices.add(device);
  }
  return freeze(structuredClone(value));
}

// Simulation only. No HTTP client, vendor credentials, remote execution or lifting containment.
export class SimulatedEndpointAdapter {
  constructor(config,policy,collectorKeys,record,requireAuthority) {
    this.config=validateEndpointPolicy(config,policy);this.collectorKeys=collectorKeys??{};
    this.record=record;this.requireAuthority=requireAuthority;this.sequences=new Map();this.receipts=new Map();
    this.devices=new Map(this.config.bindings.map(b=>[b.provider+'/'+b.deviceId,'connected']));
  }
  snapshot(){return {mode:this.config.mode,policyHash:digest(this.config),devices:[...this.devices].map(([binding,state])=>({binding,state})),receiptCount:this.receipts.size};}
  acceptAlert(envelope) {
    if(this.config.mode!=='simulate')throw new Error('endpoint_integration_disabled');
    if(JSON.stringify(envelope).length>4096)throw new Error('endpoint_alert_bound');
    const p=envelope?.payload;
    exact(p,['seq','provider','deviceId','alertId','finding']);
    if(!PROVIDERS.includes(p.provider) || !verify(this.collectorKeys[p.provider],'endpoint-alert/'+p.provider,envelope))throw new Error('endpoint_alert_authentication');
    if(!Number.isSafeInteger(p.seq) || p.seq<1 || p.seq<=(this.sequences.get(p.provider)??0))throw new Error('endpoint_alert_replay');
    if(typeof p.alertId!=='string' || !/^[A-Za-z0-9_-]{1,100}$/.test(p.alertId) || !['suspected_exfiltration','suspected_poisoning','credential_alert'].includes(p.finding))throw new Error('invalid_endpoint_alert');
    const binding=this.config.bindings.find(b=>b.provider===p.provider && b.deviceId===p.deviceId);
    if(!binding)throw new Error('endpoint_device_out_of_scope');
    if(this.receipts.size>=1000)throw new Error('endpoint_receipt_bound');
    this.sequences.set(p.provider,p.seq);
    const id='endpoint-'+digest({provider:p.provider,alertId:p.alertId});
    this.record('endpoint_alert',{provider:p.provider,alertHash:digest(p.alertId),deviceHash:digest(p.deviceId),session:binding.session,finding:p.finding,classification:'Recorded',confirmed:false});
    // Vendor alert text/severity does not create a confirmed attack or isolation permission.
    return {id,session:binding.session,kind:'suspicious'};
  }
  isolate(session,cause) {
    if(this.config.mode!=='simulate')return {status:'disabled'};
    const b=this.config.bindings.find(binding=>binding.session===session);
    if(!b)return {status:'unmapped'};
    if(!b.allowIsolation){this.record('endpoint_response_denied',{session,reason:'endpoint_isolation_not_pre_authorized'});return {status:'denied'};}
    this.requireAuthority();
    const key=b.provider+'/'+b.deviceId,requestId=digest({binding:key,evidence:cause.evidence??cause.caseId});
    if(this.receipts.has(requestId))return this.receipts.get(requestId);
    if(this.receipts.size>=1000)throw new Error('endpoint_receipt_bound');
    const before=this.devices.get(key);
    const intent={requestId,provider:b.provider,deviceHash:digest(b.deviceId),session,action:'ISOLATE_ENDPOINT',before,cause,mode:'simulate'};
    this.record('endpoint_intent',intent);
    // The deterministic fake result represents a completed simulated action, not an HTTP acceptance.
    this.devices.set(key,'simulated_isolated');
    const receipt={...intent,after:'simulated_isolated',status:'simulated_applied',classification:'Recorded'};
    this.receipts.set(requestId,receipt);
    try{this.record('endpoint_reconciliation',receipt);}catch(error){
      // Authority revocation is handled by controller panic; preserve a failed audit receipt first.
      const failed={...receipt,status:'applied_audit_failed'};this.receipts.set(requestId,failed);
      try{this.record('endpoint_reconciliation',failed);}catch{}
      throw error;
    }
    return receipt;
  }
}
