import { digest } from './protocol.js';

export class OperatorAlerts {
  constructor(){this.recent=[];this.count=0;}
  raise({reason,instance,generation,sessions,anchor}){
    const failed=['barrier_containment_failure','endpoint_response_failure'].includes(reason);
    const alert={id:digest({number:++this.count,reason,instance,generation,anchor}),
      kind:failed?'CONTAINMENT_FAILURE':'PROTECTION_TRUST_FAILURE',severity:'critical',classification:'Recorded',
      reason,instance,generation,affectedSessions:[...new Set(sessions)].slice(0,16),
      authorityStatus:'revoked',containmentStatus:'not_verified',sacrificialCoreStatus:'not_implemented',
      delivery:'local_status_only',acknowledged:false,automaticAccessRestoration:false,
      operatorMessage:failed?'Containment response failed or could not be reconciled. SENTRY execution authority has been revoked. Verify containment through an independent trusted path and review affected access before recovery.':'SENTRY protection trust was lost. Execution authority has been revoked. Independent verification and trusted recovery are required.',
      accessMessage:'SENTRY privileged actions are paused. Affected access requires verified containment and authorized recovery; no automatic restoration is promised.'};
    this.recent.push(alert);if(this.recent.length>64)this.recent.shift();return structuredClone(alert);
  }
  acknowledge(id){
    const alert=this.recent.find(a=>a.id===id);if(!alert)throw new Error('operator_alert_not_found');
    if(alert.acknowledged)throw new Error('operator_alert_already_acknowledged');
    alert.acknowledged=true;return {id,acknowledged:true,authorityChanged:false,accessRestored:false};
  }
  snapshot(){return {totalRaised:this.count,recent:structuredClone(this.recent),delivery:'local_status_only'};}
}
