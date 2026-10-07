import { performance } from 'node:perf_hooks';
import { randomBytes } from 'node:crypto';
import { digest, exact, verify } from './protocol.js';
import { Journal,appendEmergency } from './journal.js';
import { exportTraining } from './training-export.js';
import { SimulatedEndpointAdapter,validateEndpointPolicy } from './endpoint-adapter.js';
import { OperatorAlerts } from './operator-alerts.js';

// This module lives only in the trusted controller subprocess, never in SENTRY.
export class Controller {
  constructor(policy, keys, journalPath, endpointConfig={version:1,mode:'disabled',bindings:[]}) {
    this.policy = policy; this.hash = digest(policy); this.keys = keys;
    this.journal = new Journal(journalPath, keys.journal,{encrypted:true}); this.fallback = journalPath + '.emergency';
    this.start = performance.now(); this.offset = 0; this.deadline = 0;
    this.state = 'RECOVERY_REQUIRED'; this.instance = null; this.generation = 0;
    this.severed = true; this.workerToken = null; this.supervisorSeq = 0; this.observerSeq = 0; this.humanSeq = 0; this.controlSeq = 0;
    this.sessions = Object.fromEntries(policy.sessions.map(s => [s, { route: 'production', credential: true, challenged: false }]));
    this.evidence = new Map(); this.pending = new Map(); this.alerts = []; this.learning = [];
    this.metrics = { dropped: 0, challenged: 0, protected: 0, admitted: 0, reasoningCalls: 0 };
    this.actionCounter = 0; this.panicActive = false; this.inFlight = null;
    this.operatorAlerts=new OperatorAlerts();
    this.accessHolds=new Map();
    const endpointPolicy=validateEndpointPolicy(endpointConfig,policy);
    if(endpointPolicy.mode!=='disabled')this.hash=digest({policy,endpointPolicy});
    this.endpoint=new SimulatedEndpointAdapter(endpointPolicy,policy,keys.endpoint,(type,data)=>this.record(type,data),()=>this.requireLease());
    this.record('boot', { state: this.state, policyHash: this.hash });
  }
  now() { return performance.now() - this.start + this.offset; }
  record(type, data) { this.journal.append({ time: Math.floor(this.now()), type, data }); }
  snapshot() {
    return structuredClone({ state: this.state, instance: this.instance, generation: this.generation, severed: this.severed, policyHash: this.hash, leaseRemainingMs: Math.max(0, Math.floor(this.deadline-this.now())), sessions: this.sessions,accessHolds:[...this.accessHolds].map(([session,hold])=>({session,...hold})),pending: [...this.pending.values()], alerts: this.alerts,operatorAlerts:this.operatorAlerts.snapshot(),learning: this.learning, metrics: this.metrics, endpoint:this.endpoint.snapshot(),journal: { head: this.journal.head, count: this.journal.count, compression:this.journal.stats() } });
  }
  panic(reason,{session=null}={}) {
    if (this.panicActive || this.state === 'RECOVERY_REQUIRED' && this.severed) return;
    this.panicActive = true;
    const previousAuthority={ state:this.state,instance:this.instance,generation:this.generation,severed:this.severed };
    const abandonedPlans=structuredClone([...this.pending.values()]);
    const affectedSessions=[session,this.inFlight?.session,...abandonedPlans.map(p=>p.session)].filter(Boolean);
    // Revoke gate BEFORE any evidence I/O. Never depend on an alert succeeding.
    this.deadline = 0; this.severed = true; this.workerToken = null; this.pending.clear();
    if(['barrier_containment_failure','endpoint_response_failure'].includes(reason)){
      for(const target of new Set(affectedSessions)){
        if(!this.policy.sessions.includes(target) || this.policy.protectedSessions.includes(target) || this.accessHolds.has(target))continue;
        const before={held:false},after={held:true,reason,generation:this.generation};
        // Local fail-closed routing for an already targeted containment operation. No new remote action.
        this.accessHolds.set(target,after);
        for(const [type,data] of [['access_hold_intent',{session:target,reason,before}],['access_hold_reconciliation',{session:target,reason,before,after,status:'held'}]]){
          try{this.record(type,data);}catch{try{appendEmergency(this.fallback,{type,data},this.keys.journal);}catch{}}
        }
      }
    }
    const preserved = { ...this.snapshot(),abandonedPlans,previousAuthority };
    if (this.inFlight) {
      const event = { ...this.inFlight, after: this.inFlight.action === 'DROP' ? { dropped: this.metrics.dropped } : structuredClone(this.sessions[this.inFlight.session]), status: 'reconciled_after_evidence_failure' };
      try { this.record('emergency_reconciliation', event); }
      catch { try { appendEmergency(this.fallback,{type:'emergency_reconciliation',data:event},this.keys.journal); } catch {} }
      this.inFlight = null;
    }
    for (const state of ['DEGRADED','QUARANTINED','SAFE_MODE','RECOVERY_REQUIRED']) {
      this.state = state;
      const event = { reason, state, instance: this.instance, generation: this.generation, preserved };
      try { this.record('self_containment', event); }
      catch { try { appendEmergency(this.fallback,event,this.keys.journal); } catch { /* gate stays closed even if storage is lost */ } }
    }
    this.alerts.push({ kind: 'SELF_CONTAINMENT', reason, instance: this.instance });
    const reconciliation={ reason,before:previousAuthority,after:{ state:this.state,instance:this.instance,generation:this.generation,severed:this.severed,leaseRemainingMs:0 },status:'revoked' };
    try { this.record('authority_reconciliation',reconciliation); }
    catch { try { appendEmergency(this.fallback,{type:'authority_reconciliation',data:reconciliation},this.keys.journal); } catch {} }
    const operatorAlert=this.operatorAlerts.raise({reason,instance:this.instance,generation:this.generation,sessions:affectedSessions,anchor:this.journal.head});
    try{this.record('operator_alert',operatorAlert);}catch{try{appendEmergency(this.fallback,{type:'operator_alert',data:operatorAlert},this.keys.journal);}catch{}}
    this.panicActive = false;
  }
  tick() {
    if (this.state === 'NORMAL' && this.now() >= this.deadline) this.panic('lease_expired');
    if (this.state !== 'NORMAL') return;
    for (const [id, plan] of this.pending) {
      if (this.now() >= plan.deadline) {
        this.pending.delete(id);
        for (const action of plan.actions) this.execute(action, plan.session, { caseId: id, evidence: plan.evidence, trigger: 'window_expired' });
        this.record('window_closed', { caseId: id });
      }
    }
  }
  authenticate(lane, envelope) {
    if (!verify(this.keys[lane], lane, envelope)) throw new Error('authentication_failed');
    const p = envelope.payload;
    if (!Number.isSafeInteger(p.seq) || p.seq <= this[lane+'Seq']) throw new Error('replay');
    // A valid signed envelope consumes its sequence even if its command fails.
    this[lane+'Seq'] = p.seq;
    return p;
  }
  requireLease() { this.tick(); if (this.state !== 'NORMAL' || this.severed || this.now() >= this.deadline) throw new Error('authority_expired'); }
  execute(action, session, cause, { human = false } = {}) {
    // One execution route; uncertainty, traffic pressure and learned text cannot reach this directly.
    this.requireLease();
    if (!this.policy.powers.includes(action) || !this.policy.sessions.includes(session)) throw new Error('outside_authority');
    if (this.policy.protectedSessions.includes(session) && !['DROP','CHALLENGE'].includes(action)) throw new Error('protected_scope');
    if (action === 'RESTORE' && !human) throw new Error('human_required');
    const before = structuredClone(this.sessions[session]);
    const id = ++this.actionCounter;
    this.record('intent', { id, action, session, cause, before });
    this.inFlight = { id, action, session, cause, before };
    const s = this.sessions[session];
    if (action === 'DROP') this.metrics.dropped++;
    else if (action === 'CHALLENGE') { s.challenged = true; this.metrics.challenged++; }
    else if (action === 'CONTAIN' && s.route === 'production') s.route = 'sandbox';
    else if (action === 'ISOLATE') s.route = 'isolated';
    else if (action === 'REVOKE') s.credential = false;
    else if (action === 'RESTORE') { s.route = 'production'; s.challenged = false; /* never resurrect a revoked credential */ }
    const after = structuredClone(s);
    const containmentFailed=action==='CONTAIN' && after.route==='production' || action==='ISOLATE' && after.route!=='isolated';
    if(containmentFailed){
      this.record('reconciliation',{id,action,session,cause,before,after,status:'containment_failed'});
      this.inFlight=null;this.panic('barrier_containment_failure',{session});throw new Error('barrier_containment_failure');
    }
    this.record('reconciliation', { id, action, session, cause, before, after, status: 'applied' });
    this.inFlight = null;
    if(action==='ISOLATE'){
      try{this.endpoint.isolate(session,cause);}catch(error){this.panic('endpoint_response_failure',{session});throw error;}
    }
  }
  observe(p) {
    exact(p, ['seq','event']);
    exact(p.event, p.event?.kind === 'session_use' ? ['id','session','kind','device','proof'] : ['id','session','kind']);
    let e = p.event;
    if (typeof e.id !== 'string' || e.id.length < 1 || e.id.length > 100 || this.evidence.has(e.id)) throw new Error('duplicate_or_invalid_event');
    if (!this.policy.sessions.includes(e.session) || !['junk','control','legitimate','suspicious','credential_misuse','confirmed_exfiltration','session_use'].includes(e.kind)) throw new Error('invalid_event');
    if (e.kind === 'session_use') {
      if (typeof e.device !== 'string' || e.device.length > 100 || !['valid','missing'].includes(e.proof)) throw new Error('invalid_session_signal');
      const unexpectedDevice=e.device !== 'bound-device-'+e.session;
      const missingProof=e.proof !== 'valid';
      const kind=unexpectedDevice && missingProof ? 'credential_misuse' : unexpectedDevice || missingProof ? 'suspicious' : 'legitimate';
      this.record('signal_classification',{ raw:e,classification:kind,rule:'device_binding_plus_session_proof',claim:'Inferred' });
      e={ id:e.id,session:e.session,kind };
    }
    // Protected status is authenticated observer data plus fixed policy scope, not a caller label.
    if (this.policy.protectedSessions.includes(e.session)) {
      if (e.kind !== 'control') throw new Error('protected_traffic_mismatch');
      this.record('protected_admission', { event: e }); this.metrics.protected++; return;
    }
    if (e.kind === 'control') throw new Error('spoofed_control');
    if (e.kind === 'junk') {
      // Minimal deterministic barrier survives loss of SENTRY authority.
      this.record('intent', { id: ++this.actionCounter, action: 'DROP', session: e.session, cause: e.id, before: null });
      this.inFlight = { id:this.actionCounter,action:'DROP',session:e.session,cause:e.id,before:{ dropped:this.metrics.dropped } };
      this.metrics.dropped++;
      this.record('reconciliation', { id: this.actionCounter, action: 'DROP', session: e.session, cause: e.id, after: { dropped: true }, status: 'applied' }); this.inFlight = null; return;
    }
    if (e.kind === 'legitimate') {
      const s = this.sessions[e.session];
      const route = this.accessHolds.has(e.session)?'denied':s.credential ? s.route : 'denied';
      if (route === 'production') this.metrics.admitted++;
      this.record('admission', { event: e, route }); return { id:e.id,kind:e.kind };
    }
    this.requireLease();
    if (this.evidence.size >= this.policy.maxEvidence) { this.panic('evidence_capacity'); throw new Error('capacity_closed'); }
    this.evidence.set(e.id, structuredClone(e)); this.record('observation', { event: e });
    if (e.kind === 'suspicious') { this.execute('CHALLENGE', e.session, { evidence: e.id }); return { id:e.id,kind:e.kind }; }
    const profile = this.policy.profiles[e.kind];
    if (profile.delayed.length && this.pending.size >= this.policy.maxPending) { this.panic('window_capacity'); throw new Error('capacity_closed'); }
    for (const a of profile.immediate) this.execute(a, e.session, { evidence: e.id, profile: e.kind });
    if (profile.delayed.length) {
      const plan = { id: e.id, session: e.session, evidence: e.id, deadline: this.now()+this.policy.interventionMs, actions: [...profile.delayed] };
      this.pending.set(e.id, plan); this.record('window_opened', plan);
    }
    this.alerts.push({ kind: 'ATTACK', event: e.id, session: e.session }); this.record('alert', this.alerts.at(-1));
    return { id:e.id,kind:e.kind };
  }
  supervisor(p) {
    if(p.command==='export_training'){
      exact(p,['seq','command']);
      const trainingExport=exportTraining(this.journal,this.hash);
      this.record('training_export',{anchor:trainingExport.payload.anchor,samples:trainingExport.payload.samples.length,payloadHash:digest(trainingExport.payload)});
      return {trainingExport};
    }
    if(p.command==='endpoint_alert'){
      exact(p,['seq','command','envelope']);this.requireLease();
      const event=this.endpoint.acceptAlert(p.envelope);
      if(this.policy.protectedSessions.includes(event.session))throw new Error('protected_endpoint_alert_requires_human_review');
      return this.observe({seq:p.seq,event});
    }
    if (p.command === 'advance') {
      exact(p, ['seq','command','ms']);
      if (!Number.isSafeInteger(p.ms) || p.ms < 0 || p.ms > 120000) throw new Error('invalid_clock');
      this.journal.check(); this.offset += p.ms; this.tick(); this.record('clock_advanced', { ms: p.ms }); return;
    }
    if (p.command === 'attest' || p.command === 'recover') {
      exact(p, ['seq','command','instance','generation','policyHash','integrity']);
      if (p.integrity !== true || p.policyHash !== this.hash) { this.panic('integrity_failure'); throw new Error('invalid_attestation'); }
      if (typeof p.instance !== 'string' || !p.instance || p.instance.length > 100 || !Number.isSafeInteger(p.generation)) throw new Error('invalid_identity');
      this.journal.check();
      if (p.command === 'recover') {
        if (this.state !== 'RECOVERY_REQUIRED' || p.instance === this.instance || p.generation !== this.generation+1) throw new Error('clean_replacement_required');
        this.instance = p.instance; this.generation = p.generation; this.workerToken = randomBytes(32).toString('hex');
      } else if (this.state !== 'NORMAL' || p.instance !== this.instance || p.generation !== this.generation) throw new Error('recovery_required');
      this.deadline = this.now()+this.policy.leaseMs; this.state = 'NORMAL'; this.severed = false;
      this.record('attested', { instance: this.instance, generation: this.generation, policyHash: this.hash, deadline: this.deadline }); return;
    }
    if (p.command === 'integrity_failure') { exact(p, ['seq','command']); this.panic('integrity_failure'); return; }
    throw new Error('unknown_supervisor_command');
  }
  human(p) {
    if(p.command==='acknowledge_alert'){
      exact(p,['seq','command','alertId']);
      if(typeof p.alertId!=='string' || !/^[a-f0-9]{64}$/.test(p.alertId))throw new Error('invalid_operator_alert_id');
      const alert=this.operatorAlerts.recent.find(a=>a.id===p.alertId);
      if(!alert)throw new Error('operator_alert_not_found');
      if(alert.acknowledged)throw new Error('operator_alert_already_acknowledged');
      this.record('operator_alert_acknowledgment',{id:p.alertId,acknowledged:true,authorityChanged:false,accessRestored:false});
      return this.operatorAlerts.acknowledge(p.alertId);
    }
    exact(p, ['seq','command','caseId']);
    this.requireLease();
    if (p.command !== 'cancel') throw new Error('unknown_human_command');
    const plan = this.pending.get(p.caseId);
    if (!plan || this.now() >= plan.deadline) throw new Error('window_closed');
    this.pending.delete(p.caseId);
    this.record('human_override', { caseId: p.caseId });
    this.execute('RESTORE', plan.session, { caseId: p.caseId, trigger: 'human_override' }, { human: true });
  }
  worker(p) {
    if (p.command === 'status') { exact(p, ['command']); return this.snapshot(); }
    if (p.command === 'learn') {
      exact(p, ['command','recommendation']);
      if (typeof p.recommendation !== 'string' || p.recommendation.length > 2000 || this.learning.length >= 100) throw new Error('learning_bound');
      this.learning.push({ recommendation: p.recommendation, classification: 'Proposed' });
      this.record('learning_recommendation', { textHash: digest(p.recommendation), classification: 'Proposed' }); return;
    }
    if (p.command === 'propose') {
      exact(p, ['command','action','evidence','uncertainty','token']); this.requireLease();
      if (typeof p.token !== 'string' || p.token !== this.workerToken) throw new Error('instance_capability_revoked');
      if (typeof p.uncertainty !== 'number' || !Number.isFinite(p.uncertainty) || p.uncertainty < 0 || p.uncertainty > 1) throw new Error('invalid_uncertainty');
      const e = this.evidence.get(p.evidence);
      if (!e) throw new Error('trusted_evidence_required');
      const allowed = p.uncertainty > 0.2 ? ['CHALLENGE'] : ['CHALLENGE','CONTAIN'];
      if (!allowed.includes(p.action) || !this.policy.profiles[e.kind] && p.action !== 'CHALLENGE') throw new Error('proposal_denied');
      this.execute(p.action, e.session, { evidence: e.id, uncertainty: p.uncertainty, trigger: 'proposal' }); return;
    }
    throw new Error('unknown_worker_command');
  }
  handle(message) {
    try {
      if (JSON.stringify(message).length > 16384) throw new Error('message_bound');
      this.tick(); exact(message, ['lane','body']);
      if (message.lane === 'worker') {
        const data = this.worker(message.body); return { ok: true, data: data ?? this.snapshot() };
      }
      if (!['observer','supervisor','human','control'].includes(message.lane)) throw new Error('unknown_lane');
      const p = this.authenticate(message.lane, message.body);
      if(message.lane==='control' && (p.event?.kind!=='control' || !this.policy.protectedSessions.includes(p.event?.session)))throw new Error('protected_traffic_mismatch');
      const outcome=this[['observer','control'].includes(message.lane) ? 'observe' : message.lane](p);
      return { ok: true, data: this.snapshot(), ...(message.lane === 'observer' && outcome ? { observation:outcome } : {}), ...(message.lane === 'supervisor' && p.command === 'export_training' ? outcome : {}), ...(message.lane === 'supervisor' && p.command === 'recover' ? { workerToken: this.workerToken } : {}) };
    } catch (err) {
      if (/journal|ENOENT|EACCES|ENOSPC/.test(err.message)) this.panic('evidence_failure');
      try { this.record('denied', { reason: err.message, lane: message?.lane }); }
      catch { this.panic('evidence_failure'); }
      return { ok: false, error: err.message, data: this.snapshot() };
    }
  }
}
