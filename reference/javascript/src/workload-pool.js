import { fork } from 'node:child_process';
import { availableParallelism } from 'node:os';
import { fileURLToPath } from 'node:url';
import { exact } from './protocol.js';
import { channelConfig,secureChannel } from './secure-channel.js';

export function validateWorkload(c) {
  exact(c,['processes','threadsPerProcess','maxPending','reservedPending','taskTimeoutMs','maxRestarts']);
  for (const [k,min,max] of [['processes',1,4],['threadsPerProcess',1,4],['maxPending',1,256],['reservedPending',1,64],['taskTimeoutMs',100,10000],['maxRestarts',0,3]]) {
    if (!Number.isInteger(c[k]) || c[k] < min || c[k] > max) throw new Error('invalid_workload_'+k);
  }
  if (c.processes*c.threadsPerProcess > 8) throw new Error('too_many_analysis_threads');
  return Object.freeze({ ...c });
}

export class WorkloadPool {
  constructor(config) {
    this.config=validateWorkload(config);this.closed=false;this.next=0;this.jobs=new Map();this.order=[];this.normal=[];this.signal=[];
    this.processes=[];this.slots=[];
    this.metrics={ submitted:0,completed:0,rejected:0,failed:0,restarts:0,maxOutstanding:0,normalOutstanding:0,signalOutstanding:0 };
  }
  async start() {
    await Promise.all(Array.from({length:this.config.processes},(_,i)=>this.spawn(i,0)));
    return this;
  }
  spawn(index,restarts) {
    // No authority keys or instance capability are inherited by analysis processes.
    const env={ ...process.env };delete env.BARRIERS_TRUSTED_KEYS;
    const ipcConfig=channelConfig(),channel=secureChannel(ipcConfig,'parent');env.BARRIERS_IPC_SECURITY=JSON.stringify(ipcConfig);
    const child=fork(fileURLToPath(new URL('./analysis-process.js',import.meta.url)),[String(this.config.threadsPerProcess)],{env,stdio:['ignore','ignore','ignore','ipc']});
    const proc={child,channel,index,restarts,alive:true,ready:false};this.processes[index]=proc;
    for(let i=0;i<this.config.threadsPerProcess;i++)this.slots[index*this.config.threadsPerProcess+i]={proc,slot:i,job:null};
    return new Promise((resolve,reject)=>{
      let started=false;
      const timer=setTimeout(()=>{reject(new Error('analysis_start_timeout'));this.failProcess(proc,'analysis_unavailable');},5000);
      child.on('message',wire=>{
        if(this.processes[index]!==proc || !proc.alive)return;
        let m;try{m=channel.decode(wire);}catch{this.failProcess(proc,'analysis_transport_failure');return;}
        if(m.type==='ready') {started=true;clearTimeout(timer);proc.ready=true;resolve();this.dispatch();}
        if(m.type==='done') {
          const slot=this.slots[index*this.config.threadsPerProcess+m.slot];
          if(!slot || slot.proc!==proc || slot.job!==m.id)return;
          slot.job=null;this.finish(m.id,m.error?{error:'analysis_failed'}:{analysis:m.analysis});this.dispatch();
        }
      });
      child.on('error',()=>this.failProcess(proc,'analysis_unavailable'));
      child.on('exit',()=>{clearTimeout(timer);if(!started)reject(new Error('analysis_start_failure'));this.failProcess(proc,'analysis_unavailable');});
    });
  }
  failProcess(proc,error) {
    if(!proc.alive)return;proc.alive=false;proc.ready=false;
    const owned=this.slots.filter(s=>s.proc===proc);
    for(const slot of owned){if(slot.job!==null){const id=slot.job;slot.job=null;this.finish(id,{error});}}
    if(proc.child.connected)proc.child.kill();
    if(!this.closed && proc.restarts<this.config.maxRestarts){this.metrics.restarts++;this.spawn(proc.index,proc.restarts+1).catch(()=>{});}
    this.dispatch();
  }
  submit(request,{signal=false}={}) {
    if(this.closed)return Promise.resolve({error:'analysis_closed'});
    const category=signal?'signalOutstanding':'normalOutstanding';
    const bound=signal?this.config.reservedPending:this.config.maxPending;
    if(this.metrics[category]>=bound){this.metrics.rejected++;return Promise.resolve({error:'workload_overloaded'});}
    const id=++this.next;this.metrics.submitted++;this.metrics[category]++;
    const promise=new Promise(resolve=>{
      const job={id,request:structuredClone(request),category,resolve,done:false,result:null};
      job.timer=setTimeout(()=>{
        const slot=this.slots.find(s=>s.job===id);
        if(slot)this.failProcess(slot.proc,'analysis_timeout');
        else this.finish(id,{error:'analysis_timeout'});
      },this.config.taskTimeoutMs);
      this.jobs.set(id,job);this.order.push(id);(signal?this.signal:this.normal).push(id);
      this.metrics.maxOutstanding=Math.max(this.metrics.maxOutstanding,this.jobs.size);
    });
    this.dispatch();return promise;
  }
  dispatch() {
    if(this.closed)return;
    for(const slot of this.slots){
      if(!slot.proc.alive || !slot.proc.ready || slot.job!==null)continue;
      let id;
      while(this.signal.length || this.normal.length){
        const candidate=this.signal.length?this.signal.shift():this.normal.shift();
        if(this.jobs.has(candidate) && !this.jobs.get(candidate).done){id=candidate;break;}
      }
      if(id===undefined)continue;
      slot.job=id;slot.proc.child.send(slot.proc.channel.encode({type:'job',slot:slot.slot,id,request:this.jobs.get(id).request}),error=>{if(error)this.failProcess(slot.proc,'analysis_unavailable');});
    }
  }
  finish(id,result) {
    const job=this.jobs.get(id);if(!job || job.done)return;
    job.done=true;job.result=result;clearTimeout(job.timer);
    this.normal=this.normal.filter(n=>n!==id);this.signal=this.signal.filter(n=>n!==id);
    if(result.error)this.metrics.failed++;else this.metrics.completed++;
    // Deliver completions in admission order, regardless of worker finish order.
    while(this.order.length && this.jobs.get(this.order[0])?.done){
      const next=this.jobs.get(this.order.shift());this.jobs.delete(next.id);this.metrics[next.category]--;next.resolve(next.result);
    }
  }
  stats() {
    return {...this.metrics,outstanding:this.jobs.size,processes:this.config.processes,threadsPerProcess:this.config.threadsPerProcess,analysisThreads:this.config.processes*this.config.threadsPerProcess,availableLogicalProcessors:availableParallelism()};
  }
  async close() {
    this.closed=true;
    for(const id of [...this.order])this.finish(id,{error:'analysis_closed'});
    await Promise.all(this.processes.filter(p=>p.alive).map(p=>new Promise(resolve=>{p.child.once('exit',resolve);p.child.kill();})));
  }
}
