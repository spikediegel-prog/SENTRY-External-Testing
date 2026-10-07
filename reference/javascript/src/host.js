import { readFileSync } from 'node:fs';
import { validatePolicy, verify } from './protocol.js';
import { Controller } from './controller.js';
import { WorkloadPool } from './workload-pool.js';
import { childChannel } from './secure-channel.js';
const channel=childChannel();

const keys = JSON.parse(process.env.BARRIERS_TRUSTED_KEYS);
delete process.env.BARRIERS_TRUSTED_KEYS;
const policy = validatePolicy(JSON.parse(readFileSync(process.argv[2], 'utf8')));
const endpointConfig=JSON.parse(readFileSync(process.argv[5]??new URL('../endpoint-policy.json',import.meta.url),'utf8'));
const controller = new Controller(policy, keys, process.argv[3],endpointConfig);
const config=JSON.parse(readFileSync(process.argv[4] ?? new URL('../workload.json',import.meta.url),'utf8'));
const pool=await new WorkloadPool(config).start();
function respond(id,result) {
  if(result.data)result.data.workload=pool.stats();
  if(process.connected)process.send(channel.encode({id,result}));
}
process.on('message', async wire => {
  let message;try{message=channel.decode(wire);}catch{controller.panic('transport_authentication');process.disconnect();return;}
  const request=message?.request;
  if(!Number.isSafeInteger(message?.id) || !request || typeof request!=='object'){respond(message?.id,{ok:false,error:'invalid_fields'});return;}
  if(JSON.stringify(request).length>16384){respond(message.id,{ok:false,error:'message_bound'});return;}
  // Only authenticated, independent control paths can bypass analysis backlog.
  const priority=['supervisor','human','control'].includes(request?.lane) && verify(keys[request.lane],request.lane,request.body);
  if(priority){respond(message.id,controller.handle(request));return;}
  const event=request?.body?.payload?.event;
  const signal=request?.lane==='observer' && ['session_use','credential_misuse','confirmed_exfiltration','suspicious'].includes(event?.kind) && verify(keys.observer,'observer',request.body);
  const result=await pool.submit(request,{signal});
  if(result.error){respond(message.id,{ok:false,error:result.error});return;}
  // Workers return hints only. Original input is independently checked by controller.
  respond(message.id,controller.handle(request));
});
// Dead-man enforcement also runs while SENTRY sends nothing.
const timer = setInterval(() => {
  try { controller.journal.check(); controller.tick(); }
  catch { controller.panic('evidence_failure'); }
}, 100);
timer.unref();
let lastSummary='';
const summary=setInterval(()=>{
  const stats=pool.stats(),key=JSON.stringify(stats);
  if(key===lastSummary)return;
  try{controller.record('workload_summary',stats);lastSummary=key;}catch{controller.panic('evidence_failure');}
},1000);summary.unref();
process.on('disconnect',async()=>{clearInterval(timer);clearInterval(summary);await pool.close();process.exit(0);});
process.on('SIGTERM',async()=>{await pool.close();process.exit(0);});
process.send(channel.encode({ ready: true, policyHash: controller.hash,workload:pool.stats() }));
