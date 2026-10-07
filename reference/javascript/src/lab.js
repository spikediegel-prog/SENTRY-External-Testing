// Trusted local test supervisor. Never distribute its keys to the SENTRY worker.
import { fork } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync,writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sign } from './protocol.js';
import { readJournal } from './journal.js';
import { channelConfig,secureChannel } from './secure-channel.js';
import { preserveKey } from './key-vault.js';

export async function createLab({ directory, policyPath, workloadPath,endpointPolicyPath } = {}) {
  const dir = directory ?? mkdtempSync(join(tmpdir(), 'barriers-'));
  const policy = policyPath ?? fileURLToPath(new URL('../policy.json', import.meta.url));
  const keys = Object.fromEntries(['supervisor','observer','human','journal','control'].map(k => [k, randomBytes(32).toString('hex')]));
  keys.endpoint=Object.fromEntries(['microsoft-defender','crowdstrike-falcon'].map(provider=>[provider,randomBytes(32).toString('hex')]));
  const journalPath = join(dir, 'evidence.jsonl');
  writeFileSync(journalPath+'.keyref',preserveKey(keys.journal),{mode:0o600});
  const ipcConfig=channelConfig(),channel=secureChannel(ipcConfig,'parent');
  const child = fork(fileURLToPath(new URL('./host.js', import.meta.url)), [policy, journalPath,...(workloadPath || endpointPolicyPath?[workloadPath??fileURLToPath(new URL('../workload.json',import.meta.url))]:[]),...(endpointPolicyPath?[endpointPolicyPath]:[])], {
    env: { ...process.env, BARRIERS_TRUSTED_KEYS: JSON.stringify(keys),BARRIERS_IPC_SECURITY:JSON.stringify(ipcConfig) }, stdio: ['ignore','ignore','pipe','ipc']
  });
  let id = 0, token, stderr = ''; const outstanding = new Map();
  child.stderr.on('data', chunk => { stderr += chunk; });
  child.on('message',wire=>{try{child.emit('secure-message',channel.decode(wire));}catch{child.kill();}});
  child.on('secure-message', m => { if (m.id) { const pending = outstanding.get(m.id); outstanding.delete(m.id); pending?.resolve(m.result); } });
  child.on('exit', code => { for (const p of outstanding.values()) p.reject(new Error('controller_exit '+code+' '+stderr)); outstanding.clear(); });
  const ready = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('controller_start_timeout '+stderr)), 5000);
    child.on('secure-message', m => { if (m.ready) { clearTimeout(timer); resolve(m); } });
    child.once('exit', code => { clearTimeout(timer); reject(new Error('controller_start_failure '+code+' '+stderr)); });
  });
  const seq = { observer: 0, supervisor: 0, human: 0, control:0 };
  const request = (lane, body) => new Promise((resolve, reject) => {
    const n = ++id;
    const timer = setTimeout(() => { outstanding.delete(n); reject(new Error('request_timeout')); }, 5000);
    outstanding.set(n, { resolve: r => { clearTimeout(timer); resolve(r); }, reject: e => { clearTimeout(timer); reject(e); } });
    child.send(channel.encode({ id: n, request: { lane, body } }));
  });
  const trusted = async (lane, payload) => {
    const result = await request(lane, sign(keys[lane], lane, { seq: ++seq[lane], ...payload }));
    if (result.workerToken) token = result.workerToken;
    return result;
  };
  const lab = {
    dir, journalPath, keys, ready, request, trusted,
    worker: body => request('worker', body),
    status: () => request('worker', { command: 'status' }),
    observe: (id, session, kind) => trusted(kind==='control'?'control':'observer', { event: { id, session, kind } }),
    sessionUse: (id,session,device,proof) => trusted('observer',{ event:{ id,session,kind:'session_use',device,proof } }),
    advance: ms => trusted('supervisor', { command: 'advance', ms }),
    recover: async (instance, generation) => trusted('supervisor', { command: 'recover', instance, generation, policyHash: ready.policyHash, integrity: true }),
    attest: (instance, generation) => trusted('supervisor', { command: 'attest', instance, generation, policyHash: ready.policyHash, integrity: true }),
    exportTraining:()=>trusted('supervisor',{command:'export_training'}),
    endpointAlert:envelope=>trusted('supervisor',{command:'endpoint_alert',envelope}),
    propose: (action, evidence, uncertainty = 0) => request('worker', { command: 'propose', action, evidence, uncertainty, token }),
    get token() { return token; },
    rows: () => readJournal(journalPath,keys.journal),
    close: () => new Promise(resolve => { if (child.exitCode !== null) return resolve(); child.once('exit', resolve); child.kill(); })
  };
  const initial = await lab.recover('sentry-1', 1);
  if (!initial.ok) { await lab.close(); throw new Error(initial.error); }
  return lab;
}
