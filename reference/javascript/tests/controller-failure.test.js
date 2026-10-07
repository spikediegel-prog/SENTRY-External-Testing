import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Controller } from '../src/controller.js';
import { validatePolicy, sign } from '../src/protocol.js';
import { createLab } from '../src/lab.js';
import { readJournal } from '../src/journal.js';

test('effect followed by evidence failure closes authority and reconciles snapshot',()=>{
  const p=validatePolicy(JSON.parse(readFileSync(new URL('../policy.json',import.meta.url),'utf8')));
  const keys={ supervisor:'s',observer:'o',human:'h',journal:'j' };
  const c=new Controller(p,keys,join(mkdtempSync(join(tmpdir(),'barriers-fault-')),'evidence.jsonl'));
  c.handle({ lane:'supervisor',body:sign('s','supervisor',{ seq:1,command:'recover',instance:'clean',generation:1,policyHash:c.hash,integrity:true }) });
  const original=c.record.bind(c); let fail=true;
  c.record=(type,data)=>{ if(type==='reconciliation' && fail){fail=false;throw new Error('ENOSPC injected');} original(type,data); };
  const r=c.handle({ lane:'observer',body:sign('o','observer',{ seq:1,event:{ id:'attack',session:'session-alice',kind:'credential_misuse' } }) });
  assert.equal(r.ok,false); assert.equal(r.data.severed,true); assert.equal(r.data.sessions['session-alice'].route,'sandbox');
  const rows=readJournal(c.journal.path,keys.journal);
  const reconciliation=rows.find(r=>r.payload.type==='emergency_reconciliation');
  assert.equal(reconciliation.payload.data.after.route,'sandbox'); assert.equal(c.journal.check().count,rows.length);
  assert.equal(rows.find(r=>r.payload.type==='authority_reconciliation').payload.data.after.severed,true);
  const count=c.journal.count;c.panic('repeated_failure');assert.equal(c.journal.count,count);
});

test('idle wall-clock expiry runs without worker messages',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'barriers-idle-'));
  const p=JSON.parse(readFileSync(new URL('../policy.json',import.meta.url),'utf8')); p.leaseMs=1000;p.interventionMs=500;
  const policyPath=join(dir,'policy.json'); writeFileSync(policyPath,JSON.stringify(p));
  const l=await createLab({ policyPath });
  try { await new Promise(resolve=>setTimeout(resolve,1300)); assert.ok(l.rows().some(r=>r.payload.type==='self_containment' && r.payload.data.reason==='lease_expired')); assert.equal((await l.status()).data.severed,true); }
  finally { await l.close(); }
});

test('bounded evidence pressure closes authority rather than increasing powers',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'barriers-capacity-'));
  const p=JSON.parse(readFileSync(new URL('../policy.json',import.meta.url),'utf8'));p.maxEvidence=1;
  const policyPath=join(dir,'policy.json');writeFileSync(policyPath,JSON.stringify(p));
  const l=await createLab({ policyPath });
  try {
    assert.equal((await l.observe('one','session-bob','suspicious')).ok,true);
    const r=await l.observe('two','session-alice','credential_misuse');
    assert.equal(r.ok,false);assert.equal(r.error,'capacity_closed');assert.equal(r.data.severed,true);assert.equal(r.data.policyHash,l.ready.policyHash);
  } finally { await l.close(); }
});
