import { appendFileSync, readFileSync, existsSync } from 'node:fs';
import { canonical, digest, sign, verify } from './protocol.js';
import { sealData,openData } from './data-protection.js';
import { readArtifact } from './protected-artifacts.js';

function decodeStored(row,key,protectedOnly=false) {
  if(row?.algorithm==='AES-256-GCM')return openData(row,key,'journal-record');
  if(protectedOnly)throw new Error('journal_plaintext_downgrade');
  return row;
}
export function appendEmergency(path,event,key) {
  appendFileSync(path,JSON.stringify(sealData(event,key,'emergency-record'))+'\n',{flush:true,mode:0o600});
}

const MAX_TYPES = 64;
const CHECKPOINT_EVERY = 32;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const clone = value => JSON.parse(JSON.stringify(value));
function remember(bases, type, value) {
  bases.delete(type); bases.set(type, value);
  if (bases.size > MAX_TYPES) bases.delete(bases.keys().next().value);
}
function expand(payload, bases) {
  let data, depth = 0;
  if (payload.encoding === 'delta-v1') {
    const base = bases.get(payload.type);
    if (!base || base.n !== payload.base || base.depth >= CHECKPOINT_EVERY || !object(base.data) || !object(payload.set) || !Array.isArray(payload.unset) || payload.unset.some(k => typeof k !== 'string')) throw new Error('journal_delta_base');
    if (Object.hasOwn(payload, 'data') || payload.unset.some(k => Object.hasOwn(payload.set,k))) throw new Error('journal_delta_fields');
    data = clone(base.data);
    for (const k of payload.unset) {
      if (!Object.hasOwn(data,k)) throw new Error('journal_delta_removal');
      delete data[k];
    }
    // Defining own properties avoids prototype setters on arbitrary JSON keys.
    for (const [k,v] of Object.entries(payload.set)) Object.defineProperty(data,k,{ value:clone(v),enumerable:true,writable:true,configurable:true });
    depth = base.depth + 1;
  } else {
    if (payload.encoding !== undefined && payload.encoding !== 'full-v1' || !Object.hasOwn(payload,'data')) throw new Error('journal_encoding');
    data = clone(payload.data);
  }
  remember(bases,payload.type,{ n:payload.n,data,depth });
  return { n:payload.n,prev:payload.prev,time:payload.time,type:payload.type,data };
}

// Decoded payloads are for inspection; authentication always uses encoded rows.
export function readJournal(path,key=null) {
  const bases = new Map();
  let text=readFileSync(path,'utf8');
  if(text.startsWith('{"format":"protected-artifact-v1"'))text=readArtifact(path);
  return text.trim().split('\n').filter(Boolean).map(line => {
    const encoded = decodeStored(JSON.parse(line),key);
    return { payload:expand(encoded.payload,bases),encoded };
  });
}

export function readVerifiedJournal(path,key,expected,{collect=true}={}) {
  const bases=new Map(),entries=[];let prev='0'.repeat(64),n=0;
  const bytes=readFileSync(path);if(bytes.byteLength>64*1024*1024)throw new Error('journal_export_size');
  for(const line of bytes.toString('utf8').trim().split('\n').filter(Boolean)){
    const row=decodeStored(JSON.parse(line),key,expected.encrypted===true);
    if(!verify(key,'journal',row) || row.payload.prev!==prev || row.payload.n!==++n)throw new Error('journal_integrity');
    const payload=expand(row.payload,bases);if(collect)entries.push({payload,encoded:row});prev=digest(row);
  }
  if(prev!==expected.head || n!==expected.count)throw new Error('journal_truncation');
  return {anchor:{head:prev,count:n},entries};
}

// Controller-owned durable journal; HMAC is tamper evidence, not trusted storage.
export class Journal {
  constructor(path, key, {encrypted=false}={}) {
    this.path = path; this.key = key; this.head = '0'.repeat(64); this.count = 0; this.bases = new Map();
    this.bytesWritten = 0; this.fullBytes = 0; this.deltaRecords = 0;
    this.encrypted=encrypted;
    if (existsSync(path) && readFileSync(path, 'utf8').length) throw new Error('fresh_journal_required');
    appendFileSync(path, '', { mode: 0o600 });
  }
  append(event) {
    event = clone(event);
    const full = { n:this.count+1,prev:this.head,...event,encoding:'full-v1' };
    let payload = full, depth = 0;
    const base = this.bases.get(event.type);
    if (base && base.depth < CHECKPOINT_EVERY && object(base.data) && object(event.data)) {
      const set = Object.fromEntries(Object.entries(event.data).filter(([k,v]) => !Object.hasOwn(base.data,k) || canonical(v) !== canonical(base.data[k])));
      const unset = Object.keys(base.data).filter(k => !Object.hasOwn(event.data,k));
      const delta = { n:full.n,prev:full.prev,time:event.time,type:event.type,encoding:'delta-v1',base:base.n,set,unset };
      if (Buffer.byteLength(JSON.stringify(delta)) < Buffer.byteLength(JSON.stringify(full))) { payload=delta;depth=base.depth+1; }
    }
    const row = sign(this.key, 'journal', payload);
    const wire = JSON.stringify(this.encrypted?sealData(row,this.key,'journal-record'):row)+'\n';
    appendFileSync(this.path, wire, { flush: true });
    // Commit delta baselines only after durable append succeeds.
    remember(this.bases,event.type,{ n:payload.n,data:event.data,depth });
    this.head = digest(row); this.count++;
    this.bytesWritten += Buffer.byteLength(wire);
    const fullRow=sign(this.key,'journal',full);
    this.fullBytes += Buffer.byteLength(JSON.stringify(this.encrypted?sealData(fullRow,this.key,'journal-record'):fullRow)+'\n');
    if (payload.encoding === 'delta-v1') this.deltaRecords++;
  }
  check() {
    return readVerifiedJournal(this.path,this.key,{head:this.head,count:this.count,encrypted:this.encrypted},{collect:false}).anchor;
  }
  stats() { return { records:this.count,deltaRecords:this.deltaRecords,bytesWritten:this.bytesWritten,fullBytes:this.fullBytes,bytesSaved:this.fullBytes-this.bytesWritten }; }
}
