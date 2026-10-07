import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Journal, readJournal } from '../src/journal.js';
import { digest, sign } from '../src/protocol.js';

function fixture() {
  const dir=mkdtempSync(join(tmpdir(),'barriers-delta-'));
  return new Journal(join(dir,'evidence.jsonl'),'test-journal-key');
}
const encoded=j=>readFileSync(j.path,'utf8').trim().split('\n').map(JSON.parse);

test('lossless deltas reduce repeated data and periodically checkpoint',()=>{
  const j=fixture(), expected=[];
  for(let i=0;i<70;i++) {
    const data={ preserved:{ sessions:{ alice:{route:'isolated',credential:false}},notes:'x'.repeat(3000) },state:i%2?'SAFE_MODE':'QUARANTINED' };
    expected.push(data);j.append({time:i,type:'self_containment',data});
  }
  assert.deepEqual(readJournal(j.path).map(r=>r.payload.data),expected);
  assert.equal(j.check().count,70);
  const rows=encoded(j);assert.equal(rows.filter(r=>r.payload.encoding==='full-v1').length,3);
  assert.equal(j.stats().deltaRecords,67);assert.ok(j.stats().bytesSaved>150000);
  assert.equal(j.stats().bytesWritten,Buffer.byteLength(readFileSync(j.path,'utf8')));
});

test('interleaved types, removed keys and special JSON keys reconstruct exactly',()=>{
  const j=fixture(), long='x'.repeat(2000);
  const first=JSON.parse('{"__proto__":{"safe":true},"keep":"'+long+'","removed":true}');
  const second=JSON.parse('{"__proto__":{"safe":false},"keep":"'+long+'","added":[1,2]}');
  j.append({time:0,type:'a',data:first});j.append({time:1,type:'b',data:{irrelevant:true}});j.append({time:2,type:'a',data:second});
  const rows=encoded(j);assert.equal(rows[2].payload.base,1);assert.deepEqual(rows[2].payload.unset,['removed']);
  assert.deepEqual(readJournal(j.path)[2].payload.data,second);assert.equal({}.safe,undefined);j.check();
});

test('tampered delta fails MAC verification',()=>{
  const j=fixture();j.append({time:0,type:'a',data:{blob:'x'.repeat(1000),count:1}});j.append({time:1,type:'a',data:{blob:'x'.repeat(1000),count:2}});
  const rows=encoded(j);rows[1].payload.set.count=999;
  writeFileSync(j.path,rows.map(JSON.stringify).join('\n')+'\n');assert.throws(()=>j.check(),/journal_integrity/);
});

test('missing baseline and truncated tail cannot pass integrity checks',()=>{
  const j=fixture();for(let i=0;i<3;i++)j.append({time:i,type:'a',data:{blob:'x'.repeat(1000),count:i}});
  const rows=encoded(j);
  writeFileSync(j.path,rows.slice(1).map(JSON.stringify).join('\n')+'\n');assert.throws(()=>j.check(),/journal_integrity/);assert.throws(()=>readJournal(j.path),/journal_delta_base/);
  writeFileSync(j.path,rows.slice(0,-1).map(JSON.stringify).join('\n')+'\n');assert.throws(()=>j.check(),/journal_truncation/);
});

test('even authenticated malformed delta references are rejected',()=>{
  const j=fixture();j.append({time:0,type:'a',data:{blob:'x'.repeat(1000),count:1}});
  const bad=sign(j.key,'journal',{n:2,prev:j.head,time:1,type:'a',encoding:'delta-v1',base:99,set:{count:2},unset:[]});
  writeFileSync(j.path,JSON.stringify(encoded(j)[0])+'\n'+JSON.stringify(bad)+'\n');j.count=2;j.head=digest(bad);
  assert.throws(()=>j.check(),/journal_delta_base/);
});

test('failed append never advances baseline, sequence or compression counters',()=>{
  const j=fixture();j.append({time:0,type:'a',data:{blob:'x'.repeat(1000),count:1}});
  const path=j.path, before=j.stats(), head=j.head;
  j.path=join(path,'missing','evidence.jsonl');assert.throws(()=>j.append({time:1,type:'a',data:{blob:'x'.repeat(1000),count:2}}));
  assert.deepEqual(j.stats(),before);assert.equal(j.head,head);assert.equal(j.bases.get('a').n,1);
  j.path=path;j.append({time:2,type:'a',data:{blob:'x'.repeat(1000),count:3}});assert.equal(readJournal(path)[1].payload.data.count,3);j.check();
});

test('legacy full records remain readable and bounded type eviction uses full records',()=>{
  const j=fixture();const legacy=sign(j.key,'journal',{n:1,prev:j.head,time:0,type:'legacy',data:{ok:true}});
  writeFileSync(j.path,JSON.stringify(legacy)+'\n');assert.deepEqual(readJournal(j.path)[0].payload.data,{ok:true});
  const fresh=fixture();for(let i=0;i<65;i++)fresh.append({time:i,type:'type-'+i,data:{blob:'x'.repeat(1000)}});
  fresh.append({time:66,type:'type-0',data:{blob:'x'.repeat(1000)}});
  assert.equal(fresh.bases.size,64);assert.equal(encoded(fresh).at(-1).payload.encoding,'full-v1');fresh.check();
});
