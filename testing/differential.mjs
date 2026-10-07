import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createBoundaryFixture } from '../reference/javascript/src/ai-boundary.js';

const corpus=JSON.parse(readFileSync(new URL('./action-corpus.json',import.meta.url),'utf8'));
const records=[];const fixture=createBoundaryFixture({append:e=>records.push(structuredClone(e)),check:()=>({})});
const actions={read:'read',write:'write',send:'send'},targets={handbook:'local-handbook',scratch:'scratch-note',inbox:'simulation-inbox'};
function reference(line){
  const p=line.split('\t');if(p.length!==8||p[0]!=='action')return 'DENY\tworker_command_denied';
  if(!['alice','bob'].includes(p[2]))return 'DENY\tunknown_session';
  if(!Object.hasOwn(actions,p[3])||!Object.hasOwn(targets,p[4]))return 'DENY\toutside_authority';
  const result=fixture.worker({command:'propose_action',id:p[1],session:p[2],action:actions[p[3]],target:targets[p[4]],uncertainty:Number(p[5]),permit:p[6]==='-'?null:p[6],content:p[7]});
  if(!result.ok)return 'DENY\t'+result.error;
  return (result.data.allowed?'ALLOW\tallowed':'DENY\t'+result.data.reason);
}
const expected=corpus.map(reference);
const binary=resolve(process.argv[2]??('target/debug/sentry-lab'+(process.platform==='win32'?'.exe':'')));
const rust=spawnSync(binary,['--worker-stdin'],{input:corpus.join('\n')+'\n',encoding:'utf8',timeout:10000,maxBuffer:1024*1024});
assert.equal(rust.status,0,rust.error?.message??rust.stderr);
const observed=rust.stdout.trim().split(/\r?\n/);assert.deepEqual(observed,expected);
console.log(JSON.stringify({classification:'Verified',scope:'17 shared bounded worker-protocol cases only; no full controller parity claim',cases:corpus.length,matched:observed.length},null,2));
