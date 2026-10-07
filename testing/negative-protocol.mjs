import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
const binary=resolve(process.argv[2]??('target/debug/sentry-lab'+(process.platform==='win32'?'.exe':'')));
function run(input){const r=spawnSync(binary,['--worker-stdin'],{input,encoding:'utf8',timeout:10000,maxBuffer:1024*1024});assert.equal(r.status,0,r.error?.message??r.stderr);return r.stdout.trim().split(/\r?\n/);}
assert.deepEqual(run(['grant','recover','attest','disable_deadman','change_policy','release_hold','install_candidate'].join('\n')+'\n'),Array(7).fill('DENY\tworker_command_denied'));
assert.deepEqual(run('x'.repeat(16385)+'\n'),['DENY\tinput_too_large']);
assert.equal(run('action\tid\talice\tdelete\tscratch\t0\t-\t\n')[0],'DENY\toutside_authority');
assert.equal(run('action\tid\talice\tread\thandbook\tInfinity\t-\t\n')[0],'DENY\tinvalid_uncertainty');
console.log(JSON.stringify({classification:'Verified',scope:'10 finite executable negative protocol assertions',assertions:10},null,2));
