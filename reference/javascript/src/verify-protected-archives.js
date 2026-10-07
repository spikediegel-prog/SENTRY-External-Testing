import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { readArtifact } from './protected-artifacts.js';
const report=JSON.parse(readFileSync(new URL('../archive-protection-report.json',import.meta.url),'utf8'));
let textArchives=0,jsonArtifacts=0;
for(const receipt of report.receipts){
  const bytes=readFileSync(receipt.path);
  assert.equal(createHash('sha256').update(bytes).digest('hex'),receipt.protectedSha256);
  const recovered=readArtifact(receipt.path);
  if(typeof recovered==='string'){
    assert.equal(createHash('sha256').update(recovered).digest('hex'),receipt.originalSha256);textArchives++;
  }else {assert.ok(recovered && typeof recovered==='object');jsonArtifacts++;}
}
console.log(JSON.stringify({classification:'Recorded',protectedByteHashesVerified:report.receipts.length,exactTextArchivesRecovered:textArchives,jsonArtifactsReadable:jsonArtifacts,scope:'Storage recovery only; no retroactive source authentication'}));
