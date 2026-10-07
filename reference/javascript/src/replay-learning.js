import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { trainDetector } from './learning-pipeline.js';
import { verifySealed } from './learning-crypto.js';
import { readArtifact } from './protected-artifacts.js';

if(!process.argv[2])throw new Error('Usage: node src/replay-learning.js <runs/learning-directory>');
const directory=process.argv[2],key=readFileSync(join(directory,'teacher-public-key.pem'),'utf8');
const dataset=readArtifact(join(directory,'guardian-dataset.json'));
const original=readArtifact(join(directory,'shadow-model.json'));
if(!verifySealed(original,key,'shadow-model'))throw new Error('untrusted_shadow_model');
const replay=trainDetector(dataset,key,null);assert.deepEqual(replay.model.payload,original.payload);
console.log(JSON.stringify({classification:'Recorded',weightsReproduced:true,scope:'Integrity relative to bundled key; no external trust anchor or model promotion',evaluation:replay.report},null,2));
