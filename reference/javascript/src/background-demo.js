import { readFileSync,writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createBackgroundLearner } from './background-learning.js';
import { readArtifact,writeProtectedArtifact } from './protected-artifacts.js';
const directory=process.argv[2];
if(!directory)throw new Error('Usage: node src/background-demo.js <saved-learning-directory>');
const runner=createBackgroundLearner();
const result=await runner.run(readArtifact(join(directory,'guardian-dataset.json')),
  readFileSync(join(directory,'teacher-public-key.pem'),'utf8'));
writeProtectedArtifact(new URL('../background-learning-report.json',import.meta.url),result);
console.log(JSON.stringify({classification:result.classification,mode:result.mode,activeModelChanged:false}));
