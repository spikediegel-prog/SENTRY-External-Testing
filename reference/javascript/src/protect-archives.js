import { readdirSync,readFileSync,writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { writeProtectedArtifact } from './protected-artifacts.js';

const root=fileURLToPath(new URL('../runs/',import.meta.url)),receipts=[];
function protect(directory){
  for(const entry of readdirSync(directory,{withFileTypes:true})){
    const path=join(directory,entry.name);if(entry.isDirectory()){protect(path);continue;}
    if(!entry.isFile() || !/\.(json|jsonl|emergency)$/.test(entry.name))continue;
    const bytes=readFileSync(path),text=bytes.toString('utf8');
    if(text.startsWith('{"format":"protected-artifact-v1"') || text.startsWith('{"version":1,"algorithm":"AES-256-GCM"'))continue;
    const value=entry.name.endsWith('.json')?JSON.parse(text):text;
    writeProtectedArtifact(path,value);
    receipts.push({path,originalSha256:createHash('sha256').update(bytes).digest('hex'),protectedSha256:createHash('sha256').update(readFileSync(path)).digest('hex'),classification:'Recorded'});
  }
}
protect(root);
writeFileSync(new URL('../archive-protection-report.json',import.meta.url),JSON.stringify({classification:'Recorded',scope:'Encryption of saved local simulation artifacts; no retroactive source authentication',receipts},null,2)+'\n');
console.log(JSON.stringify({protectedFiles:receipts.length,classification:'Recorded'}));
