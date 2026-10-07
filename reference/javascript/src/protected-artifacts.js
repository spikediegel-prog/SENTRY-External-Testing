import { randomBytes } from 'node:crypto';
import { readFileSync,writeFileSync } from 'node:fs';
import { sealData,openData } from './data-protection.js';
import { preserveKey,retrieveKey } from './key-vault.js';
import { exact } from './protocol.js';

export function writeProtectedArtifact(path,value) {
  const key=randomBytes(32).toString('hex'),keyRef=preserveKey(key);
  writeFileSync(path,JSON.stringify({format:'protected-artifact-v1',keyRef,envelope:sealData(value,key,'artifact/'+keyRef)})+'\n',{mode:0o600});
}
export function readArtifact(path) {
  const bytes=readFileSync(path);if(bytes.length>40*1024*1024)throw new Error('artifact_size_bound');
  const value=JSON.parse(bytes.toString('utf8'));
  if(value?.format!=='protected-artifact-v1')return value; // Explicit legacy simulation compatibility.
  exact(value,['format','keyRef','envelope']);
  return openData(value.envelope,retrieveKey(value.keyRef),'artifact/'+value.keyRef);
}
