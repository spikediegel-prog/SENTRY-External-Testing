import { execFileSync } from 'node:child_process';
import { randomBytes,randomUUID } from 'node:crypto';
import { mkdirSync,readFileSync,writeFileSync,existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sealData,openData } from './data-protection.js';

// Windows user-bound key wrapping; private vault is outside the distributable outputs.
const vault=fileURLToPath(new URL('../../../.sentry-private/',import.meta.url));
let master;
function dpapi(value,operation) {
  if(process.platform!=='win32')throw new Error('windows_vault_required');
  const script="Add-Type -AssemblyName System.Security; $bytes=[Convert]::FromBase64String([Console]::In.ReadToEnd()); $result=[Security.Cryptography.ProtectedData]::"+operation+"($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser); [Console]::Out.Write([Convert]::ToBase64String($result))";
  return Buffer.from(execFileSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',script],
    {input:value.toString('base64'),encoding:'utf8',windowsHide:true,timeout:10000,maxBuffer:8192}).trim(),'base64');
}
function masterKey() {
  if(master)return master;
  mkdirSync(vault,{recursive:true,mode:0o700});
  const path=join(vault,'master.dpapi');
  if(!existsSync(path)){
    const fresh=randomBytes(32),wrapped=dpapi(fresh,'Protect');
    try{writeFileSync(path,wrapped,{flag:'wx',mode:0o600});}catch(error){if(error.code!=='EEXIST')throw error;}
    fresh.fill(0);
  }
  master=dpapi(readFileSync(path),'Unprotect');if(master.length!==32)throw new Error('invalid_vault_master');
  return master;
}
export function preserveKey(secret) {
  const keyRef=randomUUID();const envelope=sealData({secret},masterKey(),'vault-key/'+keyRef);
  writeFileSync(join(vault,keyRef+'.json'),JSON.stringify(envelope),{flag:'wx',mode:0o600});return keyRef;
}
export function retrieveKey(keyRef) {
  if(typeof keyRef!=='string' || !/^[a-f0-9-]{36}$/.test(keyRef))throw new Error('invalid_key_reference');
  return openData(JSON.parse(readFileSync(join(vault,keyRef+'.json'),'utf8')),masterKey(),'vault-key/'+keyRef).secret;
}
