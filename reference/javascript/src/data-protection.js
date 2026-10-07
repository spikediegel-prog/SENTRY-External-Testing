import { randomBytes,createCipheriv,createDecipheriv,hkdfSync } from 'node:crypto';
import { canonical,exact } from './protocol.js';

const LIMIT=24*1024*1024;
function derived(secret,context) {
  if(!(typeof secret==='string' && secret.length>0 || Buffer.isBuffer(secret) && secret.length>0))throw new Error('protection_key_required');
  return Buffer.from(hkdfSync('sha256',secret,Buffer.from('barriers-protection-v1'),Buffer.from(context),32));
}
export function sealData(value,secret,context) {
  if(typeof context!=='string' || context.length>200)throw new Error('protection_context');
  const plain=Buffer.from(JSON.stringify(value));if(plain.length>LIMIT)throw new Error('protected_data_bound');
  const nonce=randomBytes(12),cipher=createCipheriv('aes-256-gcm',derived(secret,context),nonce);
  const header={version:1,algorithm:'AES-256-GCM',context};
  cipher.setAAD(Buffer.from(canonical(header)));
  const ciphertext=Buffer.concat([cipher.update(plain),cipher.final()]);
  return {...header,nonce:nonce.toString('hex'),tag:cipher.getAuthTag().toString('hex'),ciphertext:ciphertext.toString('base64')};
}
export function openData(envelope,secret,context) {
  try {
    exact(envelope,['version','algorithm','context','nonce','tag','ciphertext']);
    if(envelope.version!==1 || envelope.algorithm!=='AES-256-GCM' || envelope.context!==context ||
      !/^[a-f0-9]{24}$/.test(envelope.nonce) || !/^[a-f0-9]{32}$/.test(envelope.tag) ||
      typeof envelope.ciphertext!=='string' || envelope.ciphertext.length>Math.ceil(LIMIT/3)*4)throw new Error('invalid_envelope');
    const ciphertext=Buffer.from(envelope.ciphertext,'base64');
    if(ciphertext.toString('base64')!==envelope.ciphertext)throw new Error('invalid_base64');
    const decipher=createDecipheriv('aes-256-gcm',derived(secret,context),Buffer.from(envelope.nonce,'hex'));
    decipher.setAAD(Buffer.from(canonical({version:1,algorithm:'AES-256-GCM',context})));
    decipher.setAuthTag(Buffer.from(envelope.tag,'hex'));
    const plain=Buffer.concat([decipher.update(ciphertext),decipher.final()]);
    return JSON.parse(plain.toString('utf8'));
  }catch {throw new Error('protected_data_authentication');}
}
