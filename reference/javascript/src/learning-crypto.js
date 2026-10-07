import { generateKeyPairSync,sign as cryptoSign,verify as cryptoVerify } from 'node:crypto';
import { canonical } from './protocol.js';

export function teacherKeys() {
  const pair=generateKeyPairSync('ed25519');
  return {privateKey:pair.privateKey,publicKey:pair.publicKey.export({type:'spki',format:'pem'})};
}
export function seal(payload,privateKey,domain) {
  return {payload,signature:cryptoSign(null,Buffer.from(domain+'\n'+canonical(payload)),privateKey).toString('base64')};
}
export function verifySealed(envelope,publicKey,domain) {
  try {return cryptoVerify(null,Buffer.from(domain+'\n'+canonical(envelope.payload)),publicKey,Buffer.from(envelope.signature,'base64'));}catch{return false;}
}
