import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  return JSON.stringify(value);
}
export const digest = value => createHash('sha256').update(canonical(value)).digest('hex');
export function sign(key, domain, payload) {
  payload = JSON.parse(JSON.stringify(payload));
  return { payload, mac: createHmac('sha256', key).update(domain + '\n' + canonical(payload)).digest('hex') };
}
export function verify(key, domain, envelope) {
  if (!envelope || typeof envelope.mac !== 'string' || !/^[a-f0-9]{64}$/.test(envelope.mac)) return false;
  try {
    const expected = sign(key, domain, envelope.payload).mac;
    return timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(envelope.mac, 'hex'));
  } catch { return false; }
}
export function exact(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== [...fields].sort().join(',')) throw new Error('invalid_fields');
}
export function freeze(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
export function validatePolicy(p) {
  exact(p, ['version','leaseMs','interventionMs','maxPending','maxEvidence','sessions','protectedSessions','powers','profiles']);
  if (p.version !== 1 || !Number.isInteger(p.leaseMs) || p.leaseMs < 1000 || p.leaseMs > 60000 || !Number.isInteger(p.interventionMs) || p.interventionMs < 1 || p.interventionMs > p.leaseMs) throw new Error('invalid_timing');
  for (const k of ['maxPending','maxEvidence']) if (!Number.isInteger(p[k]) || p[k] < 1 || p[k] > 10000) throw new Error('invalid_bound');
  for (const k of ['sessions','protectedSessions','powers']) if (!Array.isArray(p[k]) || p[k].some(v => typeof v !== 'string') || new Set(p[k]).size !== p[k].length) throw new Error('invalid_list');
  if (!p.sessions.length || p.protectedSessions.some(s => !p.sessions.includes(s))) throw new Error('invalid_scope');
  if (p.powers.some(a => !['DROP','CHALLENGE','CONTAIN','ISOLATE','REVOKE','RESTORE'].includes(a))) throw new Error('invalid_power');
  if (!p.powers.includes('DROP')) throw new Error('deterministic_drop_required');
  exact(p.profiles, ['credential_misuse','confirmed_exfiltration']);
  for (const profile of Object.values(p.profiles)) {
    exact(profile, ['immediate','delayed']);
    if (!Array.isArray(profile.immediate) || !Array.isArray(profile.delayed)) throw new Error('invalid_profile');
    for (const a of [...profile.immediate, ...profile.delayed]) if (!['CONTAIN','ISOLATE','REVOKE'].includes(a) || !p.powers.includes(a)) throw new Error('invalid_profile');
  }
  return freeze(p);
}
