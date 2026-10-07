import { randomBytes } from 'node:crypto';
import { sealData,openData } from './data-protection.js';
import { exact } from './protocol.js';

export const channelConfig=()=>({key:randomBytes(32).toString('hex'),session:randomBytes(16).toString('hex')});
export function secureChannel(config,side) {
  exact(config,['key','session']);
  if(!/^[a-f0-9]{64}$/.test(config.key) || !/^[a-f0-9]{32}$/.test(config.session) || !['parent','child'].includes(side))throw new Error('invalid_channel_config');
  const outgoing=side==='parent'?'parent-to-child':'child-to-parent';
  const incoming=side==='parent'?'child-to-parent':'parent-to-child';
  let sent=0,received=0,closed=false;
  return {
    encode(message){if(closed || sent>=1000000)throw new Error('channel_closed');return sealData({sequence:++sent,message},config.key,config.session+'/'+outgoing);},
    decode(envelope){
      if(closed)throw new Error('channel_closed');
      try {const payload=openData(envelope,config.key,config.session+'/'+incoming);exact(payload,['sequence','message']);
        if(payload.sequence!==received+1 || received>=1000000)throw new Error('channel_replay_or_order');
        received++;return payload.message;
      }catch {closed=true;throw new Error('channel_authentication_or_replay');}
    }
  };
}
export function childChannel() {
  const config=JSON.parse(process.env.BARRIERS_IPC_SECURITY);delete process.env.BARRIERS_IPC_SECURITY;
  return secureChannel(config,'child');
}
