import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { channelConfig,secureChannel } from './secure-channel.js';

// One bounded job per runner. No controller transport, execution token or teacher private key.
export function createBackgroundLearner() {
  let active=null;
  return {
    run(envelope,publicKey) {
      if(active)throw new Error('background_learning_busy');
      if(typeof publicKey!=='string' || publicKey.length>8192 || JSON.stringify(envelope).length>16*1024*1024)throw new Error('background_input_bound');
      const ipcConfig=channelConfig(),channel=secureChannel(ipcConfig,'parent');
      const child=fork(fileURLToPath(new URL('./learning-host.js',import.meta.url)),[],{
        env:{BARRIERS_IPC_SECURITY:JSON.stringify(ipcConfig)},execArgv:['--max-old-space-size=128'],stdio:['ignore','ignore','pipe','ipc']});
      let diagnostic='';child.stderr.on('data',chunk=>{diagnostic=(diagnostic+chunk.toString()).slice(-4096);});
      active=child;
      return new Promise((resolve,reject)=>{
        let settled=false;
        const finish=(error,result)=>{if(settled)return;settled=true;clearTimeout(timer);active=null;child.kill();error?reject(error):resolve(result);};
        const timer=setTimeout(()=>finish(new Error('background_learning_timeout')),30000);
        child.once('error',e=>finish(e));
        child.once('exit',(code,signal)=>finish(new Error('background_learning_stopped '+code+' '+(signal??'')+' '+diagnostic)));
        child.once('message',wire=>{try{const m=channel.decode(wire);m.ok?finish(null,m.result):finish(new Error(m.error));}catch(e){finish(e);}});
        child.send(channel.encode({envelope,publicKey}));
      });
    },
    stop(){active?.kill();}
  };
}
