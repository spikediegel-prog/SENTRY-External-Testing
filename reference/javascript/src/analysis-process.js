import { Worker } from 'node:worker_threads';
import { childChannel } from './secure-channel.js';
const channel=childChannel(),emit=message=>process.send?.(channel.encode(message));

const count = Number(process.argv[2]);
if (!Number.isInteger(count) || count < 1 || count > 4) throw new Error('invalid_thread_count');
const threads = Array.from({ length:count }, (_, slot) => {
  const worker = new Worker(new URL('./analysis-thread.js',import.meta.url));
  worker.on('message', result => emit({ type:'done',slot,...result }));
  worker.on('error', () => process.exit(1));
  return worker;
});
process.on('message', wire => {
  let message;try{message=channel.decode(wire);}catch{process.exit(1);return;}
  if (message.type === 'job' && threads[message.slot]) threads[message.slot].postMessage({ id:message.id,request:message.request });
});
process.on('disconnect', () => process.exit(0));
emit({ type:'ready' });
