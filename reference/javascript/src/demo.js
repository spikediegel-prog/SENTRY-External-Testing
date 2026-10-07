import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createLab } from './lab.js';
import { createSentryWorker } from './worker-client.js';

const dir=fileURLToPath(new URL('../runs/demo-'+Date.now()+'/',import.meta.url));
mkdirSync(dir,{ recursive:true });
const l=await createLab({ directory:dir });
let sentry=await createSentryWorker(l);
try {
  for (let i=0;i<100;i++) {
    await l.observe('noise-'+i,'session-bob','junk');
    if (i===50) {
      const detected=await l.sessionUse('compromise','session-alice','unexpected-attacker-device','missing');
      await sentry.review(detected.observation);
    }
  }
  await l.observe('health','control-health','control');
  await l.sessionUse('legit','session-bob','bound-device-session-bob','valid');
  const duringWindow=(await l.status()).data;
  await l.advance(5001);
  const contained=(await l.status()).data;
  await l.advance(30001);
  const selfContained=(await l.status()).data;
  const denied=await l.propose('CONTAIN','compromise');
  await l.recover('sentry-clean-2',2);
  const oldWorkerDenied=await sentry.review({ id:'compromise',kind:'credential_misuse' });
  await sentry.close();
  sentry=await createSentryWorker(l);
  const cleanWorkerResult=await sentry.review({ id:'compromise',kind:'credential_misuse' });
  const recovered=(await l.status()).data;
  const report={ classification:'Recorded', scope:'simulated credential/session compromise with noise', duringWindow,contained,selfContained,denied,oldWorkerDenied,cleanWorkerResult,recovered,evidence:l.journalPath };
  writeFileSync(new URL('../demo-report.json',import.meta.url),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify(report,null,2));
} finally { await sentry.close(); await l.close(); }
