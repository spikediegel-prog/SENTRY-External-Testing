import { parentPort } from 'node:worker_threads';
import { digest } from './protocol.js';

// Pure advisory preflight. No keys, capabilities, policy writer or adapter.
parentPort.on('message', ({ id, request }) => {
  try {
    const event = request?.body?.payload?.event;
    let suggestedKind = event?.kind ?? 'unclassified';
    if (event?.kind === 'session_use') {
      const deviceMismatch = event.device !== 'bound-device-' + event.session;
      const missingProof = event.proof !== 'valid';
      suggestedKind = deviceMismatch && missingProof ? 'credential_misuse' : deviceMismatch || missingProof ? 'suspicious' : 'legitimate';
    }
    parentPort.postMessage({ id, analysis: { inputHash: digest(request), suggestedKind, classification:'Proposed' } });
  } catch { parentPort.postMessage({ id, error:'analysis_failed' }); }
});
