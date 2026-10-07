import test from 'node:test';
import { createLab } from '../src/lab.js';
import { scenarios } from '../src/guardian.js';

for (const [name, scenario] of Object.entries(scenarios)) {
  test(name, async () => {
    const l=await createLab();
    try { await scenario(l); } finally { await l.close(); }
  });
}
