import { readJournal } from './journal.js';
import { readFileSync,existsSync } from 'node:fs';
import { retrieveKey } from './key-vault.js';
if (!process.argv[2]) throw new Error('Usage: node src/read-evidence.js <evidence.jsonl>');
const key=existsSync(process.argv[2]+'.keyref')?retrieveKey(readFileSync(process.argv[2]+'.keyref','utf8')):null;
for (const row of readJournal(process.argv[2],key)) console.log(JSON.stringify(row.payload));
