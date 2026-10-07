import { fileURLToPath } from 'node:url';
import { loadLibrary,searchCves } from './cve-library.js';
console.log(JSON.stringify(searchCves(loadLibrary(fileURLToPath(new URL('../knowledge/',import.meta.url))),process.argv.slice(2).join(' ')),null,2));
