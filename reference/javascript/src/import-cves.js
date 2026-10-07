import { fileURLToPath } from 'node:url';
import { importCves } from './cve-library.js';
const ids=process.argv.slice(2);
console.log(JSON.stringify(await importCves(ids.length?ids:['CVE-2023-4966','CVE-2023-42793','CVE-2024-3094'],fileURLToPath(new URL('../knowledge/',import.meta.url))),null,2));
