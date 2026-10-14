import { mkdir, copyFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const publicDir = resolve(root, 'public');
await mkdir(publicDir, { recursive: true });
await copyFile(resolve(root, 'index.html'), resolve(publicDir, 'index.html'));
console.log('Prepared public/index.html for Cloudflare Assets.');
