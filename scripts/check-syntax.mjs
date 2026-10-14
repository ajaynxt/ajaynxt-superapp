import { spawnSync } from 'node:child_process';

const result = spawnSync(process.execPath, ['--check', 'src/index.js'], { stdio: 'inherit' });
if (result.status !== 0) process.exit(result.status || 1);
console.log('Cloudflare Worker syntax check passed.');
