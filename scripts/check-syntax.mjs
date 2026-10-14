import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

for (const file of ['src/index.js']) {
  const result = spawnSync(process.execPath, ['--check', file], { stdio: 'inherit' });
  if (result.status !== 0) process.exit(result.status || 1);
}

const app = readFileSync('index.html', 'utf8');
const published = readFileSync('public/index.html', 'utf8');
if (app !== published) {
  console.error('The public/index.html asset is out of sync with the canonical index.html.');
  process.exit(1);
}

const inlineScripts = [...app.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)];
let checkedScripts = 0;
for (const [index, match] of inlineScripts.entries()) {
  const script = match[1].trim();
  if (!script) continue;
  try {
    new vm.Script(script, { filename: 'index.html#inline-script-' + (index + 1) });
    checkedScripts += 1;
  } catch (error) {
    console.error('Inline script ' + (index + 1) + ' failed syntax validation:', error.message);
    process.exit(1);
  }
}

console.log('Worker syntax passed; ' + checkedScripts + ' inline scripts parsed; public asset is synced.');
