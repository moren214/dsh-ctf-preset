import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const floors = new Map([
  ['attachment.js', { lines: 35, branches: 35, functions: 40 }],
  ['attachment-ranges.js', { lines: 55, branches: 50, functions: 70 }],
  ['ctf-progress.js', { lines: 55, branches: 55, functions: 35 }],
  ['ctf-status.js', { lines: 80, branches: 60, functions: 90 }],
  ['ctf-tools.js', { lines: 38, branches: 50, functions: 22 }],
  ['extra-tools.js', { lines: 33, branches: 55, functions: 25 }],
  ['pcap-stream.js', { lines: 65, branches: 40, functions: 55 }],
  ['platform-request.js', { lines: 90, branches: 75, functions: 80 }],
  ['pwn-pattern.js', { lines: 65, branches: 50, functions: 95 }],
]);

const child = spawn(process.execPath, [
  '--test', '--experimental-test-coverage',
  '--test-coverage-lines=40', '--test-coverage-functions=35',
  'test/*.test.js',
], { cwd: root, stdio: ['ignore', 'pipe', 'inherit'] });
let output = '';
child.stdout.on('data', chunk => {
  const text = chunk.toString();
  output += text;
  process.stdout.write(text);
});
const status = await new Promise((resolve, reject) => {
  child.once('error', reject);
  child.once('close', resolve);
});
if (status !== 0) process.exit(status ?? 1);

const report = new Map();
const row = /^\s*ℹ\s+([^|]+?)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|/gmu;
for (const match of output.matchAll(row)) {
  report.set(match[1].trim(), {
    lines: Number(match[2]), branches: Number(match[3]), functions: Number(match[4]),
  });
}

const failures = [];
for (const [file, minimum] of floors) {
  const actual = report.get(file);
  if (!actual) {
    failures.push(`${file}: coverage report row missing`);
    continue;
  }
  for (const dimension of ['lines', 'branches', 'functions']) {
    if (actual[dimension] < minimum[dimension]) {
      failures.push(`${file}: ${dimension} ${actual[dimension].toFixed(2)}% < ${minimum[dimension]}%`);
    }
  }
}

if (failures.length > 0) {
  process.stderr.write('\nCore module coverage floors failed:\n' + failures.map(item => `- ${item}`).join('\n') + '\n');
  process.exitCode = 1;
} else {
  process.stdout.write(`\nCore module coverage floors met (${floors.size} modules).\n`);
}
