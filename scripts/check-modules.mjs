import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { readFile, readdir } from 'node:fs/promises';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const files = [];

async function walk(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && ['.git', 'node_modules', 'coverage', '.ctf', '.ctf-attachments', 'work'].includes(entry.name)) continue;
    const file = join(directory, entry.name);
    if (entry.isDirectory()) await walk(file);
    else if (entry.isFile() && /\.(?:js|mjs)$/u.test(entry.name)) files.push(file);
  }
}

await walk(root);
const failures = [];
for (const file of files) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (result.status !== 0) failures.push(`${file}\n${result.stderr || result.stdout || 'node --check failed'}`);
}

const FORBIDDEN_CORE_TARGETS = [
  /^dsh-adapter\//u,
  /^presets\//u,
  /^runner\//u,
  /^ctf-tools\.js$/u,
  /^extra-tools\.js$/u,
];

for (const file of files) {
  const rel = relative(root, file).replaceAll('\\', '/');
  const source = await readFile(file, 'utf8');
  const imports = /(?:\bfrom\s*|\bimport\s*\()\s*(['"])(\.{1,2}\/[^'"]+\.(?:js|mjs))\1/gu;
  for (const match of source.matchAll(imports)) {
    const target = fileURLToPath(new URL(match[2], pathToFileURL(file)));
    if (!existsSync(target)) {
      failures.push(`${rel}: unresolved local import ${match[2]}`);
      continue;
    }
    const targetRel = relative(root, target).replaceAll('\\', '/');
    if (rel.startsWith('core/') && FORBIDDEN_CORE_TARGETS.some(rule => rule.test(targetRel))) {
      failures.push(`${rel}: core/ must not import ${targetRel}`);
    }
    if (rel.startsWith('presets/copilot/') && targetRel.startsWith('presets/autonomous/')) {
      failures.push(`${rel}: presets/copilot/ must not import ${targetRel}`);
    }
    if (rel.startsWith('presets/autonomous/') && targetRel.startsWith('presets/copilot/')) {
      failures.push(`${rel}: presets/autonomous/ must not import ${targetRel}`);
    }
  }
  if (rel.startsWith('core/')) {
    const cordisAccess = /\bctx\.(?:tools|sandboxPolicy|workingDirectory)\b/u.exec(source);
    if (cordisAccess) {
      failures.push(`${rel}: core/ must not reference Cordis host interface (${cordisAccess[0]})`);
    }
  }
}

if (failures.length) {
  process.stderr.write(failures.join('\n\n') + '\n');
  process.exitCode = 1;
} else {
  process.stdout.write(`Syntax, local imports, and layering rules checked: ${files.length} JavaScript modules.\n`);
}
