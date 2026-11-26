import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path, { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createStateStore, createArtifactStore, ToolError, describeToolError } from '../core/index.js';
import { httpRequest } from '../http-client.js';
import { apply } from '../ctf-tools.js';

const ROOT = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const HASH_RE = /^[a-f0-9]{64}$/u;

async function listRuntimeJsFiles(baseDir, rel = '') {
  const full = rel ? join(baseDir, rel) : baseDir;
  const entries = await readdir(full, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const childRel = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      if (['node_modules', '.git', 'test', 'scripts', 'coverage', '.ctf', 'skills', 'docker', 'locale'].includes(entry.name)) continue;
      files.push(...await listRuntimeJsFiles(baseDir, childRel));
    } else if (entry.isFile() && entry.name.endsWith('.js')) {
      files.push(childRel);
    }
  }
  return files;
}

function realCtx(cwd, { writable = true } = {}) {
  const tools = new Map();
  const base = cwd.replaceAll('\\', '/').replace(/\/$/u, '');
  const resolveTarget = (name, options = {}) => {
    const clean = name.replaceAll('\\', '/').replace(/\/$/u, '');
    if (options.cwd === undefined && clean === base) return { targetKey: base, displayPath: base };
    const root = (options.cwd ?? cwd).replaceAll('\\', '/').replace(/\/$/u, '');
    const targetKey = `${root}/${clean}`;
    return { targetKey, displayPath: name };
  };
  const fsSyncPromise = import('node:fs/promises');
  const ctx = {
    tools: { register(tool) { tools.set(tool.name, tool); } },
    effect() {},
    emit() {},
    workingDirectory: { async ensure() { return cwd; } },
    sandboxPolicy: { resolve() { return { mode: writable ? 'workspace-write' : 'read-only' }; } },
    fs: {
      async resolve(name, options) { return resolveTarget(name, options); },
      contains(parent, child) {
        const prefix = parent.targetKey.replace(/\/$/u, '');
        return child.targetKey === prefix || child.targetKey.startsWith(prefix + '/');
      },
      async lstat(name, options) {
        const key = resolveTarget(name, options).targetKey;
        const rel = key.startsWith(base + '/') ? key.slice(base.length + 1) : name;
        const { lstat } = await fsSyncPromise;
        try {
          const info = await lstat(join(cwd, rel));
          return { type: info.isDirectory() ? 'directory' : info.isFile() ? 'file' : 'other' };
        } catch {
          return undefined;
        }
      },
      async stat(target) {
        const rel = target.targetKey.slice(base.length + 1);
        const { stat } = await fsSyncPromise;
        try {
          const info = await stat(join(cwd, rel));
          return { type: info.isDirectory() ? 'directory' : 'file', size: info.size, version: String(info.mtimeMs) };
        } catch {
          return null;
        }
      },
      async readBytes(target) {
        const rel = target.targetKey.slice(base.length + 1);
        return readFile(join(cwd, rel));
      },
      async writeText(target, text) {
        const rel = target.targetKey.slice(base.length + 1);
        const abs = join(cwd, rel);
        const { mkdir } = await fsSyncPromise;
        await mkdir(path.dirname(abs), { recursive: true });
        await writeFile(abs, text, 'utf8');
        return { version: String(Date.now()) };
      },
    },
  };
  apply(ctx, { enableExtendedAudit: true });
  return {
    tools,
    execution: { signal: new AbortController().signal, agent: { session: { id: 'core-contracts-test', header: { cwd } } } },
  };
}

test('zero bare throw/new Error across runtime JS modules and zero writeFileSync in extra-tools.js', async () => {
  const files = await listRuntimeJsFiles(ROOT);
  assert.ok(files.length >= 60);
  const offenders = [];
  for (const rel of files) {
    const src = await readFile(join(ROOT, rel), 'utf8');
    if (/\bnew\s+(?:Error|TypeError|RangeError)\s*\(/u.test(src)) {
      offenders.push(rel);
    }
  }
  assert.deepEqual(offenders, [], `Found bare Error construction in: ${offenders.join(', ')}`);

  const extraSrc = await readFile(join(ROOT, 'extra-tools.js'), 'utf8');
  assert.doesNotMatch(extraSrc, /\bwriteFileSync\s*\(/u, 'extra-tools.js must not use synchronous writeFileSync');
  assert.doesNotMatch(extraSrc, /\bctx\.(?:tools|fs|sandboxPolicy|workingDirectory|effect)\b/u, 'extra-tools.js must not reference Cordis ctx');

  const graphSrc = await readFile(join(ROOT, 'ctf-graph.js'), 'utf8');
  assert.doesNotMatch(graphSrc, /^const\s+mutationQueues\s*=\s*new\s+Map/mu, 'ctf-graph.js must not keep module-level mutationQueues');

  const submissionSrc = await readFile(join(ROOT, 'submission.js'), 'utf8');
  assert.doesNotMatch(submissionSrc, /^const\s+patternWorkers\s*=\s*new\s+Set/mu, 'submission.js must not keep module-level patternWorkers');
});

test('ToolError retryable and side_effect_may_have_occurred semantics hold for GET vs POST timeout', async t => {
  assert.equal(new ToolError('timeout', 't').retryable, true);
  assert.equal(new ToolError('unsupported', 'u').retryable, false);
  assert.equal(describeToolError(new ToolError('network', 'n', undefined, { sideEffectMayHaveOccurred: true })).side_effect_may_have_occurred, true);

  const server = http.createServer((_req, res) => {
    // Deliberately hang longer than timeout_ms without replying.
    const tmr = setTimeout(() => {
      try { res.end('late'); } catch { /* ignore */ }
    }, 1500);
    tmr.unref?.();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const { port } = server.address();
  const targetUrl = `http://127.0.0.1:${port}/slow`;

  await assert.rejects(
    httpRequest({ url: targetUrl, method: 'GET', timeout_ms: 1000 }),
    error => error instanceof ToolError && error.kind === 'timeout' && error.retryable === true && error.side_effect_may_have_occurred === false,
  );
  await assert.rejects(
    httpRequest({ url: targetUrl, method: 'POST', body: 'x=1', timeout_ms: 1000 }),
    error => error instanceof ToolError && error.kind === 'timeout' && error.retryable === true && error.side_effect_may_have_occurred === true,
  );
});

test('extra-tools run through unified executor (result_id + request_sha256) and support source_result_id materialization', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'ctf-contracts-rt-'));
  try {
    // Minimal minimal valid 64-byte ELF64 header
    const elf = Buffer.alloc(64);
    Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]).copy(elf, 0);
    elf.writeUInt16LE(2, 16); // ET_EXEC
    elf.writeUInt16LE(62, 18); // EM_X86_64
    elf.writeUInt32LE(1, 20);
    elf.writeBigUInt64LE(0x401000n, 24);
    elf.writeUInt16LE(64, 52);

    const fakeResultId = createHash('sha256').update('elf-fixture').digest('hex');
    const stateStore = createStateStore(cwd);
    const artifactStore = createArtifactStore(cwd, { stateStore });
    artifactStore.putArtifact({ resultId: fakeResultId, tool: 'upstream_fixture', bytes: elf });
    assert.ok(existsSync(join(cwd, '.ctf', 'artifacts')));

    // Minimal valid 8-bit PCM WAV for stego_audio unified executor check
    const fmt = Buffer.alloc(16);
    fmt.writeUInt16LE(1, 0); fmt.writeUInt16LE(1, 2); fmt.writeUInt32LE(8000, 4);
    fmt.writeUInt32LE(8000, 8); fmt.writeUInt16LE(1, 12); fmt.writeUInt16LE(8, 14);
    const c = (tag, d) => { const h = Buffer.alloc(8); h.write(tag, 0); h.writeUInt32LE(d.length, 4); return Buffer.concat([h, d]); };
    const body = Buffer.concat([Buffer.from('WAVE'), c('fmt ', fmt), c('data', Buffer.alloc(32, 0x55))]);
    const hdr = Buffer.alloc(8); hdr.write('RIFF', 0); hdr.writeUInt32LE(body.length, 4);
    await writeFile(join(cwd, 'tone.wav'), Buffer.concat([hdr, body]));

    const { tools, execution } = realCtx(cwd);

    // Extra tool goes through unified executor and receives result_id + artifact_sha256 (persisted in ArtifactStore)
    const lsb = JSON.parse(await tools.get('stego_audio').execute({
      file_path: 'tone.wav', action: 'lsb', max_bytes: 4,
    }, execution));
    assert.equal(lsb.status, 'ok', JSON.stringify(lsb));
    assert.match(lsb.result_id ?? '', HASH_RE);
    assert.match(lsb.artifact_sha256 ?? '', HASH_RE);

    // Core tool inspect_elf materializes upstream ArtifactStore binary via source_result_id alone (no file_path)
    const elfRes = JSON.parse(await tools.get('inspect_elf').execute({
      source_result_id: fakeResultId,
    }, execution));
    assert.equal(elfRes.ok, undefined, JSON.stringify(elfRes));
    assert.equal(elfRes.source_result_id, fakeResultId);
    assert.equal(elfRes.machine, 'x86-64');
    assert.match(elfRes.result_id ?? '', HASH_RE);
  } finally {
    await rm(cwd, { recursive: true, force: true, maxRetries: 8, retryDelay: 50 });
  }
});
