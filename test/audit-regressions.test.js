// 审计回归用例：为 0.51.0 修复的六处缺陷各锁定一个可执行断言。
// 这些用例不依赖 Docker / Chrome / 网络，可以在 CI 的 ubuntu 与 windows 上跑。
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { lstat as fsLstat, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { apply } from '../ctf-tools.js';
import { inspectMedia } from '../media-reader.js';
import { pcapStream } from '../pcap-stream.js';

const PYTHON = process.platform === 'win32' ? 'python' : 'python3';
const RESULT_HASH = /^[a-f0-9]{64}$/u;

function pythonAvailable() {
  try {
    execFileSync(PYTHON, ['-c', 'print(1)'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function workspaceCtx(cwd, config = {}) {
  const tools = new Map();
  const clean = cwd.replaceAll('\\', '/').replace(/[\\/]$/u, '');
  const resolveTarget = (name, options = {}) => {
    if (typeof name === 'object' && name !== null && typeof name.targetKey === 'string') return name;
    const norm = String(name).replaceAll('\\', '/');
    if (/^[A-Za-z]:\//u.test(norm) || norm.startsWith('/')) return { targetKey: norm, displayPath: norm };
    const base = (options.cwd ?? clean).replaceAll('\\', '/').replace(/[\\/]$/u, '');
    const targetKey = `${base}/${norm}`;
    return { targetKey, displayPath: targetKey };
  };
  const full = (name, options) => {
    const key = resolveTarget(name, options).targetKey;
    return key.startsWith(clean + '/') ? join(cwd, key.slice(clean.length + 1)) : key;
  };
  const info = async (target) => {
    const stat = await fsLstat(target);
    return { type: stat.isDirectory() ? 'directory' : stat.isSymbolicLink() ? 'symlink' : 'file', size: stat.size, version: `${stat.size}:${Math.trunc(stat.mtimeMs)}` };
  };
  const ctx = {
    tools: { register(tool) { tools.set(tool.name, tool); } },
    effect() {},
    emit() {},
    workingDirectory: { async ensure() { return cwd; } },
    sandboxPolicy: { resolve() { return { mode: 'workspace-write' }; } },
    fs: {
      async resolve(name, options) { return resolveTarget(name, options); },
      contains(parent, child) {
        const base = parent.targetKey.replace(/[\\/]$/u, '');
        return child.targetKey === base || child.targetKey.startsWith(base + '/');
      },
      async lstat(name, options) {
        try { return await info(full(name, options)); } catch { return undefined; }
      },
      async stat(resolved) {
        try { return await info(full(resolved)); } catch { return null; }
      },
      async readBytes(resolved) { return readFile(full(resolved)); },
      async writeBytes(resolved, bytes) { await writeFile(full(resolved), bytes); },
      async writeText(resolved, text) { await writeFile(full(resolved), text, 'utf8'); },
    },
  };
  apply(ctx, { compact: true, pythonPath: PYTHON, ...config });
  const execution = {
    signal: new AbortController().signal,
    agent: { session: { header: { cwd }, id: 'audit-' + Math.random().toString(36).slice(2, 8) } },
  };
  return { tools, execution, ctx };
}

function classicPcap() {
  const payload = Buffer.from('GET /flag HTTP/1.0\r\nHost: t\r\n\r\n');
  const eth = Buffer.alloc(14);
  eth.writeUInt16BE(0x0800, 12);
  const ip = Buffer.alloc(20);
  ip[0] = 0x45;
  ip.writeUInt16BE(20 + 20 + payload.length, 2);
  ip[8] = 64;
  ip[9] = 6;
  Buffer.from([10, 0, 0, 1]).copy(ip, 12);
  Buffer.from([10, 0, 0, 2]).copy(ip, 16);
  const tcp = Buffer.alloc(20);
  tcp.writeUInt16BE(40000, 0);
  tcp.writeUInt16BE(80, 2);
  tcp.writeUInt32BE(1000, 4);
  tcp[12] = 0x50;
  tcp[13] = 0x18;
  const frame = Buffer.concat([eth, ip, tcp, payload]);
  const global = Buffer.alloc(24);
  global.writeUInt32LE(0xa1b2c3d4, 0);
  global.writeUInt16LE(2, 4);
  global.writeUInt16LE(4, 6);
  global.writeUInt32LE(65535, 16);
  global.writeUInt32LE(1, 20);
  const header = Buffer.alloc(16);
  header.writeUInt32LE(1600000000, 0); // 2020-09-13T12:26:40Z
  header.writeUInt32LE(0, 4);
  header.writeUInt32LE(frame.length, 8);
  header.writeUInt32LE(frame.length, 12);
  return Buffer.concat([global, header, frame]);
}

function gguf(entries) {
  const chunks = [Buffer.from('GGUF', 'ascii')];
  const u32 = value => { const b = Buffer.alloc(4); b.writeUInt32LE(value, 0); return b; };
  const u64 = value => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(value), 0); return b; };
  const str = text => { const b = Buffer.from(text, 'utf8'); return Buffer.concat([u64(b.length), b]); };
  chunks.push(u32(3), u64(0), u64(entries.length)); // GGUF v3: tensor_count 在前，kv_count 在后
  for (const [key, value] of entries) {
    chunks.push(str(key));
    if (Array.isArray(value)) {
      chunks.push(u32(9), u32(8), u64(value.length), ...value.map(str));
    } else if (typeof value === 'string') {
      chunks.push(u32(8), str(value));
    } else if (Number.isInteger(value)) {
      chunks.push(u32(4), u32(value));
    } else {
      throw new Error('unsupported gguf fixture value');
    }
  }
  return Buffer.concat(chunks);
}

function safetensors(header, data = Buffer.alloc(0)) {
  const json = Buffer.from(JSON.stringify(header), 'utf8');
  const length = Buffer.alloc(8);
  length.writeBigUInt64LE(BigInt(json.length), 0);
  return Buffer.concat([length, json, data]);
}

test('pcap_stream 的 UTC 时间过滤真的生效（修复前恒为空）', async t => {
  const cwd = await mkdtemp(join(tmpdir(), 'ctf-audit-pcap-'));
  t.after(() => rm(cwd, { recursive: true, force: true, maxRetries: 8, retryDelay: 40 }));
  await writeFile(join(cwd, 'one.pcap'), classicPcap());
  const inside = await pcapStream({
    file_path: 'one.pcap',
    filter: { start_utc: '2020-01-01T00:00:00Z', end_utc: '2021-01-01T00:00:00Z' },
  }, { cwd });
  assert.equal(inside.flows.length, 1, '位于时间窗内的包必须保留');
  assert.deepEqual(inside.flows[0].first_packet.timestamp_utc, '2020-09-13T12:26:40Z');
  const outside = await pcapStream({
    file_path: 'one.pcap',
    filter: { start_utc: '2021-01-01T00:00:00Z' },
  }, { cwd });
  assert.equal(outside.flows.length, 0, '时间窗外的包必须被过滤');
});

test('GGUF 字符串数组元素里的模板注入必须判为 high', async t => {
  if (!pythonAvailable()) return t.skip('此运行环境缺少 Python。');
  const payload = "{{namespace.__init__.__globals__['os'].popen('id').read()}}";
  const bytes = gguf([
    ['general.name', 'audit-fixture'],
    ['tokenizer.chat_template', ['safe-template', payload, 'another-safe']],
  ]);
  const report = await inspectMedia(bytes, { kind: 'model' }, undefined, { async resolvePython() { return PYTHON; } });
  assert.equal(report.format, 'gguf');
  assert.equal(report.risk_level, 'high', '数组元素内的注入不能被跳过');
  assert.ok(report.findings.some(f => f.kind === 'suspicious_metadata_template' && f.key === 'tokenizer.chat_template'));
});

test('Safetensors __metadata__ 里的模板注入必须判为 high', async t => {
  if (!pythonAvailable()) return t.skip('此运行环境缺少 Python。');
  const bytes = safetensors({
    __metadata__: { format: 'pt', note: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}" },
    'layer.weight': { dtype: 'F32', shape: [2, 2], data_offsets: [0, 16] },
  }, Buffer.alloc(16));
  const report = await inspectMedia(bytes, { kind: 'model' }, undefined, { async resolvePython() { return PYTHON; } });
  assert.equal(report.format, 'safetensors');
  assert.equal(report.risk_level, 'high');
  assert.ok(report.findings.some(f => f.kind === 'suspicious_metadata_template'));
});

test('Ghidra 反编译契约：返回 image_base 且接受相对地址', async () => {
  const source = await readFile(new URL('../sandbox-runner.js', import.meta.url), 'utf8');
  assert.ok((source.match(/'image_base': img_base_hex/gu) ?? []).length >= 2,
    'list 与 function 两种模式都必须回报 image_base');
  assert.match(source, /item\['offset'\] = hex\(entry_off - img_base\)/u, 'list 必须附带相对偏移');
  assert.match(source, /rel_s == target_norm/u, 'function 必须同时按绝对地址与相对地址匹配');
});

test('ctf_sandbox 的返回必须带 result_id（零拷贝链路）', async t => {
  const cwd = await mkdtemp(join(tmpdir(), 'ctf-audit-sandbox-'));
  t.after(() => rm(cwd, { recursive: true, force: true, maxRetries: 8, retryDelay: 40 }));
  const { tools, execution } = workspaceCtx(cwd);
  const sandbox = tools.get('ctf_sandbox');
  assert.ok(sandbox, 'ctf_sandbox 必须注册');
  const report = JSON.parse(await sandbox.execute({ action: 'status', timeout_ms: 60000 }, execution));
  assert.match(report.result_id ?? '', RESULT_HASH, '沙箱状态输出必须带 result_id');
});

test('提交账本出现坏行时不再让工具整体失败', async t => {
  const cwd = await mkdtemp(join(tmpdir(), 'ctf-audit-ledger-'));
  t.after(() => rm(cwd, { recursive: true, force: true, maxRetries: 8, retryDelay: 40 }));
  const good = JSON.stringify({ kind: 'check', flag_sha256: 'a'.repeat(64), verdict: 'local', at: '2026-01-01T00:00:00.000Z' });
  await writeFile(join(cwd, '.ctf-submissions.jsonl'), [good, '{"kind": "check"', 'not json at all', good, ''].join('\n'));
  const { tools, execution } = workspaceCtx(cwd);
  const submit = tools.get('check_flag');
  const report = JSON.parse(await submit.execute({
    flag: 'demo{abcd1234}', source: 'audit fixture', record: true,
  }, execution));
  assert.notEqual(report.status, 'failed');
  assert.equal(report.corrupted_receipts, 2, '坏行必须被计数并回报，而不是静默丢弃');
});
