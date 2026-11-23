import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import { apply } from '../ctf-tools.js';
import { inspectAttachment } from '../attachment.js';
import { createRangeInspector, inspectLogWindow } from '../attachment-ranges.js';
import { cleanHttpResponse, platformBase, platformCredential, platformRequest } from '../platform-request.js';
import { cyclicPattern } from '../pwn-pattern.js';
import { manageProgress } from '../ctf-progress.js';

function storedZip(name, content) {
  const nameBytes = Buffer.from(name);
  const data = Buffer.from(content);
  const crc32 = bytes => {
    let crc = 0xffffffff;
    for (const byte of bytes) {
      crc ^= byte;
      for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
    return (crc ^ 0xffffffff) >>> 0;
  };
  const crc = crc32(data);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0x0800, 6);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(nameBytes.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0x0800, 8);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(nameBytes.length, 28);
  const directoryOffset = local.length + nameBytes.length + data.length;
  const directorySize = central.length + nameBytes.length;
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(directorySize, 12);
  end.writeUInt32LE(directoryOffset, 16);
  return Buffer.concat([local, nameBytes, data, central, nameBytes, end]);
}

function testContext(files, config = {}, cwd = process.cwd()) {
  const root = cwd;
  const entries = new Map(Object.entries(files).map(([name, bytes]) => [name, {
    bytes: Buffer.from(bytes), version: 'fixture-v1',
  }]));
  const tools = new Map();
  const resolveTarget = (name, options = {}) => {
    const targetKey = options.cwd ? `${options.cwd.replace(/[\\/]$/u, '')}/${name}` : name;
    return { targetKey, displayPath: targetKey };
  };
  const ctx = {
    tools: { register(tool) { tools.set(tool.name, tool); } },
    effect() {},
    workingDirectory: { async ensure() { return root; } },
    sandboxPolicy: { resolve() { return { mode: 'read-only' }; } },
    fs: {
      async resolve(name, options) { return resolveTarget(name, options); },
      contains(parent, child) {
        return child.targetKey === parent.targetKey || child.targetKey.startsWith(parent.targetKey.replace(/[\\/]$/u, '') + '/');
      },
      async lstat(name, options) {
        const target = resolveTarget(name, options);
        const relative = target.targetKey.slice(root.length + 1);
        if (entries.has(relative)) return { type: 'file' };
        if ([...entries.keys()].some(file => file.startsWith(relative.replace(/[\\/]$/u, '') + '/'))) return { type: 'directory' };
        return undefined;
      },
      async stat(target) {
        const name = target.targetKey.slice(root.length + 1);
        const entry = entries.get(name);
        return entry ? { type: 'file', size: entry.bytes.length, version: entry.version } : null;
      },
      async readBytes(target) {
        const name = target.targetKey.slice(root.length + 1);
        return entries.get(name)?.bytes;
      },
      async readByteRange(target, { offset, length }) {
        const name = target.targetKey.slice(root.length + 1);
        return entries.get(name)?.bytes.subarray(offset, offset + length);
      },
    },
  };
  apply(ctx, { compact: true, ...config });
  const session = { header: { cwd: root }, id: 'core-success-fixture' };
  const execution = { signal: new AbortController().signal, agent: { session } };
  return { tools, execution };
}

test('平台响应脱敏，并在发请求前拒绝未配置或明文令牌', async () => {
  const response = cleanHttpResponse({
    status: 200,
    status_text: 'token-secret',
    body: 'token-secret',
    body_hex: Buffer.from('token-secret').toString('hex'),
    headers: { Authorization: 'Bearer token-secret', 'x-note': 'token-secret' },
  }, 'token-secret');
  assert.equal(response.status_text, '[已脱敏]');
  assert.equal(response.body, '[已脱敏]');
  assert.equal(response.body_hex, undefined);
  assert.equal(response.body_redacted, true);
  assert.equal(response.headers.Authorization, '[已脱敏]');
  assert.equal(response.headers['x-note'], '[已脱敏]');
  assert.equal(platformBase({ platformUrl: ' https://board.example/api ' }), 'https://board.example/api');

  const envName = 'CTF_TEST_PLATFORM_REQUEST_TOKEN';
  const previous = process.env[envName];
  process.env[envName] = 'secret-token';
  try {
    assert.deepEqual(platformCredential({ platformTokenEnv: envName }), { tokenEnv: envName, token: 'secret-token' });
    await assert.rejects(platformRequest({}, undefined, 'GET', '/status'), error => error.kind === 'dependency');
    await assert.rejects(platformRequest({ platformUrl: 'https://board.example/?q=x' }, undefined, 'GET', '/status'),
      error => error.kind === 'unsupported');
    await assert.rejects(platformRequest({ platformUrl: 'http://board.example', platformTokenEnv: envName }, undefined, 'GET', '/status'),
      error => error.kind === 'permission');
    let sent;
    const successful = await platformRequest({
      platformUrl: 'https://board.example/api', platformTokenEnv: envName,
    }, undefined, 'GET', '/status', undefined, async (request, options) => {
      sent = { request, options };
      return { status: 200, body: 'secret-token', headers: {} };
    });
    assert.equal(sent.request.url, 'https://board.example/api/status');
    assert.equal(sent.request.headers.Authorization, 'Bearer secret-token');
    assert.equal(sent.request.follow_redirects, false);
    assert.equal(typeof sent.options.authorize, 'function');
    assert.equal(successful.body, '[已脱敏]');
    await assert.rejects(platformRequest({ platformUrl: 'https://board.example' }, undefined, 'GET', '/status', undefined,
      async () => { throw new Error('fixture network failure'); }), /fixture network failure/u);
  } finally {
    if (previous === undefined) delete process.env[envName];
    else process.env[envName] = previous;
  }
});

test('附件检查成功返回 WebAssembly 结构和 SHA-256，未知二进制明确标记 unsupported', () => {
  const wasm = Buffer.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0]);
  const report = inspectAttachment(wasm, { offset: 0, limit: 10 });
  assert.equal(report.status, 'ok');
  assert.equal(report.format, 'WebAssembly');
  assert.equal(report.sha256, createHash('sha256').update(wasm).digest('hex'));
  const unknown = inspectAttachment(Buffer.from([0, 255, 1, 2]), { offset: 0, limit: 10 });
  assert.equal(unknown.status, 'unsupported');
  assert.match(unknown.sha256, /^[a-f0-9]{64}$/u);
});

test('分段读取核对原件版本和 SHA-256，并按 UTF-8 边界返回文本', async () => {
  const bytes = Buffer.from('A界BC');
  const target = { targetKey: 'fixture.bin' };
  const fs = {
    async readByteRange(_target, { offset, length }) { return bytes.subarray(offset, offset + length); },
    async stat() { return { type: 'file', size: bytes.length, version: 'v1' }; },
  };
  const inspect = createRangeInspector(fs);
  const file = { target, size: bytes.length, version: 'v1' };
  const report = await inspect(file, undefined, undefined, async ({ read }) => {
    const selected = await read(1, 3);
    return { report: { hex: selected.toString('hex') } };
  });
  assert.equal(report.hex, Buffer.from('界').toString('hex'));
  assert.equal(report.sha256, createHash('sha256').update(bytes).digest('hex'));
  assert.equal(report.size, bytes.length);
  assert.ok(report.bytes_read >= bytes.length);
  const text = await inspectLogWindow({ size: bytes.length, read: async (offset, length) => bytes.subarray(offset, offset + length) }, 1, 3);
  assert.equal(text.report.text, '界');
  await assert.rejects(inspect(file, undefined, 'f'.repeat(64), async () => ({ report: {} })), /SHA-256/u);
});

test('DSH 附件、进度和心跳工具可走通成功与失败路径', async () => {
  const zip = storedZip('flag.txt', 'flag{fixture}');
  const binary = Buffer.from('prefix FLAG{slice} suffix');
  const { tools, execution } = testContext({ 'sample.zip': zip, 'sample.bin': binary });
  const range = JSON.parse(await tools.get('read_binary_range').execute({
    file_path: 'sample.bin', byte_offset: 7, byte_length: 5, encoding: 'hex', strings: true,
  }, execution));
  assert.equal(range.ok, undefined);
  assert.equal(range.data, Buffer.from('FLAG{').toString('hex'));
  assert.equal(range.hash_scope, 'file');
  assert.match(range.sha256, /^[a-f0-9]{64}$/u);

  const member = JSON.parse(await tools.get('read_archive_member').execute({
    file_path: 'sample.zip', member_index: 0, format_hint: 'zip',
  }, execution));
  assert.equal(member.member_name, 'flag.txt');
  assert.equal(member.data, 'flag{fixture}');
  assert.match(member.member_sha256, /^[a-f0-9]{64}$/u);

  const cyclic = JSON.parse(await tools.get('pwn_cyclic').execute({ operation: 'create', length: 16 }, execution));
  assert.equal(cyclic.pattern, 'aaaabaaacaaadaaa');
  const archive = JSON.parse(await tools.get('archive_crack').execute({
    file_path: 'sample.zip', action: 'info',
  }, execution));
  assert.equal(archive.status, 'ok');
  assert.equal(archive.entries[0].name, 'flag.txt');
  assert.equal(archive.encrypted_count, 0);

  const documents = new Map();
  const progressFiles = {
    cwd: process.cwd(), sessionId: 'core-success-fixture',
    normalizePath: value => value.split(/[\\/]/u).filter(Boolean).join('/'),
    async readDocument(name) {
      return documents.get(name) ?? { name, text: '', version: undefined };
    },
    async writeDocument(document, content) {
      const current = documents.get(document.name);
      documents.set(document.name, { name: document.name, text: content, version: (current?.version ?? 0) + 1 });
    },
    async readEvidence() { return null; },
    readResult() { return undefined; },
    listResults() { return []; },
  };
  await manageProgress({ action: 'save', revision: 'absent', progress: {
    confirmed: [], ruled_out: [], pending: ['verify challenge output'],
  } }, progressFiles);
  const progressContext = testContext(Object.fromEntries([...documents].map(([name, doc]) => [name, Buffer.from(doc.text)])));
  const loaded = JSON.parse(await progressContext.tools.get('ctf_progress').execute({ action: 'load' }, progressContext.execution));
  assert.equal(loaded.status, 'loaded', JSON.stringify(loaded));
  assert.deepEqual(loaded.progress.pending, ['verify challenge output']);

  const statusContext = testContext({});
  const status = JSON.parse(await statusContext.tools.get('ctf_status').execute({ action: 'show' }, statusContext.execution));
  assert.equal(status.status, 'status');
  assert.equal(status.records, 0);
  assert.ok(status.warnings.some(warning => warning.code === 'status_records_low'));

  const failed = JSON.parse(await tools.get('read_binary_range').execute({ file_path: '../outside.bin' }, execution));
  assert.equal(failed.ok, false);
  assert.equal(failed.error.kind, 'path');
});

test('CTF 循环模式扩展工具可生成并定位模式，非法操作返回错误', () => {
  const created = cyclicPattern({ operation: 'create', length: 32 });
  assert.equal(created.pattern.slice(0, 16), 'aaaabaaacaaadaaa');
  const known = Buffer.from(created.pattern).subarray(10, 14);
  const found = cyclicPattern({ operation: 'find', value: known.toString('hex') });
  assert.equal(found.offset, 10);
  assert.throws(() => cyclicPattern({ operation: 'unknown' }), /operation/u);
});

test('最低兼容 DSH 可在无 systemPrompt 服务时回退并报告能力', async () => {
  const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
  const { tools, execution } = testContext({}, { pythonPath: process.execPath });
  const doctor = JSON.parse(await tools.get('ctf_doctor').execute({ action: 'check' }, execution));
  assert.equal(doctor.host_capabilities.supported_dsh_range, manifest.engines.dsh);
  assert.equal(doctor.host_capabilities.tools_register, true);
  assert.equal(doctor.host_capabilities.filesystem, true);
  assert.equal(doctor.host_capabilities.system_prompt_context, false);
  assert.equal(doctor.missing.length, 0);
  assert.ok(doctor.optional_missing.includes('dsh:systemPrompt.context'));
  assert.match(doctor.checks.find(check => check.name === 'dsh:systemPrompt.context').detail, /SKILL\.md/u);
});

test('PCAP 工具对完整空捕获成功，对截断文件返回结构化错误', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'ctf-pcap-tool-'));
  try {
    const valid = Buffer.alloc(24);
    valid.writeUInt32LE(0xa1b2c3d4, 0);
    valid.writeUInt16LE(2, 4);
    valid.writeUInt16LE(4, 6);
    valid.writeUInt32LE(65535, 16);
    valid.writeUInt32LE(1, 20);
    const invalid = Buffer.from([0xd4, 0xc3, 0xb2, 0xa1]);
    await writeFile(join(cwd, 'empty.pcap'), valid);
    await writeFile(join(cwd, 'truncated.pcap'), invalid);
    const { tools, execution } = testContext({ 'empty.pcap': valid, 'truncated.pcap': invalid }, {}, cwd);
    const success = JSON.parse(await tools.get('pcap_stream').execute({ file_path: 'empty.pcap' }, execution));
    assert.equal(success.status, 'ok');
    assert.equal(success.packets, 0);
    const failure = JSON.parse(await tools.get('pcap_stream').execute({ file_path: 'truncated.pcap' }, execution));
    assert.equal(failure.ok, false);
    assert.match(failure.error.message, /PCAP 文件头|抓包格式/u);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
