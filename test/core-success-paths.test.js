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

function testContext(files, config = {}, cwd = process.cwd(), { writable = false } = {}) {
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
    emit() {},
    workingDirectory: { async ensure() { return root; } },
    sandboxPolicy: { resolve() { return { mode: writable ? 'workspace-write' : 'read-only' }; } },
    fs: {
      async resolve(name, options) { return resolveTarget(name, options); },
      contains(parent, child) {
        return child.targetKey === parent.targetKey || child.targetKey.startsWith(parent.targetKey.replace(/[\\/]$/u, '') + '/');
      },
      async lstat(name, options) {
        const target = resolveTarget(name, options);
        const relative = target.targetKey.slice(root.length + 1);
        if (entries.has(relative)) return { type: 'file' };
        if (writable && relative === '.ctf') return { type: 'directory' };
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
      async writeText(target, text, intent) {
        assert.equal(writable, true);
        const name = target.targetKey.slice(root.length + 1);
        const previous = entries.get(name);
        assert.equal(intent.kind, previous === undefined ? 'createIfAbsent' : 'replaceIfVersion');
        if (previous !== undefined) assert.equal(intent.version, previous.version);
        const version = 'fixture-v' + (Number(previous?.version.slice(9) ?? 0) + 1);
        entries.set(name, { bytes: Buffer.from(text), version });
        return { version };
      },
    },
  };
  apply(ctx, { compact: true, enableExtendedAudit: true, ...config });
  const session = { header: { cwd: root }, id: 'core-success-fixture' };
  const execution = { signal: new AbortController().signal, agent: { session } };
  return { tools, execution, entries };
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
    assert.equal(sent.request.follow_redirects, true);
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

test('格式签名跨块命中后能在原件的不同 ZIP 区间验证和读取成员', async () => {
  const prefix = Buffer.alloc(1024 * 1024 - 2, 0x2e);
  const firstZip = storedZip('first.txt', 'first observation');
  const separator = Buffer.from('unrelated data');
  const secondZip = storedZip('second.txt', 'second observation');
  const tail = Buffer.alloc(1024 * 1024 + 1024, 0x2e);
  const bytes = Buffer.concat([prefix, firstZip, separator, secondZip, tail]);
  const { tools, execution } = testContext({ 'wrapped.bin': bytes });
  const file_path = 'wrapped.bin';
  const call = async (tool, args) => JSON.parse(await tools.get(tool).execute({ file_path, ...args }, execution));

  const scan = await call('scan_binary', {});
  assert.equal(scan.stop_reason, 'eof');
  assert.equal(scan.hash_scope, 'range');
  assert.equal(scan.sha256, undefined);
  assert.ok(scan.bytes_read <= bytes.length + 30);
  assert.deepEqual(scan.matches.map(hit => hit.signature), ['zip', 'zip_end', 'zip', 'zip_end']);
  assert.equal(scan.matches[0].byte_offset, prefix.length);
  assert.equal(scan.matches[1].byte_offset, prefix.length + firstZip.length - 22);
  assert.equal(scan.matches[0].range_sha256, createHash('sha256').update(firstZip.subarray(0, 4)).digest('hex'));

  const fileHash = createHash('sha256').update(bytes).digest('hex');
  const ranges = [];
  for (let i = 0; i < scan.matches.length; i += 2) {
    const start = scan.matches[i].byte_offset;
    const footer = scan.matches[i + 1].byte_offset;
    const endRecord = await call('read_binary_range', {
      byte_offset: footer, byte_length: 22, encoding: 'hex', hash_scope: 'range',
    });
    const commentLength = Buffer.from(endRecord.data, 'hex').readUInt16LE(20);
    ranges.push({ archive_offset: start, archive_length: footer + 22 + commentLength - start });
  }
  assert.deepEqual(ranges.map(range => range.archive_length), [firstZip.length, secondZip.length]);
  for (const [i, expectedName] of ['first.txt', 'second.txt'].entries()) {
    const selection = ranges[i];
    const archive = await call('inspect_attachment', { ...selection, expected_sha256: fileHash });
    assert.equal(archive.status, 'ok', JSON.stringify(archive));
    assert.equal(archive.layout.rows[0].name, expectedName);
    assert.deepEqual(archive.archive_range, { byte_offset: selection.archive_offset, byte_length: selection.archive_length });
    assert.equal(archive.sha256, fileHash);
    const member = await call('read_archive_member', {
      ...selection, expected_sha256: archive.sha256, member_index: archive.layout.rows[0].member_index,
    });
    assert.equal(member.member_name, expectedName, JSON.stringify(member));
    assert.equal(member.data, ['first observation', 'second observation'][i]);
    assert.equal(member.byte_offset, 0);
    assert.equal(member.sha256, fileHash);
    assert.deepEqual(member.archive_range, archive.archive_range);
  }

  const partial = await call('inspect_attachment', { ...ranges[0], archive_length: firstZip.length - 1 });
  assert.equal(partial.ok, false);
  const outOfBounds = await call('read_archive_member', { archive_offset: bytes.length, archive_length: 1, member_index: 0 });
  assert.equal(outOfBounds.error.kind, 'size');
  const missingLength = await call('inspect_attachment', { archive_offset: prefix.length });
  assert.equal(missingLength.error.kind, 'unsupported');
});

test('二进制搜索跨扫描页匹配并按首次未返回的命中续查', async () => {
  const bytes = Buffer.from('A界界界B');
  const { tools, execution } = testContext({ 'words.bin': bytes });
  const call = async args => JSON.parse(await tools.get('scan_binary').execute({ file_path: 'words.bin', ...args }, execution));
  const first = await call({ mode: 'utf8', pattern: '界界', scan_bytes: 2 });
  assert.equal(first.stop_reason, 'scan_limit');
  assert.equal(first.next_byte_offset, 2);
  assert.deepEqual(first.matches.map(hit => [hit.byte_offset, hit.byte_length]), [[1, 6]]);
  const second = await call({ mode: 'utf8', pattern: '界界', byte_offset: first.next_byte_offset });
  assert.deepEqual(second.matches.map(hit => hit.byte_offset), [4]);
  assert.equal(second.next_byte_offset, null);

  const page = await call({ mode: 'hex', pattern: 'e7 95 8c', max_matches: 1, hash_scope: 'file' });
  assert.equal(page.sha256, createHash('sha256').update(bytes).digest('hex'));
  assert.equal(page.stop_reason, 'match_limit');
  assert.equal(page.next_byte_offset, 4);
  const remaining = await call({ mode: 'hex', pattern: 'e7958c', byte_offset: page.next_byte_offset, expected_sha256: page.sha256 });
  assert.deepEqual(remaining.matches.map(hit => hit.byte_offset), [4, 7]);
  assert.equal(remaining.next_byte_offset, null);
  assert.equal((await call({ mode: 'hex', pattern: 'f' })).error.kind, 'encoding');
  assert.equal((await call({ byte_offset: bytes.length + 1 })).error.kind, 'size');
});

test('同一题从伪 ZIP 候选、完整成员计算到记录和复核假设', async () => {
  const fakeEnd = Buffer.alloc(22);
  fakeEnd.writeUInt32LE(0x06054b50);
  fakeEnd.writeUInt16LE(1, 8);
  fakeEnd.writeUInt16LE(1, 10);
  fakeEnd.writeUInt32LE(46, 12);
  fakeEnd.writeUInt32LE(1000, 16);
  const padding = Buffer.concat([Buffer.from([0x50, 0x4b, 3, 4]), fakeEnd, Buffer.from('padding')]);
  const payload = 'verified observation\n'.repeat(301);
  const encoded = Buffer.from(payload).toString('base64');
  const zip = storedZip('observation.txt', encoded);
  const file_path = 'observations.bin';
  const bytes = Buffer.concat([padding, zip, Buffer.from('irrelevant suffix')]);
  const { tools, execution, entries } = testContext({ [file_path]: bytes }, {}, process.cwd(), { writable: true });
  const call = async (tool, args, current = execution) => JSON.parse(await tools.get(tool).execute(args, current));
  const scan = await call('scan_binary', { file_path });
  assert.match(scan.result_id, /^[a-f0-9]{64}$/u);
  const checked = await call('inspect_attachment', { file_path, scan_result_id: scan.result_id });
  assert.equal(checked.status, 'ok', JSON.stringify(checked));
  assert.deepEqual(checked.candidates.map(candidate => candidate.status), ['rejected', 'confirmed']);
  const confirmed = checked.candidates[1];
  assert.deepEqual(confirmed.archive_range, { byte_offset: padding.length, byte_length: zip.length });
  const member = await call('read_archive_member', {
    file_path, member_index: confirmed.layout.rows[0].member_index, byte_length: 5,
    archive_offset: confirmed.archive_range.byte_offset, archive_length: confirmed.archive_range.byte_length,
    expected_sha256: checked.sha256,
  });
  assert.equal(member.byte_length, 5);
  assert.equal(member.member_size, encoded.length);
  assert.match(member.result_id, /^[a-f0-9]{64}$/u);
  const expected = createHash('sha256').update(payload).digest('hex');
  const args = { steps: [
    { operation: 'convert_encoding', from_encoding: 'base64', to_encoding: 'utf8', inputs: [{ result_id: member.result_id }] },
    { operation: 'hash', algorithm: 'sha256', inputs: [{ step: 1 }], expected },
  ], candidates: [{ label: '完整成员', checkpoints: [2] }] };
  const result = await call('calculate_offline', args);
  assert.equal(result.status, 'ok', JSON.stringify(result));
  assert.deepEqual(result.candidates, [{ label: '完整成员', status: 'match' }]);
  assert.equal(result.steps[1].result, expected);
  assert.equal(result.steps[0].result_chars, payload.length);
  assert.equal(result.input_evidence[0].data_bytes, encoded.length);
  assert.equal(result.input_evidence[0].source.sha256, checked.sha256);
  assert.equal(result.input_evidence[0].source.file_path, file_path);
  assert.deepEqual(result.input_evidence[0].archive_range, confirmed.archive_range);

  const slice = await call('read_binary_range', { file_path, byte_offset: padding.length, byte_length: 4 });
  const sliceResult = await call('calculate_offline', { steps: [{
    operation: 'hash', algorithm: 'sha256', from_encoding: 'hex',
    inputs: [{ result_id: slice.result_id, encoding: 'hex' }], expected: slice.range_sha256,
  }] });
  assert.equal(sliceResult.status, 'ok', JSON.stringify(sliceResult));
  assert.equal(sliceResult.input_evidence[0].source.byte_offset, padding.length);
  assert.equal(sliceResult.input_evidence[0].data_bytes, 4);
  const wrongTool = await call('calculate_offline', { steps: [{
    operation: 'hash', algorithm: 'sha256', inputs: [{ result_id: scan.result_id }],
  }] });
  assert.equal(wrongTool.error.kind, 'unsupported');

  const saved = await call('ctf_progress', {
    action: 'save', revision: 'absent', progress: { confirmed: [], ruled_out: [], pending: [], experiments: [
      { label: '完整解码', hypothesis: '完整解码值具有标准哈希', pointer: '/steps/1/result', expected, result_id: result.result_id },
      { label: '另一候选', hypothesis: '解码值符合另一个哈希', pointer: '/steps/1/result', expected: '0'.repeat(64), result_id: result.result_id },
      { label: '预览不能当全文', hypothesis: '预览是全文', pointer: '/steps/0/result', expected: 'preview', result_id: result.result_id },
    ] },
  });
  assert.equal(saved.status, 'saved', JSON.stringify(saved));
  assert.deepEqual(saved.experiment_status.map(row => row.status), ['supported', 'refuted', 'insufficient']);
  assert.ok(entries.get('notes.md').bytes.toString('utf8').includes('单题验证记录'));

  const restarted = { ...execution, agent: { session: { ...execution.agent.session, id: 'fixture-restarted' } } };
  const query = { action: 'experiments', experiment_query: { tool: 'calculate_offline', args } };
  const lookup = await call('ctf_progress', query, restarted);
  assert.deepEqual(lookup.experiments.map(row => row.status), ['supported', 'refuted']);
  assert.equal(lookup.experiments[0].observation_status, 'recorded');
  assert.equal(lookup.experiments[0].actual, expected);
  const replayed = await call('calculate_offline', args, restarted);
  assert.equal(replayed.steps?.[1]?.result, expected, JSON.stringify(replayed));

  const changed = Buffer.from(bytes);
  changed[changed.length - 1] ^= 1;
  entries.set(file_path, { bytes: changed, version: 'fixture-v2' });
  const staleLookup = await call('ctf_progress', query, restarted);
  assert.deepEqual(staleLookup.experiments.map(row => row.status), ['insufficient', 'insufficient']);
  const staleScan = await call('inspect_attachment', { file_path, scan_result_id: scan.result_id });
  assert.equal(staleScan.error.kind, 'conflict');
  const staleInput = await call('calculate_offline', args, restarted);
  assert.equal(staleInput.ok, false);
  assert.match(staleInput.error.message, /SHA-256/u);
});

test('附件片段可直接转为大整数，并用模逆和同余区分大小端候选', async () => {
  const payloadHex = '0001000000000000000002';
  const payload = Buffer.from(payloadHex, 'hex');
  const file_path = 'numbers.bin';
  const { tools, execution, entries } = testContext({
    [file_path]: Buffer.concat([Buffer.from([0xaa, 0xbb]), payload, Buffer.from([0xcc])]),
  });
  const call = async (tool, args) => JSON.parse(await tools.get(tool).execute(args, execution));
  const slice = await call('read_binary_range', { file_path, byte_offset: 2, byte_length: 11 });
  assert.match(slice.result_id, /^[a-f0-9]{64}$/u);
  const source = { result_id: slice.result_id };
  const args = { steps: [
    { operation: 'bytes_to_integer', inputs: [source], byte_order: 'big' },
    { operation: 'modular_inverse', inputs: [{ step: 1 }, '19'], expected: '13' },
    { operation: 'integer_to_bytes', inputs: [{ step: 1 }], byte_order: 'big', byte_length: 11, expected: payloadHex },
    { operation: 'multiply', inputs: [{ step: 1 }, { step: 2 }] },
    { operation: 'check_congruence', inputs: [{ step: 4 }, '1', '19'], expected: 'true' },
    { operation: 'bytes_to_integer', inputs: [{ ...source, encoding: 'base64' }], byte_order: 'little' },
    { operation: 'multiply', inputs: [{ step: 6 }, { step: 2 }] },
    { operation: 'check_congruence', inputs: [{ step: 7 }, '1', '19'], expected: 'true' },
  ], candidates: [
    { label: '大端', checkpoints: [2, 3, 5] },
    { label: '小端', checkpoints: [8] },
  ] };
  const result = await call('calculate_offline', args);
  assert.equal(result.steps?.[0].result, '4722366482869645213698', JSON.stringify(result));
  assert.equal(result.steps[0].byte_length, 11);
  assert.equal(result.steps[1].result, '13');
  assert.equal(result.steps[1].gcd, '1');
  assert.equal(result.steps[1].product_remainder, '1');
  assert.equal(result.steps[2].result, payloadHex);
  assert.equal(result.steps[5].result, '2417851639229258349412608');
  assert.equal(result.steps[7].left_remainder, '9');
  assert.deepEqual(result.candidates, [
    { label: '大端', status: 'match' }, { label: '小端', status: 'mismatch', first_mismatch: 8 },
  ]);
  assert.match(result.request_sha256, /^[a-f0-9]{64}$/u);
  assert.deepEqual(result.input_evidence.map(item => [item.encoding, item.source.byte_offset, item.source.sha256]), [
    ['hex', 2, slice.sha256], ['base64', 2, slice.sha256],
  ]);
  const changed = Buffer.from(entries.get(file_path).bytes);
  changed[2] ^= 1;
  entries.set(file_path, { bytes: changed, version: 'fixture-v2' });
  assert.equal((await call('calculate_offline', args)).error.kind, 'conflict');
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
