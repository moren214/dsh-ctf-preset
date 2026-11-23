import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, unlink, rmdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { createHash } from 'node:crypto';
import { handleSubmission, classifyVerdict } from '../submission.js';
import { downloadAttachment } from '../attachment-transfer.js';
import { createNetworkBoundary } from '../network-boundary.js';
import { manageProgress } from '../ctf-progress.js';
import { createToolResults } from '../ctf-result-values.js';
import { appendEvidenceIndex, decodeEvidenceIndex, encodeEvidenceEntry } from '../evidence-index.js';
import { inspectArchive } from '../archive.js';
import { pcapStream } from '../pcap-stream.js';
import { inspectCapture as inspectPcapBlocks } from '../capture.js';
import { parsePcapngQuery } from '../pcapng-statistics.js';
import { verifyFlaskResponse } from '../flask-response.js';
import { apply } from '../ctf-tools.js';

const hash = value => createHash('sha256').update(value).digest('hex');

test('本地校验不计为平台提交，明确失败与未知响应不会算通过', async () => {
  let entries = [];
  let version = 0;
  let sends = 0;
  const files = {
    async read() { return { receipts: structuredClone(entries), document: version }; },
    async write(doc, received) { assert.equal(doc, version++); entries = received; },
  };
  const args = { flag: 'demo{sample-review}', source: 'test fixture', challenge: 'local-fixture' };
  const platform = 'https://example.invalid';
  const send = async () => {
    sends++;
    return { status: 200, body: '{"data":{"status":"correct"}}' };
  };
  assert.equal((await handleSubmission(args, files, undefined, platform)).ready, true);
  assert.deepEqual(entries, []);
  assert.equal((await handleSubmission({ ...args, record: true }, files, undefined, platform)).ready, true);
  assert.equal(entries[0].kind, 'check');
  assert.equal((await handleSubmission(args, files, send, platform)).verdict, 'accepted');
  assert.equal((await handleSubmission(args, files, send, platform)).verdict, 'rejected_local');
  assert.equal(sends, 1);
  assert.ok(!JSON.stringify(entries).includes(args.flag));
  assert.equal(classifyVerdict({ status: 200, body: '{"correct":false}' }), 'rejected');
  assert.equal(classifyVerdict({ status: 200, body: '{"success":true}' }), 'unknown');
  assert.equal(classifyVerdict({ status: 200, body: '{"accepted":true}', truncated: true }), 'unknown');
});

test('下载逐跳检查 DNS，拒绝越权跳转并支持已有取消信号', async () => {
  const resolveAddress = async name => [{ address: name === 'outside.example' ? '8.8.8.8' : '10.0.0.1', family: 4 }];
  let requests = 0;
  const response = (statusCode, headers) => Object.assign(Readable.from([]), { statusCode, headers });
  const request = async (_url, pinned) => {
    requests++;
    assert.deepEqual(pinned, { address: '8.8.8.8', family: 4 });
    return response(302, { location: 'https://outside-private.example/a' });
  };
  await assert.rejects(downloadAttachment('https://outside.example/a', 'unused-output', { resolveAddress, request }), /授权地址范围/u);
  await assert.rejects(downloadAttachment('https://outside.example/a', 'unused-output', {
    resolveAddress, request, signal: AbortSignal.abort(),
  }));
  assert.equal(requests, 1);
  const scope = createNetworkBoundary();
  await assert.rejects(scope.http('https://example.invalid/'), /尚未/u);
  await assert.rejects(scope.tcp('example.invalid', 80), /尚未/u);
});

test('状态保存中断可恢复，手改交接保留正文，状态副本恢复已提交版本', async () => {
  const documents = new Map();
  let failProjection = false;
  const files = {
    normalizePath: path => path, readResult: () => undefined, readEvidence: async () => null,
    async readDocument(name) { return { name, text: documents.get(name)?.text ?? '', version: documents.get(name)?.version }; },
    async writeDocument(doc, text) {
      if (failProjection && doc.name === 'notes.md') throw new Error('simulated interruption');
      const current = documents.get(doc.name);
      assert.equal(doc.version, current?.version);
      documents.set(doc.name, { text, version: (current?.version ?? 0) + 1 });
    },
  };
  const run = args => manageProgress(args, files);
  const progress = label => ({ confirmed: [], pending: [label], ruled_out: [] });
  const first = await run({ action: 'save', revision: 'absent', progress: progress('prior') });
  failProjection = true;
  const second = await run({ action: 'save', revision: first.revision, progress: progress('new') });
  assert.match(second.warning, /状态已提交/u);
  failProjection = false;
  const loaded = await run({ action: 'load' });
  assert.deepEqual(loaded.progress.pending, ['new']);
  assert.equal((await run({ action: 'repair', revision: loaded.revision })).status, 'repaired');
  await run({ action: 'handoff' });
  const handoff = documents.get('handoff.md');
  documents.set('handoff.md', { ...handoff, text: handoff.text.replace('已有进展', '队员手写段落') });
  assert.equal((await run({ action: 'handoff' })).persisted, true);
  assert.match(documents.get('handoff.md').text, /队员手写段落/u);
  documents.delete('.ctf/state.json');
  const missing = await run({ action: 'load' });
  assert.deepEqual(missing.progress.pending, ['new']);
  assert.equal((await run({ action: 'repair', revision: missing.revision })).status, 'repaired');
  const revision = (await run({ action: 'load' })).revision;
  const attempts = await Promise.allSettled(['one', 'two'].map(label => run({ action: 'save', revision, progress: progress(label) })));
  assert.equal(attempts.filter(outcome => outcome.status === 'fulfilled').length, 1);
});

test('落盘证据使用原路径引用和已记录状态，工具 FD 不跨会话', () => {
  const cache = createToolResults();
  const session = {};
  const source = { file_path: 'fixture.txt', sha256: hash('fixture') };
  const id = cache.remember(session, 'fixture', 'read_log_range',
    { file: 'fixture.txt', sha256: source.sha256, byte_offset: 1, byte_length: 4, text: 'ixtu' }, [source]);
  assert.equal(cache.get({}, 'fixture', id), undefined);
  const entry = encodeEvidenceEntry(id, cache.get(session, 'fixture', id));
  const restored = decodeEvidenceIndex(appendEvidenceIndex('', id, entry)).get(id);
  assert.equal(restored.persisted, true);
  assert.equal(restored.report.byte_offset, 1);
  assert.equal(restored.summary.fields.get('/text').value, 'ixtu');
});

function tarSample() {
  const header = Buffer.alloc(512);
  header.write('fixture.txt', 0);
  header.write('00000000004\0', 124);
  header.fill(32, 148, 156);
  header.write('0', 156);
  header.write('ustar\0', 257);
  header.write(header.reduce((sum, value) => sum + value, 0).toString(8).padStart(6, '0') + '\0 ', 148);
  const body = Buffer.alloc(512);
  body.write('data');
  return Buffer.concat([header, body, Buffer.alloc(1024)]);
}

test('TAR 结束块之后的字节和拼接归档可定位', () => {
  const tar = tarSample();
  const padding = Buffer.alloc(512);
  const report = inspectArchive(Buffer.concat([tar, padding, tar]), { offset: 0, limit: 10 });
  assert.equal(report.layout.total, 1);
  assert.equal(report.archive_end, tar.length);
  assert.equal(report.trailing_offset, tar.length + padding.length);
  assert.equal(report.trailing_size, tar.length);
  assert.equal(report.trailing_format_hint, 'TAR');
  const shortTerminator = tar.subarray(0, tar.length - 512);
  const compatible = inspectArchive(Buffer.concat([shortTerminator, Buffer.from('tail')]), { offset: 0, limit: 10 });
  assert.equal(compatible.layout.rows[0].name, 'fixture.txt');
  assert.equal(compatible.trailing_offset, shortTerminator.length);
  assert.equal(compatible.trailing_size, 4);
  assert.equal(compatible.warnings.length, 1);
  assert.throws(() => inspectArchive(tar.subarray(0, 1024), { offset: 0, limit: 10 }), /归档结束块/u);
});

function segment(seq, flags, text = '') {
  const tcp = Buffer.alloc(20);
  tcp.writeUInt16BE(50200, 0);
  tcp.writeUInt16BE(8080, 2);
  tcp.writeUInt32BE(seq, 4);
  tcp[12] = 0x50;
  tcp[13] = flags;
  return Buffer.concat([tcp, Buffer.from(text)]);
}

function cooked(payload, id = 0, frag = 0) {
  const head = Buffer.alloc(36);
  head.writeUInt16BE(0x0800, 14);
  head[16] = 0x45;
  head.writeUInt16BE(payload.length + 20, 18);
  head.writeUInt16BE(id, 20);
  head.writeUInt16BE(frag, 22);
  head[25] = 6;
  head.set([192, 0, 2, 1, 192, 0, 2, 2], 28);
  return Buffer.concat([head, payload]);
}

function pcap(frames, linkType = 113) {
  const head = Buffer.alloc(24);
  head.writeUInt32LE(0xa1b2c3d4);
  head.writeUInt16LE(2, 4);
  head.writeUInt16LE(4, 6);
  head.writeUInt32LE(65535, 16);
  head.writeUInt32LE(linkType, 20);
  return Buffer.concat([head, ...frames.flatMap(frame => {
    const row = Buffer.alloc(16);
    row.writeUInt32LE(1, 0);
    row.writeUInt32LE(234567, 4);
    row.writeUInt32LE(frame.length, 8);
    row.writeUInt32LE(frame.length, 12);
    return [row, frame];
  })]);
}

function loopback(payload, protocol, bigEndian = false) {
  const header = Buffer.alloc(4);
  if (bigEndian) header.writeUInt32BE(2);
  else header.writeUInt32LE(2);
  const ip = cooked(payload).subarray(16);
  ip[9] = protocol;
  return Buffer.concat([header, ip]);
}

function dnsTxtResponse(truncated = false) {
  const head = Buffer.from('123481800001000100000000', 'hex');
  const question = Buffer.from('076669787475726504746573740000100001', 'hex');
  const answer = Buffer.from('c00c001000010000003c0008036f6e650374776f', 'hex');
  const dns = Buffer.concat([head, question, truncated ? answer.subarray(0, -1) : answer]);
  const udp = Buffer.alloc(8);
  udp.writeUInt16BE(53);
  udp.writeUInt16BE(52000, 2);
  udp.writeUInt16BE(udp.length + dns.length, 4);
  return Buffer.concat([udp, dns]);
}

async function inspectCapture(bytes) {
  const cwd = await mkdtemp(join(tmpdir(), 'dsh-ctf-pcap-'));
  const file = join(cwd, 'test.pcap');
  try {
    await writeFile(file, bytes);
    return await pcapStream({ file_path: 'test.pcap' }, { cwd });
  } finally {
    await unlink(file).catch(() => {});
    await rmdir(cwd);
  }
}

test('BSD 回环双字节序、压缩 DNS 查询名、TXT 与捕获时间', async () => {
  const tcp = loopback(segment(10, 0x18, 'hello'), 6, true);
  const dns = loopback(dnsTxtResponse(), 17);
  const truncated = loopback(dnsTxtResponse(true), 17);
  const report = await inspectCapture(pcap([tcp, dns, truncated], 0));
  assert.equal(report.link_type, 0);
  assert.equal(report.flows[0].payload_text, 'hello');
  assert.equal(report.flows[0].first_packet.timestamp_utc, '1970-01-01T00:00:01.234567Z');
  assert.equal(report.flows[0].first_packet.file_offset, 24);
  assert.equal(report.dns_udp.responses, 2);
  const [complete, incomplete] = report.dns_udp.samples;
  assert.equal(complete.questions[0].qname, 'fixture.test');
  assert.deepEqual(complete.txt_answers[0].strings, ['one', 'two']);
  assert.equal(complete.txt_answers[0].name, 'fixture.test');
  assert.equal(complete.timestamp_utc, '1970-01-01T00:00:01.234567Z');
  assert.equal(incomplete.malformed, true);
});

function pcapngBlock(type, data) {
  const block = Buffer.alloc(12 + Math.ceil(data.length / 4) * 4);
  block.writeUInt32LE(type);
  block.writeUInt32LE(block.length, 4);
  data.copy(block, 8);
  block.writeUInt32LE(block.length, block.length - 4);
  return block;
}

test('PCAPNG DNS 样本使用接口时钟并区分没有时间戳的 SPB', async () => {
  const frame = loopback(dnsTxtResponse(), 17);
  const section = Buffer.alloc(16);
  section.writeUInt32LE(0x1a2b3c4d);
  section.writeUInt16LE(1, 4);
  section.writeBigInt64LE(-1n, 8);
  const iface = Buffer.from('00000000ffff000009000100090000000e0008000100000000000000', 'hex');
  const enhanced = Buffer.alloc(20);
  enhanced.writeUInt32LE(1500000001, 8);
  enhanced.writeUInt32LE(frame.length, 12);
  enhanced.writeUInt32LE(frame.length, 16);
  const simple = Buffer.alloc(4);
  simple.writeUInt32LE(frame.length);
  const bytes = Buffer.concat([pcapngBlock(0x0a0d0d0a, section), pcapngBlock(1, iface),
    pcapngBlock(6, Buffer.concat([enhanced, frame])), pcapngBlock(3, Buffer.concat([simple, frame]))]);
  const report = await inspectCapture(bytes);
  assert.equal(report.link_type, 0);
  assert.deepEqual(report.dns_udp.samples.map(sample => sample.timestamp_utc), ['1970-01-01T00:00:02.500000001Z', null]);
  const end_utc = '1970-01-01T00:00:02.500000001Z';
  const exclusive = inspectPcapBlocks(bytes, { offset: 0, limit: 8 }, parsePcapngQuery({ end_utc }));
  const inclusive = inspectPcapBlocks(bytes, { offset: 0, limit: 8 }, parsePcapngQuery({ end_utc, end_inclusive: true }));
  assert.equal(exclusive.packet_count, 0);
  assert.equal(inclusive.packet_count, 1);
  assert.equal(inclusive.file_packet_count, 2);
});

test('Linux SLL、坏帧、IPv4 乱序分片、相同四元组两次连接', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'dsh-ctf-pcap-'));
  const file = join(cwd, 'test.pcap');
  const tcp = segment(11, 0x18, 'alpha');
  try {
    await writeFile(file, pcap([cooked(segment(10, 2)), Buffer.from([1]),
      cooked(tcp.subarray(16), 10, 2), cooked(tcp.subarray(0, 16), 10, 0x2000),
      cooked(segment(16, 4)), cooked(segment(100, 2)), cooked(segment(101, 0x18, 'beta'))]));
    const report = await pcapStream({ file_path: 'test.pcap' }, { cwd });
    assert.equal(report.skipped.invalid_packet, 1);
    assert.equal(report.ip_fragments.reassembled, 1);
    assert.deepEqual(report.flows.map(flow => flow.payload_text), ['alpha', 'beta']);
    assert.notEqual(report.flows[0].connection_id, report.flows[1].connection_id);
  } finally {
    await unlink(file).catch(() => {});
    await rmdir(cwd);
  }
});

test('经典 PCAP 的坏记录与截断结尾在两个入口具有相同的诊断', async () => {
  const frame = loopback(segment(100, 0x18, 'fixture'), 6);
  const bytes = pcap([frame, frame], 0);
  bytes.writeUInt32LE(1, 24 + 12);
  const capture = Buffer.concat([bytes, Buffer.alloc(7)]);
  const layout = inspectPcapBlocks(capture, { offset: 0, limit: 8 });
  const streams = await inspectCapture(capture);
  for (const report of [layout, streams]) {
    assert.equal(report.status, 'partial');
    assert.equal(report.complete, false);
    assert.equal(report.packet_count, 1);
    assert.equal(report.packet_records, 2);
    assert.equal(report.malformed_packets, 1);
    assert.deepEqual(report.issues.map(issue => issue.code), ['invalid_packet', 'truncated_record']);
  }
  assert.deepEqual(streams.issues, layout.issues);
  assert.equal(streams.flows[0].payload_text, 'fixture');
});

test('PCAPNG 跳过引用未知接口的包，保留后续完整包', async () => {
  const frame = loopback(segment(100, 0x18, 'fixture'), 6);
  const section = Buffer.alloc(16);
  section.writeUInt32LE(0x1a2b3c4d);
  section.writeUInt16LE(1, 4);
  section.writeBigInt64LE(-1n, 8);
  const iface = Buffer.from('00000000ffff0000', 'hex');
  const packet = Buffer.alloc(20);
  packet.writeUInt32LE(frame.length, 12);
  packet.writeUInt32LE(frame.length, 16);
  const invalid = Buffer.from(packet);
  invalid.writeUInt32LE(1);
  const bytes = Buffer.concat([pcapngBlock(0x0a0d0d0a, section), pcapngBlock(1, iface),
    pcapngBlock(6, Buffer.concat([invalid, frame])), pcapngBlock(6, Buffer.concat([packet, frame]))]);
  const layout = inspectPcapBlocks(bytes, { offset: 0, limit: 8 });
  const streams = await inspectCapture(bytes);
  assert.equal(layout.complete, true);
  assert.equal(layout.status, 'partial');
  assert.equal(layout.packet_count, 1);
  assert.deepEqual(streams.issues, layout.issues);
  assert.equal(streams.flows[0].payload_text, 'fixture');
});

test('Flask 旧日志不被当作本次响应，隐式行缺少候选时保留证据不足', async () => {
  const file_path = 'route.py';
  const python = Buffer.from('def check():\n    return "ok"\n');
  const rawHttp = Buffer.from('local response');
  const sha256 = hash(python);
  const request = { method: 'GET', path: '/check', request_id: 'review' };
  const site = { file_path, sha256, line: 2 };
  const files = {
    normalizePath: path => path,
    readSource: async path => ({ bytes: path === file_path ? python : rawHttp }),
    result(id) { return reports.get(id); },
  };
  const http = { correlation: 'request_id', request, observations: [{ match: 'matched', status_code: 200,
    recorded_at: '2025-02-01T00:00:00Z', format: 'access_jsonl', source: { file_path: 'access.log', sha256: hash(rawHttp) } }] };
  const trace = { request, status: 'matched', match_count: 1, sources: [site],
    trace: { hook_count: 0, hooks: [], handler: { name: 'check', status_site_count: 1, status_sites: [{ status_code: 200, source: site, implicit: true }] } } };
  const a = hash('http');
  const b = hash('trace');
  const reports = new Map([[a, { tool: 'verify_http_evidence', report: http }], [b, { tool: 'trace_flask_route', report: trace }]]);
  const run = (line, timestamp) => verifyFlaskResponse({
    http_result_id: a, trace_result_id: b, observation_index: 0, file_path: 'events.jsonl',
  }, { ...files, readEvent: async () => ({
    bytes: Buffer.from(JSON.stringify({ ...request, timestamp, event: 'response_returned', status: 200, source: { ...site, line } }) + '\n'),
  }) });
  assert.equal((await run(2, '2025-01-01T00:00:00Z')).status, 'candidates');
  assert.equal((await run(2, '2025-02-01T00:00:00Z')).status, 'correlated');
  assert.equal((await run(3, '2025-02-01T00:00:00Z')).status, 'insufficient');
});

test('扩展工具声明全部必填字段，GDB 原命令入口在启动前拒绝', async () => {
  const tools = new Map();
  apply({ tools: { register(tool) { tools.set(tool.name, tool); } }, effect() {}, fs: {} }, {});
  for (const tool of tools.values()) {
    assert.ok(tool.parameters.required.every(name => Object.hasOwn(tool.parameters.properties, name)), tool.name);
  }
  const answer = JSON.parse(await tools.get('gdb_driver').execute({
    file_path: 'sample', action: 'script', commands: ['show version'],
  }, {}));
  assert.equal(answer.ok, false);
});
