import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, open, readFile, rm, stat as statFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path, { join } from 'node:path';
import { deflateSync } from 'node:zlib';
import test from 'node:test';
import { apply } from '../ctf-tools.js';
import { pcapStream } from '../pcap-stream.js';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const python = execFileSync(process.platform === 'win32' ? 'python' : 'python3',
  ['-c', 'import sys; print(sys.executable)'], { encoding: 'utf8' }).trim();

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(name, data) {
  const kind = Buffer.from(name);
  const size = Buffer.alloc(4);
  size.writeUInt32BE(data.length);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([kind, data])));
  return Buffer.concat([size, kind, data, crc]);
}

function grayPng(width, height, samples) {
  const raw = Buffer.alloc((width + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (width + 1)] = 0;
    for (let x = 0; x < width; x++) raw[y * (width + 1) + x + 1] = samples[y * width + x];
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 0;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', header), pngChunk('IDAT', deflateSync(raw)), pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

function storedZip(name, content) {
  const nameBytes = Buffer.from(name);
  const data = Buffer.from(content);
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

function toolContext(files, options = {}) {
  const cwd = options.cwd ?? 'D:/misc-capabilities-fixture';
  const cwdKey = cwd.replaceAll('\\', '/');
  const entries = new Map(Object.entries(files).map(([name, bytes]) => [name, { bytes: Buffer.from(bytes), version: 'v1' }]));
  const tools = new Map();
  const target = (name, options = {}) => {
    if (path.isAbsolute(name)) return { targetKey: name.replaceAll('\\', '/'), displayPath: name };
    const base = (options.cwd ?? cwd).replaceAll('\\', '/').replace(/[\\/]$/u, '');
    return { targetKey: `${base}/${name}`, displayPath: `${base}/${name}` };
  };
  const ctx = {
    tools: { register(tool) { tools.set(tool.name, tool); } },
    effect() {}, emit() {},
    workingDirectory: { async ensure() { return cwd; } },
    sandboxPolicy: { resolve() { return { mode: options.writable ? 'workspace-write' : 'read-only' }; } },
    fs: {
      async resolve(name, options) { return target(name, options); },
      contains(parent, child) {
        const base = parent.targetKey.replace(/[\\/]$/u, '');
        return child.targetKey === base || child.targetKey.startsWith(base + '/');
      },
      async lstat(name, options) {
        const resolved = target(name, options).targetKey;
        if ([...entries.keys()].some(key => resolved === `${cwdKey}/${key}`)) return { type: 'file' };
        try {
          const info = await statFile(resolved);
          return { type: info.isDirectory() ? 'directory' : info.isFile() ? 'file' : 'other' };
        } catch {
          return undefined;
        }
      },
      async stat(resolved) {
        const name = resolved.targetKey.slice(cwdKey.length + 1);
        const entry = entries.get(name);
        return entry ? { type: 'file', size: entry.bytes.length, version: entry.version } : null;
      },
      async readBytes(resolved) {
        return entries.get(resolved.targetKey.slice(cwdKey.length + 1))?.bytes;
      },
      async readByteRange(resolved, { offset, length }) {
        return entries.get(resolved.targetKey.slice(cwdKey.length + 1))?.bytes.subarray(offset, offset + length);
      },
    },
  };
  apply(ctx, { compact: true, pythonPath: python });
  return { tools, execution: { signal: new AbortController().signal, agent: { session: { header: { cwd }, id: 'misc-fixture' } } } };
}

async function call(tools, name, args, execution) {
  const text = await tools.get(name).execute(args, execution);
  return JSON.parse(text);
}

test('归档成员、PNG 连续位流和 PDF 附件可直接传给下一工具', async t => {
  const pillow = spawnSync(python, ['-c', 'import PIL'], { windowsHide: true });
  const pymupdf = spawnSync(python, ['-c', 'import pymupdf'], { windowsHide: true });
  if (pillow.status !== 0 || pymupdf.status !== 0) return t.skip('此运行环境缺少 Pillow 或 PyMuPDF。');

  const payload = grayPng(1, 1, [0x7f]);
  const bits = [...payload].flatMap(byte => Array.from({ length: 8 }, (_, index) => (byte >> (7 - index)) & 1));
  const png = grayPng(bits.length, 1, bits.map(bit => 0x80 | bit));
  const pdfScript = [
    'import sys, pymupdf',
    'data = sys.stdin.buffer.read()',
    'doc = pymupdf.open()',
    'doc.new_page()',
    'doc.embfile_add("payload.png", data, desc="fixture")',
    'sys.stdout.buffer.write(doc.tobytes())',
  ].join('\n');
  const pdf = spawnSync(python, ['-c', pdfScript], { input: png, windowsHide: true, maxBuffer: 2 * 1024 * 1024 });
  assert.equal(pdf.status, 0, pdf.stderr.toString());
  const dbScript = [
    'import sqlite3, sys',
    'db = sqlite3.connect(":memory:")',
    'db.execute("create table flags (value text)")',
    'db.execute("insert into flags values (?)", ("ctf{read_only}",))',
    'sys.stdout.buffer.write(db.serialize())',
  ].join('\n');
  const database = spawnSync(python, ['-c', dbScript], { windowsHide: true, maxBuffer: 2 * 1024 * 1024 });
  assert.equal(database.status, 0, database.stderr.toString());

  const fixtures = toolContext({
    'challenge.zip': storedZip('nested/payload.png', png),
    'challenge.pdf': pdf.stdout,
    'challenge.sqlite': database.stdout,
    'challenge.docx': storedZip('word/document.xml', '<w:document xmlns:w="urn:w"><w:t>office evidence</w:t></w:document>'),
  });
  const { tools, execution } = fixtures;

  const member = await call(tools, 'read_archive_member', { file_path: 'challenge.zip', member_index: 0 }, execution);
  assert.equal(member.member_sha256, sha256(png), JSON.stringify(member));
  const firstPage = await call(tools, 'read_png_pixels', {
    source_result_id: member.result_id, operation: 'bitstream', bit_index: 0, bit_offset: 0, bit_count: 64, bit_order: 'msb_first',
  }, execution);
  const secondPage = await call(tools, 'read_png_pixels', {
    source_result_id: member.result_id, operation: 'bitstream', bit_index: 0, bit_offset: 64,
    bit_count: (payload.length - 8) * 8, bit_order: 'msb_first',
  }, execution);
  assert.equal(firstPage.hex, payload.subarray(0, 8).toString('hex'));
  assert.equal(secondPage.hex, payload.subarray(8).toString('hex'));
  assert.equal(firstPage.padding_bits, 0);
  assert.equal(firstPage.source_evidence.member_sha256, sha256(png));
  const image = await call(tools, 'inspect_media', {
    kind: 'image', source_result_ids: [firstPage.result_id, secondPage.result_id],
  }, execution);
  assert.equal(image.format, 'PNG', JSON.stringify(image));
  assert.equal(image.width, 1);
  assert.equal(image.data_sha256, sha256(payload));
  const outOfOrder = await call(tools, 'inspect_media', {
    kind: 'image', source_result_ids: [secondPage.result_id, firstPage.result_id],
  }, execution);
  assert.equal(outOfOrder.ok, false);

  const pdfList = await call(tools, 'inspect_media', { file_path: 'challenge.pdf', kind: 'pdf', pdf_action: 'list_attachments' }, execution);
  assert.equal(pdfList.attachment_count, 1);
  const pdfAttachment = await call(tools, 'inspect_media', {
    file_path: 'challenge.pdf', kind: 'pdf', pdf_action: 'read_attachment', attachment_index: 0,
  }, execution);
  assert.equal(pdfAttachment.artifact_sha256, sha256(png));
  const embeddedImage = await call(tools, 'inspect_media', {
    kind: 'image', source_result_id: pdfAttachment.result_id,
  }, execution);
  assert.equal(embeddedImage.format, 'PNG');
  const rendered = await call(tools, 'inspect_media', {
    file_path: 'challenge.pdf', kind: 'pdf', pdf_action: 'render_page', page_offset: 0, render_dpi: 72,
  }, execution);
  const renderedImage = await call(tools, 'inspect_media', { kind: 'image', source_result_id: rendered.result_id }, execution);
  assert.equal(renderedImage.format, 'PNG');

  const sqlite = await call(tools, 'inspect_media', { file_path: 'challenge.sqlite', kind: 'sqlite', sqlite_table: 'flags' }, execution);
  assert.deepEqual(sqlite.rows, [['ctf{read_only}']]);
  const deniedWrite = await call(tools, 'inspect_media', {
    file_path: 'challenge.sqlite', kind: 'sqlite', sqlite_query: 'DELETE FROM flags',
  }, execution);
  assert.equal(deniedWrite.status, 'invalid');

  const office = await call(tools, 'inspect_media', { file_path: 'challenge.docx', kind: 'office' }, execution);
  assert.match(office.sections[0].text, /office evidence/u);
});

function wav24ExtensibleWithPng(payload, startFrame = 3) {
  const bits = [...payload].flatMap(byte => Array.from({ length: 8 }, (_, index) => (byte >> (7 - index)) & 1));
  const channels = 2;
  const frameCount = startFrame + bits.length + 2;
  const data = Buffer.alloc(frameCount * channels * 3);
  for (let frame = 0; frame < frameCount; frame++) {
    const left = 0x7fffff - frame;
    const right = frame >= startFrame && frame < startFrame + bits.length
      ? 0x100000 | bits[frame - startFrame] : 0x100000;
    for (const [channel, value] of [left, right].entries()) {
      const offset = (frame * channels + channel) * 3;
      data[offset] = value & 255;
      data[offset + 1] = (value >> 8) & 255;
      data[offset + 2] = (value >> 16) & 255;
    }
  }
  const fmt = Buffer.alloc(40);
  fmt.writeUInt16LE(0xfffe, 0);
  fmt.writeUInt16LE(channels, 2);
  fmt.writeUInt32LE(48000, 4);
  fmt.writeUInt32LE(48000 * channels * 3, 8);
  fmt.writeUInt16LE(channels * 3, 12);
  fmt.writeUInt16LE(24, 14);
  fmt.writeUInt16LE(24, 18);
  fmt.writeUInt32LE(3, 20);
  Buffer.from('0100000000001000800000aa00389b71', 'hex').copy(fmt, 24);
  const riff = Buffer.alloc(12);
  riff.write('RIFF', 0);
  riff.write('WAVE', 8);
  const fmtHead = Buffer.alloc(8);
  fmtHead.write('fmt ', 0);
  fmtHead.writeUInt32LE(fmt.length, 4);
  const dataHead = Buffer.alloc(8);
  dataHead.write('data', 0);
  dataHead.writeUInt32LE(data.length, 4);
  const bytes = Buffer.concat([riff, fmtHead, fmt, dataHead, data]);
  bytes.writeUInt32LE(bytes.length - 8, 4);
  return bytes;
}

test('24 位 WAVEFORMATEXTENSIBLE 可按时间段和声道提取，并把结果交给图像读取器', async t => {
  if (spawnSync(python, ['-c', 'import PIL'], { windowsHide: true }).status !== 0) return t.skip('此运行环境缺少 Pillow。');
  const payload = grayPng(1, 1, [0x2a]);
  const startFrame = 3;
  const fixtures = toolContext({ 'carrier.wav': wav24ExtensibleWithPng(payload, startFrame) });
  const { tools, execution } = fixtures;
  const audio = await call(tools, 'stego_audio', {
    file_path: 'carrier.wav', action: 'lsb', bit_index: 0, bit_order: 'msb_first',
    start_frame: startFrame, frame_count: payload.length * 8, channels: [1],
  }, execution);
  assert.equal(audio.bits_read, payload.length * 8);
  assert.equal(audio.hex, payload.toString('hex'));
  assert.equal(audio.start_frame, startFrame);
  assert.deepEqual(audio.selected_channels, [1]);
  assert.match(audio.result_id, /^[a-f0-9]{64}$/u);
  const image = await call(tools, 'inspect_media', { kind: 'image', source_result_id: audio.result_id }, execution);
  assert.equal(image.format, 'PNG');
  assert.equal(image.width, 1);
});

function pcm8Wav(samples, withInfo = false) {
  const fmt = Buffer.alloc(16);
  fmt.writeUInt16LE(1, 0);
  fmt.writeUInt16LE(1, 2);
  fmt.writeUInt32LE(48000, 4);
  fmt.writeUInt32LE(48000, 8);
  fmt.writeUInt16LE(1, 12);
  fmt.writeUInt16LE(8, 14);
  const chunk = (name, data) => {
    const header = Buffer.alloc(8);
    header.write(name, 0);
    header.writeUInt32LE(data.length, 4);
    return Buffer.concat([header, data, data.length % 2 ? Buffer.alloc(1) : Buffer.alloc(0)]);
  };
  const chunks = [chunk('fmt ', fmt)];
  if (withInfo) {
    const name = Buffer.from('fixture\0');
    const sub = Buffer.alloc(8);
    sub.write('INAM', 0);
    sub.writeUInt32LE(name.length, 4);
    chunks.push(chunk('LIST', Buffer.concat([Buffer.from('INFO'), sub, name])));
  }
  chunks.push(chunk('data', samples));
  const body = Buffer.concat([Buffer.from('WAVE'), ...chunks]);
  const header = Buffer.alloc(8);
  header.write('RIFF', 0);
  header.writeUInt32LE(body.length, 4);
  return Buffer.concat([header, body]);
}

test('WAV 信息、时间秒数、频谱图与模板写入路径可用；音频参数错误会被拦截', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'dsh-ctf-audio-'));
  try {
    const samples = Buffer.from(Array.from({ length: 512 }, (_, index) => 128 + Math.round(90 * Math.sin(index * Math.PI / 8))));
    const fixtures = toolContext({ 'fixture.wav': pcm8Wav(samples, true) }, { cwd, writable: true });
    const { tools, execution } = fixtures;
    const info = await call(tools, 'stego_audio', {
      file_path: 'fixture.wav', action: 'info', start_seconds: 0.001, duration_seconds: 0.002, channels: [0],
    }, execution);
    assert.equal(info.tags.INAM, 'fixture');
    assert.equal(info.start_frame, 48);
    assert.equal(info.end_frame, 144);
    assert.deepEqual(info.selected_channels, [0]);

    const spectrum = await call(tools, 'stego_audio', {
      file_path: 'fixture.wav', action: 'spectrum', fft_size: 256, start_frame: 0, frame_count: 256,
      path: 'spectrum.png',
    }, execution);
    assert.equal(spectrum.status, 'ok');
    assert.equal(spectrum.width, 1);
    assert.equal(spectrum.height, 128);
    assert.equal(spectrum.sha256, sha256(await readFile(join(cwd, 'spectrum.png'))));

    const template = await call(tools, 'crypto_solver', { action: 'template', kind: 'z3_bitvec' }, execution);
    assert.equal(template.status, 'ok');
    assert.equal(template.kind, 'z3_bitvec');

    const invalidOrder = await call(tools, 'stego_audio', {
      file_path: 'fixture.wav', action: 'lsb', bit_order: 'middle_first',
    }, execution);
    assert.equal(invalidOrder.ok, false);
    const conflict = await call(tools, 'stego_audio', {
      file_path: 'fixture.wav', action: 'lsb', start_frame: 1, start_seconds: 0.001,
    }, execution);
    assert.equal(conflict.ok, false);
    const offset = await call(tools, 'stego_audio', {
      file_path: 'fixture.wav', action: 'lsb', sample_offset: 1,
    }, execution);
    assert.equal(offset.ok, false);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

function pcapHeader(linkType = 113) {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4, 0);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(0, 16);
  header.writeUInt32LE(linkType, 20);
  return header;
}

function tcpFrame() {
  const frame = Buffer.alloc(57);
  frame.writeUInt16BE(0x0800, 14);
  frame[16] = 0x45;
  frame.writeUInt16BE(41, 18);
  frame[25] = 6;
  frame.set([192, 0, 2, 1, 192, 0, 2, 2], 28);
  frame.writeUInt16BE(50200, 36);
  frame.writeUInt16BE(8080, 38);
  frame.writeUInt32BE(10, 40);
  frame[48] = 0x50;
  frame[49] = 0x18;
  frame[56] = 0x41;
  return frame;
}

function pcapngBlock(type, data) {
  const size = 12 + Math.ceil(data.length / 4) * 4;
  const block = Buffer.alloc(size);
  block.writeUInt32LE(type, 0);
  block.writeUInt32LE(size, 4);
  data.copy(block, 8);
  block.writeUInt32LE(size, size - 4);
  return block;
}

async function writeLargeCapture(file, format) {
  const captureBytes = 13 * 1024 * 1024;
  const frame = Buffer.alloc(captureBytes);
  tcpFrame().copy(frame);
  const handle = await open(file, 'w');
  const digest = createHash('sha256');
  const write = async chunk => {
    digest.update(chunk);
    let offset = 0;
    while (offset < chunk.length) {
      const { bytesWritten } = await handle.write(chunk, offset, chunk.length - offset);
      offset += bytesWritten;
    }
  };
  try {
    if (format === 'PCAP') {
      await write(pcapHeader());
      for (let index = 0; index < 5; index++) {
        const record = Buffer.alloc(16);
        record.writeUInt32LE(1, 0);
        record.writeUInt32LE(index, 4);
        record.writeUInt32LE(frame.length, 8);
        record.writeUInt32LE(frame.length, 12);
        await write(record);
        await write(frame);
      }
    } else {
      const section = Buffer.alloc(16);
      section.writeUInt32LE(0x1a2b3c4d, 0);
      section.writeUInt16LE(1, 4);
      section.writeBigInt64LE(-1n, 8);
      await write(pcapngBlock(0x0a0d0d0a, section));
      const iface = Buffer.alloc(8);
      iface.writeUInt16LE(113, 0);
      await write(pcapngBlock(1, iface));
      for (let index = 0; index < 5; index++) {
        const header = Buffer.alloc(20);
        header.writeUInt32LE(index, 4);
        header.writeUInt32LE(frame.length, 12);
        header.writeUInt32LE(frame.length, 16);
        await write(pcapngBlock(6, Buffer.concat([header, frame])));
      }
    }
  } finally {
    await handle.close();
  }
  return digest.digest('hex');
}

test('经典 PCAP 与 PCAPNG 超过 64 MiB 时分块读取并保留哈希和过滤范围', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'dsh-ctf-stream-large-'));
  try {
    for (const format of ['PCAP', 'PCAPNG']) {
      const file = join(cwd, format + '.capture');
      const expectedHash = await writeLargeCapture(file, format);
      const report = await pcapStream({ file_path: format + '.capture', filter: {
        protocol: 'tcp', src_ip: '192.0.2.1', src_port: 50200, dst_port: 8080,
      } }, { cwd });
      assert.equal(report.format, format);
      assert.equal(report.sha256, expectedHash);
      assert.equal(report.capture_scope.packet_records, 5);
      assert.equal(report.capture_scope.filtered, true);
      assert.equal(report.capture_scope.filtered_ipv4_packets, 0);
      assert.equal(report.tcp_packets, 5);
      const filtered = await pcapStream({ file_path: format + '.capture', filter: { dst_port: 80 } }, { cwd });
      assert.equal(filtered.tcp_packets, 0);
      assert.equal(filtered.capture_scope.filtered_ipv4_packets, 5);
    }
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
