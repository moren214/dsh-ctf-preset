import { createHash } from 'node:crypto';
import { inspectArchive } from './archive.js';
import { checkRange, inPage, label, page } from './attachment-layout.js';
import { inspectCapture } from './capture.js';
import { inspectElf } from './elf.js';
import { inspectImage } from './image-metadata.js';

const ELF_MAGIC = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);
const WASM_MAGIC = Buffer.from([0x00, 0x61, 0x73, 0x6d]);
const WASM_SECTIONS = [
  'custom', 'type', 'import', 'function', 'table', 'memory', 'global',
  'export', 'start', 'element', 'code', 'data', 'data_count', 'tag',
];

function hex(value) {
  return `0x${value.toString(16)}`;
}

export function readPeHeader(bytes) {
  const format = 'PE';
  checkRange(bytes.length, 0, 64, 'DOS 文件头');
  const pe = bytes.readUInt32LE(0x3c);
  checkRange(bytes.length, pe, 24, 'PE 文件头');
  if (pe < 64 || bytes.readUInt32LE(pe) !== 0x00004550) {
    return { format: 'MZ', status: 'unsupported', reason: 'DOS 文件头没有指向受支持的 PE 签名。' };
  }
  const machine = bytes.readUInt16LE(pe + 4);
  const total = bytes.readUInt16LE(pe + 6);
  const optionalSize = bytes.readUInt16LE(pe + 20);
  const flags = bytes.readUInt16LE(pe + 22);
  const optional = pe + 24;
  checkRange(bytes.length, optional, optionalSize, 'PE 可选头');
  if (optionalSize < 2) throw new Error('附件结构无效：PE 可选头缺失。');
  const magic = bytes.readUInt16LE(optional);
  if (magic !== 0x10b && magic !== 0x20b) {
    return { format, status: 'unsupported', reason: '当前检查覆盖 PE32 和 PE32+。' };
  }
  if (optionalSize < (magic === 0x10b ? 96 : 112)) throw new Error('附件结构无效：PE 可选头长度不足。');
  const entry = bytes.readUInt32LE(optional + 16);
  const firstSection = optional + optionalSize;
  checkRange(bytes.length, firstSection, total * 40, 'PE 节表');
  const imageBase = magic === 0x10b ? BigInt(bytes.readUInt32LE(optional + 28)) : bytes.readBigUInt64LE(optional + 24);
  return { format, status: 'ok', magic, machine, flags, total, entry, optional, firstSection, imageBase, headerSize: bytes.readUInt32LE(optional + 60) };
}

export function* peSections(bytes, { firstSection, total }) {
  for (let index = 0; index < total; index++) {
    const start = firstSection + index * 40;
    const virtualSize = bytes.readUInt32LE(start + 8);
    const rva = bytes.readUInt32LE(start + 12);
    const rawSize = bytes.readUInt32LE(start + 16);
    const rawOffset = bytes.readUInt32LE(start + 20);
    const characteristics = bytes.readUInt32LE(start + 36);
    if (rawSize > 0) checkRange(bytes.length, rawOffset, rawSize, 'PE 节数据');
    const name = label(bytes.subarray(start, start + 8).toString('latin1').split('\0', 1)[0]);
    yield { index, start, name, virtualSize, rva, rawSize, rawOffset, characteristics };
  }
}

function inspectPe(bytes, paging) {
  const header = readPeHeader(bytes);
  if (header.status !== 'ok') return header;
  const { format, magic, machine, flags, total, entry, optional } = header;
  const rows = [];
  const entryOffsets = new Set();
  for (const { index, name, virtualSize, rva, rawSize, rawOffset, characteristics } of peSections(bytes, header)) {
    const displacement = entry - rva;
    if (entry !== 0 && displacement >= 0 && displacement < Math.min(rawSize, virtualSize || rawSize)) {
      entryOffsets.add(rawOffset + displacement);
    }
    if (inPage(index, paging)) {
      rows.push({
        name,
        rva: hex(rva),
        virtual_size: virtualSize,
        file_offset: rawSize === 0 ? null : rawOffset,
        file_size: rawSize,
        executable: (characteristics & 0x20000000) !== 0,
      });
    }
  }
  return {
    format,
    status: 'ok',
    variant: magic === 0x10b ? 'PE32' : 'PE32+',
    machine: ({ 0x14c: 'x86', 0x8664: 'x86-64', 0x1c4: 'ARM', 0xaa64: 'AArch64' })[machine] ?? hex(machine),
    dll: (flags & 0x2000) !== 0,
    entry_rva: hex(entry),
    entry_file_offset: entryOffsets.size === 1 ? entryOffsets.values().next().value : null,
    subsystem: bytes.readUInt16LE(optional + 68),
    layout: page('sections', total, rows, paging.offset),
  };
}

function wasmSize(bytes, start) {
  let result = 0;
  for (let index = 0; index < 5; index++) {
    const offset = start + index;
    checkRange(bytes.length, offset, 1, 'WebAssembly 节大小');
    const byte = bytes[offset];
    if (index === 4 && byte > 15) break;
    result += (byte & 0x7f) * 2 ** (index * 7);
    if ((byte & 0x80) === 0) return { size: result, payload: offset + 1 };
  }
  throw new Error('附件结构无效：WebAssembly 节大小不是有效的 varuint32。');
}

export function wasmVersion(bytes) {
  checkRange(bytes.length, 0, 8, 'WebAssembly 文件头');
  return bytes.readUInt32LE(4);
}

export function* wasmSections(bytes) {
  let index = 0;
  let cursor = 8;
  while (cursor < bytes.length) {
    if (index >= 65536) throw new Error('WebAssembly 节数量超出检查上限。');
    const id = bytes[cursor];
    const { size, payload } = wasmSize(bytes, cursor + 1);
    checkRange(bytes.length, payload, size, 'WebAssembly 节内容');
    yield { index, id, name: WASM_SECTIONS[id] ?? 'unknown', start: cursor, payload, size };
    cursor = payload + size;
    index++;
  }
}

function inspectWasm(bytes, paging) {
  const format = 'WebAssembly';
  const version = wasmVersion(bytes);
  if (version !== 1) return { format, status: 'unsupported', version, reason: '当前支持 WebAssembly core module 版本 1。' };
  let total = 0;
  const rows = [];
  for (const { index, id, name, payload, size } of wasmSections(bytes)) {
    if (inPage(index, paging)) rows.push({ id, name, file_offset: payload, file_size: size });
    total++;
  }
  return { format, status: 'ok', version, layout: page('sections', total, rows, paging.offset) };
}

export function inspectAttachment(bytes, paging, pcapngQuery, formatHint) {
  const prefix = bytes.subarray(0, 4);
  if (pcapngQuery === undefined && prefix.equals(ELF_MAGIC)) return { status: 'ok', ...inspectElf(bytes, paging) };
  let report;
  if (pcapngQuery !== undefined) {
    report = inspectCapture(bytes, paging, pcapngQuery);
  } else if (formatHint === 'zlib' || formatHint === 'deflate_raw') {
    report = inspectArchive(bytes, paging, formatHint);
  } else if (prefix.equals(WASM_MAGIC)) {
    report = inspectWasm(bytes, paging);
  } else {
    report = inspectImage(bytes, paging) ?? inspectCapture(bytes, paging) ?? inspectArchive(bytes, paging, formatHint);
    if (report === undefined && bytes[0] === 0x4d && bytes[1] === 0x5a) report = inspectPe(bytes, paging);
  }
  report ??= {
    format: 'unknown', status: 'unsupported',
    reason: '可检查 PNG、JPEG、ELF、PE、ZIP、ZIP64、7z、RAR、TAR、TAR.GZ、gzip、zlib、bzip2、xz 和 raw Deflate（需指定格式），以及 PCAP、PCAPNG 和 WebAssembly。未知格式可使用 read_binary_range。',
  };
  return { ...report, size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
}
