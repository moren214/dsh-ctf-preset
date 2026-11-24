import { createHash } from 'node:crypto';
import { ToolError } from './tool-errors.js';

const BLOCK_BYTES = 1024 * 1024;
const DEFAULT_SCAN_BYTES = 32 * BLOCK_BYTES;
const MAX_SCAN_BYTES = 64 * BLOCK_BYTES;
const DEFAULT_MATCHES = 16;
const MAX_MATCHES = 48;
const MAX_PATTERN_BYTES = 256;
const MAX_PATTERN_CHARS = 3 * MAX_PATTERN_BYTES;
const MODES = ['signatures', 'hex', 'utf8'];

function needle(bytes, signature) {
  return { bytes, signature, sha256: createHash('sha256').update(bytes).digest('hex') };
}

// These are candidate signatures. A matching header alone does not validate a container.
const SIGNATURES = [
  ['zip', '504b0304'],
  ['zip_end', '504b0506'],
  ['gzip', '1f8b08'],
  ['7z', '377abcaf271c'],
  ['rar4', '526172211a0700'],
  ['rar5', '526172211a070100'],
  ['png', '89504e470d0a1a0a'],
  ['jpeg', 'ffd8ff'],
  ['pdf', '255044462d'],
  ['sqlite', '53514c69746520666f726d6174203300'],
  ['elf', '7f454c46'],
  ['wasm', '0061736d'],
  ['pcap', 'd4c3b2a1'],
  ['pcap', 'a1b2c3d4'],
  ['pcap', '4d3cb2a1'],
  ['pcap', 'a1b23c4d'],
  ['pcapng', '0a0d0d0a'],
].map(([format, hex]) => needle(Buffer.from(hex, 'hex'), format));

export const BINARY_SCAN_PROPERTIES = {
  mode: { type: 'string', enum: MODES, default: 'signatures', description: 'signatures/hex/utf8。' },
  pattern: { type: 'string', maxLength: MAX_PATTERN_CHARS, description: 'hex/utf8 匹配模式。' },
  byte_offset: { type: 'integer', minimum: 0, default: 0 },
  scan_bytes: { type: 'integer', minimum: 1, maximum: MAX_SCAN_BYTES, default: DEFAULT_SCAN_BYTES },
  max_matches: { type: 'integer', minimum: 1, maximum: MAX_MATCHES, default: DEFAULT_MATCHES },
  hash_scope: { type: 'string', enum: ['range', 'file'] },
};

function parsePattern(mode, pattern) {
  if (mode === 'signatures') {
    if (pattern !== undefined) throw new ToolError('unsupported', '查找指定内容时请设置 mode 为 hex 或 utf8。');
    return SIGNATURES;
  }
  if (typeof pattern !== 'string' || pattern.length === 0 || pattern.length > MAX_PATTERN_CHARS) {
    throw new ToolError('encoding', 'pattern 须包含 1 至 256 字节的匹配内容。');
  }
  const value = mode === 'hex' ? pattern.replace(/\s+/gu, '') : pattern;
  if (mode === 'hex' && !/^(?:[0-9a-f]{2})+$/iu.test(value)) {
    throw new ToolError('encoding', 'hex 模式按两位十六进制表示一个字节，例如 50 4b 03 04。');
  }
  const bytes = Buffer.from(value, mode);
  if (bytes.length > MAX_PATTERN_BYTES || (mode === 'utf8' && bytes.toString('utf8') !== value)) {
    throw new ToolError('encoding', '匹配内容须是有效编码，且最多 256 字节。');
  }
  return [needle(bytes)];
}

export function parseBinaryScan(args) {
  const {
    mode = 'signatures', pattern, byte_offset: offset = 0,
    scan_bytes: scanBytes = DEFAULT_SCAN_BYTES, max_matches: maxMatches = DEFAULT_MATCHES,
    hash_scope: hashScope,
  } = args;
  if (!MODES.includes(mode) || (hashScope !== undefined && !['range', 'file'].includes(hashScope))) {
    throw new ToolError('unsupported', 'mode 须为 signatures、hex 或 utf8，hash_scope 须为 range 或 file。');
  }
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(scanBytes)
    || scanBytes < 1 || scanBytes > MAX_SCAN_BYTES || !Number.isSafeInteger(maxMatches)
    || maxMatches < 1 || maxMatches > MAX_MATCHES) {
    throw new ToolError('size', '请输入非负偏移、1 字节至 64 MiB 的扫描范围和 1 至 48 的匹配上限。');
  }
  return { mode, offset, scanBytes, maxMatches, hashScope, needles: parsePattern(mode, pattern) };
}

function earliestMatch(cursors, blockLength) {
  let earliest;
  for (const cursor of cursors) {
    if (cursor.index >= 0 && cursor.index < blockLength && (earliest === undefined || cursor.index < earliest.index)) {
      earliest = cursor;
    }
  }
  return earliest;
}

export async function scanBinary({ size, read }, { mode, offset, scanBytes, maxMatches, needles }, signal) {
  if (offset > size) throw new ToolError('size', 'byte_offset 超出了原件大小。');
  const end = offset + Math.min(size - offset, scanBytes);
  const lookahead = Math.max(...needles.map(item => item.bytes.length)) - 1;
  const matches = [];
  function report(stop, stopReason) {
    return {
      mode, byte_offset: offset, scanned_byte_length: stop - offset,
      matches, stop_reason: stopReason, next_byte_offset: stop < size ? stop : null,
    };
  }

  for (let start = offset; start < end;) {
    signal?.throwIfAborted();
    const blockLength = Math.min(end - start, BLOCK_BYTES);
    // Inspect each start position once, with enough lookahead for a straddling pattern.
    const chunk = await read(start, Math.min(size - start, blockLength + lookahead));
    const cursors = needles.map(item => ({ item, index: chunk.indexOf(item.bytes) }));
    for (let match = earliestMatch(cursors, blockLength); match; match = earliestMatch(cursors, blockLength)) {
      const byteOffset = start + match.index;
      if (matches.length === maxMatches) return report(byteOffset, 'match_limit');
      const { bytes, signature, sha256 } = match.item;
      matches.push({
        byte_offset: byteOffset, byte_length: bytes.length, range_sha256: sha256,
        ...(signature === undefined ? {} : { signature }),
      });
      match.index = chunk.indexOf(bytes, match.index + 1);
    }
    start += blockLength;
  }
  return report(end, end === size ? 'eof' : 'scan_limit');
}
