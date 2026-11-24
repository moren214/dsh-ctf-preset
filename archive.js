import { addAbortSignal } from 'node:stream';
import { createGunzip, createInflate, createInflateRaw, gunzipSync, inflateRawSync, inflateSync } from 'node:zlib';
import { checkRange, inPage, label, MAX_ARCHIVE_MEMBER_BYTES, MAX_ATTACHMENT_BYTES, MAX_MEMBER_NAME, page } from './attachment-layout.js';
import { inspectZip, isZip } from './zip-directory.js';

const SAFE_INTEGER = BigInt(Number.MAX_SAFE_INTEGER);
const TAR_BLOCK = 512;
const TAR_END = Buffer.alloc(2 * TAR_BLOCK);
const TAR_ZERO_BLOCK = TAR_END.subarray(0, TAR_BLOCK);
const USTAR = Buffer.from('ustar\0');
const GNU_TAR = Buffer.from('ustar ');
const GNU_SPARSE_PREFIX = 'GNU.sparse.';
const TAR_TYPES = {
  0: 'file', 1: 'hard_link', 2: 'symbolic_link', 3: 'character_device',
  4: 'block_device', 5: 'directory', 6: 'fifo', 7: 'contiguous_file',
};
const TAR_SPARSE = { status: 'unsupported', reason: '当前 TAR 目录检查不支持 GNU 稀疏条目。' };

function isTar(bytes) {
  const magic = bytes.subarray(257, 263);
  return magic.equals(USTAR) || magic.equals(GNU_TAR) || bytes.subarray(0, TAR_END.length).equals(TAR_END);
}

function tarNumber(bytes, binary = true) {
  if (binary && bytes[0] === 0x80) {
    let value = 0n;
    for (const byte of bytes.subarray(1)) value = (value << 8n) + BigInt(byte);
    if (value <= SAFE_INTEGER) return Number(value);
  } else {
    const value = bytes.toString('latin1').replace(/^[\0 ]+|[\0 ]+$/gu, '');
    if (value === '') return 0;
    if (/^[0-7]+$/u.test(value)) return Number.parseInt(value, 8);
  }
  throw new Error('附件结构无效：TAR 数值字段格式不受支持或超出范围。');
}

function tarText(bytes) {
  const preview = bytes.subarray(0, MAX_MEMBER_NAME * 4);
  const end = preview.indexOf(0);
  return label((end < 0 ? preview : preview.subarray(0, end)).toString('utf8'), MAX_MEMBER_NAME);
}

function readPax(data, fields) {
  let cursor = 0;
  while (cursor < data.length) {
    const lengthEnd = data.subarray(cursor, cursor + 9).indexOf(0x20);
    if (lengthEnd < 1) throw new Error('附件结构无效：PAX 扩展长度字段无效。');
    const digits = data.toString('latin1', cursor, cursor + lengthEnd);
    if (!/^[1-9][0-9]*$/u.test(digits)) {
      throw new Error('附件结构无效：PAX 扩展长度字段无效。');
    }
    const size = Number(digits);
    checkRange(data.length, cursor, size, 'PAX 扩展记录');
    const start = cursor + lengthEnd + 1;
    const end = cursor + size;
    if (end <= start || data[end - 1] !== 0x0a) throw new Error('附件结构无效：PAX 扩展记录不完整。');
    const pair = data.subarray(start, end - 1);
    const equals = pair.indexOf(0x3d);
    if (equals < 1) throw new Error('附件结构无效：PAX 元数据缺少键值分隔符。');
    const key = pair.toString('latin1', 0, Math.min(GNU_SPARSE_PREFIX.length, equals));
    if (key === GNU_SPARSE_PREFIX) return false;
    if (key === 'path') fields.path = pair.length > equals + 1 ? tarText(pair.subarray(equals + 1)) : null;
    if (key === 'size') {
      const value = pair.toString('latin1', equals + 1, equals + 18);
      const memberSize = Number(value);
      if (value.length > 16 || !/^[0-9]*$/u.test(value) || !Number.isSafeInteger(memberSize)) {
        throw new Error('附件结构无效：PAX 条目大小字段无效。');
      }
      fields.size = value === '' ? null : memberSize;
    }
    cursor = end;
  }
  return true;
}

function tarHeader(bytes, cursor) {
  const header = bytes.subarray(cursor, cursor + TAR_BLOCK);
  const checksum = tarNumber(header.subarray(148, 156), false);
  let computed = 0;
  for (let index = 0; index < TAR_BLOCK; index++) {
    computed += index >= 148 && index < 156 ? 32 : header[index];
  }
  if (checksum !== computed) throw new Error('附件结构无效：TAR 条目头校验和不匹配。');
  return header;
}

function inspectTar(bytes, paging, format) {
  const globalFields = {};
  let memberFields = {};
  let awaitingMember = false;
  let cursor = 0;
  let endBlocks;
  let total = 0;
  const rows = [];
  for (;;) {
    checkRange(bytes.length, cursor, TAR_BLOCK, 'TAR 条目头或归档结束块');
    if (bytes.subarray(cursor, cursor + TAR_BLOCK).equals(TAR_ZERO_BLOCK)) {
      if (awaitingMember) throw new Error('附件结构无效：TAR 扩展条目不完整。');
      endBlocks = bytes.subarray(cursor, cursor + TAR_END.length).equals(TAR_END) ? 2 : 1;
      break;
    }
    const header = tarHeader(bytes, cursor);
    const flag = String.fromCharCode(header[156] || 0x30);
    if (flag === 'S') return { format, ...TAR_SPARSE };
    const extension = ['x', 'g', 'L', 'K'].includes(flag);
    const headerSize = tarNumber(header.subarray(124, 136));
    const paxSize = Object.hasOwn(memberFields, 'size') ? memberFields.size : globalFields.size;
    const size = extension ? headerSize : (paxSize ?? headerSize);
    const data = cursor + TAR_BLOCK;
    const padded = Math.ceil(size / TAR_BLOCK) * TAR_BLOCK;
    checkRange(bytes.length, data, padded, 'TAR 条目内容及填充');

    if (extension) {
      if (flag === 'g' || flag === 'x') {
        if (!readPax(bytes.subarray(data, data + size), flag === 'g' ? globalFields : memberFields)) {
          return { format, ...TAR_SPARSE };
        }
      } else if (flag === 'L') {
        memberFields.path = tarText(bytes.subarray(data, data + size));
      }
      if (flag !== 'g') awaitingMember = true;
    } else {
      if (inPage(total, paging)) {
        const prefix = header.subarray(257, 263).equals(USTAR) ? tarText(header.subarray(345, 500)) : '';
        const shortName = tarText(header.subarray(0, 100));
        const paxPath = Object.hasOwn(memberFields, 'path') ? memberFields.path : globalFields.path;
        const name = paxPath ?? (prefix ? prefix + '/' + shortName : shortName);
        rows.push({ member_index: total, name: label(name, MAX_MEMBER_NAME),
          ...(name.length > MAX_MEMBER_NAME ? { name_truncated: true } : {}),
          type: TAR_TYPES[flag] ?? 'unknown', size, header_offset: cursor });
      }
      memberFields = {};
      awaitingMember = false;
      total++;
    }
    cursor = data + padded;
  }
  const end = cursor + endBlocks * TAR_BLOCK;
  let trailing = end;
  while (trailing + TAR_BLOCK <= bytes.length && bytes.subarray(trailing, trailing + TAR_BLOCK).equals(TAR_ZERO_BLOCK)) {
    trailing += TAR_BLOCK;
  }
  return {
    format,
    status: 'ok',
    offset_space: ['TAR.GZ', 'TAR.ZLIB', 'TAR.DEFLATE', 'TAR.BZIP2', 'TAR.XZ'].includes(format) ? 'uncompressed' : 'file',
    archive_end: end,
    ...(endBlocks === 1 ? { warnings: ['TAR 只有一个全零结束块，按非标准归档读取。'] } : {}),
    ...(trailing < bytes.length ? {
      trailing_offset: trailing, trailing_size: bytes.length - trailing,
      ...(isTar(bytes.subarray(trailing)) ? { trailing_format_hint: 'TAR' } : {}),
    } : {}),
    layout: page('members', total, rows, paging.offset),
  };
}

function isGzip(bytes) {
  return bytes[0] === 0x1f && bytes[1] === 0x8b;
}

function isZlib(bytes) {
  if (bytes.length < 2) return false;
  const method = bytes[0] & 0x0f;
  const windowSize = bytes[0] >>> 4;
  return method === 8 && windowSize <= 7 && ((bytes[0] << 8) | bytes[1]) % 31 === 0;
}

function compressionKind(bytes, formatHint) {
  if (formatHint === 'zlib' || formatHint === 'deflate_raw') return formatHint;
  if (isGzip(bytes)) return 'gzip';
  if (isZlib(bytes)) return 'zlib';
  return undefined;
}

function compressedFormat(kind, payload) {
  if (!isTar(payload)) return kind;
  return { gzip: 'TAR.GZ', zlib: 'TAR.ZLIB', deflate_raw: 'TAR.DEFLATE' }[kind];
}

function decompressBuffer(bytes, kind) {
  if (kind === 'gzip') return gunzipSync(bytes, { maxOutputLength: MAX_ATTACHMENT_BYTES });
  if (kind === 'zlib') return inflateSync(bytes, { maxOutputLength: MAX_ATTACHMENT_BYTES });
  return inflateRawSync(bytes, { maxOutputLength: MAX_ATTACHMENT_BYTES });
}

function unpackTarOrCompressed(bytes, formatHint) {
  if (formatHint === undefined && isTar(bytes)) return { format: 'TAR', payload: bytes };
  const kind = compressionKind(bytes, formatHint);
  if (kind === undefined) return undefined;
  let payload;
  try {
    payload = decompressBuffer(bytes, kind);
  } catch (error) {
    if (error.code === 'ERR_BUFFER_TOO_LARGE') throw new Error('解压后的数据超过 32 MiB。');
    throw new Error('附件结构无效：压缩流无法读取或校验失败。');
  }
  return { format: compressedFormat(kind, payload), payload };
}

function gzipMember(payload) {
  return { member_index: 0, name: 'payload', type: 'file', size: payload.length };
}

export function inspectArchive(bytes, paging, formatHint) {
  if (formatHint === undefined && isZip(bytes)) return inspectZip(bytes, paging);
  const archive = unpackTarOrCompressed(bytes, formatHint);
  if (archive === undefined) return undefined;
  const { format, payload } = archive;
  if (!['gzip', 'zlib', 'deflate_raw'].includes(format)) return inspectTar(payload, paging, format);
  const rows = inPage(0, paging) ? [gzipMember(payload)] : [];
  return { format, status: 'ok', offset_space: 'uncompressed', layout: page('members', 1, rows, paging.offset) };
}

export function inspectDecompressedStream(bytes, paging, format) {
  if (isTar(bytes)) return inspectTar(bytes, paging, 'TAR.' + format.toUpperCase());
  const rows = inPage(0, paging) ? [gzipMember(bytes)] : [];
  return { format, status: 'ok', offset_space: 'uncompressed', layout: page('members', 1, rows, paging.offset) };
}

async function unpackCompressedMember(bytes, kind, signal) {
  signal?.throwIfAborted();
  const stream = kind === 'gzip' ? createGunzip()
    : kind === 'zlib' ? createInflate() : createInflateRaw();
  if (signal) addAbortSignal(signal, stream);
  let size = 0;
  let format;
  const chunks = [];
  stream.end(bytes);
  try {
    for await (const chunk of stream) {
      chunks.push(chunk);
      size += chunk.length;
      if (format === undefined && size >= TAR_END.length) {
        format = compressedFormat(kind, Buffer.concat(chunks, size));
      }
      if (format === kind && size > MAX_ARCHIVE_MEMBER_BYTES) throw new Error('归档成员解压后须在 1 MiB 内。');
      if (format !== kind && size > MAX_ATTACHMENT_BYTES) throw new Error('解压后的 TAR 超过 32 MiB。');
    }
  } catch (error) {
    signal?.throwIfAborted();
    if (error.code?.startsWith('Z_')) throw new Error('附件结构无效：压缩流无法读取或校验失败。');
    throw error;
  }
  const payload = Buffer.concat(chunks, size);
  return { format: format ?? compressedFormat(kind, payload), payload };
}

export async function readTarOrCompressedMember(bytes, memberIndex, signal, formatHint) {
  const kind = compressionKind(bytes, formatHint);
  const archive = kind !== undefined ? await unpackCompressedMember(bytes, kind, signal)
    : isTar(bytes) ? { format: 'TAR', payload: bytes } : undefined;
  if (archive === undefined) return undefined;
  const { format, payload } = archive;
  if (format === kind) {
    if (memberIndex !== 0) throw new Error('压缩的单文件使用 member_index 0。');
    return { format, name: gzipMember(payload).name, bytes: payload };
  }
  const report = inspectTar(payload, { offset: memberIndex, limit: 1 }, format);
  if (report.status !== 'ok') throw new Error(report.reason);
  const [member] = report.layout.rows;
  if (member === undefined) throw new Error('member_index 超出归档目录范围。');
  if (!['file', 'contiguous_file'].includes(member.type)) throw new Error('请选择 TAR 中的普通文件成员。');
  if (member.size > MAX_ARCHIVE_MEMBER_BYTES) throw new Error('归档成员解压后须在 1 MiB 内。');
  const contentOffset = member.header_offset + TAR_BLOCK;
  return { format, name: member.name, bytes: payload.subarray(contentOffset, contentOffset + member.size) };
}

export async function readDecompressedStreamMember(bytes, memberIndex, signal, format) {
  if (isTar(bytes)) {
    const member = await readTarOrCompressedMember(bytes, memberIndex, signal);
    if (member === undefined) return undefined;
    return { ...member, format: 'TAR.' + format.toUpperCase() };
  }
  if (memberIndex !== 0) throw new Error('压缩的单文件使用 member_index 0。');
  if (bytes.length > MAX_ARCHIVE_MEMBER_BYTES) throw new Error('压缩的单文件成员解压后须在 1 MiB 内。');
  return { format, name: gzipMember(bytes).name, bytes };
}
