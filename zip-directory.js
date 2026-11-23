import { crc32, inflateRawSync } from 'node:zlib';
import { checkRange, label, MAX_ARCHIVE_MEMBER_BYTES, MAX_ATTACHMENT_BYTES, MAX_MEMBER_NAME, page } from './attachment-layout.js';

const ZIP_LOCAL = 0x04034b50;
const ZIP_END = 0x06054b50;
const ZIP_SPANNED = 0x08074b50;
const ZIP_CENTRAL = 0x02014b50;
const ZIP_SIGNATURE = 0x05054b50;
const ZIP64_END = 0x06064b50;
const ZIP64_LOCATOR = 0x07064b50;
const ZIP_SPLIT = { format: 'ZIP', status: 'unsupported', reason: '归档目录检查支持单卷 ZIP 和 ZIP64。' };
const U32_MAX = 0xffffffff;
const U16_MAX = 0xffff;
const SAFE_INTEGER = BigInt(Number.MAX_SAFE_INTEGER);
const LOCAL_HEADER_BYTES = 30;
const CENTRAL_HEADER_BYTES = 46;
const ZIP64_END_BYTES = 56;
const ZIP64_LOCATOR_BYTES = 20;
const ZIP_END_BYTES = 22;
const MAX_TRAILING_BYTES = 1024 * 1024;
const ZIP_TAIL_BYTES = ZIP_END_BYTES + U16_MAX + ZIP64_LOCATOR_BYTES + MAX_TRAILING_BYTES;
const ZIP_END_SIGNATURE = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
const MAX_FOOTER_CANDIDATES = 64;

export function isZip(bytes) {
  return bytes.length >= 4 && [ZIP_LOCAL, ZIP_END, ZIP_SPANNED, ZIP64_END].includes(bytes.readUInt32LE(0));
}

function* zipEnds(bytes) {
  const minimum = Math.max(0, bytes.length - ZIP_TAIL_BYTES);
  let cursor = bytes.length - ZIP_END_BYTES;
  let candidates = 0;
  while (cursor >= minimum && candidates < MAX_FOOTER_CANDIDATES) {
    const end = bytes.lastIndexOf(ZIP_END_SIGNATURE, cursor);
    if (end < minimum) return;
    const archiveEnd = end + ZIP_END_BYTES + bytes.readUInt16LE(end + 20);
    if (archiveEnd <= bytes.length && bytes.length - archiveEnd <= MAX_TRAILING_BYTES) {
      candidates++;
      yield { end, archiveEnd };
    }
    cursor = end - 1;
  }
}

function locateDirectory(tail, tailOffset, { end, archiveEnd }, embedded) {
  const metadata = { archiveEnd: tailOffset + archiveEnd, trailingSize: tail.length - archiveEnd };
  const locator = end - ZIP64_LOCATOR_BYTES;
  if (locator >= 0 && tail.readUInt32LE(locator) === ZIP64_LOCATOR) {
    if (tail.readUInt32LE(locator + 4) !== 0 || tail.readUInt32LE(locator + 16) !== 1) return null;
    const locatorOffset = tailOffset + locator;
    const recordOffset = tail.readBigUInt64LE(locator + 8);
    if (recordOffset > BigInt(locatorOffset - ZIP64_END_BYTES)) {
      throw new Error('附件结构无效：ZIP64 结束记录偏移越界。');
    }
    return { ...metadata, recordOffset: Number(recordOffset), locatorOffset };
  }
  const disk = tail.readUInt16LE(end + 4);
  const directoryDisk = tail.readUInt16LE(end + 6);
  const diskCount = tail.readUInt16LE(end + 8);
  const total = tail.readUInt16LE(end + 10);
  const size = tail.readUInt32LE(end + 12);
  const declaredStart = tail.readUInt32LE(end + 16);
  if (disk !== 0 || directoryDisk !== 0 || diskCount !== total) return null;
  if (size === U32_MAX || declaredStart === U32_MAX) throw new Error('附件结构无效：缺少 ZIP64 中央目录定位记录。');
  const footerOffset = tailOffset + end;
  const start = embedded ? footerOffset - size : declaredStart;
  const adjustment = start - declaredStart;
  if (adjustment < 0 || (total === 0 && footerOffset !== 0)
    || (metadata.trailingSize > 0 && start + size !== footerOffset)) {
    throw new Error('附件结构无效：ZIP 中央目录与结束记录的位置不一致。');
  }
  checkRange(footerOffset, start, size, 'ZIP 中央目录');
  if (total * CENTRAL_HEADER_BYTES > size) throw new Error('附件结构无效：ZIP 中央目录无法容纳声明的条目数。');
  return { ...metadata, start, size, total, adjustment, zip64: false };
}

function zip64Directory(bytes, { recordOffset, locatorOffset, archiveEnd, trailingSize }) {
  if (bytes.readUInt32LE(0) !== ZIP64_END) throw new Error('附件结构无效：缺少 ZIP64 结束记录签名。');
  const length = bytes.readBigUInt64LE(4);
  if (length < 44n || length !== BigInt(locatorOffset - recordOffset - 12)) {
    throw new Error('附件结构无效：ZIP64 结束记录长度与定位记录不一致。');
  }
  const total = bytes.readBigUInt64LE(32);
  if (bytes.readUInt32LE(16) !== 0 || bytes.readUInt32LE(20) !== 0 || bytes.readBigUInt64LE(24) !== total) return null;
  const start = bytes.readBigUInt64LE(48);
  const size = bytes.readBigUInt64LE(40);
  if (start + size > BigInt(recordOffset) || total * BigInt(CENTRAL_HEADER_BYTES) > size) {
    throw new Error('附件结构无效：ZIP64 中央目录越界。');
  }
  return { archiveEnd, trailingSize, start: Number(start), size: Number(size), total: Number(total), adjustment: 0, zip64: true };
}

function zip64Extra(bytes, cursor, end) {
  while (cursor < end) {
    checkRange(end, cursor, 4, 'ZIP 条目扩展头');
    const field = bytes.readUInt16LE(cursor);
    const length = bytes.readUInt16LE(cursor + 2);
    const content = cursor + 4;
    checkRange(end, content, length, 'ZIP 条目扩展内容');
    if (field === 1) return bytes.subarray(content, content + length);
    cursor = content + length;
  }
  throw new Error('附件结构无效：ZIP 条目缺少要求的 ZIP64 扩展字段。');
}

function zip64Member(bytes, member) {
  let cursor = 0;
  // ZIP64 values appear in this order, only for ordinary fields set to their maximum.
  for (const key of ['original', 'packed', 'localOffset']) {
    if (member[key] !== U32_MAX) continue;
    checkRange(bytes.length, cursor, 8, 'ZIP64 条目的大小或偏移');
    const value = bytes.readBigUInt64LE(cursor);
    member[key] = value <= SAFE_INTEGER ? Number(value) : value.toString();
    cursor += 8;
  }
  if (member.disk === U16_MAX) {
    checkRange(bytes.length, cursor, 4, 'ZIP64 条目的磁盘号');
    member.disk = bytes.readUInt32LE(cursor);
  }
}

function readMember(bytes, cursor) {
  checkRange(bytes.length, cursor, CENTRAL_HEADER_BYTES, 'ZIP 中央目录条目');
  if (bytes.readUInt32LE(cursor) !== ZIP_CENTRAL) throw new Error('附件结构无效：ZIP 中央目录条目签名不匹配。');
  const nameLength = bytes.readUInt16LE(cursor + 28);
  const extraLength = bytes.readUInt16LE(cursor + 30);
  const commentLength = bytes.readUInt16LE(cursor + 32);
  const nameStart = cursor + CENTRAL_HEADER_BYTES;
  const nameEnd = nameStart + nameLength;
  const extraEnd = nameEnd + extraLength;
  checkRange(bytes.length, nameStart, nameLength + extraLength + commentLength, 'ZIP 中央目录条目内容');
  if (nameLength === 0) throw new Error('附件结构无效：ZIP 条目名称为空。');

  const member = {
    original: bytes.readUInt32LE(cursor + 24),
    packed: bytes.readUInt32LE(cursor + 20),
    localOffset: bytes.readUInt32LE(cursor + 42),
    disk: bytes.readUInt16LE(cursor + 34),
  };
  const zip64 = member.original === U32_MAX || member.packed === U32_MAX
    || member.localOffset === U32_MAX || member.disk === U16_MAX;
  if (zip64) zip64Member(zip64Extra(bytes, nameEnd, extraEnd), member);
  return { ...member, zip64, nameStart, nameEnd, extraEnd, next: extraEnd + commentLength };
}

function indexDirectory(bytes, directory) {
  let { zip64 } = directory;
  const offsets = new Uint32Array(directory.total + 1);
  let firstLocalOffset;
  let cursor = 0;
  for (let index = 0; index < directory.total; index++) {
    offsets[index] = cursor;
    const member = readMember(bytes, cursor);
    if (member.disk !== 0) return null;
    if (typeof member.localOffset === 'number') {
      firstLocalOffset = Math.min(firstLocalOffset ?? member.localOffset, member.localOffset);
    }
    zip64 ||= member.zip64;
    cursor = member.next;
  }
  offsets[directory.total] = cursor;
  if (cursor !== bytes.length) {
    checkRange(bytes.length, cursor, 6, 'ZIP 中央目录附加记录');
    if (bytes.readUInt32LE(cursor) !== ZIP_SIGNATURE || cursor + 6 + bytes.readUInt16LE(cursor + 4) !== bytes.length) {
      throw new Error('附件结构无效：ZIP 中央目录大小与条目不一致。');
    }
  }
  return { ...directory, zip64, offsets, firstLocalOffset };
}

function memberPage(index, { offset, limit }) {
  const first = Math.min(offset, index.total);
  const last = Math.min(first + limit, index.total);
  return { start: index.offsets[first], end: index.offsets[last], count: last - first };
}

function decodeName(bytes, encoding) {
  try { return new TextDecoder(encoding, { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { return undefined; }
}

function unicodeName(nameBytes, extra) {
  for (let offset = 0; offset + 4 <= extra.length;) {
    const id = extra.readUInt16LE(offset);
    const length = extra.readUInt16LE(offset + 2);
    const start = offset + 4;
    offset = start + length;
    if (offset > extra.length) return undefined;
    if (id === 0x7075 && length > 5 && extra[start] === 1 && extra.readUInt32LE(start + 1) === crc32(nameBytes)) {
      return decodeName(extra.subarray(start + 5, offset), 'utf-8');
    }
  }
  return undefined;
}

function memberName(nameBytes, flags, extra) {
  const utf8 = decodeName(nameBytes, 'utf-8');
  const unicode = unicodeName(nameBytes, extra);
  const ascii = nameBytes.every(byte => byte < 0x80);
  let name = unicode ?? utf8;
  let name_encoding = ascii && unicode === undefined ? 'ASCII' : 'UTF-8';
  let guessed = false;
  if (name === undefined && (flags & 0x0800) === 0) {
    const legacy = decodeName(nameBytes, 'gb18030');
    if (legacy !== undefined && /\p{Script=Han}/u.test(legacy)) {
      name = legacy;
      name_encoding = 'GB18030';
      guessed = true;
    }
  }
  if (name === undefined) {
    name_encoding = 'raw bytes';
    return { name: label(nameBytes.toString('latin1'), MAX_MEMBER_NAME), name_encoding,
      name_hex: nameBytes.subarray(0, MAX_MEMBER_NAME).toString('hex'), ...(nameBytes.length > MAX_MEMBER_NAME ? { name_truncated: true } : {}) };
  }
  return { name: label(name, MAX_MEMBER_NAME), name_encoding,
    ...(guessed ? { name_encoding_guessed: true } : {}), ...(name.length > MAX_MEMBER_NAME ? { name_truncated: true } : {}) };
}

function zipReport(bytes, index, paging, count) {
  const rows = [];
  let cursor = 0;
  for (let row = 0; row < count; row++) {
    const member = readMember(bytes, cursor);
    const flags = bytes.readUInt16LE(cursor + 8);
    rows.push({
      member_index: paging.offset + row,
      ...memberName(bytes.subarray(member.nameStart, member.nameEnd), flags, bytes.subarray(member.nameEnd, member.extraEnd)),
      method_id: bytes.readUInt16LE(cursor + 10),
      encrypted: (flags & 1) !== 0,
      compressed_size: member.packed,
      uncompressed_size: member.original,
    });
    cursor = member.next;
  }
  return { format: 'ZIP', status: 'ok', variant: index.zip64 ? 'ZIP64' : 'ZIP',
    ...(index.archiveOffset > 0 ? { archive_offset: index.archiveOffset } : {}),
    ...(index.trailingSize > 0 ? { trailing_offset: index.archiveEnd, trailing_size: index.trailingSize } : {}),
    layout: page('members', index.total, rows, paging.offset) };
}

export function inspectZip(bytes, paging) {
  let problem;
  let split = false;
  for (const footer of zipEnds(bytes)) {
    try {
      let directory = locateDirectory(bytes, 0, footer, false);
      if (directory?.recordOffset !== undefined) {
        directory = zip64Directory(bytes.subarray(directory.recordOffset, directory.recordOffset + ZIP64_END_BYTES), directory);
      }
      const entries = directory && bytes.subarray(directory.start, directory.start + directory.size);
      const index = entries && indexDirectory(entries, directory);
      if (index) {
        const { start, end, count } = memberPage(index, paging);
        return zipReport(entries.subarray(start, end), index, paging, count);
      }
      split = true;
    } catch (error) {
      if (!structuralError(error)) throw error;
      problem ??= error;
    }
  }
  if (split) return ZIP_SPLIT;
  throw problem ?? missingFooter();
}

function structuralError(error) {
  return error?.message?.startsWith('附件结构无效：') === true;
}

function missingFooter() {
  return new Error('附件结构无效：缺少完整的 ZIP 中央目录结束记录。');
}

async function loadZipIndex({ size, read }, cachedIndex, probeEmbedded) {
  if (cachedIndex !== undefined && (cachedIndex.archiveOffset === undefined || probeEmbedded || cachedIndex.sfx)) {
    return { index: cachedIndex };
  }
  const prefix = await read(0, Math.min(4, size));
  const leading = isZip(prefix);
  const sfx = prefix[0] === 0x4d && prefix[1] === 0x5a;
  if (!leading && !sfx && !probeEmbedded) return undefined;
  const tailOffset = Math.max(0, size - ZIP_TAIL_BYTES);
  const tail = await read(tailOffset, size - tailOffset);
  const range = (offset, length) => offset < tailOffset
    ? read(offset, length)
    : tail.subarray(offset - tailOffset, offset - tailOffset + length);
  let problem;
  let split = false;
  for (const footer of zipEnds(tail)) {
    try {
      let directory = locateDirectory(tail, tailOffset, footer, !leading);
      if (directory?.recordOffset !== undefined) {
        directory = zip64Directory(await range(directory.recordOffset, ZIP64_END_BYTES), directory);
      }
      if (directory?.size > MAX_ATTACHMENT_BYTES) {
        throw new Error('附件结构无效：ZIP 中央目录超过 32 MiB。');
      }
      if (directory?.total > 0 && (await range(directory.start, 4)).readUInt32LE(0) !== ZIP_CENTRAL) {
        throw new Error('附件结构无效：ZIP 中央目录条目签名不匹配。');
      }
      const entries = directory && await range(directory.start, directory.size);
      const index = entries && indexDirectory(entries, directory);
      if (!index) {
        split = true;
        continue;
      }
      if (!leading) {
        const offset = index.firstLocalOffset + index.adjustment;
        if (!Number.isSafeInteger(offset) || offset <= 0 || offset + LOCAL_HEADER_BYTES > index.start
          || (await range(offset, 4)).readUInt32LE(0) !== ZIP_LOCAL) continue;
        index.archiveOffset = offset;
        index.sfx = sfx;
      }
      return { index, entries };
    } catch (error) {
      if (!structuralError(error)) throw error;
      problem ??= error;
    }
  }
  if (!leading) return undefined;
  if (split) return null;
  throw problem ?? missingFooter();
}

export async function inspectZipRanges(reader, paging, cachedIndex, probeEmbedded = false) {
  const loaded = await loadZipIndex(reader, cachedIndex, probeEmbedded);
  if (loaded === undefined) return undefined;
  if (loaded === null) return { report: ZIP_SPLIT };
  const { index, entries } = loaded;
  const { start, end, count } = memberPage(index, paging);
  const window = entries ? entries.subarray(start, end) : await reader.read(index.start + start, end - start);
  return { report: zipReport(window, index, paging, count), zipIndex: index };
}

async function loadZipData(read, limit, member, flags, method, nameBytes, checksum) {
  const { localOffset, original, packed } = member;
  checkRange(limit, localOffset, LOCAL_HEADER_BYTES, 'ZIP 本地成员头');
  const header = await read(localOffset, LOCAL_HEADER_BYTES);
  const localFlags = header.readUInt16LE(6);
  if (header.readUInt32LE(0) !== ZIP_LOCAL || ((localFlags ^ flags) & ~1) !== 0 || header.readUInt16LE(8) !== method) {
    throw new Error('附件结构无效：ZIP 本地成员头与中央目录不一致。');
  }
  const nameLength = header.readUInt16LE(26);
  const nameOffset = localOffset + LOCAL_HEADER_BYTES;
  const dataOffset = nameOffset + nameLength + header.readUInt16LE(28);
  checkRange(limit, dataOffset, packed, 'ZIP 成员压缩数据');
  if (nameLength !== nameBytes.length || !(await read(nameOffset, nameLength)).equals(nameBytes)) {
    throw new Error('附件结构无效：ZIP 本地成员名与中央目录不一致。');
  }
  if ((flags & 8) === 0) {
    const localPacked = header.readUInt32LE(18);
    const localOriginal = header.readUInt32LE(22);
    if (header.readUInt32LE(14) !== checksum || (localPacked !== U32_MAX && localPacked !== packed)
      || (localOriginal !== U32_MAX && localOriginal !== original)) {
      throw new Error('附件结构无效：ZIP 本地成员大小或 CRC 与中央目录不一致。');
    }
  }
  const compressed = await read(dataOffset, packed);
  if (method === 0) {
    if (packed !== original) throw new Error('附件结构无效：ZIP Store 成员大小不一致。');
    return { bytes: compressed, encryptionFlag: Boolean((flags | localFlags) & 1) };
  }
  try {
    const { buffer, engine } = inflateRawSync(compressed, { maxOutputLength: Math.max(1, original), info: true });
    if (engine.bytesWritten === packed) return { bytes: buffer, encryptionFlag: Boolean((flags | localFlags) & 1) };
  } catch {
    // The advertised uncompressed size is also a hard decompression limit.
  }
  throw new Error('附件结构无效：ZIP Deflate 成员无法按声明的长度解压。');
}

export async function readZipMember(reader, memberIndex, cachedIndex, probeEmbedded = false) {
  const loaded = await loadZipIndex(reader, cachedIndex, probeEmbedded);
  if (loaded === undefined) return undefined;
  if (loaded === null) throw new Error('当前支持单卷 ZIP 和 ZIP64 成员。');
  const { index, entries } = loaded;
  const { start, end, count } = memberPage(index, { offset: memberIndex, limit: 1 });
  if (count === 0) throw new Error('member_index 超出归档目录范围。');
  const row = entries ? entries.subarray(start, end) : await reader.read(index.start + start, end - start);
  const member = readMember(row, 0);
  const flags = row.readUInt16LE(8);
  const method = row.readUInt16LE(10);
  const nameBytes = row.subarray(member.nameStart, member.nameEnd);
  const attributes = row.readUInt32LE(38);
  const unixType = [3, 19].includes(row[5]) ? attributes >>> 28 : 0;
  if (nameBytes.at(-1) === 0x2f || nameBytes.at(-1) === 0x5c || (attributes & 0x10)
    || (unixType !== 0 && unixType !== 8)) {
    throw new Error('请选择 ZIP 中的普通文件成员。');
  }
  if (flags & 0x40 || method === 99) throw new Error('此 ZIP 成员使用单独的加密格式。已知口令读取支持传统 ZipCrypto。');
  if (method !== 0 && method !== 8) throw new Error(`暂不支持 ZIP 压缩方法 ${method}。可读取 Store 和 Deflate 成员。`);
  if (!Number.isSafeInteger(member.localOffset)) throw new Error('ZIP 成员头偏移超出可读取范围。');
  member.localOffset += index.adjustment;
  if (!Number.isSafeInteger(member.localOffset)) throw new Error('ZIP 成员头偏移超出可读取范围。');
  if (typeof member.original !== 'number' || member.original > MAX_ARCHIVE_MEMBER_BYTES) {
    throw new Error('归档成员解压后须在 1 MiB 内。');
  }
  if (typeof member.packed !== 'number' || member.packed > MAX_ATTACHMENT_BYTES) throw new Error('ZIP 成员压缩数据超过 32 MiB。');
  const checksum = row.readUInt32LE(16);
  let data;
  try {
    data = await loadZipData(reader.read, index.start, member, flags, method, nameBytes, checksum);
    if (data.bytes.length !== member.original || crc32(data.bytes) !== checksum) {
      throw new Error('附件结构无效：ZIP 成员解压长度或 CRC-32 校验值不匹配。');
    }
  } catch (error) {
    if (error?.name === 'AbortError') throw error;
    if (flags & 1) throw new Error('ZIP 成员带加密标记且无法按未加密数据通过校验，请提供已知口令。');
    throw error;
  }
  const { bytes, encryptionFlag } = data;
  return { bytes, ...memberName(nameBytes, flags, row.subarray(member.nameEnd, member.extraEnd)),
    ...(encryptionFlag ? { encryption_flag_only: true } : {}), format: 'ZIP', variant: index.zip64 ? 'ZIP64' : 'ZIP', zipIndex: index };
}
