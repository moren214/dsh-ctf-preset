import { crc32, inflateSync } from 'node:zlib';
import { inPage, label, page } from './attachment-layout.js';
import { inspectExif } from './exif.js';

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const PNG_COLORS = {
  0: { mode: 'grayscale', depths: [1, 2, 4, 8, 16] },
  2: { mode: 'truecolor', depths: [8, 16] },
  3: { mode: 'indexed', depths: [1, 2, 4, 8] },
  4: { mode: 'grayscale_alpha', depths: [8, 16] },
  6: { mode: 'truecolor_alpha', depths: [8, 16] },
};
const MAX_DECODED_TEXT = 64 * 1024;
const JPEG_EXIF = Buffer.from('Exif\0\0', 'ascii');
const JPEG_MARKERS = new Map([
  [0x01, 'TEM'], [0xc4, 'DHT'], [0xcc, 'DAC'], [0xd8, 'SOI'], [0xd9, 'EOI'],
  [0xda, 'SOS'], [0xdb, 'DQT'], [0xdc, 'DNL'], [0xdd, 'DRI'], [0xde, 'DHP'], [0xdf, 'EXP'], [0xfe, 'COM'],
]);
const JPEG_FRAMES = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);

class ImageStructureError extends Error {
  constructor(status, offset, message) {
    super(message);
    this.status = status;
    this.offset = offset;
  }
}

function requireBytes(bytes, offset, length, description) {
  if (length > bytes.length - offset) throw new ImageStructureError('truncated', offset, description + '不完整。');
}

function trailing(bytes, end) {
  const trailingSize = bytes.length - end;
  return { image_end_offset: end, trailing_size: trailingSize, ...(trailingSize ? { trailing_offset: end } : {}) };
}

function previewText(bytes, encoding) {
  const decoded = bytes.toString(encoding, 0, Math.min(bytes.length, 384));
  return { value: label(decoded), preview_truncated: bytes.length > 384 || decoded.length > 96 };
}

function pngText(bytes, fileOffset, type) {
  const separator = bytes.indexOf(0);
  if (separator < 1 || separator > 79) return { status: 'invalid', reason: 'PNG 文本关键字无效。' };
  const keyword = label(bytes.toString('latin1', 0, separator));
  let start = separator + 1;
  let compressed = type === 'zTXt';
  const encoding = type === 'iTXt' ? 'utf8' : 'latin1';
  if (type === 'zTXt') {
    if (bytes[start] !== 0) return { status: 'invalid', keyword, reason: 'zTXt 压缩方法无效。' };
    start++;
  } else if (type === 'iTXt') {
    const flag = bytes[start];
    if ((flag !== 0 && flag !== 1) || bytes[start + 1] !== 0) {
      return { status: 'invalid', keyword, reason: 'iTXt 压缩标志或方法无效。' };
    }
    compressed = flag === 1;
    const languageEnd = bytes.indexOf(0, start + 2);
    const translationEnd = languageEnd === -1 ? -1 : bytes.indexOf(0, languageEnd + 1);
    if (translationEnd === -1) return { status: 'invalid', keyword, reason: 'iTXt 语言或翻译字段不完整。' };
    start = translationEnd + 1;
  }
  const metadata = { keyword, file_offset: fileOffset + start, compressed };
  let value = bytes.subarray(start);
  if (compressed) {
    try {
      value = inflateSync(value, { maxOutputLength: MAX_DECODED_TEXT });
    } catch (error) {
      return error.code === 'ERR_BUFFER_TOO_LARGE'
        ? { ...metadata, status: 'too_large', reason: '解压后的 PNG 文本超过 64 KiB。' }
        : { ...metadata, status: 'invalid', reason: 'PNG 文本压缩数据无效。' };
    }
  }
  return { ...metadata, status: 'ok', ...previewText(value, encoding) };
}

function readPngHeader(bytes, offset, length) {
  if (length !== 13) throw new ImageStructureError('invalid', offset, 'IHDR 的数据长度应为 13。');
  const width = bytes.readUInt32BE(offset);
  const height = bytes.readUInt32BE(offset + 4);
  const bitDepth = bytes[offset + 8];
  const colorType = bytes[offset + 9];
  const color = PNG_COLORS[colorType];
  if (width === 0 || height === 0 || width > 0x7fffffff || height > 0x7fffffff
    || !color?.depths.includes(bitDepth) || bytes[offset + 10] !== 0 || bytes[offset + 11] !== 0 || bytes[offset + 12] > 1) {
    throw new ImageStructureError('invalid', offset, 'PNG 尺寸、位深或 IHDR 参数无效。');
  }
  return { width, height, bit_depth: bitDepth, color_type: colorType, color_mode: color.mode,
    interlaced: bytes[offset + 12] === 1, file_offset: offset };
}

function inspectPng(bytes, paging) {
  requireBytes(bytes, 0, PNG_SIGNATURE.length, 'PNG 文件签名');
  if (!PNG_SIGNATURE.equals(bytes.subarray(0, 8))) throw new ImageStructureError('invalid', 0, 'PNG 文件签名无效。');
  const rows = [];
  let cursor = PNG_SIGNATURE.length;
  let count = 0;
  let image;
  let exif;
  let animation;
  let seenImageData = false;
  while (cursor < bytes.length) {
    requireBytes(bytes, cursor, 12, 'PNG 数据块头或 CRC');
    const dataSize = bytes.readUInt32BE(cursor);
    const type = bytes.toString('latin1', cursor + 4, cursor + 8);
    if (dataSize > 0x7fffffff || !/^[A-Za-z]{4}$/u.test(type)) {
      throw new ImageStructureError('invalid', cursor, 'PNG 数据块类型或长度无效。');
    }
    if ((count === 0) !== (type === 'IHDR')) throw new ImageStructureError('invalid', cursor, 'IHDR 须为首个 PNG 数据块。');
    const dataStart = cursor + 8;
    const dataEnd = dataStart + dataSize;
    requireBytes(bytes, dataStart, dataSize + 4, `PNG ${type} 数据或 CRC`);
    if (crc32(bytes.subarray(cursor + 4, dataEnd)) !== bytes.readUInt32BE(dataEnd)) {
      throw new ImageStructureError('invalid', dataEnd, `PNG ${type} 的 CRC-32 校验失败。`);
    }
    if (type === 'IHDR') image = readPngHeader(bytes, dataStart, dataSize);
    if (type === 'eXIf' && exif?.status !== 'ok') exif = inspectExif(bytes.subarray(dataStart, dataEnd), dataStart);
    if (type === 'acTL' && dataSize === 8) animation = {
      frame_count: bytes.readUInt32BE(dataStart), loop_count: bytes.readUInt32BE(dataStart + 4),
    };
    if (type === 'IDAT') seenImageData = true;
    if (inPage(count, paging)) {
      const row = { type, file_offset: cursor, data_offset: dataStart, data_size: dataSize };
      if (type === 'tEXt' || type === 'zTXt' || type === 'iTXt') row.text = pngText(bytes.subarray(dataStart, dataEnd), dataStart, type);
      rows.push(row);
    }
    count++;
    if (type === 'IEND') {
      if (dataSize !== 0 || !seenImageData) throw new ImageStructureError('invalid', cursor, 'PNG IEND 长度无效或缺少 IDAT。');
      return { status: 'ok', image, ...(exif ? { exif } : {}), ...(animation ? { animation } : {}),
        ...trailing(bytes, dataEnd + 4), layout: page('chunks', count, rows, paging.offset) };
    }
    cursor = dataEnd + 4;
  }
  throw new ImageStructureError('truncated', cursor, 'PNG 缺少结束块 IEND。');
}

function jpegMarkerName(marker) {
  if (marker >= 0xe0 && marker <= 0xef) return 'APP' + (marker - 0xe0);
  if (JPEG_FRAMES.has(marker)) return 'SOF' + (marker - 0xc0);
  return JPEG_MARKERS.get(marker) ?? ('FF' + marker.toString(16).toUpperCase().padStart(2, '0'));
}

function jpegFrame(bytes, offset, length) {
  if (length < 6) throw new ImageStructureError('invalid', offset, 'JPEG 帧头不完整。');
  const bitDepth = bytes[offset];
  const height = bytes.readUInt16BE(offset + 1);
  const width = bytes.readUInt16BE(offset + 3);
  const components = bytes[offset + 5];
  if (width === 0 || components === 0 || length !== 6 + 3 * components) {
    throw new ImageStructureError('invalid', offset, 'JPEG 帧头尺寸或分量无效。');
  }
  return { width, height, bit_depth: bitDepth, components, file_offset: offset };
}

function nextMarker(bytes, offset, inScan) {
  let cursor = offset;
  while (cursor < bytes.length) {
    if (inScan) {
      cursor = bytes.indexOf(0xff, cursor);
      if (cursor === -1) break;
    } else if (bytes[cursor] !== 0xff) {
      throw new ImageStructureError('invalid', cursor, 'JPEG 段标记无效。');
    }
    while (cursor < bytes.length && bytes[cursor] === 0xff) cursor++;
    if (cursor === bytes.length) break;
    const marker = bytes[cursor];
    const restart = marker >= 0xd0 && marker <= 0xd7;
    if (inScan && (marker === 0 || restart)) {
      cursor++;
      continue;
    }
    if (marker === 0 || restart || marker === 0xd8) {
      throw new ImageStructureError('invalid', cursor - 1, 'JPEG 标记出现在无效位置。');
    }
    return { marker, fileOffset: cursor - 1, following: cursor + 1 };
  }
  throw new ImageStructureError('truncated', bytes.length, 'JPEG 缺少结束标记 EOI。');
}

function inspectJpeg(bytes, paging) {
  const rows = [];
  let count = 0;
  function add(marker, file_offset, fields = {}) {
    if (inPage(count, paging)) rows.push({ marker: jpegMarkerName(marker), file_offset, ...fields });
    count++;
  }
  add(0xd8, 0);
  let offset = 2;
  let inScan = false;
  let seenScan = false;
  let image;
  let exif;
  for (;;) {
    const { marker, fileOffset, following } = nextMarker(bytes, offset, inScan);
    inScan = false;
    if (marker === 0xd9) {
      if (!image?.height || !seenScan) throw new ImageStructureError('invalid', fileOffset, 'JPEG 缺少完整的帧头或扫描。');
      add(marker, fileOffset);
      return { status: 'ok', image, exif, ...trailing(bytes, following), layout: page('segments', count, rows, paging.offset) };
    }
    if (marker === 0x01) {
      add(marker, fileOffset);
      offset = following;
      continue;
    }
    requireBytes(bytes, following, 2, 'JPEG 段长度');
    const length = bytes.readUInt16BE(following);
    if (length < 2) throw new ImageStructureError('invalid', following, 'JPEG 段长度无效。');
    requireBytes(bytes, following, length, 'JPEG 段数据');
    const dataOffset = following + 2;
    const dataSize = length - 2;
    offset = following + length;
    const fields = { data_offset: dataOffset, data_size: dataSize };
    if (JPEG_FRAMES.has(marker)) {
      const frame = jpegFrame(bytes, dataOffset, dataSize);
      image ??= frame;
      fields.frame = frame;
    } else if (marker === 0xdc && image?.height === 0) {
      if (dataSize !== 2 || bytes.readUInt16BE(dataOffset) === 0) throw new ImageStructureError('invalid', dataOffset, 'JPEG DNL 行数无效。');
      image = { ...image, height: bytes.readUInt16BE(dataOffset), height_file_offset: dataOffset };
    } else if (marker === 0xe1 && dataSize >= JPEG_EXIF.length && JPEG_EXIF.equals(bytes.subarray(dataOffset, dataOffset + JPEG_EXIF.length))) {
      fields.metadata = 'EXIF';
      if (exif?.status !== 'ok') exif = inspectExif(bytes.subarray(dataOffset + JPEG_EXIF.length, offset), dataOffset + JPEG_EXIF.length);
    } else if (marker === 0xfe && inPage(count, paging)) {
      fields.comment = previewText(bytes.subarray(dataOffset, offset), 'utf8');
    }
    add(marker, fileOffset, fields);
    if (marker === 0xda) {
      if (dataSize < 4 || bytes[dataOffset] === 0 || dataSize !== 4 + 2 * bytes[dataOffset]) {
        throw new ImageStructureError('invalid', dataOffset, 'JPEG 扫描头长度或分量无效。');
      }
      inScan = true;
      seenScan = true;
    }
  }
}

export function inspectImage(bytes, paging) {
  const png = PNG_SIGNATURE.subarray(0, 4).equals(bytes.subarray(0, 4));
  const jpeg = bytes[0] === 0xff && bytes[1] === 0xd8;
  if (!png && !jpeg) return undefined;
  const format = png ? 'PNG' : 'JPEG';
  try {
    return { format, ...(png ? inspectPng(bytes, paging) : inspectJpeg(bytes, paging)) };
  } catch (error) {
    if (!(error instanceof ImageStructureError)) throw error;
    return { format, status: error.status, issue: { file_offset: error.offset, reason: error.message } };
  }
}
