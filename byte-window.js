import { createHash } from 'node:crypto';

const ENCODINGS = ['auto', 'hexdump', 'hex', 'base64', 'utf8'];
export const MAX_WINDOW_BYTES = 4096;
const MAX_STRINGS = 32;
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export const BYTE_WINDOW_PROPERTIES = {
  byte_offset: { type: 'integer', minimum: 0 },
  byte_length: { type: 'integer', minimum: 1, maximum: MAX_WINDOW_BYTES },
  encoding: { type: 'string', enum: ENCODINGS },
};

export function parseByteWindow(args, defaultEncoding, defaultLength) {
  const { byte_offset: offset = 0, byte_length: length = defaultLength, encoding = defaultEncoding } = args;
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(length) || length < 1
    || length > MAX_WINDOW_BYTES || !ENCODINGS.includes(encoding)) {
    throw new Error('请输入非负整数偏移、有效的编码和 1 至 4096 的字节数。');
  }
  return { offset, length, encoding };
}

export function windowLength(size, { offset, length }) {
  if (offset > size) throw new Error('byte_offset 超出原件或归档成员大小。');
  return Math.min(length, size - offset);
}

function hexdump(bytes, offset) {
  const addressWidth = Math.max(8, (offset + bytes.length).toString(16).length);
  const rows = [];
  for (let index = 0; index < bytes.length; index += 16) {
    const row = bytes.subarray(index, index + 16);
    const address = (offset + index).toString(16).padStart(addressWidth, '0');
    const hex = [...row].map(byte => byte.toString(16).padStart(2, '0')).join(' ');
    const ascii = row.toString('latin1').replace(/[^\x20-\x7e]/gu, '.');
    rows.push(`${address}  ${hex.padEnd(47)}  |${ascii}|`);
  }
  return rows.join('\n');
}

function utf8(bytes) {
  try {
    const text = UTF8.decode(bytes);
    if (!/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/u.test(text)) return text;
  } catch {
    // The caller can use an exact byte encoding for an incomplete UTF-8 character.
  }
  return undefined;
}

export function describeByteWindow(bytes, size, { offset, encoding }) {
  const text = encoding === 'auto' || encoding === 'utf8' ? utf8(bytes) : undefined;
  if (encoding === 'auto') encoding = text === undefined ? 'hexdump' : 'utf8';
  if (encoding === 'utf8' && text === undefined) throw new Error('这段数据不是完整的 UTF-8 文本，请改用 hex、hexdump 或 base64。');
  const data = encoding === 'utf8' ? text : encoding === 'hexdump' ? hexdump(bytes, offset) : bytes.toString(encoding);
  return {
    byte_offset: offset,
    byte_length: bytes.length,
    next_byte_offset: offset + bytes.length < size ? offset + bytes.length : null,
    encoding,
    data,
    range_sha256: createHash('sha256').update(bytes).digest('hex'),
  };
}

export function printableStrings(bytes, offset, minimum) {
  const strings = [];
  for (const match of bytes.toString('latin1').matchAll(/[\x20-\x7e]+/gu)) {
    const [text] = match;
    if (text.length < minimum) continue;
    if (strings.length === MAX_STRINGS) return { strings, strings_truncated: true };
    strings.push({ byte_offset: offset + match.index, byte_length: text.length, text });
  }
  return { strings, strings_truncated: false };
}
