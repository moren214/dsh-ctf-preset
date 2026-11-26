import { inflateRawSync } from 'node:zlib';
import { ToolError } from '../contracts/errors.js';

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? (value >>> 1) ^ 0xedb88320 : value >>> 1;
    table[index] = value >>> 0;
  }
  return table;
})();

export function crc32(buffer) {
  let value = 0xffffffff;
  for (let index = 0; index < buffer.length; index += 1) {
    value = CRC_TABLE[(value ^ buffer[index]) & 0xff] ^ (value >>> 8);
  }
  return (value ^ 0xffffffff) >>> 0;
}

export function parseZipEntries(buffer) {
  let eocd = -1;
  const lowerBound = Math.max(0, buffer.length - 65558);
  for (let index = buffer.length - 22; index >= lowerBound; index -= 1) {
    if (buffer.readUInt32LE(index) === 0x06054b50) { eocd = index; break; }
  }
  if (eocd < 0) throw new ToolError('unsupported', '找不到 ZIP 中央目录，可能不是 ZIP 文件。');
  const count = buffer.readUInt16LE(eocd + 10);
  const offset = buffer.readUInt32LE(eocd + 16);
  if (count === 0xffff || offset === 0xffffffff) {
    throw new ToolError('unsupported', '暂不支持 ZIP64；可用 shell 里的 7z/unzip 查看。');
  }
  const entries = [];
  let cursor = offset;
  for (let index = 0; index < count; index += 1) {
    if (cursor + 46 > buffer.length || buffer.readUInt32LE(cursor) !== 0x02014b50) break;
    const flags = buffer.readUInt16LE(cursor + 8);
    const method = buffer.readUInt16LE(cursor + 10);
    const time = buffer.readUInt16LE(cursor + 12);
    const crc = buffer.readUInt32LE(cursor + 16);
    const compressedSize = buffer.readUInt32LE(cursor + 20);
    const size = buffer.readUInt32LE(cursor + 24);
    const nameLength = buffer.readUInt16LE(cursor + 28);
    const extraLength = buffer.readUInt16LE(cursor + 30);
    const commentLength = buffer.readUInt16LE(cursor + 32);
    const localOffset = buffer.readUInt32LE(cursor + 42);
    const name = buffer.toString('utf8', cursor + 46, cursor + 46 + nameLength);
    if (localOffset + 30 > buffer.length || buffer.readUInt32LE(localOffset) !== 0x04034b50) {
      throw new ToolError('unsupported', `本地文件头损坏：${name}。`);
    }
    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localOffset + 28);
    const dataOffset = localOffset + 30 + localNameLength + localExtraLength;
    if (dataOffset + compressedSize > buffer.length) throw new ToolError('unsupported', `压缩数据越界：${name}。`);
    entries.push({
      name, flags, method, time, crc, compressedSize, size, dataOffset,
      encrypted: (flags & 1) !== 0,
      checkByte: (flags & 8) !== 0 ? (time >>> 8) & 0xff : (crc >>> 24) & 0xff,
      directory: name.endsWith('/'),
    });
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

function zipKeys(password) {
  let k0 = 0x12345678;
  let k1 = 0x23456789;
  let k2 = 0x34567890;
  const bytes = Buffer.from(password, 'latin1');
  for (let index = 0; index < bytes.length; index += 1) {
    const byte = bytes[index];
    k0 = (CRC_TABLE[(k0 ^ byte) & 0xff] ^ (k0 >>> 8)) >>> 0;
    k1 = (((k1 + (k0 & 0xff)) >>> 0) * 134775813 + 1) >>> 0;
    k2 = (CRC_TABLE[(k2 ^ (k1 >>> 24)) & 0xff] ^ (k2 >>> 8)) >>> 0;
  }
  return [k0, k1, k2];
}

function decryptZipCrypto(bytes, keys, length) {
  const plain = Buffer.alloc(length);
  let [k0, k1, k2] = keys;
  for (let index = 0; index < length; index += 1) {
    const temp = (k2 | 2) >>> 0;
    const byte = bytes[index] ^ (((temp * (temp ^ 1)) >>> 8) & 0xff);
    plain[index] = byte;
    k0 = (CRC_TABLE[(k0 ^ byte) & 0xff] ^ (k0 >>> 8)) >>> 0;
    k1 = (((k1 + (k0 & 0xff)) >>> 0) * 134775813 + 1) >>> 0;
    k2 = (CRC_TABLE[(k2 ^ (k1 >>> 24)) & 0xff] ^ (k2 >>> 8)) >>> 0;
  }
  return { plain, keys: [k0, k1, k2] };
}

function tryZipCrypto(buffer, entry, password) {
  if (entry.compressedSize < 12) return false;
  const keys = zipKeys(password);
  const header = buffer.subarray(entry.dataOffset, entry.dataOffset + 12);
  const first = decryptZipCrypto(header, keys, 12);
  if (first.plain[11] !== entry.checkByte) return false;
  const body = buffer.subarray(entry.dataOffset + 12, entry.dataOffset + entry.compressedSize);
  const second = decryptZipCrypto(body, first.keys, body.length);
  const plain = second.plain;
  try {
    const data = entry.method === 0 ? plain : inflateRawSync(plain, { maxOutputLength: Math.max(entry.size, 1) + 1024 });
    return data.length === entry.size && crc32(data) === entry.crc;
  } catch {
    return false;
  }
}

const COMMON_PASSWORDS = [
  '123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111', '1234567',
  'dragon', '123123', 'baseball', 'abc123', 'football', 'monkey', 'letmein', 'shadow', 'master',
  '666666', 'qwertyuiop', '123321', 'mustang', '1234567890', 'michael', '654321', 'superman',
  '1qaz2wsx', '7777777', '121212', '000000', 'qazwsx', '123qwe', 'killer', 'trustno1', 'jordan',
  'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster', 'soccer', 'harley', 'batman', 'andrew',
  'tigger', 'sunshine', 'iloveyou', '2000', 'charlie', 'robert', 'thomas', 'hockey', 'ranger',
  'daniel', 'starwars', 'klaster', '112233', 'george', 'computer', 'michelle', 'jessica',
  'pepper', '1111', 'zxcvbn', '555555', '11111111', '131313', 'freedom', '777777', 'pass',
  'maggie', '159753', 'aaaaaa', 'ginger', 'princess', 'joshua', 'cheese', 'amanda', 'summer',
  'love', 'ashley', 'nicole', 'chelsea', 'biteme', 'matthew', 'access', 'yankees', '987654321',
  'dallas', 'austin', 'thunder', 'taylor', 'matrix', 'flag', 'admin', 'root', 'test', 'ctf',
  'password1', 'P@ssw0rd', 'Passw0rd', 'admin123', 'root123', 'tomcat', 'welcome', 'secret',
];

const MASK_CHARS = {
  l: 'abcdefghijklmnopqrstuvwxyz',
  u: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  d: '0123456789',
  h: '0123456789abcdef',
  s: '!@#$%^&*()-_=+[]{};:,.<>?/~`\'"\\|',
  a: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>?/~`\'"\\|',
};

function maskSlots(mask) {
  const slots = [];
  for (let index = 0; index < mask.length; index += 1) {
    if (mask[index] === '?' && index + 1 < mask.length) {
      const next = mask[index + 1];
      if (MASK_CHARS[next]) { slots.push([...MASK_CHARS[next]]); index += 1; continue; }
      if (next === '?') { slots.push(['?']); index += 1; continue; }
    }
    slots.push([mask[index]]);
  }
  return slots;
}

function* maskCandidates(slots, minimum, maximum) {
  const size = slots.length;
  if (size === 0) return;
  const index = new Array(size).fill(0);
  for (;;) {
    const length = size;
    if (length >= minimum && length <= maximum) {
      let value = '';
      for (let position = 0; position < size; position += 1) value += slots[position][index[position]];
      yield value;
    }
    let position = size - 1;
    while (position >= 0) {
      index[position] += 1;
      if (index[position] < slots[position].length) break;
      index[position] = 0;
      position -= 1;
    }
    if (position < 0) return;
  }
}

function* candidatesFor(args, wordlistText) {
  if (Array.isArray(args.passwords)) {
    for (const password of args.passwords) {
      if (typeof password === 'string' && password.length <= 64) yield password;
    }
  }
  if (typeof wordlistText === 'string') {
    for (const line of wordlistText.split(/\r?\n/u)) {
      if (line.length > 0 && line.length <= 64) yield line;
    }
  }
  if (typeof args.mask === 'string' && args.mask.length > 0) {
    const slots = maskSlots(args.mask);
    const minimum = Number.isSafeInteger(args.min_length) ? args.min_length : 0;
    const maximum = Number.isSafeInteger(args.max_length) ? args.max_length : 64;
    yield* maskCandidates(slots, minimum, maximum);
    return;
  }
  yield* COMMON_PASSWORDS;
}

export async function crackZip(buffer, entry, args, wordlistText, signal) {
  const timeoutMs = Math.min(Math.max(args.timeout_ms ?? 30000, 1000), 120000);
  const deadline = Date.now() + timeoutMs;
  let tried = 0;
  for (const password of candidatesFor(args, wordlistText)) {
    if ((tried & 0xff) === 0) {
      signal?.throwIfAborted();
      if (Date.now() > deadline) return { status: 'not_found', timed_out: true, tried };
      if (tried > 0) await new Promise(resolve => setImmediate(resolve));
    }
    tried += 1;
    if (tryZipCrypto(buffer, entry, password)) return { status: 'found', password, tried };
  }
  signal?.throwIfAborted();
  return { status: 'not_found', timed_out: false, tried };
}
