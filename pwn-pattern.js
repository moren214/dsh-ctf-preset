import { ToolError } from './tool-errors.js';
const ALPHABET = 'abcdefghijklmnopqrstuvwxyz';
const ORDER = 4;
const MAX_PATTERN = 1024 * 1024;
const MAX_OUTPUT = 4096;
const MAX_VALUE_BYTES = 16;

let cachedPattern;

function sequence() {
  if (cachedPattern !== undefined) return cachedPattern;
  const k = ALPHABET.length;
  const n = ORDER;
  const a = new Array(k * n + 1).fill(0);
  const digits = [];
  function db(t, p) {
    if (t > n) {
      if (n % p === 0) {
        for (let index = 1; index <= p; index++) digits.push(a[index]);
      }
      return;
    }
    a[t] = a[t - p];
    db(t + 1, p);
    for (let value = a[t - p] + 1; value < k; value++) {
      a[t] = value;
      db(t + 1, t);
    }
  }
  db(1, 1);
  const text = digits.map(digit => ALPHABET[digit]).join('');
  cachedPattern = text;
  return cachedPattern;
}

function parseValue(raw, byteOrder) {
  if (typeof raw !== 'string' || raw.length === 0) {
    throw new ToolError('unsupported', 'value 必须是十六进制字节串或 0x 开头的整数。');
  }
  if (/^0x[0-9a-f]+$/iu.test(raw)) {
    const value = BigInt(raw);
    if (value > 0xffffffffffffffffn) throw new ToolError('size', 'value 不能超过 8 字节。');
    const width = Math.max(1, Math.ceil(value.toString(16).length / 2));
    const bytes = Buffer.alloc(width);
    if (byteOrder === 'big') {
      let rest = value;
      for (let index = width - 1; index >= 0; index--) {
        bytes[index] = Number(rest & 0xffn);
        rest >>= 8n;
      }
    } else {
      let rest = value;
      for (let index = 0; index < width; index++) {
        bytes[index] = Number(rest & 0xffn);
        rest >>= 8n;
      }
    }
    return bytes;
  }
  if (!/^(?:[0-9a-f]{2})+$/iu.test(raw)) {
    throw new ToolError('unsupported', 'value 必须是不带 0x 的偶数位十六进制字节串。');
  }
  const bytes = Buffer.from(raw, 'hex');
  if (bytes.length > MAX_VALUE_BYTES) throw new ToolError('unsupported', `value 最多 ${MAX_VALUE_BYTES} 字节。`);
  return bytes;
}

function create(length) {
  const size = length ?? 256;
  if (!Number.isInteger(size) || size < 1 || size > MAX_OUTPUT) {
    throw new ToolError('unsupported', `length 必须是 1–${MAX_OUTPUT} 的整数。`);
  }
  const pattern = sequence();
  if (size > pattern.length) throw new ToolError('unsupported', `循环模式最多 ${pattern.length} 字符。`);
  return {
    operation: 'create',
    length: size,
    pattern: pattern.slice(0, size),
    notes: [
      'De Bruijn 阶 4，字母表 a–z，与 pwntools cyclic 的起始序列对齐。',
      '完整模式长度 ' + pattern.length + '，单次最多返回 ' + MAX_OUTPUT + ' 字符。',
    ],
  };
}

function find(raw, byteOrder) {
  const needle = parseValue(raw, byteOrder ?? 'little');
  const pattern = sequence();
  const text = needle.toString('latin1');
  const offsets = [];
  let cursor = pattern.indexOf(text);
  while (cursor !== -1) {
    offsets.push(cursor);
    if (offsets.length > 32) break;
    cursor = pattern.indexOf(text, cursor + 1);
  }
  if (offsets.length === 0 && needle.length > 4) {
    const prefix = text.slice(0, 4);
    let start = pattern.indexOf(prefix);
    while (start !== -1) {
      offsets.push(start);
      if (offsets.length > 32) break;
      start = pattern.indexOf(prefix, start + 1);
    }
    return {
      operation: 'find',
      value: needle.toString('hex'),
      value_bytes: needle.length,
      offset: offsets.length === 1 ? offsets[0] : null,
      occurrences: offsets.length,
      ambiguous: offsets.length !== 1,
      matched_prefix: offsets.length > 0,
      offsets,
      notes: offsets.length === 0
        ? ['模式中没有该字节串。']
        : ['完整字节串未命中，返回 4 字节前缀的候选偏移；请用更长的泄露值复核。'],
    };
  }
  return {
    operation: 'find',
    value: needle.toString('hex'),
    value_bytes: needle.length,
    offset: offsets.length === 1 ? offsets[0] : null,
    occurrences: offsets.length,
    ambiguous: offsets.length !== 1,
    matched_prefix: false,
    offsets,
    notes: offsets.length === 1
      ? ['offset 为 0 起始的字节偏移。']
      : offsets.length === 0 ? ['模式中没有该字节串。'] : ['该字节串在模式中出现多次，请提供更长字节后重试。'],
  };
}

export const PWN_PATTERN_PROPERTIES = {
  operation: { type: 'string', enum: ['create', 'find'], description: 'create 生成循环模式；find 查找字节串在模式中的偏移。' },
  length: { type: 'integer', minimum: 1, maximum: MAX_OUTPUT, description: 'create 返回的字符数，默认 256。' },
  value: {
    type: 'string', minLength: 1, maxLength: 34,
    description: 'find 的十六进制字节串（如 6c616161）；0x 开头按整数处理，默认小端。',
  },
  byte_order: { type: 'string', enum: ['little', 'big'], description: '0x 整数的字节序，默认 little。' },
};

export function cyclicPattern(input) {
  if (input.operation === 'create') return create(input.length);
  if (input.operation === 'find') {
    if (input.value === undefined) throw new ToolError('unsupported', 'find 需要 value。');
    return find(input.value, input.byte_order);
  }
  throw new ToolError('unsupported', 'operation 必须是 create 或 find。');
}
