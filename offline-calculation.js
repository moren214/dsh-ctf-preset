import { checkPrimeSync, createCipheriv, createDecipheriv, createHash, createHmac } from 'node:crypto';

const MAX_STEPS = 12;
const MAX_VALUE_CHARACTERS = 4096;
const MAX_RESULT_CHARACTERS = 65536;
const LONG_INPUT_OPERATIONS = new Set(['encode', 'decode', 'convert_encoding', 'hash', 'hmac', 'xor', 'aes_encrypt', 'aes_decrypt']);
const MAX_MODULAR_BITS = 4096;
const RSA_ATTACK_MODES = ['factor', 'fermat', 'wiener', 'common_modulus', 'broadcast', 'small_e'];
const DEFAULT_ATTACK_ITERATIONS = 100000;
const MAX_ATTACK_ITERATIONS = 1000000;
const MAX_ATTACK_INPUTS = 6;
const MAX_ATTACK_MODULI = MAX_ATTACK_INPUTS / 2;
const TRIAL_DIVISION_LIMIT = 65536;
const SMALL_E_MAX_MULTIPLIER = 10000;
const MAX_SMALL_EXPONENT = 64n;
const CONTINUED_FRACTION_LIMIT = 10000;
const DIGITS = '0123456789abcdefghijklmnopqrstuvwxyz';
const ENCODINGS = ['utf8', 'hex', 'base64', 'base64url'];
export const WORD_WIDTHS = [8, 16, 32, 64];
const BYTE_ORDERS = ['little', 'big'];
const HASH_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512'];
const SCHEMES = ['base32', 'base58', 'base85', 'url', 'form', 'html', 'html_bytes'];
const AES_MODES = ['ecb', 'cbc', 'ctr'];
const PADDINGS = ['pkcs7', 'none'];
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE85_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~';
const MAX_KEY_BYTES = 1024;

class CalculationError extends Error {}

function parseInteger(value, radix = 10) {
  const signed = value[0] === '+' || value[0] === '-';
  const digits = signed ? value.slice(1) : value;
  if (radix === 10) {
    if (digits.length === 0 || /[^0-9]/u.test(digits)) throw new CalculationError('需要带可选正负号的十进制整数。');
    return BigInt(value);
  }
  if (digits.length === 0 || /[^0-9A-Za-z]/u.test(digits)) throw new CalculationError('整数中包含进制不支持的字符。');
  let result = 0n;
  const base = BigInt(radix);
  for (const char of digits.toLowerCase()) {
    const digit = DIGITS.indexOf(char);
    if (digit >= radix) throw new CalculationError('整数中有数字超出了指定进制。');
    result = result * base + BigInt(digit);
  }
  return value[0] === '-' ? -result : result;
}

function integerDivide(value, divisor) {
  if (divisor === 0n) throw new CalculationError('除数须为非零整数。');
  return value / divisor;
}

function modulo(value, modulus) {
  if (modulus <= 0n) throw new CalculationError('模数须为正整数。');
  const remainder = value % modulus;
  return remainder < 0n ? remainder + modulus : remainder;
}

function modularPower(base, exponent, modulus) {
  if (exponent < 0n) throw new CalculationError('模幂的指数须为非负整数。');
  if (exponent.toString(2).length > MAX_MODULAR_BITS || modulus.toString(2).length > MAX_MODULAR_BITS) {
    throw new CalculationError('模幂的指数和模数各限 4096 位二进制。');
  }
  let factor = modulo(base, modulus);
  let result = 1n % modulus;
  while (exponent !== 0n) {
    if ((exponent & 1n) === 1n) result = (result * factor) % modulus;
    exponent >>= 1n;
    factor = (factor * factor) % modulus;
  }
  return result;
}

function decodeBytes(value, encoding) {
  const input = encoding === 'base64' || encoding === 'base64url' ? value.replace(/[\t\r\n\f ]/gu, '') : value;
  const bytes = Buffer.from(input, encoding);
  if (encoding === 'utf8') return bytes;
  const canonical = bytes.toString(encoding);
  if (encoding === 'hex') {
    if (canonical !== input.toLowerCase()) throw new CalculationError('Hex 输入须由成对的十六进制数字组成。');
  } else {
    const bare = canonical.replace(/=+$/u, '');
    const padded = bare.padEnd(Math.ceil(bare.length / 4) * 4, '=');
    if (input !== bare && input !== padded) throw new CalculationError('编码的字母表、填充或末尾位不符合所选格式。');
  }
  return bytes;
}

function convertEncoding([input], { from_encoding, to_encoding }) {
  const bytes = decodeBytes(input, from_encoding);
  if (to_encoding !== 'utf8') return bytes.toString(to_encoding);
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new CalculationError('解码所得字节不是有效的 UTF-8。');
  }
}

function decimalOperation(operation) {
  return values => operation(...values.map(value => parseInteger(value))).toString();
}

function wordOperand(value) {
  if (!/^[+-]?0x[\da-f]+$/iu.test(value)) return parseInteger(value);
  const sign = value[0];
  const magnitude = BigInt(sign === '+' || sign === '-' ? value.slice(1) : value);
  return sign === '-' ? -magnitude : magnitude;
}

function wordResult(width, value) {
  return BigInt.asUintN(width, value).toString();
}

const WORD_BINARY = {
  word_add: (a, b) => a + b,
  word_subtract: (a, b) => a - b,
  word_multiply: (a, b) => a * b,
  word_xor: (a, b) => a ^ b,
  word_and: (a, b) => a & b,
  word_or: (a, b) => a | b,
};

function rotate(value, count, bits, right) {
  const shift = count % bits;
  return right ? (value >> shift) | (value << (bits - shift)) : (value << shift) | (value >> (bits - shift));
}

const WORD_SHIFTS = {
  word_shl: (value, count, bits) => count >= bits ? 0n : value << count,
  word_lshr: (value, count, bits) => count >= bits ? 0n : value >> count,
  word_ashr: (value, count, bits) => BigInt.asIntN(Number(bits), value) >> (count < bits ? count : bits),
  word_rol: (value, count, bits) => rotate(value, count, bits, false),
  word_ror: (value, count, bits) => rotate(value, count, bits, true),
};

export const WORD_ACCUMULATOR_OPERATIONS = [...Object.keys(WORD_BINARY), ...Object.keys(WORD_SHIFTS)];

function wordBytes(input, width, order) {
  if (input.length !== width / 4 || /[^\da-f]/iu.test(input)) throw new CalculationError('Hex 字节数须与指定字宽一致。');
  const bytes = Buffer.from(input, 'hex');
  return order === 'little' ? bytes.reverse() : bytes;
}

const WORD_OPERATIONS = {
  ...Object.fromEntries(Object.entries(WORD_BINARY).map(([name, operation]) => [name, {
    inputs: 2, options: ['width'], run: ([a, b], { width }) => wordResult(width, operation(wordOperand(a), wordOperand(b))),
  }])),
  ...Object.fromEntries(Object.entries(WORD_SHIFTS).map(([name, operation]) => [name, {
    inputs: 2, options: ['width'], run: ([value, shift], { width }) => {
      const count = wordOperand(shift);
      if (count < 0n) throw new CalculationError('移位或旋转次数须为非负整数。');
      return wordResult(width, operation(BigInt.asUintN(width, wordOperand(value)), count, BigInt(width)));
    },
  }])),
  word_not: { inputs: 1, options: ['width'], run: ([value], { width }) => wordResult(width, ~wordOperand(value)) },
  word_truncate: { inputs: 1, options: ['width'], run: ([value], { width }) => wordResult(width, wordOperand(value)) },
  word_as_signed: {
    inputs: 1, options: ['width'], run: ([value], { width }) => BigInt.asIntN(width, wordOperand(value)).toString(),
  },
  word_sign_extend: {
    inputs: 1, options: ['from_width', 'width'],
    run: ([value], { from_width, width }) => wordResult(width, BigInt.asIntN(from_width, wordOperand(value))),
  },
  word_from_bytes: {
    inputs: 1, options: ['width', 'byte_order'],
    run: ([input], { width, byte_order }) => BigInt(`0x${wordBytes(input, width, byte_order).toString('hex')}`).toString(),
  },
  word_to_bytes: {
    inputs: 1, options: ['width', 'byte_order'],
    run: ([input], { width, byte_order }) => {
      const hex = BigInt.asUintN(width, wordOperand(input)).toString(16).padStart(width / 4, '0');
      return wordBytes(hex, width, byte_order).toString('hex');
    },
  },
};

function hexBytes(value, label) {
  const text = value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
  if (text.length === 0 || text.length % 2 !== 0 || /[^\da-f]/iu.test(text)) {
    throw new CalculationError(label + '须为成对的十六进制数字。');
  }
  return Buffer.from(text, 'hex');
}

function bytesToText(bytes, encoding, label = '结果') {
  if (encoding === 'hex') return bytes.toString('hex');
  if (encoding === 'base64') return bytes.toString('base64');
  if (encoding === 'base64url') return bytes.toString('base64url');
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new CalculationError(label + '不是有效的 UTF-8，请改用 hex 或 base64 输出。');
  }
}

function encodeBase32(bytes) {
  let buffer = 0;
  let bits = 0;
  let out = '';
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(buffer << (5 - bits)) & 31];
  while (out.length % 8 !== 0) out += '=';
  return out;
}

function decodeBase32(value) {
  const clean = value.replace(/=+$/u, '').toUpperCase();
  if (!/^[A-Z2-7]*$/u.test(clean) || clean.length % 8 === 1 || clean.length % 8 === 3 || clean.length % 8 === 6) {
    throw new CalculationError('Base32 输入含非法字符或长度不合法。');
  }
  let buffer = 0;
  let bits = 0;
  const out = [];
  for (const char of clean) {
    buffer = (buffer << 5) | BASE32_ALPHABET.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      out.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
      buffer &= (1 << bits) - 1;
    }
  }
  if (bits > 0 && buffer !== 0) throw new CalculationError('Base32 末尾填充位不为零。');
  return Buffer.from(out);
}

function encodeBase58(bytes) {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  let out = '';
  while (value > 0n) {
    out = BASE58_ALPHABET[Number(value % 58n)] + out;
    value /= 58n;
  }
  return '1'.repeat(zeros) + out;
}

function decodeBase58(value) {
  let zeros = 0;
  while (zeros < value.length && value[zeros] === '1') zeros++;
  let result = 0n;
  for (const char of value) {
    const digit = BASE58_ALPHABET.indexOf(char);
    if (digit < 0) throw new CalculationError('Base58 输入含非法字符。');
    result = result * 58n + BigInt(digit);
  }
  let hex = result.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const body = result === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex');
  return Buffer.concat([Buffer.alloc(zeros), body]);
}

function encodeBase85(bytes) {
  let out = '';
  for (let offset = 0; offset < bytes.length; offset += 4) {
    const chunk = Buffer.alloc(4);
    bytes.copy(chunk, 0, offset, Math.min(offset + 4, bytes.length));
    let value = chunk.readUInt32BE(0);
    let group = '';
    for (let index = 0; index < 5; index++) {
      group = BASE85_ALPHABET[value % 85] + group;
      value = Math.floor(value / 85);
    }
    out += group;
  }
  return out.slice(0, Math.ceil(bytes.length * 5 / 4));
}

function decodeBase85(value) {
  const padded = value + '~'.repeat((5 - (value.length % 5)) % 5);
  const out = [];
  for (let offset = 0; offset < padded.length; offset += 5) {
    let group = 0;
    for (const char of padded.slice(offset, offset + 5)) {
      const digit = BASE85_ALPHABET.indexOf(char);
      if (digit < 0) throw new CalculationError('Base85 输入含非法字符。');
      group = group * 85 + digit;
    }
    if (group > 0xffffffff) throw new CalculationError('Base85 分组数值超出 32 位。');
    const chunk = Buffer.alloc(4);
    chunk.writeUInt32BE(group >>> 0, 0);
    out.push(chunk);
  }
  return Buffer.concat(out).subarray(0, Math.floor(value.length * 4 / 5));
}

function encodeUrl(bytes, form) {
  let out = '';
  const unescaped = form ? /[A-Za-z0-9*._-]/u : /[A-Za-z0-9_.~-]/u;
  for (const byte of bytes) {
    const char = String.fromCharCode(byte);
    if (form && byte === 32) out += '+';
    else out += unescaped.test(char) ? char : '%' + byte.toString(16).toUpperCase().padStart(2, '0');
  }
  return out;
}

function decodeUrl(text, form) {
  const out = [];
  for (let index = 0; index < text.length;) {
    const char = String.fromCodePoint(text.codePointAt(index));
    if (char === '%') {
      const hex = text.slice(index + 1, index + 3);
      if (!/^[\da-f]{2}$/iu.test(hex)) throw new CalculationError('URL 编码中的百分号后须跟两位十六进制数字。');
      out.push(Number.parseInt(hex, 16));
      index += 3;
    } else if (form && char === '+') {
      out.push(32);
      index++;
    } else {
      out.push(...Buffer.from(char, 'utf8'));
      index += char.length;
    }
  }
  return Buffer.from(out);
}

const HTML_ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0',
  copy: '\u00a9', reg: '\u00ae', trade: '\u2122', hellip: '\u2026',
  mdash: '\u2014', ndash: '\u2013', lsquo: '\u2018', rsquo: '\u2019',
  ldquo: '\u201c', rdquo: '\u201d', laquo: '\u00ab', raquo: '\u00bb',
  times: '\u00d7', divide: '\u00f7', euro: '\u20ac', pound: '\u00a3',
  yen: '\u00a5', cent: '\u00a2', deg: '\u00b0', plusmn: '\u00b1',
};

function encodeHtml(text) {
  return text.replace(/[&<>"']/gu, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}

function byteHtml(text) {
  const bytes = [];
  for (const char of decodeHtml(text)) {
    const value = char.codePointAt(0);
    if (value > 255) throw new CalculationError('html_bytes 仅接受 0 至 255 的实体值。');
    bytes.push(value);
  }
  return Buffer.from(bytes);
}

function decodeHtml(text) {
  return text.replace(/&(#x[\da-f]+|#\d+|[a-z]+);/giu, (match, body) => {
    if (body[0] === '#') {
      const code = body[1] === 'x' || body[1] === 'X' ? Number.parseInt(body.slice(2), 16) : Number.parseInt(body.slice(1), 10);
      if (!Number.isInteger(code) || code < 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) {
        throw new CalculationError('HTML 实体中的码点超出范围。');
      }
      return String.fromCodePoint(code);
    }
    const named = HTML_ENTITIES[body.toLowerCase()];
    if (named === undefined) throw new CalculationError('不支持的 HTML 命名实体：' + body + '。');
    return named;
  });
}

function encodeScheme([input], step) {
  const scheme = step.scheme;
  const bytes = decodeBytes(input, step.from_encoding ?? 'utf8');
  if (scheme === 'base32') return encodeBase32(bytes);
  if (scheme === 'base58') return encodeBase58(bytes);
  if (scheme === 'base85') return encodeBase85(bytes);
  if (scheme === 'url' || scheme === 'form') return encodeUrl(bytes, scheme === 'form');
  if (scheme === 'html_bytes') return Array.from(bytes, byte => '&#x' + byte.toString(16).padStart(2, '0') + ';').join('');
  return encodeHtml(bytesToText(bytes, 'utf8', '待编码内容'));
}

function decodeScheme([input], step) {
  const scheme = step.scheme;
  let bytes;
  if (scheme === 'base32') bytes = decodeBase32(input);
  else if (scheme === 'base58') bytes = decodeBase58(input);
  else if (scheme === 'base85') bytes = decodeBase85(input);
  else if (scheme === 'url' || scheme === 'form') bytes = decodeUrl(input, scheme === 'form');
  else if (scheme === 'html_bytes') bytes = byteHtml(input);
  else bytes = Buffer.from(decodeHtml(input), 'utf8');
  return bytesToText(bytes, step.to_encoding ?? 'utf8', '解码结果');
}

function hashOperation([input], step) {
  const bytes = decodeBytes(input, step.from_encoding ?? 'utf8');
  const digest = createHash(step.algorithm).update(bytes).digest();
  return bytesToText(digest, step.to_encoding ?? 'hex', '哈希结果');
}

function hmacOperation([input, key], step) {
  const data = decodeBytes(input, step.from_encoding ?? 'utf8');
  const secret = step.key_encoding === 'hex' ? hexBytes(key, 'HMAC 密钥') : Buffer.from(key, 'utf8');
  if (secret.length === 0 || secret.length > MAX_KEY_BYTES) throw new CalculationError('HMAC 密钥须为 1 至 1024 字节。');
  const digest = createHmac(step.algorithm, secret).update(data).digest();
  return bytesToText(digest, step.to_encoding ?? 'hex', 'HMAC 结果');
}

function xorKey(value, encoding) {
  const key = encoding === 'hex' ? hexBytes(value, 'XOR 密钥') : Buffer.from(value, 'utf8');
  if (key.length === 0 || key.length > MAX_KEY_BYTES) throw new CalculationError('XOR 密钥须为 1 至 1024 字节。');
  return key;
}

function xorBytes(data, key) {
  const out = Buffer.alloc(data.length);
  for (let index = 0; index < data.length; index++) out[index] = data[index] ^ key[index % key.length];
  return out;
}

function xorOperation([input], step) {
  const data = decodeBytes(input, step.from_encoding ?? 'utf8');
  return bytesToText(xorBytes(data, xorKey(step.key, step.key_encoding ?? 'utf8')), step.to_encoding ?? 'hex', 'XOR 结果');
}

const ENGLISH_FREQUENCY = [
  8.17, 1.49, 2.78, 4.25, 12.7, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77, 4.03, 2.41,
  6.75, 7.51, 1.93, 0.10, 5.99, 6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07,
];

function plainScore(bytes) {
  if (bytes.length === 0) return -1000;
  const text = bytes.toString('latin1');
  let printable = 0;
  const counts = new Array(26).fill(0);
  let letters = 0;
  for (const byte of bytes) {
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) printable++;
    const lower = byte >= 65 && byte <= 90 ? byte + 32 : byte;
    if (lower >= 97 && lower <= 122) {
      counts[lower - 97]++;
      letters++;
    }
  }
  const ratio = printable / bytes.length;
  let score = ratio * 20;
  if (ratio < 0.7) score -= 100;
  if (/flag\{|ctf\{|key\{/iu.test(text)) score += 100;
  else if (/[a-z]{3,}\{[^}\n]{2,}\}/iu.test(text)) score += 30;
  if (letters > 0) {
    let chi = 0;
    for (let index = 0; index < 26; index++) {
      const expected = bytes.length * ENGLISH_FREQUENCY[index] / 100;
      chi += (counts[index] - expected) ** 2 / Math.max(expected, 0.01);
    }
    score -= chi * 0.05;
  }
  return score;
}

function displayBytes(bytes) {
  let out = '';
  for (const byte of bytes) {
    if (byte === 10) out += '\\n';
    else if (byte === 13) out += '\\r';
    else if (byte === 9) out += '\\t';
    else if (byte >= 32 && byte <= 126) out += String.fromCharCode(byte);
    else out += '\\x' + byte.toString(16).padStart(2, '0');
  }
  return out;
}

function bruteforceLines(candidates, top) {
  return candidates
    .sort((left, right) => right.score - left.score || left.order - right.order)
    .slice(0, top)
    .map(candidate => candidate.label + ' score=' + candidate.score.toFixed(1) + ' ' + displayBytes(candidate.bytes))
    .join('\n');
}

function xorBruteforce([input], step) {
  const data = decodeBytes(input, step.from_encoding ?? 'utf8');
  const candidates = [];
  for (let key = 0; key < 256; key++) {
    const decoded = xorBytes(data, Buffer.from([key]));
    candidates.push({ order: key, label: 'key=0x' + key.toString(16).padStart(2, '0'), score: plainScore(decoded), bytes: decoded });
  }
  return bruteforceLines(candidates, step.top ?? 5);
}

function caesarShift(text, shift) {
  return text.replace(/[A-Za-z]/gu, char => {
    const base = char >= 'a' ? 97 : 65;
    return String.fromCharCode(((char.charCodeAt(0) - base + shift) % 26 + 26) % 26 + base);
  });
}

function caesarOperation([input], step) {
  const shift = step.decrypt ? -step.shift : step.shift;
  return caesarShift(input, shift);
}

function caesarBruteforce([input], step) {
  const candidates = [];
  for (let shift = 1; shift <= 25; shift++) {
    const text = caesarShift(input, -shift);
    candidates.push({ order: shift, label: 'shift=' + shift, score: plainScore(Buffer.from(text, 'utf8')), bytes: Buffer.from(text, 'utf8') });
  }
  return bruteforceLines(candidates, step.top ?? 5);
}

function atbashOperation([input]) {
  return input.replace(/[A-Za-z]/gu, char => {
    const base = char >= 'a' ? 97 : 65;
    return String.fromCharCode(base + (25 - (char.charCodeAt(0) - base)));
  });
}

function vigenereOperation([input, key], step) {
  const letters = key.replace(/[^A-Za-z]/gu, '').toUpperCase();
  if (letters.length === 0) throw new CalculationError('Vigenère 密钥须至少包含一个字母。');
  let index = 0;
  return input.replace(/[A-Za-z]/gu, char => {
    const base = char >= 'a' ? 97 : 65;
    const shift = letters.charCodeAt(index % letters.length) - 65;
    index++;
    const offset = step.decrypt ? -shift : shift;
    return String.fromCharCode(((char.charCodeAt(0) - base + offset) % 26 + 26) % 26 + base);
  });
}

function inverseModulo(value, modulus) {
  for (let candidate = 1; candidate < modulus; candidate++) {
    if ((value * candidate) % modulus === 1) return candidate;
  }
  throw new CalculationError('仿射密码的 a 与 26 不互质。');
}

function affineOperation([input], step) {
  const inverse = inverseModulo(step.a, 26);
  return input.replace(/[A-Za-z]/gu, char => {
    const base = char >= 'a' ? 97 : 65;
    const value = char.charCodeAt(0) - base;
    const mapped = step.decrypt ? (inverse * (value - step.b) % 26 + 26) % 26 : (step.a * value + step.b) % 26;
    return String.fromCharCode(base + mapped);
  });
}

function affineBruteforce([input], step) {
  const candidates = [];
  for (let a = 1; a < 26; a++) {
    if (a % 2 === 0 || a === 13) continue;
    for (let b = 0; b < 26; b++) {
      const text = affineOperation([input], { a, b, decrypt: true });
      candidates.push({ order: a * 26 + b, label: 'a=' + a + ' b=' + b, score: plainScore(Buffer.from(text, 'utf8')), bytes: Buffer.from(text, 'utf8') });
    }
  }
  return bruteforceLines(candidates, step.top ?? 5);
}

function railFenceOperation([input], step) {
  const rails = step.rails;
  if (rails >= input.length) return input;
  if (!step.decrypt) {
    const rows = Array.from({ length: rails }, () => []);
    let row = 0;
    let direction = 1;
    for (const char of input) {
      rows[row].push(char);
      if (row === 0) direction = 1;
      else if (row === rails - 1) direction = -1;
      row += direction;
    }
    return rows.flat().join('');
  }
  const pattern = [];
  let row = 0;
  let direction = 1;
  for (let index = 0; index < input.length; index++) {
    pattern.push(row);
    if (row === 0) direction = 1;
    else if (row === rails - 1) direction = -1;
    row += direction;
  }
  const counts = new Array(rails).fill(0);
  for (const value of pattern) counts[value]++;
  let cursor = 0;
  const rows = counts.map(count => {
    const slice = input.slice(cursor, cursor + count).split('');
    cursor += count;
    return slice;
  });
  let out = '';
  for (const value of pattern) out += rows[value].shift();
  return out;
}

function aesOperation([input], step, decrypt) {
  const key = hexBytes(step.key, 'AES 密钥');
  if (![16, 24, 32].includes(key.length)) throw new CalculationError('AES 密钥须为 16、24 或 32 字节。');
  const mode = step.mode ?? 'cbc';
  const padding = step.padding ?? (mode === 'ctr' ? 'none' : 'pkcs7');
  if (mode === 'ctr' && padding !== 'none') throw new CalculationError('AES-CTR 不使用分组填充，padding 须为 none。');
  let iv = null;
  if (mode !== 'ecb') {
    iv = hexBytes(step.iv ?? '', 'AES IV');
    if (iv.length !== 16) throw new CalculationError('AES 的 IV 须为 16 字节。');
  }
  if (mode === 'ecb' && step.iv !== undefined) throw new CalculationError('ECB 模式不需要 IV。');
  const data = decodeBytes(input, step.from_encoding ?? 'utf8');
  const algorithm = 'aes-' + key.length * 8 + '-' + mode;
  let output;
  try {
    const cipher = decrypt ? createDecipheriv(algorithm, key, iv) : createCipheriv(algorithm, key, iv);
    if (mode !== 'ctr') cipher.setAutoPadding(padding === 'pkcs7');
    output = Buffer.concat([cipher.update(data), cipher.final()]);
  } catch (error) {
    throw new CalculationError('AES 运算失败：' + (error instanceof Error ? error.message : String(error)));
  }
  return bytesToText(output, step.to_encoding ?? 'hex', 'AES 结果');
}

function parseBigInteger(value, base, label) {
  const text = value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
  if (base === 16) {
    if (text.length === 0 || /[^\da-f]/iu.test(text)) throw new CalculationError(label + '须为十六进制整数。');
    return BigInt('0x' + text);
  }
  if (/^0x/iu.test(value)) throw new CalculationError(label + '为十进制整数，不能带 0x 前缀。');
  if (!/^\d+$/u.test(text)) throw new CalculationError(label + '须为非负十进制整数。');
  return BigInt(text);
}

function rsaOperation([message], step, decrypt) {
  const modulus = parseBigInteger(step.n, 10, '模数 n');
  const exponent = parseBigInteger(decrypt ? step.d : step.e, 10, decrypt ? '私钥指数 d' : '公钥指数 e');
  if (modulus <= 1n) throw new CalculationError('RSA 模数 n 须大于 1。');
  if (exponent <= 0n) throw new CalculationError('RSA 指数须为正整数。');
  const value = parseBigInteger(message, step.input_base ?? 10, 'RSA 输入');
  if (value < 0n || value >= modulus) throw new CalculationError('RSA 输入须为 0 到 n-1 之间的整数。');
  const result = modularPower(value, exponent, modulus);
  return (step.output_base === 16 ? result.toString(16) : result.toString());
}

function integerSquareRoot(value) {
  if (value < 2n) return value;
  let guess = 1n << BigInt(Math.ceil(value.toString(2).length / 2) + 1);
  while (true) {
    const next = (guess + value / guess) >> 1n;
    if (next >= guess) break;
    guess = next;
  }
  while (guess * guess > value) guess--;
  while ((guess + 1n) * (guess + 1n) <= value) guess++;
  return guess;
}

function integerNthRoot(value, degree) {
  if (value < 2n) return value;
  const bigDegree = BigInt(degree);
  let guess = 1n << BigInt(Math.ceil(value.toString(2).length / degree) + 1);
  while (true) {
    const next = ((bigDegree - 1n) * guess + value / guess ** (bigDegree - 1n)) / bigDegree;
    if (next >= guess) break;
    guess = next;
  }
  while (guess ** bigDegree > value) guess--;
  while ((guess + 1n) ** bigDegree <= value) guess++;
  return guess;
}

function integerRootOperation([input], step) {
  const value = parseBigInteger(input, 10, '开方输入');
  if (value < 2n) return value.toString();
  const root = integerNthRoot(value, step.degree);
  if (root ** BigInt(step.degree) !== value) throw new CalculationError('输入不是完全 ' + step.degree + ' 次方。');
  return root.toString();
}

function greatestCommonDivisor(left, right) {
  let a = left < 0n ? -left : left;
  let b = right < 0n ? -right : right;
  while (b !== 0n) {
    const remainder = a % b;
    a = b;
    b = remainder;
  }
  return a;
}

function extendedEuclid(left, right) {
  let [oldRemainder, remainder] = [left, right];
  let [oldLeft, leftCoefficient] = [1n, 0n];
  let [oldRight, rightCoefficient] = [0n, 1n];
  while (remainder !== 0n) {
    const quotient = oldRemainder / remainder;
    [oldRemainder, remainder] = [remainder, oldRemainder - quotient * remainder];
    [oldLeft, leftCoefficient] = [leftCoefficient, oldLeft - quotient * leftCoefficient];
    [oldRight, rightCoefficient] = [rightCoefficient, oldRight - quotient * rightCoefficient];
  }
  return { gcd: oldRemainder, x: oldLeft, y: oldRight };
}

function modularInverse(value, modulus) {
  const result = extendedEuclid(modulo(value, modulus), modulus);
  if (result.gcd !== 1n) return null;
  return modulo(result.x, modulus);
}

function attackModulus(value, label) {
  if (value <= 1n) throw new CalculationError(label + ' 须大于 1。');
  if (value.toString(2).length > MAX_MODULAR_BITS) throw new CalculationError(label + ' 超过 4096 位二进制上限。');
  return value;
}

function attackExponent(value, label) {
  if (value <= 1n) throw new CalculationError(label + ' 须大于 1。');
  if (value.toString(2).length > MAX_MODULAR_BITS) throw new CalculationError(label + ' 超过 4096 位二进制上限。');
  return value;
}

function attackCipher(value, modulus) {
  if (value >= modulus) throw new CalculationError('密文 c 须为 0 到 n-1 之间的整数。');
  return value;
}

function bigIntBytes(value) {
  if (value === 0n) return Buffer.from([0]);
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  return Buffer.from(hex, 'hex');
}

function plaintextFields(value) {
  const bytes = bigIntBytes(value);
  const printable = bytes.every(byte => byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126));
  const fields = { plaintext: value.toString() };
  if (printable) fields.text = bytes.toString('latin1');
  else fields.plaintext_hex = bytes.toString('hex');
  return fields;
}

function attackResult(mode, fields) {
  const output = { mode };
  if (fields.factors !== undefined) output.factors = fields.factors;
  if (fields.d !== undefined) output.d = fields.d;
  if (fields.plaintext !== undefined) Object.assign(output, plaintextFields(fields.plaintext));
  if (fields.iterations !== undefined) output.iterations = fields.iterations;
  if (fields.note !== undefined) output.note = fields.note;
  let text = JSON.stringify(output);
  if (text.length > MAX_VALUE_CHARACTERS && output.plaintext !== undefined) {
    delete output.plaintext;
    delete output.plaintext_hex;
    delete output.text;
    output.note = (output.note === undefined ? '' : output.note + ' ') + '明文字段超过 4096 字符上限，已省略。';
    text = JSON.stringify(output);
  }
  return text;
}

function pollardBrent(n, maxIterations) {
  if (n % 2n === 0n) return { factor: 2n, iterations: 0 };
  if (n % 3n === 0n) return { factor: 3n, iterations: 0 };
  let iterations = 0;
  for (const seed of [1n, 2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n]) {
    let y = 2n;
    let power = 1;
    let product = 1n;
    let divisor = 1n;
    let x = 0n;
    while (divisor === 1n) {
      x = y;
      for (let index = 0; index < power; index++) {
        y = (y * y + seed) % n;
        iterations++;
        if (iterations > maxIterations) return null;
      }
      let offset = 0;
      while (offset < power && divisor === 1n) {
        const size = Math.min(128, power - offset);
        for (let index = 0; index < size; index++) {
          y = (y * y + seed) % n;
          product = (product * modulo(x - y, n)) % n;
          iterations++;
        }
        divisor = greatestCommonDivisor(product, n);
        offset += size;
        if (iterations > maxIterations) return null;
      }
      power *= 2;
    }
    if (divisor !== n) return { factor: divisor, iterations };
  }
  return null;
}

function factorComposite(n, maxIterations) {
  if (n === 2n) throw new CalculationError('n 太小，试除失败：n 为素数。');
  let iterations = 0;
  let factor = null;
  let exhausted = false;
  if (n % 2n === 0n) {
    factor = 2n;
  } else {
    for (let candidate = 3n; candidate < BigInt(TRIAL_DIVISION_LIMIT); candidate += 2n) {
      if (candidate * candidate > n) {
        exhausted = true;
        break;
      }
      iterations++;
      if (n % candidate === 0n) {
        factor = candidate;
        break;
      }
    }
  }
  if (factor === null) {
    if (exhausted) throw new CalculationError('n 太小，试除失败：没有 65536 以内的因子，n 可能是素数。');
    const found = pollardBrent(n, maxIterations);
    if (found === null) throw new CalculationError('Pollard rho 在 ' + maxIterations + ' 次迭代内未找到因子。');
    factor = found.factor;
    iterations += found.iterations;
  }
  if (factor <= 1n || factor >= n) throw new CalculationError('分解失败：未得到非平凡因子。');
  const other = n / factor;
  return { factors: factor < other ? [factor, other] : [other, factor], iterations };
}

function decryptWithFactors(n, e, c, factors) {
  const [p, q] = factors;
  if (p === q || p * q !== n || p < 2n || q < 2n || !checkPrimeSync(p, { checks: 16 }) || !checkPrimeSync(q, { checks: 16 })) {
    throw new CalculationError('分解结果不是两个不同的素数，无法核验 RSA 明文。');
  }
  const totient = (p - 1n) * (q - 1n);
  const d = modularInverse(e, totient);
  if (d === null) return { note: 'e 与 φ(n) 不互质，未能求出私钥 d。' };
  const plaintext = modularPower(c, d, n);
  if (modularPower(plaintext, e, n) !== c) {
    throw new CalculationError('明文未通过重新加密核对。');
  }
  return { d, plaintext };
}

function factorAttackResult(mode, factors, decrypted, iterations) {
  return attackResult(mode, {
    factors: factors.map(value => value.toString()),
    d: decrypted.d === undefined ? undefined : decrypted.d.toString(),
    plaintext: decrypted.plaintext,
    iterations,
    note: decrypted.note,
  });
}

function rsaFactorAttack(n, e, c, maxIterations) {
  const { factors, iterations } = factorComposite(n, maxIterations);
  return factorAttackResult('factor', factors, decryptWithFactors(n, e, c, factors), iterations);
}

function rsaFermatAttack(n, e, c, maxIterations) {
  if (n === 2n) throw new CalculationError('n 太小，试除失败：n 为素数。');
  let factors;
  let iterations = 0;
  if (n % 2n === 0n) {
    factors = [2n, n / 2n];
  } else {
    let side = integerSquareRoot(n);
    if (side * side < n) side += 1n;
    let difference = side * side - n;
    let found = false;
    for (let attempts = 0; attempts < maxIterations; attempts++) {
      const root = integerSquareRoot(difference);
      if (root * root === difference) {
        const p = side - root;
        const q = side + root;
        if (p > 1n && q > 1n && p * q === n) {
          factors = p < q ? [p, q] : [q, p];
          iterations = attempts;
          found = true;
          break;
        }
        if (p <= 1n) break;
      }
      difference += 2n * side + 1n;
      side += 1n;
    }
    if (!found) throw new CalculationError('Fermat 在 ' + maxIterations + ' 次迭代内未找到非平凡因子：两因子可能相差过大。');
  }
  return factorAttackResult('fermat', factors, decryptWithFactors(n, e, c, factors), iterations);
}

function continuedFractionConvergents(numerator, denominator) {
  const convergents = [];
  let previousNumerator = 0n;
  let currentNumerator = 1n;
  let previousDenominator = 1n;
  let currentDenominator = 0n;
  let dividend = numerator;
  let divisor = denominator;
  while (divisor !== 0n && convergents.length < CONTINUED_FRACTION_LIMIT) {
    const quotient = dividend / divisor;
    const nextNumerator = quotient * currentNumerator + previousNumerator;
    const nextDenominator = quotient * currentDenominator + previousDenominator;
    convergents.push([nextNumerator, nextDenominator]);
    previousNumerator = currentNumerator;
    currentNumerator = nextNumerator;
    previousDenominator = currentDenominator;
    currentDenominator = nextDenominator;
    const remainder = dividend - quotient * divisor;
    dividend = divisor;
    divisor = remainder;
  }
  return convergents;
}

function rsaWienerAttack(n, e, c) {
  for (const [index, [numerator, denominator]] of continuedFractionConvergents(e, n).entries()) {
    if (numerator === 0n || denominator <= 1n) continue;
    const scaled = e * denominator - 1n;
    if (scaled % numerator !== 0n) continue;
    const totient = scaled / numerator;
    const sum = n - totient + 1n;
    const discriminant = sum * sum - 4n * n;
    if (discriminant < 0n) continue;
    const root = integerSquareRoot(discriminant);
    if (root * root !== discriminant) continue;
    const p = (sum + root) / 2n;
    const q = (sum - root) / 2n;
    if (p <= 1n || q <= 1n || p * q !== n) continue;
    const plaintext = modularPower(c, denominator, n);
    if (modularPower(plaintext, e, n) !== c) continue;
    return attackResult('wiener', {
      factors: (p < q ? [p, q] : [q, p]).map(value => value.toString()),
      d: denominator.toString(),
      plaintext,
      iterations: index + 1,
    });
  }
  throw new CalculationError('Wiener 未找到连分数收敛：d 可能不够小。');
}

function signedPower(base, exponent, modulus, inverseError) {
  if (exponent >= 0n) return modularPower(base, exponent, modulus);
  const inverse = modularInverse(base, modulus);
  if (inverse === null) throw new CalculationError(inverseError);
  return modularPower(inverse, -exponent, modulus);
}

function commonModulusAttack(n, e1, c1, e2, c2) {
  if (greatestCommonDivisor(e1, e2) !== 1n) throw new CalculationError('e1/e2 不互质，无法使用共模攻击。');
  const { x, y } = extendedEuclid(e1, e2);
  const first = signedPower(c1, x, n, 'c1 与 n 不互质，无法求模逆。');
  const second = signedPower(c2, y, n, 'c2 与 n 不互质，无法求模逆。');
  return attackResult('common_modulus', { plaintext: (first * second) % n });
}

function broadcastAttack(pairs, exponent) {
  if (exponent < 2n || exponent > MAX_SMALL_EXPONENT) {
    throw new CalculationError('广播攻击的公钥指数 e 须为 2 至 64。');
  }
  let modulus = 1n;
  for (const [value] of pairs) {
    if (greatestCommonDivisor(modulus, value) !== 1n) throw new CalculationError('广播攻击要求各模数 n 两两互质。');
    modulus *= value;
  }
  let combined = 0n;
  for (const [value, cipher] of pairs) {
    const partial = modulus / value;
    const inverse = modularInverse(partial, value);
    if (inverse === null) throw new CalculationError('广播攻击要求各模数 n 两两互质。');
    combined = (combined + cipher * partial * inverse) % modulus;
  }
  const root = integerNthRoot(combined, Number(exponent));
  if (root ** exponent !== combined) {
    throw new CalculationError('CRT 结果不是完全 ' + exponent.toString() + ' 次方：模数乘积可能小于 m^e，请增加一组模数。');
  }
  return attackResult('broadcast', {
    plaintext: root,
    note: 'e=' + exponent.toString() + '，共 ' + pairs.length + ' 组模数。',
  });
}

function smallExponentAttack(n, e, c) {
  if (e > MAX_SMALL_EXPONENT) throw new CalculationError('小指数攻击的公钥指数 e 须为 2 至 64。');
  const degree = Number(e);
  for (let multiplier = 0; multiplier <= SMALL_E_MAX_MULTIPLIER; multiplier++) {
    const candidate = c + BigInt(multiplier) * n;
    const root = integerNthRoot(candidate, degree);
    if (root ** e === candidate) return attackResult('small_e', { plaintext: root, iterations: multiplier });
  }
  throw new CalculationError('在 k ≤ ' + SMALL_E_MAX_MULTIPLIER + ' 范围内未找到完全 ' + e.toString() + ' 次方。');
}

function rsaAttackOperation(values, step) {
  const maxIterations = step.max_iterations ?? DEFAULT_ATTACK_ITERATIONS;
  if (['factor', 'fermat', 'wiener', 'small_e'].includes(step.rsa_mode)) {
    const [n, e, c] = values.map((value, index) => parseBigInteger(value, 10, '输入 ' + (index + 1)));
    attackModulus(n, '模数 n');
    attackExponent(e, '公钥指数 e');
    attackCipher(c, n);
    if (step.rsa_mode === 'factor') return rsaFactorAttack(n, e, c, maxIterations);
    if (step.rsa_mode === 'fermat') return rsaFermatAttack(n, e, c, maxIterations);
    if (step.rsa_mode === 'wiener') return rsaWienerAttack(n, e, c);
    return smallExponentAttack(n, e, c);
  }
  if (step.rsa_mode === 'common_modulus') {
    const [n, e1, c1, e2, c2] = values.map((value, index) => parseBigInteger(value, 10, '输入 ' + (index + 1)));
    attackModulus(n, '模数 n');
    attackExponent(e1, 'e1');
    attackExponent(e2, 'e2');
    attackCipher(c1, n);
    attackCipher(c2, n);
    return commonModulusAttack(n, e1, c1, e2, c2);
  }
  const pairs = [];
  for (let index = 0; index < values.length; index += 2) {
    const n = parseBigInteger(values[index], 10, '输入 ' + (index + 1));
    attackModulus(n, '模数 n');
    const c = attackCipher(parseBigInteger(values[index + 1], 10, '输入 ' + (index + 2)), n);
    pairs.push([n, c]);
  }
  const exponent = step.e === undefined
    ? 3n
    : attackExponent(parseBigInteger(step.e, 10, '公钥指数 e'), '公钥指数 e');
  return broadcastAttack(pairs, exponent);
}

function validateRsaAttackStep(step) {
  if (typeof step.rsa_mode !== 'string' || !RSA_ATTACK_MODES.includes(step.rsa_mode)) {
    throw new CalculationError('rsa_mode 须为 factor、fermat、wiener、common_modulus、broadcast 或 small_e。');
  }
  if (step.max_iterations !== undefined
    && (!Number.isInteger(step.max_iterations) || step.max_iterations < 1 || step.max_iterations > MAX_ATTACK_ITERATIONS)) {
    throw new CalculationError('max_iterations 须为 1 至 1000000 的整数。');
  }
  const count = Array.isArray(step.inputs) ? step.inputs.length : 0;
  const fixedCounts = { factor: 3, fermat: 3, wiener: 3, small_e: 3, common_modulus: 5 };
  if (step.rsa_mode === 'broadcast') {
    if (count < 4 || count > MAX_ATTACK_MODULI * 2 || count % 2 !== 0) {
      throw new CalculationError('broadcast 模式需要 2 至 3 组 (n, c) 输入，即 4 或 6 个输入。');
    }
  } else if (count !== fixedCounts[step.rsa_mode]) {
    throw new CalculationError(step.rsa_mode + ' 模式需要 ' + fixedCounts[step.rsa_mode] + ' 个输入。');
  }
  if (step.rsa_mode !== 'broadcast' && step.e !== undefined) {
    throw new CalculationError('只有 broadcast 模式需要额外提供 e。');
  }
  if (step.e !== undefined && (typeof step.e !== 'string' || !/^\d+$/u.test(step.e))) {
    throw new CalculationError('广播攻击的公钥指数 e 须为十进制字符串。');
  }
}

function hexText(value) {
  const text = value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
  return text.length > 0 && text.length % 2 === 0 && /^[\da-f]+$/iu.test(text);
}

function validateAesStep(step) {
  if (typeof step.key !== 'string' || !hexText(step.key)) throw new CalculationError('须提供十六进制 AES 密钥。');
  const mode = step.mode ?? 'cbc';
  if (!AES_MODES.includes(mode)) throw new CalculationError('AES 模式须为 ecb、cbc 或 ctr。');
  if (step.padding !== undefined && !PADDINGS.includes(step.padding)) throw new CalculationError('AES 填充须为 pkcs7 或 none。');
  if (mode === 'ecb' && step.iv !== undefined) throw new CalculationError('ECB 模式不需要 IV。');
  if (mode !== 'ecb' && (typeof step.iv !== 'string' || !hexText(step.iv) || step.iv.replace(/^0x/iu, '').length !== 32)) {
    throw new CalculationError('CBC 或 CTR 模式须提供 16 字节十六进制 IV。');
  }
  if (step.from_encoding !== undefined && !ENCODINGS.includes(step.from_encoding)) throw new CalculationError('AES 输入编码须为 utf8、hex、base64 或 base64url。');
  if (step.to_encoding !== undefined && !ENCODINGS.includes(step.to_encoding)) throw new CalculationError('AES 输出编码须为 utf8、hex、base64 或 base64url。');
}

function validateRsaStep(step, decrypt) {
  const exponentName = decrypt ? 'd' : 'e';
  if (typeof step.n !== 'string' || !/^\d+$/u.test(step.n)) throw new CalculationError('须提供十进制模数 n。');
  if (typeof step[exponentName] !== 'string' || !/^\d+$/u.test(step[exponentName])) throw new CalculationError('须提供十进制指数 ' + exponentName + '。');
  if (step.input_base !== undefined && step.input_base !== 10 && step.input_base !== 16) throw new CalculationError('RSA 输入进制须为 10 或 16。');
  if (step.output_base !== undefined && step.output_base !== 10 && step.output_base !== 16) throw new CalculationError('RSA 输出进制须为 10 或 16。');
}

const OPERATIONS = {
  add: { inputs: 2, run: decimalOperation((a, b) => a + b) },
  subtract: { inputs: 2, run: decimalOperation((a, b) => a - b) },
  multiply: { inputs: 2, run: decimalOperation((a, b) => a * b) },
  integer_divide: { inputs: 2, run: decimalOperation(integerDivide) },
  modulo: { inputs: 2, run: decimalOperation(modulo) },
  modular_power: { inputs: 3, run: decimalOperation(modularPower) },
  convert_base: {
    inputs: 1,
    options: ['from_base', 'to_base'],
    run: ([input], { from_base, to_base }) => parseInteger(input, from_base).toString(to_base),
  },
  convert_encoding: {
    inputs: 1,
    options: ['from_encoding', 'to_encoding'],
    run: convertEncoding,
  },
  hash: {
    inputs: 1,
    options: ['algorithm', 'from_encoding', 'to_encoding'],
    validate(step) {
      if (!HASH_ALGORITHMS.includes(step.algorithm)) throw new CalculationError('须指定 md5、sha1、sha256 或 sha512 哈希算法。');
      if (step.from_encoding !== undefined && !ENCODINGS.includes(step.from_encoding)) throw new CalculationError('哈希输入编码须为 utf8、hex、base64 或 base64url。');
      if (step.to_encoding !== undefined && !['hex', 'base64', 'base64url'].includes(step.to_encoding)) throw new CalculationError('哈希输出编码须为 hex、base64 或 base64url。');
    },
    run: hashOperation,
  },
  hmac: {
    inputs: 2,
    options: ['algorithm', 'from_encoding', 'key_encoding', 'to_encoding'],
    validate(step) {
      if (!HASH_ALGORITHMS.includes(step.algorithm)) throw new CalculationError('须指定 md5、sha1、sha256 或 sha512 哈希算法。');
      if (step.key_encoding !== undefined && !['utf8', 'hex'].includes(step.key_encoding)) throw new CalculationError('HMAC 密钥编码须为 utf8 或 hex。');
      if (step.from_encoding !== undefined && !ENCODINGS.includes(step.from_encoding)) throw new CalculationError('HMAC 输入编码须为 utf8、hex、base64 或 base64url。');
      if (step.to_encoding !== undefined && !['hex', 'base64', 'base64url'].includes(step.to_encoding)) throw new CalculationError('HMAC 输出编码须为 hex、base64 或 base64url。');
    },
    run: hmacOperation,
  },
  encode: {
    inputs: 1,
    options: ['scheme', 'from_encoding'],
    validate(step) {
      if (!SCHEMES.includes(step.scheme)) throw new CalculationError('须指定 base32、base58、base85、url、form、html 或 html_bytes。');
      if (step.from_encoding !== undefined && !ENCODINGS.includes(step.from_encoding)) throw new CalculationError('编码输入须为 utf8、hex、base64 或 base64url。');
    },
    run: encodeScheme,
  },
  decode: {
    inputs: 1,
    options: ['scheme', 'to_encoding'],
    validate(step) {
      if (!SCHEMES.includes(step.scheme)) throw new CalculationError('须指定 base32、base58、base85、url、form、html 或 html_bytes。');
      if (step.to_encoding !== undefined && !ENCODINGS.includes(step.to_encoding)) throw new CalculationError('解码输出须为 utf8、hex、base64 或 base64url。');
    },
    run: decodeScheme,
  },
  xor: {
    inputs: 1,
    options: ['key', 'key_encoding', 'from_encoding', 'to_encoding'],
    validate(step) {
      if (typeof step.key !== 'string' || step.key.length === 0) throw new CalculationError('须提供 XOR 密钥。');
      if (step.key_encoding !== undefined && !['utf8', 'hex'].includes(step.key_encoding)) throw new CalculationError('XOR 密钥编码须为 utf8 或 hex。');
      if (step.from_encoding !== undefined && !ENCODINGS.includes(step.from_encoding)) throw new CalculationError('XOR 输入编码须为 utf8、hex、base64 或 base64url。');
      if (step.to_encoding !== undefined && !ENCODINGS.includes(step.to_encoding)) throw new CalculationError('XOR 输出编码须为 utf8、hex、base64 或 base64url。');
    },
    run: xorOperation,
  },
  xor_bruteforce: {
    inputs: 1,
    options: ['from_encoding', 'top'],
    validate(step) {
      if (step.from_encoding !== undefined && !ENCODINGS.includes(step.from_encoding)) throw new CalculationError('XOR 输入编码须为 utf8、hex、base64 或 base64url。');
      if (step.top !== undefined && (!Number.isInteger(step.top) || step.top < 1 || step.top > 10)) throw new CalculationError('返回候选数须为 1 至 10。');
    },
    run: xorBruteforce,
  },
  caesar: {
    inputs: 1,
    options: ['shift', 'decrypt'],
    validate(step) {
      if (!Number.isInteger(step.shift) || step.shift < 0 || step.shift > 25) throw new CalculationError('凯撒位移须为 0 至 25 的整数。');
      if (step.decrypt !== undefined && typeof step.decrypt !== 'boolean') throw new CalculationError('decrypt 须为布尔值。');
    },
    run: caesarOperation,
  },
  caesar_bruteforce: {
    inputs: 1,
    options: ['top'],
    validate(step) {
      if (step.top !== undefined && (!Number.isInteger(step.top) || step.top < 1 || step.top > 26)) throw new CalculationError('返回候选数须为 1 至 26。');
    },
    run: caesarBruteforce,
  },
  atbash: { inputs: 1, options: [], run: atbashOperation },
  vigenere: {
    inputs: 2,
    options: ['decrypt'],
    validate(step) {
      if (step.decrypt !== undefined && typeof step.decrypt !== 'boolean') throw new CalculationError('decrypt 须为布尔值。');
    },
    run: vigenereOperation,
  },
  affine: {
    inputs: 1,
    options: ['a', 'b', 'decrypt'],
    validate(step) {
      if (!Number.isInteger(step.a) || step.a < 1 || step.a > 25 || step.a % 2 === 0 || step.a === 13) {
        throw new CalculationError('仿射密码的 a 须为 1 至 25 中与 26 互质的整数。');
      }
      if (!Number.isInteger(step.b) || step.b < 0 || step.b > 25) throw new CalculationError('仿射密码的 b 须为 0 至 25 的整数。');
      if (step.decrypt !== undefined && typeof step.decrypt !== 'boolean') throw new CalculationError('decrypt 须为布尔值。');
    },
    run: affineOperation,
  },
  affine_bruteforce: {
    inputs: 1,
    options: ['top'],
    validate(step) {
      if (step.top !== undefined && (!Number.isInteger(step.top) || step.top < 1 || step.top > 10)) throw new CalculationError('返回候选数须为 1 至 10。');
    },
    run: affineBruteforce,
  },
  rail_fence: {
    inputs: 1,
    options: ['rails', 'decrypt'],
    validate(step) {
      if (!Number.isInteger(step.rails) || step.rails < 2 || step.rails > 32) throw new CalculationError('栅栏数须为 2 至 32 的整数。');
      if (step.decrypt !== undefined && typeof step.decrypt !== 'boolean') throw new CalculationError('decrypt 须为布尔值。');
    },
    run: railFenceOperation,
  },
  aes_encrypt: {
    inputs: 1,
    options: ['key', 'iv', 'mode', 'padding', 'from_encoding', 'to_encoding'],
    validate(step) { validateAesStep(step); },
    run: (values, step) => aesOperation(values, step, false),
  },
  aes_decrypt: {
    inputs: 1,
    options: ['key', 'iv', 'mode', 'padding', 'from_encoding', 'to_encoding'],
    validate(step) { validateAesStep(step); },
    run: (values, step) => aesOperation(values, step, true),
  },
  rsa_encrypt: {
    inputs: 1,
    options: ['n', 'e', 'input_base', 'output_base'],
    validate(step) { validateRsaStep(step, false); },
    run: (values, step) => rsaOperation(values, step, false),
  },
  rsa_decrypt: {
    inputs: 1,
    options: ['n', 'd', 'input_base', 'output_base'],
    validate(step) { validateRsaStep(step, true); },
    run: (values, step) => rsaOperation(values, step, true),
  },
  rsa_attack: {
    inputs: 'variable',
    options: ['rsa_mode', 'max_iterations', 'e'],
    validate(step) { validateRsaAttackStep(step); },
    run: rsaAttackOperation,
  },
  integer_root: {
    inputs: 1,
    options: ['degree'],
    validate(step) {
      if (!Number.isInteger(step.degree) || step.degree < 2 || step.degree > 64) throw new CalculationError('开方次数须为 2 至 64 的整数。');
    },
    run: integerRootOperation,
  },
  ...WORD_OPERATIONS,
};

const VALUE = { type: 'string', maxLength: MAX_VALUE_CHARACTERS };
const BASE = { type: 'integer', minimum: 2, maximum: 36 };
const ENCODING = { type: 'string', enum: ENCODINGS };
export const CALCULATION_PROPERTIES = {
  steps: {
    type: 'array', minItems: 1, maxItems: MAX_STEPS,
    items: {
      type: 'object',
      additionalProperties: false,
      required: ['operation', 'inputs'],
      properties: {
        operation: {
          type: 'string', enum: Object.keys(OPERATIONS),
          description: '整数运算依次输入左值和右值。word_ 运算指定字宽，移位和旋转的第二项为次数。hash/hmac 指定 algorithm；encode/decode 指定 base32、base58、base85、url 或 html；xor 指定 key；古典密码用 shift/a/b/rails；aes_* 指定 key、mode 和 IV；rsa_* 指定 n 与 e 或 d；rsa_attack 用 rsa_mode 指定攻击方式；integer_root 指定开方次数。',
        },
        inputs: {
          type: 'array', minItems: 1, maxItems: MAX_ATTACK_INPUTS,
          items: {
            anyOf: [VALUE, {
              type: 'object', additionalProperties: false, required: ['step'],
              properties: { step: { type: 'integer', minimum: 1, maximum: MAX_STEPS } },
            }],
          },
          description: '直接输入字符串，或用 {"step":1} 引用前序结果。整数输入为十进制字符串，word_ 运算也接受 0x 十六进制，word_from_bytes 使用不带 0x 的等宽 Hex。rsa_attack 的 broadcast 模式按 n、c 成对排列，用 4 或 6 个输入。',
        },
        from_base: BASE,
        to_base: BASE,
        from_encoding: ENCODING,
        to_encoding: ENCODING,
        width: { type: 'integer', enum: WORD_WIDTHS },
        from_width: { type: 'integer', enum: WORD_WIDTHS },
        byte_order: { type: 'string', enum: BYTE_ORDERS },
        algorithm: { type: 'string', enum: HASH_ALGORITHMS },
        scheme: { type: 'string', enum: SCHEMES },
        key: { ...VALUE, description: 'HMAC、XOR、AES 的密钥。' },
        key_encoding: { type: 'string', enum: ['utf8', 'hex'] },
        shift: { type: 'integer', minimum: 0, maximum: 25 },
        decrypt: { type: 'boolean' },
        a: { type: 'integer', minimum: 1, maximum: 25 },
        b: { type: 'integer', minimum: 0, maximum: 25 },
        rails: { type: 'integer', minimum: 2, maximum: 32 },
        mode: { type: 'string', enum: AES_MODES },
        rsa_mode: {
          type: 'string', enum: RSA_ATTACK_MODES,
          description: 'rsa_attack 的攻击方式：factor、fermat、wiener、common_modulus、broadcast 或 small_e。',
        },
        max_iterations: {
          type: 'integer', minimum: 1, maximum: MAX_ATTACK_ITERATIONS,
          description: 'rsa_attack 的 factor 和 fermat 迭代上限，默认 100000。',
        },
        padding: { type: 'string', enum: PADDINGS },
        iv: { ...VALUE, description: 'AES CBC/CTR 的 16 字节十六进制 IV。' },
        n: { ...VALUE, description: 'RSA 模数，十进制。' },
        e: { ...VALUE, description: 'RSA 公钥指数，十进制。rsa_attack 的 broadcast 模式用它指定指数，默认 3。' },
        d: { ...VALUE, description: 'RSA 私钥指数，十进制。' },
        input_base: { type: 'integer', enum: [10, 16] },
        output_base: { type: 'integer', enum: [10, 16] },
        top: { type: 'integer', minimum: 1, maximum: 26 },
        degree: { type: 'integer', minimum: 2, maximum: 64 },
        expected: { ...VALUE, description: '本步的可选样例值，按完整字符串比对。' },
        result_offset: { type: 'integer', minimum: 0, maximum: MAX_RESULT_CHARACTERS, description: '本步返回文本的字符起点，从 0 开始。计算链使用完整值。' },
      },
    },
  },
};

function fitsValue(value, maximum = MAX_VALUE_CHARACTERS) {
  return typeof value === 'string' && value.length <= 2 * maximum
    && [...value].length <= maximum && !/\p{Cs}/u.test(value);
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validInput(input, index) {
  if (fitsValue(input)) return true;
  return isObject(input) && Object.keys(input).length === 1
    && Object.hasOwn(input, 'step') && Number.isInteger(input.step)
    && input.step >= 1 && input.step <= index;
}

function isBase(value) {
  return Number.isInteger(value) && value >= 2 && value <= 36;
}

function validateSteps(steps) {
  if (!Array.isArray(steps) || steps.length < 1 || steps.length > MAX_STEPS) {
    throw new Error('请提供 1 至 12 个计算步骤。');
  }
  for (const [index, step] of steps.entries()) {
    const number = index + 1;
    if (!isObject(step) || typeof step.operation !== 'string' || !Object.hasOwn(OPERATIONS, step.operation)) {
      throw new Error('第 ' + number + ' 步的运算类型无效。');
    }
    const spec = OPERATIONS[step.operation];
    const allowed = ['operation', 'inputs', 'expected', 'result_offset', ...(spec.options ?? [])];
    if (!Object.keys(step).every(key => allowed.includes(key))) {
      throw new Error('第 ' + number + ' 步含有当前运算用不到的参数。');
    }
    const inputCount = Array.isArray(step.inputs) ? step.inputs.length : 0;
    const countValid = spec.inputs === 'variable'
      ? inputCount >= 1 && inputCount <= MAX_ATTACK_INPUTS
      : inputCount === spec.inputs;
    if (!Array.isArray(step.inputs) || !countValid
      || ![...step.inputs].every(value => validInput(value, index))) {
      const expected = spec.inputs === 'variable' ? '1 至 ' + MAX_ATTACK_INPUTS : spec.inputs;
      throw new Error('第 ' + number + ' 步需要 ' + expected + ' 个有效字符串或前序步骤引用。');
    }
    if (step.expected !== undefined && !fitsValue(step.expected)) {
      throw new Error('第 ' + number + ' 步的期望值须为不超过 4096 字符的有效文本。');
    }
    if (step.result_offset !== undefined && (!Number.isInteger(step.result_offset)
      || step.result_offset < 0 || step.result_offset > MAX_RESULT_CHARACTERS)) {
      throw new Error('第 ' + number + ' 步的 result_offset 超出结果范围上限。');
    }
    if (step.operation === 'convert_base' && (!isBase(step.from_base) || !isBase(step.to_base))) {
      throw new Error('第 ' + number + ' 步须指定 2 至 36 的起始和目标进制。');
    }
    if (step.operation === 'convert_encoding'
      && (!ENCODINGS.includes(step.from_encoding) || !ENCODINGS.includes(step.to_encoding))) {
      throw new Error('第 ' + number + ' 步须指定 utf8、hex、base64 或 base64url 编码。');
    }
    if (spec.options?.includes('width') && !WORD_WIDTHS.includes(step.width)) {
      throw new Error('第 ' + number + ' 步须指定 8、16、32 或 64 位字宽。');
    }
    if (spec.options?.includes('from_width') && (!WORD_WIDTHS.includes(step.from_width) || step.from_width > step.width)) {
      throw new Error('第 ' + number + ' 步的原字宽须为 8、16、32 或 64，且最多等于目标字宽。');
    }
    if (spec.options?.includes('byte_order') && !BYTE_ORDERS.includes(step.byte_order)) {
      throw new Error('第 ' + number + ' 步须指定 little 或 big 字节序。');
    }
    if (spec.validate) {
      try {
        spec.validate(step);
      } catch (error) {
        if (error instanceof CalculationError) throw new Error('第 ' + number + ' 步' + error.message);
        throw error;
      }
    }
  }
}

function runStep(step, index, completed) {
  const record = { step: index + 1, ...step };
  const values = [];
  for (const input of step.inputs) {
    const value = typeof input === 'string' ? input : completed[input.step - 1].result;
    if (value === undefined) return { ...record, status: 'blocked', blocked_by: input.step };
    values.push(value);
  }
  try {
    if (!LONG_INPUT_OPERATIONS.has(step.operation) && values.some(value => !fitsValue(value))) {
      throw new CalculationError('本步的输入超过 4096 字符。');
    }
    const result = OPERATIONS[step.operation].run(values, step);
    const maximum = step.operation === 'rsa_attack' ? MAX_VALUE_CHARACTERS : MAX_RESULT_CHARACTERS;
    if (!fitsValue(result, maximum)) throw new CalculationError('结果不是有效文本，或超过 ' + maximum + ' 字符上限。');
    const check = step.expected === undefined ? undefined : result === step.expected ? 'match' : 'mismatch';
    return { ...record, status: 'computed', result, check };
  } catch (error) {
    if (!(error instanceof CalculationError)) throw error;
    return { ...record, status: 'error', reason: error.message };
  }
}

function resultPreview(step) {
  if (step.result === undefined || (step.result_offset === undefined && fitsValue(step.result))) return step;
  const characters = [...step.result];
  const offset = Math.min(step.result_offset ?? 0, characters.length);
  const end = Math.min(offset + MAX_VALUE_CHARACTERS, characters.length);
  return { ...step, result: characters.slice(offset, end).join(''), result_offset: offset, result_chars: characters.length,
    result_sha256: createHash('sha256').update(step.result).digest('hex'), next_result_offset: end < characters.length ? end : null };
}

export function calculateSteps(steps) {
  validateSteps(steps);
  const completed = [];
  for (const [index, step] of steps.entries()) completed.push(runStep(step, index, completed));
  const checks = {
    matched: completed.filter(step => step.check === 'match').length,
    mismatched: completed.filter(step => step.check === 'mismatch').length,
  };
  const incomplete = completed.some(step => step.status !== 'computed');
  const status = incomplete ? 'incomplete' : checks.mismatched > 0 ? 'mismatch' : 'ok';
  const firstMismatch = completed.find(step => step.check === 'mismatch');
  return { status, checks, ...(firstMismatch ? { first_mismatch: firstMismatch.step } : {}), steps: completed.map(resultPreview) };
}
