// CTF preset 的扩展工具：浏览器会话、gdb 调试、压缩包口令、音频隐写、APK 检查、
// 云元数据探测、密码学模板。全部工具遵守有界读取，失败时返回结构化错误。
import { spawn } from 'node:child_process';
import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { stat } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { deflateSync, inflateRawSync } from 'node:zlib';
import { BROWSER_TIMEOUT_MS, createBrowserSession } from './browser-session.js';
import { isLocalWorkbenchPath } from './workbench-config.js';
import { describeToolError, ToolError } from './tool-errors.js';

const MAX_INPUT_BYTES = 256 * 1024 * 1024;
const MAX_TEXT_OUTPUT = 64 * 1024;

function registerTool(ctx, toolName, description, properties, run, required = ['file_path'], observe, config) {
  const schema = required.includes('file_path') && !Object.hasOwn(properties, 'file_path')
    ? { file_path: { type: 'string', description: '本题工作区内的相对附件路径。' }, ...properties } : properties;
  ctx.tools.register({
    name: toolName,
    description,
    parameters: { type: 'object', properties: schema, additionalProperties: false, required },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
    async execute(args, execution) {
      const askedFile = typeof args?.file_path === 'string' ? args.file_path : undefined;
      try {
        if (!args || typeof args !== 'object' || Array.isArray(args)
          || Object.keys(args).some(key => !Object.hasOwn(schema, key))
          || required.some(key => !Object.hasOwn(args, key))) {
          throw new ToolError('unsupported', '参数缺失或含工具未声明的字段。');
        }
        const report = await run(args, execution);
        const output = { file: askedFile, ...report };
        const capture = await observe?.(toolName, args, execution, output);
        return JSON.stringify({ ...output, ...capture }, null, config?.compact === false ? 2 : 0);
      } catch (error) {
        return JSON.stringify({ ok: false, file: askedFile, error: describeToolError(error) }, null, config?.compact === false ? 2 : 0);
      }
    },
  });
}

function resolveInput(cwd, value, label = 'file_path') {
  if (typeof value !== 'string' || value.length === 0) throw new ToolError('path', `需要提供 ${label}。`);
  return path.isAbsolute(value) ? value : path.resolve(cwd, value);
}

function childEnvironment() {
  const keys = new Set(['path', 'systemroot', 'systemdrive', 'windir', 'temp', 'tmp', 'home', 'userprofile',
    'programfiles', 'programfiles(x86)', 'localappdata', 'appdata', 'comspec', 'pathext', 'lang', 'lc_all', 'java_home']);
  return Object.fromEntries(Object.entries(process.env).filter(([key]) => keys.has(key.toLowerCase())));
}

function requireWritable(ctx, execution) {
  const policy = ctx.sandboxPolicy?.resolve?.({ session: execution.agent?.session });
  if (policy?.mode === 'read-only') throw new ToolError('path', '当前会话是只读权限，无法写入文件。');
}

function truncate(text, limit = MAX_TEXT_OUTPUT) {
  const value = String(text);
  if (value.length <= limit) return value;
  return `${value.slice(0, limit)}\n…（输出已截断，共 ${value.length} 字符）`;
}

function spawnCapture(command, args, options = {}) {
  const { timeoutMs = 30000, cwd, env = childEnvironment(), maxBytes = 256 * 1024, signal } = options;
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(command, args, { cwd, env, windowsHide: true, signal, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (error) {
      reject(error);
      return;
    }
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let settled = false;
    const collect = (chunk, target) => {
      const next = target + chunk.toString('utf8');
      return next.length > maxBytes ? next.slice(0, maxBytes) : next;
    };
    const timer = setTimeout(() => {
      if (settled) return;
      timedOut = true;
      try { child.kill(); } catch { /* ignore */ }
    }, timeoutMs);
    child.stdout?.on('data', chunk => { stdout = collect(chunk, stdout); });
    child.stderr?.on('data', chunk => { stderr = collect(chunk, stderr); });
    child.on('error', error => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', code => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: code ?? -1, stdout, stderr, timedOut });
    });
  });
}

function commandCandidates(name) {
  const extensions = process.platform === 'win32' ? ['', '.exe', '.cmd', '.bat', '.ps1'] : [''];
  const directories = (process.env.PATH ?? '').split(path.delimiter).filter(Boolean);
  return directories.flatMap(directory => extensions.map(extension => path.join(directory, name + extension)));
}

function findOnPath(name) {
  for (const candidate of commandCandidates(name)) {
    try { if (statSync(candidate).isFile()) return candidate; } catch { /* keep looking */ }
  }
  return undefined;
}

async function firstLocalFile(candidates) {
  for (const candidate of candidates.filter(isLocalWorkbenchPath)) {
    try { if ((await stat(candidate)).isFile()) return candidate; } catch { /* keep looking */ }
  }
  return undefined;
}

export function findOnPathAsync(name) {
  return firstLocalFile(commandCandidates(name));
}

// ── ZIP 与 ZipCrypto ──────────────────────────────────────────────────────────

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? (value >>> 1) ^ 0xedb88320 : value >>> 1;
    table[index] = value >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let value = 0xffffffff;
  for (let index = 0; index < buffer.length; index += 1) {
    value = CRC_TABLE[(value ^ buffer[index]) & 0xff] ^ (value >>> 8);
  }
  return (value ^ 0xffffffff) >>> 0;
}

function parseZipEntries(buffer) {
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

function* candidatesFor(args, cwd) {
  if (Array.isArray(args.passwords)) {
    for (const password of args.passwords) {
      if (typeof password === 'string' && password.length <= 64) yield password;
    }
  }
  if (typeof args.wordlist === 'string') {
    const file = resolveInput(cwd, args.wordlist, 'wordlist');
    const info = fileInfo(file);
    if (info.size > 64 * 1024 * 1024) throw new ToolError('size', '字典超过 64 MiB。');
    const text = readFileSync(file, 'utf8');
    for (const line of text.split(/\r?\n/u)) {
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

function crackZip(buffer, entry, args, cwd) {
  const timeoutMs = Math.min(Math.max(args.timeout_ms ?? 30000, 1000), 120000);
  const deadline = Date.now() + timeoutMs;
  let tried = 0;
  for (const password of candidatesFor(args, cwd)) {
    if ((tried & 0x3ff) === 0 && Date.now() > deadline) {
      return { status: 'not_found', timed_out: true, tried };
    }
    tried += 1;
    if (tryZipCrypto(buffer, entry, password)) return { status: 'found', password, tried };
  }
  return { status: 'not_found', timed_out: false, tried };
}

// ── PNG 渲染 ──────────────────────────────────────────────────────────────────

function pngChunk(type, data) {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(data.length, 0);
  head.write(type, 4, 'ascii');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), data])), 0);
  return Buffer.concat([head, data, crc]);
}

function writePng(file, width, height, rgb) {
  const stride = width * 3;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let row = 0; row < height; row += 1) {
    raw[row * (stride + 1)] = 0;
    rgb.copy(raw, row * (stride + 1) + 1, row * stride, row * stride + stride);
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 2;
  const png = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', header),
    pngChunk('IDAT', deflateSync(raw, { level: 9 })),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
  writeFileSync(file, png, { flag: 'wx' });
  return png.length;
}

// ── WAV 与频谱 ────────────────────────────────────────────────────────────────

function parseWav(buffer) {
  if (buffer.length < 12 || buffer.toString('ascii', 0, 4) !== 'RIFF' || buffer.toString('ascii', 8, 12) !== 'WAVE') {
    throw new ToolError('unsupported', '只支持 WAV（RIFF/WAVE）；FLAC、MP3 元数据请用 inspect_media 或 shell。');
  }
  const chunks = [];
  let cursor = 12;
  while (cursor + 8 <= buffer.length) {
    const id = buffer.toString('ascii', cursor, cursor + 4);
    const size = buffer.readUInt32LE(cursor + 4);
    const dataOffset = cursor + 8;
    chunks.push({ id, size, dataOffset });
    cursor += 8 + size + (size & 1);
    if (cursor <= dataOffset) break;
  }
  const fmt = chunks.find(chunk => chunk.id === 'fmt ');
  const data = chunks.find(chunk => chunk.id === 'data');
  if (!fmt || !data) throw new ToolError('unsupported', 'WAV 缺少 fmt 或 data 块。');
  if (fmt.size < 16 || fmt.dataOffset + fmt.size > buffer.length || data.dataOffset + data.size > buffer.length) {
    throw new ToolError('unsupported', 'WAV 的 fmt 或 data 块被截断。');
  }
  const format = buffer.readUInt16LE(fmt.dataOffset);
  const channels = buffer.readUInt16LE(fmt.dataOffset + 2);
  const sampleRate = buffer.readUInt32LE(fmt.dataOffset + 4);
  const bitsPerSample = buffer.readUInt16LE(fmt.dataOffset + 14);
  if (channels < 1 || channels > 32 || sampleRate < 1) throw new ToolError('unsupported', 'WAV 声道数或采样率无效。');
  if (![8, 16].includes(bitsPerSample)) {
    throw new ToolError('unsupported', `暂不支持 ${bitsPerSample} 位 PCM，仅支持 8/16 位。`);
  }
  if (format !== 1) throw new ToolError('unsupported', '只支持 PCM（format=1）的 WAV。');
  const frameSize = channels * (bitsPerSample / 8);
  const frames = Math.floor(data.size / frameSize);
  const tags = {};
  for (const chunk of chunks) {
    if (chunk.id !== 'LIST' || chunk.size < 12) continue;
    const listType = buffer.toString('ascii', chunk.dataOffset, chunk.dataOffset + 4);
    if (listType !== 'INFO') continue;
    let position = chunk.dataOffset + 4;
    while (position + 8 <= chunk.dataOffset + chunk.size) {
      const tag = buffer.toString('ascii', position, position + 4);
      const length = buffer.readUInt32LE(position + 4);
      tags[tag] = buffer.toString('utf8', position + 8, Math.min(position + 8 + length, chunk.dataOffset + chunk.size))
        .replace(/\0+$/u, '');
      position += 8 + length + (length & 1);
    }
  }
  return { chunks, fmt: { format, channels, sampleRate, bitsPerSample }, data, frames, tags };
}

function sampleAt(buffer, wav, frame, channel) {
  const bytes = wav.fmt.bitsPerSample / 8;
  const offset = wav.data.dataOffset + (frame * wav.fmt.channels + channel) * bytes;
  if (wav.fmt.bitsPerSample === 8) return (buffer[offset] - 128) / 128;
  return buffer.readInt16LE(offset) / 32768;
}

function fftMagnitudes(samples) {
  const size = samples.length;
  const real = Float64Array.from(samples);
  const imag = new Float64Array(size);
  for (let index = 1, position = 0; index < size; index += 1) {
    let bit = size >> 1;
    for (; position & bit; bit >>= 1) position &= ~bit;
    position |= bit;
    if (index < position) {
      [real[index], real[position]] = [real[position], real[index]];
      [imag[index], imag[position]] = [imag[position], imag[index]];
    }
  }
  for (let length = 2; length <= size; length <<= 1) {
    const angle = (-2 * Math.PI) / length;
    const half = length >> 1;
    const stepCos = Math.cos(angle);
    const stepSin = Math.sin(angle);
    for (let start = 0; start < size; start += length) {
      let cos = 1;
      let sin = 0;
      for (let offset = 0; offset < half; offset += 1) {
        const even = start + offset;
        const odd = even + half;
        const oddReal = real[odd] * cos - imag[odd] * sin;
        const oddImag = real[odd] * sin + imag[odd] * cos;
        const evenReal = real[even];
        const evenImag = imag[even];
        real[even] = evenReal + oddReal;
        imag[even] = evenImag + oddImag;
        real[odd] = evenReal - oddReal;
        imag[odd] = evenImag - oddImag;
        const nextCos = cos * stepCos - sin * stepSin;
        sin = cos * stepSin + sin * stepCos;
        cos = nextCos;
      }
    }
  }
  const magnitudes = new Float64Array(size >> 1);
  for (let index = 0; index < magnitudes.length; index += 1) {
    magnitudes[index] = Math.hypot(real[index], imag[index]);
  }
  return magnitudes;
}

function colorFor(value) {
  const clamped = Math.min(1, Math.max(0, value));
  const red = Math.round(255 * Math.min(1, clamped * 2));
  const green = Math.round(255 * Math.min(1, Math.max(0, clamped * 2 - 0.5)));
  const blue = Math.round(255 * (1 - clamped));
  return [red, green, blue];
}

function renderSpectrum(file, windows, sampleRate, fftSize, hopSize) {
  const width = windows.length;
  const height = Math.min(fftSize / 2, 256);
  const rgb = Buffer.alloc(width * height * 3);
  let peak = 1e-9;
  for (const bins of windows) peak = Math.max(peak, ...bins);
  const peaks = new Float64Array(fftSize / 2);
  for (let column = 0; column < width; column += 1) {
    const bins = windows[column];
    for (const [index, value] of bins.entries()) peaks[index] = Math.max(peaks[index], value);
    for (let row = 0; row < height; row += 1) {
      const start = Math.floor((height - 1 - row) * bins.length / height);
      const end = Math.floor((height - row) * bins.length / height);
      let amplitude = 0;
      for (let bin = start; bin < end; bin += 1) amplitude = Math.max(amplitude, bins[bin]);
      const decibels = 20 * Math.log10(Math.max(1e-6, amplitude / peak));
      const [red, green, blue] = colorFor((decibels + 72) / 72);
      const position = (row * width + column) * 3;
      rgb[position] = red;
      rgb[position + 1] = green;
      rgb[position + 2] = blue;
    }
  }
  const bytes = writePng(file, width, height, rgb);
  const dominant = Array.from(peaks, (value, index) => ({ value, index }))
    .sort((left, right) => right.value - left.value).slice(0, 8)
    .map(item => ({ hz: Math.round(item.index * sampleRate / fftSize), magnitude: Number(item.value.toFixed(3)) }));
  return { file, width, height, bytes, fft_size: fftSize, hop_size: hopSize, bin_hz: sampleRate / fftSize,
    time_step_s: hopSize / sampleRate, frequency_axis: 'low_to_high_bottom_to_top', peaks: dominant };
}

// ── 浏览器（CDP） ────────────────────────────────────────────────────────────

function browserCandidates() {
  const candidates = [];
  if (process.env.CHROME_PATH) candidates.push(process.env.CHROME_PATH);
  if (process.platform === 'win32') {
    candidates.push(
      'C:/Program Files/Google/Chrome/Application/chrome.exe',
      'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
      'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
      'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    );
  } else if (process.platform === 'darwin') {
    candidates.push(
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    );
  } else {
    candidates.push('/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/microsoft-edge');
  }
  return candidates;
}

export function detectBrowser(config) {
  return firstLocalFile(config?.browserPath ? [config.browserPath] : browserCandidates());
}

export function detectGdb(config) {
  const configured = config?.gdbPath || process.env.GDB;
  return configured ? firstLocalFile([configured]) : findOnPathAsync('gdb');
}

// ── APK ──────────────────────────────────────────────────────────────────────

function findJavaTool(candidates) {
  for (const name of candidates) {
    const found = findOnPath(name);
    if (found) return { name, path: found };
  }
  return undefined;
}

// ── 云元数据 ──────────────────────────────────────────────────────────────────

const TEMPLATES = {
  'z3_bitvec': [
    '# z3 位向量模板：把题目的约束逐条改成 BitVec 表达式，解出 chars。',
    'from z3 import *',
    '',
    'n = 16  # 已知字符数，按题目修改',
    'chars = [BitVec(f"c{i}", 8) for i in range(n)]',
    'solver = Solver()',
    'for c in chars:',
    '    solver.add(32 <= c, c <= 126)',
    '',
    '# TODO：把题目里的等式、异或、移位关系写成 solver.add(...)',
    '# 例如 solver.add(chars[0] ^ chars[1] == 0x33)',
    '',
    'print(solver.check())',
    'model = solver.model()',
    'print("".join(chr(model[c].as_long()) for c in chars))',
    '',
  ].join('\n'),
  'coppersmith': [
    '# Coppersmith 模板（需要 fpylll 和 sympy）：一元小根。',
    'from fpylll import IntegerMatrix, LLL',
    'from sympy import Poly, symbols, RR',
    '',
    'x = symbols("x")',
    '# TODO：把题目的模方程写成 f(x) = (known + x)^e - c mod n',
    'n = 0',
    'f = 0',
    '',
    'def coppersmith(poly, modulus, beta=0.5, mm=3, tt=4):',
    '    """教学版：只演示构造，实际题按已知位宽调整 mm/tt/epsilon。"""',
    '    raise NotImplementedError("按题目补全多项式与上界，再跑 LLL")',
    '',
    'print("修改 f 与 n 后运行 coppersmith(f, n)")',
    '',
  ].join('\n'),
  'lattice': [
    '# 格/HNP 模板（需要 fpylll）：把已知点构造进矩阵后做 LLL/BKZ。',
    'from fpylll import IntegerMatrix, LLL, BKZ',
    '',
    'dim = 4',
    'matrix = IntegerMatrix(dim, dim)',
    '# TODO：按题目填入已知关系 a_i * k + b_i mod n 的格基',
    'for i in range(dim):',
    '    matrix[i, i] = 1',
    '',
    'LLL.reduction(matrix)',
    'print(matrix)',
    '',
  ].join('\n'),
  'aes_mode': [
    '# AES 模式分析模板：根据 oracle 行为判断 ECB/CBC/CTR。',
    'from Crypto.Cipher import AES  # 需要 pycryptodome',
    '',
    'def oracle(data):',
    '    """TODO：把题目给的加密接口包在这里，返回密文 bytes。"""',
    '    raise NotImplementedError',
    '',
    'c1 = oracle(b"A" * 16)',
    'c2 = oracle(b"B" * 16)',
    'print("长度:", len(c1))',
    'print("ECB 可能:", oracle(b"A" * 16) == oracle(b"A" * 16))',
    '',
  ].join('\n'),
};

// ── 注册 ─────────────────────────────────────────────────────────────────────

export function registerExtraTools(ctx, config, access) {
  const register = (name, description, properties, run, required) =>
    registerTool(ctx, name, description, properties, run, required, access.observe, config);
  const browsers = new WeakMap();
  const activeBrowsers = new Set();
  ctx.effect(() => () => Promise.allSettled([...activeBrowsers].map(browser => browser.close())), 'CTF browser sessions');
  function getBrowser(session, key) {
    let byWorkspace = browsers.get(session);
    if (byWorkspace === undefined) {
      byWorkspace = new Map();
      browsers.set(session, byWorkspace);
    }
    let browser = byWorkspace.get(key);
    if (browser === undefined) {
      browser = createBrowserSession({
        resolveBinary: () => detectBrowser(config),
        authorize: access.authorize,
        environment: childEnvironment,
        onStart() {
          if (activeBrowsers.size >= 8) throw new ToolError('dependency', '浏览器会话数量已达上限，请关闭不用的会话。');
          activeBrowsers.add(browser);
        },
        onStop: () => activeBrowsers.delete(browser),
      });
      byWorkspace.set(key, browser);
    }
    return browser;
  }

  register('browser_session',
    '在可信 Chrome/Edge 中查看已授权来源的页面、DOM、Cookie 属性和截图。',
    {
      action: { type: 'string', enum: ['open', 'dom', 'screenshot', 'cookies', 'title', 'close', 'status', 'list'], description: '操作类型。' },
      url: { type: 'string', description: 'open 时要打开的 http(s) 地址。' },
      selector: { type: 'string', description: 'dom 时可选的 CSS 选择器。' },
      path: { type: 'string', description: 'screenshot 的保存路径，默认当前工作目录下的 screenshot-时间戳.png。' },
      timeout_ms: { type: 'integer', minimum: 1000, maximum: 60000, description: '本次操作含浏览器启动的等待上限，默认 15000。' },
    },
    async (args, execution) => {
      const location = await access.location(execution);
      const action = args.action;
      const browser = getBrowser(execution.agent.session, location.directoryKey);
      if (action === 'close') {
        const closed = await browser.close();
        return { status: closed.process_exited && closed.profile_removed ? 'closed' : 'partial', ...closed };
      }
      const timeout = args.timeout_ms ?? BROWSER_TIMEOUT_MS;
      if (!Number.isSafeInteger(timeout) || timeout < 1000 || timeout > 60000) {
        throw new ToolError('unsupported', 'timeout_ms 须在 1000 至 60000 内。');
      }
      return browser.run(timeout, execution.signal, async signal => {
        if (action === 'status') return { status: await browser.status(signal) };
        if (action === 'open') {
          if (typeof args.url !== 'string') throw new ToolError('unsupported', 'open 需要 url。');
          if (args.url !== 'about:blank') await access.authorize(args.url, signal);
          const target = await browser.ensure(signal);
          return { status: 'opened', ...await browser.navigate(target, args.url, signal) };
        }
        if (action === 'screenshot') requireWritable(ctx, execution);
        if (action === 'cookies' && args.url !== undefined) await access.authorize(args.url, signal);
        const target = await browser.ensure(signal);
        const evaluate = expression => browser.evaluate(target, expression, signal);
        if (action === 'dom') {
          const expression = args.selector === undefined
            ? 'document.documentElement ? document.documentElement.outerHTML : ""'
            : `(() => { const node = document.querySelector(${JSON.stringify(args.selector)}); return node ? node.outerHTML : null; })()`;
          return { status: 'dom', title: await evaluate('document.title'), html: truncate(await evaluate(expression) ?? '', 256 * 1024) };
        }
        if (action === 'title') return { status: 'title', title: await evaluate('document.title') };
        if (action === 'screenshot') {
          const file = await access.output(location, args.path ?? ('screenshot-' + Date.now() + '.png'));
          return { status: 'screenshot', file, ...await browser.screenshot(target, file, signal) };
        }
        if (action === 'cookies') {
          const cookies = await browser.cookies(target, args.url, signal);
          return { status: 'cookies', cookies: cookies.map(cookie => ({
            name: cookie.name, domain: cookie.domain, path: cookie.path,
            secure: cookie.secure, httpOnly: cookie.httpOnly,
          })) };
        }
        if (action === 'list') return { status: 'targets', targets: await browser.list(target, signal) };
        throw new ToolError('unsupported', `未知操作：${action}。`);
      });
    },
    ['action'],
  );

  register('gdb_driver',
    '用本机 GDB 对题目附件做预设的静态文件检查。',
    {
      action: { type: 'string', enum: ['inspect'] },
      kind: { type: 'string', enum: ['files', 'sections'], description: '查看文件或节。' },
      timeout_ms: { type: 'integer', minimum: 1000, maximum: 120000 },
    },
    async (args, execution) => {
      if (args.action !== 'inspect' || !['files', 'sections'].includes(args.kind ?? 'files')) {
        throw new ToolError('unsupported', 'GDB 只开放预设的静态文件检查。');
      }
      const location = await access.location(execution);
      const binary = await access.input(location, args.file_path);
      const gdb = await detectGdb(config);
      if (!gdb || !path.isAbsolute(gdb)) throw new ToolError('dependency', '配置本机 GDB 的绝对路径，或通过系统 PATH 安装。');
      const command = args.kind === 'sections' ? 'maintenance info sections' : 'info files';
      const result = await spawnCapture(gdb, ['-q', '-batch', '-nx', '-nh', '-iex', 'set auto-load off',
        '-iex', 'set debuginfod enabled off', '--se=' + binary, '-ex', command], {
        cwd: path.dirname(gdb), timeoutMs: Math.min(Math.max(args.timeout_ms ?? 30000, 1000), 120000),
        signal: execution.signal,
      });
      return { status: result.timedOut ? 'timeout' : result.code === 0 ? 'ok' : 'failed',
        exit_code: result.code, stdout: truncate(result.stdout), stderr: truncate(result.stderr) };
    },
    ['file_path', 'action'],
  );

  register('archive_crack',
    '检查 ZIP 结构并尝试破解 ZipCrypto 口令（字典、内置弱口令、掩码）。命中后校验解压 CRC。支持 john/hashcat 存在性提示。',
    {
      action: { type: 'string', enum: ['info', 'crack'], description: 'info 列出条目；crack 尝试口令。' },
      wordlist: { type: 'string', description: '字典文件路径（工作区相对或绝对）。' },
      mask: { type: 'string', description: '掩码，例如 ?l?l?l?d；支持 ?l ?u ?d ?h ?s ?a 和字面字符。' },
      passwords: { type: 'array', items: { type: 'string' }, maxItems: 256, description: '直接给出的候选口令。' },
      min_length: { type: 'integer', minimum: 0, maximum: 64, description: '掩码生成口令的最小长度。' },
      max_length: { type: 'integer', minimum: 1, maximum: 64, description: '掩码生成口令的最大长度。' },
      timeout_ms: { type: 'integer', minimum: 1000, maximum: 120000, description: '破解时间上限，默认 30000。' },
    },
    async (args, execution) => {
      const location = await access.location(execution);
      const cwd = location.cwd;
      const file = await access.input(location, args.file_path);
      if (args.wordlist !== undefined) await access.input(location, args.wordlist);
      const { bytes: buffer } = await access.read(location, args.file_path, MAX_INPUT_BYTES);
      const entries = parseZipEntries(buffer);
      if (args.action === 'info') {
        return {
          status: 'ok',
          input_sha256: createHash('sha256').update(buffer).digest('hex'),
          entries: entries.map(entry => ({
            name: entry.name, size: entry.size, compressed_size: entry.compressedSize,
            encrypted: entry.encrypted, method: entry.method, is_directory: entry.directory,
          })),
          encrypted_count: entries.filter(entry => entry.encrypted).length,
          tools: { john: Boolean(findOnPath('john')), hashcat: Boolean(findOnPath('hashcat')), zip2john: Boolean(findOnPath('zip2john')) },
        };
      }
      const target = entries.find(entry => entry.encrypted && !entry.directory);
      if (!target) return { status: 'not_encrypted', message: '没有加密条目。' };
      if (target.method === 99) throw new ToolError('unsupported', '该条目是 AES 加密（WinZip AE），暂不支持；可用 john/hashcat 或 shell 处理。');
      const result = crackZip(buffer, target, args, cwd);
      return { ...result, entry: { name: target.name, method: target.method }, timeout_ms: args.timeout_ms ?? 30000 };
    },
    ['file_path', 'action'],
  );

  register('stego_audio',
    '检查 WAV 元数据并进行 LSB 提取或频谱图渲染（PNG）。二进制位提取会返回 Hex 与可打印文本。',
    {
      action: { type: 'string', enum: ['info', 'lsb', 'spectrum'], description: '操作类型。' },
      bit_index: { type: 'integer', minimum: 0, maximum: 15, description: '提取第几位，默认 0。' },
      bit_order: { type: 'string', enum: ['lsb_first', 'msb_first'], description: '位序，默认 lsb_first。' },
      max_bytes: { type: 'integer', minimum: 1, maximum: 65536, description: '最多输出字节数，默认 4096。' },
      fft_size: { type: 'integer', minimum: 256, maximum: 8192, description: '每个时间窗的 FFT 点数，须为 2 的幂，默认 2048。' },
      path: { type: 'string', description: '时频谱图保存路径，默认工作目录 spectrum-*.png。' },
    },
    async (args, execution) => {
      const location = await access.location(execution);
      const { bytes: buffer } = await access.read(location, args.file_path, MAX_INPUT_BYTES);
      const wav = parseWav(buffer);
      const inputHash = createHash('sha256').update(buffer).digest('hex');
      const base = {
        input_sha256: inputHash, format: 'wav', channels: wav.fmt.channels, sample_rate: wav.fmt.sampleRate,
        bits_per_sample: wav.fmt.bitsPerSample, frames: wav.frames,
        duration_s: Number((wav.frames / wav.fmt.sampleRate).toFixed(3)),
        tags: wav.tags, chunks: wav.chunks.map(chunk => ({ id: chunk.id, size: chunk.size, offset: chunk.dataOffset })),
      };
      if (args.action === 'info') return { status: 'ok', ...base };
      if (args.action === 'lsb') {
        const bitIndex = args.bit_index ?? 0;
        const maxBytes = Math.min(Math.max(args.max_bytes ?? 4096, 1), 65536);
        if (bitIndex >= wav.fmt.bitsPerSample) throw new ToolError('unsupported', `bit_index 超出 ${wav.fmt.bitsPerSample} 位采样范围。`);
        const samples = wav.frames * wav.fmt.channels;
        const bits = [];
        const limit = Math.min(samples, maxBytes * 8);
        for (let frame = 0; frame < wav.frames && bits.length < limit; frame += 1) {
          for (let channel = 0; channel < wav.fmt.channels && bits.length < limit; channel += 1) {
            const byteOffset = wav.data.dataOffset + (frame * wav.fmt.channels + channel) * (wav.fmt.bitsPerSample / 8);
            const sample = wav.fmt.bitsPerSample === 8 ? buffer[byteOffset] : buffer.readUInt16LE(byteOffset);
            bits.push((sample >> bitIndex) & 1);
          }
        }
        const bytes = [];
        for (let index = 0; index + 8 <= bits.length; index += 8) {
          let value = 0;
          if ((args.bit_order ?? 'lsb_first') === 'lsb_first') {
            for (let offset = 0; offset < 8; offset += 1) value |= bits[index + offset] << offset;
          } else {
            for (let offset = 0; offset < 8; offset += 1) value = (value << 1) | bits[index + offset];
          }
          bytes.push(value);
        }
        const data = Buffer.from(bytes);
        const printable = data.toString('utf8').replace(/[^\x20-\x7e\u4e00-\u9fff]/gu, '.');
        return {
          status: 'ok', input_sha256: inputHash, bit_index: bitIndex, bits_read: bits.length, bytes: data.length,
          hex: data.toString('hex'), text: truncate(printable, 4096),
          sha256: createHash('sha256').update(data).digest('hex'),
        };
      }
      if (args.action === 'spectrum') {
        requireWritable(ctx, execution);
        const fftSize = args.fft_size ?? 2048;
        if (!Number.isInteger(fftSize) || fftSize < 256 || fftSize > 8192 || (fftSize & (fftSize - 1)) !== 0) {
          throw new ToolError('unsupported', 'fft_size 须为 256 至 8192 内的 2 的幂。');
        }
        if (wav.frames === 0) throw new ToolError('unsupported', 'WAV 没有完整 PCM 帧。');
        const maxWindows = 192;
        const hopSize = Math.max(fftSize / 4, Math.ceil(Math.max(0, wav.frames - fftSize) / (maxWindows - 1)));
        const windowCount = 1 + Math.ceil(Math.max(0, wav.frames - fftSize) / hopSize);
        const coefficients = Float64Array.from({ length: fftSize }, (_, index) =>
          0.5 - 0.5 * Math.cos((2 * Math.PI * index) / (fftSize - 1)));
        const windows = [];
        for (let column = 0; column < windowCount; column += 1) {
          execution.signal?.throwIfAborted();
          const mono = new Float64Array(fftSize);
          const start = column * hopSize;
          for (let index = 0; index < fftSize && start + index < wav.frames; index += 1) {
            let sum = 0;
            for (let channel = 0; channel < wav.fmt.channels; channel += 1) sum += sampleAt(buffer, wav, start + index, channel);
            mono[index] = sum / wav.fmt.channels * coefficients[index];
          }
          windows.push(fftMagnitudes(mono));
          if (column % 8 === 7) await new Promise(resolve => setImmediate(resolve));
        }
        const fileOut = await access.output(location, args.path ?? ('spectrum-' + Date.now() + '.png'));
        const rendered = renderSpectrum(fileOut, windows, wav.fmt.sampleRate, fftSize, hopSize);
        return { status: 'ok', ...rendered, input_sha256: inputHash, sha256: createHash('sha256').update(readFileSync(fileOut)).digest('hex') };
      }
      throw new ToolError('unsupported', `未知操作：${args.action}。`);
    },
    ['file_path', 'action'],
  );

  register('mobile_apk',
    '检查 APK 结构（manifest、dex、ABI、签名块），或在安装 apktool/jadx 时反编译，在安装 apksigner/jarsigner 时校验签名。',
    {
      action: { type: 'string', enum: ['info', 'decompile', 'signature'], description: '操作类型。' },
      output_dir: { type: 'string', description: 'decompile 输出目录，默认工作区 .apk-<文件名>。' },
      timeout_ms: { type: 'integer', minimum: 1000, maximum: 300000, description: '反编译上限，默认 120000。' },
    },
    async (args, execution) => {
      const location = await access.location(execution);
      const cwd = location.cwd;
      const file = await access.input(location, args.file_path);
      if (args.wordlist !== undefined) await access.input(location, args.wordlist);
      const { bytes: buffer } = await access.read(location, args.file_path, MAX_INPUT_BYTES);
      const entries = parseZipEntries(buffer);
      const directoryEntries = entries.filter(entry => !entry.directory);
      const signingBlock = buffer.includes(Buffer.from('APK Sig Block 42', 'ascii'));
      if (args.action === 'info') {
        const abis = [...new Set(entries.map(entry => /^lib\/([^/]+)\//u.exec(entry.name)?.[1]).filter(Boolean))];
        return {
          status: 'ok', input_sha256: createHash('sha256').update(buffer).digest('hex'),
          entries: directoryEntries.slice(0, 200).map(entry => ({ name: entry.name, size: entry.size })),
          entry_count: directoryEntries.length,
          has_manifest: entries.some(entry => entry.name === 'AndroidManifest.xml'),
          dex_files: entries.filter(entry => /^classes\d*\.dex$/u.test(entry.name)).map(entry => entry.name),
          dex_total_size: entries.filter(entry => /^classes\d*\.dex$/u.test(entry.name)).reduce((sum, entry) => sum + entry.size, 0),
          abis,
          native_libs: entries.filter(entry => entry.name.startsWith('lib/')).length,
          assets: entries.filter(entry => entry.name.startsWith('assets/')).length,
          signature_files: entries.filter(entry => /^META-INF\/.*\.(RSA|DSA|EC)$/iu.test(entry.name)).map(entry => entry.name),
          signing_block: signingBlock,
          tools: {
            apktool: Boolean(findJavaTool(['apktool', 'apktool.bat'])),
            jadx: Boolean(findJavaTool(['jadx', 'jadx.bat'])),
            apksigner: Boolean(findJavaTool(['apksigner', 'apksigner.bat'])),
            jarsigner: Boolean(findJavaTool(['jarsigner'])),
          },
          hint: '反编译用 action=decompile；签名校验用 action=signature。未安装工具时按提示安装或改用 shell。',
        };
      }
      if (args.action === 'decompile') {
        requireWritable(ctx, execution);
        const jadx = findJavaTool(['jadx', 'jadx.bat']);
        const apktool = findJavaTool(['apktool', 'apktool.bat']);
        if (!jadx && !apktool) throw new ToolError('dependency', '没有找到 jadx 或 apktool。', '安装 jadx（https://github.com/skylot/jadx）或 apktool 后重试。');
        const output = await access.output(location, args.output_dir ?? ('.apk-' + path.basename(file, path.extname(file))), true);
        const command = jadx
          ? { bin: jadx.path, args: ['-d', output, '--no-res', file] }
          : { bin: apktool.path, args: ['d', '-f', '-o', output, file] };
        const result = await spawnCapture(command.bin, command.args, {
          cwd, signal: execution.signal, timeoutMs: Math.min(Math.max(args.timeout_ms ?? 120000, 1000), 300000),
        });
        return {
          status: result.timedOut ? 'timeout' : (result.code === 0 ? 'ok' : 'failed'),
          tool: jadx ? 'jadx' : 'apktool', output_dir: output, exit_code: result.code,
          stdout: truncate(result.stdout), stderr: truncate(result.stderr),
        };
      }
      if (args.action === 'signature') {
        const apksigner = findJavaTool(['apksigner', 'apksigner.bat']);
        const jarsigner = findJavaTool(['jarsigner']);
        if (!apksigner && !jarsigner) throw new ToolError('dependency', '没有找到 apksigner 或 jarsigner。', '安装 Android SDK build-tools 或 JDK 后重试；也可以直接读 META-INF 签名文件。');
        const command = apksigner
          ? { bin: apksigner.path, args: ['verify', '--print-certs', file] }
          : { bin: jarsigner.path, args: ['-verify', '-verbose', '-certs', file] };
        const result = await spawnCapture(command.bin, command.args, { cwd, timeoutMs: 60000 });
        return {
          status: result.code === 0 ? 'ok' : 'failed',
          tool: apksigner ? 'apksigner' : 'jarsigner', exit_code: result.code,
          stdout: truncate(result.stdout), stderr: truncate(result.stderr),
        };
      }
      throw new ToolError('unsupported', `未知操作：${args.action}。`);
    },
    ['file_path', 'action'],
  );

  register('cloud_metadata',
    '保留旧工具入口，提示使用工作区中的脱敏日志。',
    { action: { type: 'string', description: '旧入口操作。' } },
    async () => { throw new ToolError('unsupported', '宿主元数据与凭据探测已关闭。可读取题目目录里的脱敏记录。'); },
    ['action'],
  );

  register('crypto_solver',
    '检查可信工作台 Python 的依赖，生成工作区内的已有计算模板。',
    {
      action: { type: 'string', enum: ['check', 'template'], description: '操作类型。' },
      kind: { type: 'string', enum: ['z3_bitvec', 'coppersmith', 'lattice', 'aes_mode'], description: 'template 的模板种类。' },

    },
    async (args, execution) => {
      const location = await access.location(execution);
      const python = await access.python(execution.signal);
      if (args.action === 'check') {
        const probe = async imports => {
          const code = imports.map(name => `import ${name}`).join('; ');
          try {
            const result = await spawnCapture(python, ['-I', '-B', '-c', `${code}; print("ok")`], { timeoutMs: 8000 });
            return { ok: /ok/u.test(result.stdout), exit_code: result.code };
          } catch (error) {
            return { ok: false, error: describeToolError(error).kind };
          }
        };
        const [z3, fpylll, crypto, sympy] = await Promise.all([
          probe(['z3']), probe(['fpylll']), probe(['Crypto']), probe(['sympy']),
        ]);
        return { status: 'ok', python, modules: { z3, fpylll, pycryptodome: crypto, sympy } };
      }
      if (args.action === 'template') {
        const kind = args.kind;
        if (typeof kind !== 'string' || !Object.hasOwn(TEMPLATES, kind)) throw new ToolError('unsupported', `未知模板：${kind}。`);
        requireWritable(ctx, execution);
        const file = await access.output(location, '.ctf-templates/' + kind + '.py');
        writeFileSync(file, TEMPLATES[kind], { flag: 'wx' });
        return { status: 'ok', file, kind, preview: TEMPLATES[kind].split('\n').slice(0, 6).join('\n') };
      }
      throw new ToolError('unsupported', `未知操作：${args.action}。`);
    },
    ['action'],
  );
}
