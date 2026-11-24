// CTF preset 的扩展工具：浏览器会话、gdb 调试、压缩包口令、音频隐写、APK 检查、
// 云元数据探测、密码学模板。全部工具遵守有界读取，失败时返回结构化错误。
import { spawn } from 'node:child_process';
import { closeSync, openSync, readFileSync, readSync, statSync, writeFileSync } from 'node:fs';
import { stat } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { deflateSync, inflateRawSync } from 'node:zlib';
import { BROWSER_TIMEOUT_MS, createBrowserSession } from './browser-session.js';
import { isLocalWorkbenchPath } from './workbench-config.js';
import { describeToolError, ToolError } from './tool-errors.js';
import { detectSandbox, runSandboxCommand } from './sandbox-runner.js';
import { CRYPTO_SOLVE_OPERATIONS, runCryptoSolve } from './crypto-toolbox.js';

const MAX_INPUT_BYTES = 256 * 1024 * 1024;
const MAX_TEXT_OUTPUT = 64 * 1024;
const GDB_ATOM = '(?:\\$[A-Za-z][A-Za-z0-9_]*|0x[0-9a-f]{1,16}|[0-9]{1,16}|[A-Za-z_][A-Za-z0-9_.@$]*)';
const GDB_EXPR = `${GDB_ATOM}(?:\\s*[+-]\\s*${GDB_ATOM}){0,3}`;
const GDB_CAST = '(?:\\((?:void|char|int|long|unsigned\\s+long|uint64_t|uint32_t|int64_t|int32_t)\\s*\\*{1,2}\\))';
const GDB_VALUE = `(?:\\*(?:${GDB_CAST})?\\s*)?(?:${GDB_EXPR}|\\(${GDB_EXPR}\\))`;
const GDB_COMMAND_PATTERNS = [
  new RegExp(`^(?:break|b)\\s+\\*?${GDB_EXPR}$`, 'iu'),
  /^(?:run|start|starti|continue|c|step|s|stepi|si|next|n|nexti|ni|finish|fin|kill)$/iu,
  /^(?:bt|backtrace)(?:\s+[0-9]{1,3})?$/iu,
  /^(?:info|i)\s+(?:registers|reg|r)(?:\s+[A-Za-z0-9_]+){0,8}$/iu,
  /^(?:info|i)\s+(?:all-registers|frame|files|proc\s+mappings|args|locals|functions|variables|breakpoints|b)$/iu,
  new RegExp(`^(?:info|i)\\s+symbol\\s+${GDB_EXPR}$`, 'iu'),
  /^frame(?:\s+[0-9]{1,4})?$/iu,
  new RegExp(`^x\\/(?:[1-9][0-9]{0,2})?(?:[bghw][xduoctafis]?|[xduoctafis][bghw]?)?\\s+${GDB_VALUE}$`, 'iu'),
  new RegExp(`^(?:disassemble|disas)(?:\\s+${GDB_EXPR}(?:\\s*,\\s*${GDB_EXPR})?)?$`, 'iu'),
  new RegExp(`^(?:p|print)(?:\\/[xduoctafs]|\\s+\\/[xduoctafs])?\\s+${GDB_VALUE}$`, 'iu'),
];

function registerTool(ctx, toolName, description, properties, run, required = ['file_path'], observe, getConfig) {
  const schema = required.includes('file_path') && !Object.hasOwn(properties, 'file_path')
    ? { file_path: { type: 'string', description: '本题工作区内的相对附件路径。' }, ...properties } : properties;
  ctx.tools.register({
    name: toolName,
    description,
    parameters: { type: 'object', properties: schema, additionalProperties: false, required },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
    async execute(args, execution) {
      const askedFile = typeof args?.file_path === 'string' ? args.file_path : undefined;
      const spacing = () => (getConfig()?.compact === false ? 2 : 0);
      try {
        if (!args || typeof args !== 'object' || Array.isArray(args)
          || Object.keys(args).some(key => !Object.hasOwn(schema, key))
          || required.some(key => !Object.hasOwn(args, key))) {
          throw new ToolError('unsupported', '参数缺失或含工具未声明的字段。');
        }
        const report = await run(args, execution);
        const artifactBytes = Buffer.isBuffer(report?.__artifact_bytes) ? report.__artifact_bytes : undefined;
        if (artifactBytes !== undefined) delete report.__artifact_bytes;
        const output = { file: askedFile, ...report };
        const capture = await observe?.(toolName, args, execution, output, artifactBytes);
        return JSON.stringify({ ...output, ...capture }, null, spacing());
      } catch (error) {
        return JSON.stringify({ ok: false, file: askedFile, error: describeToolError(error) }, null, spacing());
      }
    },
  });
}

function childEnvironment() {
  const keys = new Set(['path', 'systemroot', 'systemdrive', 'windir', 'temp', 'tmp', 'home', 'userprofile',
    'programfiles', 'programfiles(x86)', 'localappdata', 'appdata', 'comspec', 'pathext', 'lang', 'lc_all', 'java_home']);
  return Object.fromEntries(Object.entries(process.env).filter(([key]) => keys.has(key.toLowerCase())));
}

function requireWritable(ctx, execution) {
  const policy = ctx.sandboxPolicy?.resolve?.({ session: execution.agent?.session });
  if (policy?.mode === 'read-only') throw new ToolError('permission', '当前会话是只读权限，无法写入文件。');
}

function truncate(text, limit = MAX_TEXT_OUTPUT) {
  const value = String(text);
  if (value.length <= limit) return value;
  return `${value.slice(0, limit)}\n…（输出已截断，共 ${value.length} 字符）`;
}

function spawnCapture(command, args, options = {}) {
  const { timeoutMs = 30000, cwd, env = childEnvironment(), maxBytes = 256 * 1024, signal, killTree = false } = options;
  return new Promise((resolve, reject) => {
    if (killTree && signal?.aborted) {
      reject(signal.reason ?? new Error('子进程已取消。'));
      return;
    }
    let child;
    try {
      child = spawn(command, args, { cwd, env, windowsHide: true, ...(killTree && process.platform !== 'win32' ? { detached: true } : {}),
        ...(!killTree && signal ? { signal } : {}), stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (error) {
      reject(error);
      return;
    }
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let settled = false;
    let abortReason;
    const terminate = () => {
      if (killTree && child.pid) {
        if (process.platform === 'win32') {
          const taskkill = process.env.SystemRoot ? path.join(process.env.SystemRoot, 'System32', 'taskkill.exe') : 'taskkill';
          try {
            const killer = spawn(taskkill, ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
            killer.on('error', () => {});
            killer.unref();
          }
          catch { /* Fall back to killing the debugger process below. */ }
        } else {
          try { process.kill(-child.pid, 'SIGKILL'); } catch { /* Process group may already have exited. */ }
        }
      }
      try { child.kill(); } catch { /* Process may already have exited. */ }
    };
    const abort = () => {
      if (settled) return;
      abortReason = signal?.reason ?? new Error('子进程已取消。');
      terminate();
    };
    const collect = (chunk, target) => {
      const next = target + chunk.toString('utf8');
      return next.length > maxBytes ? next.slice(0, maxBytes) : next;
    };
    const timer = setTimeout(() => {
      if (settled) return;
      timedOut = true;
      terminate();
    }, timeoutMs);
    if (killTree && signal) {
      signal.addEventListener('abort', abort, { once: true });
      if (signal.aborted) abort();
    }
    child.stdout?.on('data', chunk => { stdout = collect(chunk, stdout); });
    child.stderr?.on('data', chunk => { stderr = collect(chunk, stderr); });
    child.on('error', error => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      reject(abortReason ?? error);
    });
    child.on('close', code => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      if (abortReason !== undefined) reject(abortReason);
      else resolve({ code: code ?? -1, stdout, stderr, timedOut });
    });
  });
}

function validatedGdbCommands(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 24) {
    throw new ToolError('unsupported', 'debug 需要 1 至 24 条 GDB 命令。');
  }
  return value.map(command => {
    if (typeof command !== 'string' || command.length > 256 || /[\0\r\n;]/u.test(command)) {
      throw new ToolError('unsupported', 'GDB 命令须为单行文本且不超过 256 字符。');
    }
    const normalized = command.trim();
    if (!GDB_COMMAND_PATTERNS.some(pattern => pattern.test(normalized))) {
      throw new ToolError('unsupported', `GDB 命令不在只读调试白名单内：${normalized.slice(0, 80)}。`);
    }
    return normalized;
  });
}

function validatedGdbArgs(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 16) {
    throw new ToolError('unsupported', 'args 须为最多 16 项的字符串数组。');
  }
  return value.map((item, idx) => {
    if (typeof item !== 'string' || item.length > 256 || /[\0\r\n]/u.test(item)) {
      throw new ToolError('unsupported', `args[${idx}] 须为不超过 256 字符的单行字符串。`);
    }
    return item;
  });
}

function quoteGdbPath(value) {
  return '"' + value.replaceAll('\\', '/').replaceAll('"', '\\"') + '"';
}

function quoteGdbArg(value, posix) {
  return posix ? "'" + value.replaceAll("'", "'\\''") + "'" : quoteGdbPath(value);
}

function isElfBinary(filePath) {
  let fd;
  try {
    fd = openSync(filePath, 'r');
    const head = Buffer.alloc(4);
    const n = readSync(fd, head, 0, 4, 0);
    return n === 4 && head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* ignore */ }
    }
  }
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

async function crackZip(buffer, entry, args, wordlistText, signal) {
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
  let format = buffer.readUInt16LE(fmt.dataOffset);
  if (format === 0xfffe) {
    const pcmGuid = Buffer.from('0100000000001000800000aa00389b71', 'hex');
    if (fmt.size < 40 || !buffer.subarray(fmt.dataOffset + 24, fmt.dataOffset + 40).equals(pcmGuid)) {
      throw new ToolError('unsupported', 'WAVEFORMATEXTENSIBLE 只支持标准 PCM 子格式。');
    }
    format = buffer.readUInt16LE(fmt.dataOffset + 24);
  }
  const channels = buffer.readUInt16LE(fmt.dataOffset + 2);
  const sampleRate = buffer.readUInt32LE(fmt.dataOffset + 4);
  const blockAlign = buffer.readUInt16LE(fmt.dataOffset + 12);
  const bitsPerSample = buffer.readUInt16LE(fmt.dataOffset + 14);
  if (channels < 1 || channels > 32 || sampleRate < 1) throw new ToolError('unsupported', 'WAV 声道数或采样率无效。');
  if (![8, 16, 24].includes(bitsPerSample)) {
    throw new ToolError('unsupported', `暂不支持 ${bitsPerSample} 位 PCM，支持 8/16/24 位。`);
  }
  if (format !== 1) throw new ToolError('unsupported', '只支持 PCM（format=1）的 WAV。');
  const frameSize = channels * (bitsPerSample / 8);
  if (blockAlign !== frameSize) throw new ToolError('unsupported', 'WAV block_align 与声道数及位深不匹配。');
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
  if (wav.fmt.bitsPerSample === 16) return buffer.readInt16LE(offset) / 32768;
  let value = buffer[offset] | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 16);
  if (value & 0x800000) value -= 0x1000000;
  return value / 8388608;
}

function rawSampleAt(buffer, wav, frame, channel) {
  const bytes = wav.fmt.bitsPerSample / 8;
  const offset = wav.data.dataOffset + (frame * wav.fmt.channels + channel) * bytes;
  if (wav.fmt.bitsPerSample === 8) return buffer[offset];
  if (wav.fmt.bitsPerSample === 16) return buffer.readUInt16LE(offset);
  return buffer[offset] | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 16);
}

function audioSelection(wav, args) {
  if (args.start_frame !== undefined && args.start_seconds !== undefined) throw new ToolError('unsupported', 'start_frame 和 start_seconds 只能选一个。');
  if (args.frame_count !== undefined && args.duration_seconds !== undefined) throw new ToolError('unsupported', 'frame_count 和 duration_seconds 只能选一个。');
  const start = args.start_frame ?? Math.floor((args.start_seconds ?? 0) * wav.fmt.sampleRate);
  const count = args.frame_count ?? (args.duration_seconds === undefined
    ? wav.frames - start : Math.ceil(args.duration_seconds * wav.fmt.sampleRate));
  if (!Number.isSafeInteger(start) || start < 0 || !Number.isSafeInteger(count) || count < 1 || start + count > wav.frames) {
    throw new ToolError('unsupported', '音频选段必须落在完整 PCM 帧范围内。');
  }
  const channels = args.channels ?? Array.from({ length: wav.fmt.channels }, (_, index) => index);
  if (!Array.isArray(channels) || channels.length < 1 || channels.length > wav.fmt.channels
    || new Set(channels).size !== channels.length || channels.some(channel => !Number.isInteger(channel) || channel < 0 || channel >= wav.fmt.channels)) {
    throw new ToolError('unsupported', 'channels 须是 WAV 中有效且不重复的声道编号。');
  }
  const sampleOffset = args.sample_offset ?? 0;
  if (!Number.isSafeInteger(sampleOffset) || sampleOffset < 0 || sampleOffset % 8 !== 0
    || sampleOffset > count * channels.length) throw new ToolError('unsupported', 'sample_offset 须按字节对齐并位于所选音频段内。');
  return { start, count, end: start + count, channels, sampleOffset };
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
    '# Z3 位向量求解脚手架：将字节约束写成 BitVec 等式后求解。',
    'from z3 import BitVec, Solver, sat',
    '',
    'def solve_bytes(length=8):',
    '    chars = [BitVec(f"c{i}", 8) for i in range(length)]',
    '    solver = Solver()',
    '    for c in chars:',
    '        solver.add(c >= 0x20, c <= 0x7e)',
    '    # 示例约束（解题时替换为题目真实方程）',
    '    target = b"CTF_TEST"[:length]',
    '    for i, b in enumerate(target):',
    '        solver.add((chars[i] ^ 0x2A) == (b ^ 0x2A))',
    '    if solver.check() != sat:',
    '        return None',
    '    model = solver.model()',
    '    return bytes(model[c].as_long() for c in chars)',
    '',
    'if __name__ == "__main__":',
    '    ans = solve_bytes()',
    '    print("result:", ans.decode("ascii", "replace") if ans else "unsat")',
    '',
  ].join('\n'),
  'coppersmith': [
    '# Coppersmith 一元小根求解脚手架（依赖 fpylll 与 sympy）：Howgrave-Graham + LLL。',
    'from fpylll import IntegerMatrix, LLL',
    'from sympy import Poly, ZZ, symbols',
    '',
    'def coppersmith_univariate(coeffs_desc, modulus, bound_x, m=2, t=2):',
    '    """对首一多项式 f(x) = sum(c_i * x^i) mod modulus 寻找 |x| <= bound_x 的整数根。"""',
    '    x = symbols("x")',
    '    f = Poly(coeffs_desc, x, domain=ZZ)',
    '    d = f.degree()',
    '    if d <= 0:',
    '        raise ValueError("多项式次数必须大于 0")',
    '    polys = []',
    '    for i in range(m):',
    '        for j in range(d):',
    '            polys.append(Poly((modulus ** (m - i)) * (x ** j) * (f.as_expr() ** i), x, domain=ZZ))',
    '    for k in range(t):',
    '        polys.append(Poly((x ** k) * (f.as_expr() ** m), x, domain=ZZ))',
    '    dim = len(polys)',
    '    mat = IntegerMatrix(dim, dim)',
    '    for row, p in enumerate(polys):',
    '        for col in range(dim):',
    '            mat[row, col] = int(p.nth(col)) * (bound_x ** col)',
    '    LLL.reduction(mat)',
    '    roots = set()',
    '    for row in range(dim):',
    '        scaled = [int(mat[row, col]) // (bound_x ** col) for col in range(dim)]',
    '        if all(c == 0 for c in scaled):',
    '            continue',
    '        cand_poly = Poly(list(reversed(scaled)), x, domain=ZZ)',
    '        for r in cand_poly.ground_roots().keys():',
    '            r_int = int(r)',
    '            if abs(r_int) <= bound_x and int(f.eval(r_int)) % modulus == 0:',
    '                roots.add(r_int)',
    '    return sorted(roots)',
    '',
    'if __name__ == "__main__":',
    '    # 示例：解 (known + x)^3 - c == 0 (mod n)',
    '    n = 1000003 * 1000033',
    '    known = 123456000',
    '    secret_x = 42',
    '    c = pow(known + secret_x, 3, n)',
    '    x = symbols("x")',
    '    poly = Poly((known + x) ** 3 - c, x, domain=ZZ)',
    '    print("roots:", coppersmith_univariate(poly.all_coeffs(), n, bound_x=1000, m=2, t=2))',
    '',
  ].join('\n'),
  'lattice': [
    '# 格规约 / 线性同余小解求解脚手架（依赖 fpylll）：Kannan 嵌入 + LLL/BKZ。',
    'from fpylll import IntegerMatrix, LLL, BKZ',
    '',
    'def solve_linear_modular(a_list, b_list, modulus, bound, use_bkz=False):',
    '    """求解 k * a_i + b_i == e_i (mod modulus)，其中 |e_i| <= bound。"""',
    '    n = len(a_list)',
    '    dim = n + 2',
    '    mat = IntegerMatrix(dim, dim)',
    '    for i in range(n):',
    '        mat[i, i] = modulus',
    '        mat[n, i] = a_list[i] % modulus',
    '        mat[n + 1, i] = b_list[i] % modulus',
    '    mat[n, n] = 1',
    '    mat[n + 1, n + 1] = bound',
    '    if use_bkz:',
    '        BKZ.reduction(mat, BKZ.Param(block_size=min(20, dim)))',
    '    else:',
    '        LLL.reduction(mat)',
    '    candidates = []',
    '    for row in range(dim):',
    '        if abs(mat[row, n + 1]) == bound:',
    '            sign = 1 if mat[row, n + 1] > 0 else -1',
    '            k = (sign * int(mat[row, n])) % modulus',
    '            candidates.append(k)',
    '    return sorted(set(candidates))',
    '',
    'if __name__ == "__main__":',
    '    modulus = 65537',
    '    secret_k = 1337',
    '    a_vals = [101, 211, 307, 409, 503]',
    '    errors = [3, -2, 5, -1, 4]',
    '    b_vals = [(e - secret_k * a) % modulus for a, e in zip(a_vals, errors)]',
    '    print("candidates:", solve_linear_modular(a_vals, b_vals, modulus, bound=16))',
    '',
  ].join('\n'),
  'aes_mode': [
    '# AES 分组模式诊断脚手架（依赖 pycryptodome）：块长探测、ECB 重复块检测与 CBC/CTR 属性验证。',
    'from Crypto.Cipher import AES',
    'from Crypto.Util.Padding import pad, unpad',
    '',
    'def detect_block_size(encrypt_fn, max_len=64):',
    '    base = len(encrypt_fn(b""))',
    '    for i in range(1, max_len + 1):',
    '        size = len(encrypt_fn(b"A" * i))',
    '        if size > base:',
    '            return size - base',
    '    return None',
    '',
    'def is_ecb_like(encrypt_fn, block_size=16):',
    '    sample = encrypt_fn(b"A" * (block_size * 4))',
    '    blocks = [sample[i:i + block_size] for i in range(0, len(sample), block_size)]',
    '    return len(blocks) != len(set(blocks))',
    '',
    'def demo_local_oracle():',
    '    key = b"0123456789abcdef"',
    '    ecb = lambda pt: AES.new(key, AES.MODE_ECB).encrypt(pad(pt, 16))',
    '    cbc = lambda pt: AES.new(key, AES.MODE_CBC, iv=b"fedcba9876543210").encrypt(pad(pt, 16))',
    '    print("ECB block_size:", detect_block_size(ecb), "ecb_detected:", is_ecb_like(ecb))',
    '    print("CBC block_size:", detect_block_size(cbc), "ecb_detected:", is_ecb_like(cbc))',
    '    ct = cbc(b"hello_ctf_block_mode")',
    '    pt = unpad(AES.new(key, AES.MODE_CBC, iv=b"fedcba9876543210").decrypt(ct), 16)',
    '    print("CBC roundtrip ok:", pt == b"hello_ctf_block_mode")',
    '',
    'if __name__ == "__main__":',
    '    demo_local_oracle()',
    '',
  ].join('\n'),
};

// ── 注册 ─────────────────────────────────────────────────────────────────────

export function registerExtraTools(ctx, configSource, access) {
  const getConfig = typeof configSource === 'function' ? configSource : () => configSource ?? {};
  const register = (name, description, properties, run, required) =>
    registerTool(ctx, name, description, properties, run, required, access.observe, getConfig);
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
        resolveBinary: () => detectBrowser(getConfig()),
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
    '隔离 Chrome/Edge 会话：open/dom/screenshot/cookies/storage/network/console 及可写交互（click/fill/select/press/wait_for）。',
    {
      action: { type: 'string', enum: ['open', 'dom', 'screenshot', 'cookies', 'title', 'close', 'status', 'list', 'click', 'fill', 'select', 'press', 'wait_for', 'storage', 'network', 'console'] },
      url: { type: 'string' },
      selector: { type: 'string', maxLength: 1024 },
      value: { type: 'string', maxLength: 16384 },
      key: { type: 'string', enum: ['Enter', 'Tab', 'Escape', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Space', 'Backspace', 'Delete'] },
      storage_type: { type: 'string', enum: ['local', 'session'] },
      include_values: { type: 'boolean', default: true },
      request_id: { type: 'string', maxLength: 256, description: 'network 读指定请求响应体。' },
      clear_logs: { type: 'boolean', default: false },
      wait_ms: { type: 'integer', minimum: 250, maximum: 30000 },
      path: { type: 'string' },
      timeout_ms: { type: 'integer', minimum: 1000, maximum: 60000 },
    },
    async (args, execution) => {
      const location = await access.location(execution);
      const action = args.action;
      if (['click', 'fill', 'select', 'press'].includes(action)) requireWritable(ctx, execution);
      if (args.selector !== undefined && (typeof args.selector !== 'string' || args.selector.length === 0 || args.selector.length > 1024)) {
        throw new ToolError('unsupported', 'selector 须为不超过 1024 字符的 CSS 选择器。');
      }
      if (['click', 'fill', 'select', 'press', 'wait_for'].includes(action)
        && (typeof args.selector !== 'string' || args.selector.length === 0)) {
        throw new ToolError('unsupported', `${action} 需要非空 CSS selector。`);
      }
      if (args.value !== undefined && (typeof args.value !== 'string' || args.value.length > 16384)) {
        throw new ToolError('unsupported', 'value 须为不超过 16384 字符的文本。');
      }
      if (['fill', 'select'].includes(action) && typeof args.value !== 'string') {
        throw new ToolError('unsupported', `${action} 需要字符串 value。`);
      }
      if (action === 'press' && !['Enter', 'Tab', 'Escape', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Space', 'Backspace', 'Delete'].includes(args.key)) {
        throw new ToolError('unsupported', 'press 的 key 须为 Enter、Tab、Escape、方向键、Space、Backspace 或 Delete。');
      }
      const waitMs = args.wait_ms ?? 10000;
      if (action === 'wait_for' && (!Number.isSafeInteger(waitMs) || waitMs < 250 || waitMs > 30000)) {
        throw new ToolError('unsupported', 'wait_ms 须在 250 至 30000 内。');
      }
      const storageType = args.storage_type ?? 'local';
      if (action === 'storage' && !['local', 'session'].includes(storageType)) {
        throw new ToolError('unsupported', 'storage_type 须为 local 或 session。');
      }
      if (args.include_values !== undefined && typeof args.include_values !== 'boolean') {
        throw new ToolError('unsupported', 'include_values 须为布尔值。');
      }
      if (args.clear_logs !== undefined && typeof args.clear_logs !== 'boolean') {
        throw new ToolError('unsupported', 'clear_logs 须为布尔值。');
      }
      if (args.request_id !== undefined && (typeof args.request_id !== 'string' || args.request_id.length === 0 || args.request_id.length > 256)) {
        throw new ToolError('unsupported', 'request_id 须为非空字符串。');
      }
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
        if (action === 'press') {
          const result = await browser.press(target, args.selector, args.key, signal);
          if (result.status === 'invalid_selector') throw new ToolError('unsupported', 'CSS selector 语法无效。');
          if (result.status === 'match_count') throw new ToolError('missing', `CSS selector 匹配 ${result.count} 个元素，交互要求恰好一个。`);
          if (result.status !== 'pressed') throw new ToolError('unsupported', `无法向页面元素发送按键：${result.status}。`);
          return { ...result, selector: args.selector };
        }
        if (['click', 'fill', 'select'].includes(action)) {
          const result = await browser.interact(target, action, args.selector, args.value, signal);
          const expected = { click: 'clicked', fill: 'filled', select: 'selected' }[action];
          if (result.status === 'invalid_selector') throw new ToolError('unsupported', 'CSS selector 语法无效。');
          if (result.status === 'match_count') throw new ToolError('missing', `CSS selector 匹配 ${result.count} 个元素，交互要求恰好一个。`);
          if (result.status !== expected) throw new ToolError('unsupported', `页面元素无法执行 ${action}：${result.status}。`);
          return { ...result, selector: args.selector };
        }
        if (action === 'wait_for') {
          const result = await browser.waitFor(target, args.selector, waitMs, signal);
          if (result.status === 'invalid_selector') throw new ToolError('unsupported', 'CSS selector 语法无效。');
          return { ...result, selector: args.selector, wait_ms: waitMs };
        }
        if (action === 'storage') return { ...await browser.storage(target, storageType, signal), storage_type: storageType };
        if (action === 'screenshot') {
          const file = await access.output(location, args.path ?? ('screenshot-' + Date.now() + '.png'));
          return { status: 'screenshot', file, ...await browser.screenshot(target, file, signal) };
        }
        if (action === 'cookies') {
          const includeValues = args.include_values !== false;
          const token = access.platformToken?.() ?? '';
          const hide = text => token && typeof text === 'string' ? text.replaceAll(token, '[已脱敏]') : text;
          const cookies = await browser.cookies(target, args.url, signal);
          return { status: 'cookies', include_values: includeValues, cookies: cookies.map(cookie => ({
            name: cookie.name,
            ...(includeValues ? {
              value: hide(String(cookie.value ?? '').slice(0, 4096)),
              ...(String(cookie.value ?? '').length > 4096 ? { value_truncated: true } : {}),
            } : {}),
            domain: cookie.domain, path: cookie.path,
            secure: cookie.secure, httpOnly: cookie.httpOnly,
            ...(cookie.sameSite ? { sameSite: cookie.sameSite } : {}),
            ...(typeof cookie.expires === 'number' && cookie.expires > 0 ? { expires: cookie.expires } : {}),
          })) };
        }
        if (action === 'network') {
          if (args.request_id !== undefined) {
            return { status: 'network_body', ...await browser.responseBody(target, args.request_id, signal) };
          }
          const requests = browser.network(target, args.clear_logs === true);
          return { status: 'network', count: requests.length, requests };
        }
        if (action === 'console') {
          const entries = browser.console(target, args.clear_logs === true);
          return { status: 'console', count: entries.length, entries };
        }
        if (action === 'list') return { status: 'targets', targets: await browser.list(target, signal) };
        throw new ToolError('unsupported', `未知操作：${action}。`);
      });
    },
    ['action'],
  );

  register('gdb_driver',
    '用 GDB 检查或调试工作区二进制（Windows 下遇 Linux ELF 自动桥接 Docker/WSL2 Linux GDB）；严格只读白名单，禁用 shell/Python/init。',
    {
      action: { type: 'string', enum: ['inspect', 'debug'] },
      kind: { type: 'string', enum: ['files', 'sections'] },
      commands: { type: 'array', minItems: 1, maxItems: 24, items: { type: 'string', maxLength: 256 }, description: 'GDB 白名单命令列表。' },
      args: { type: 'array', maxItems: 16, items: { type: 'string', maxLength: 256 }, description: '程序命令行参数。' },
      stdin_file: { type: 'string', maxLength: 1024 },
      timeout_ms: { type: 'integer', minimum: 1000, maximum: 120000 },
    },
    async (args, execution) => {
      if (!['inspect', 'debug'].includes(args.action)) throw new ToolError('unsupported', 'action 须为 inspect 或 debug。');
      if (args.action === 'inspect' && !['files', 'sections'].includes(args.kind ?? 'files')) {
        throw new ToolError('unsupported', 'inspect 的 kind 须为 files 或 sections。');
      }
      if (args.action === 'debug') requireWritable(ctx, execution);
      const location = await access.location(execution);
      const binary = await access.input(location, args.file_path);
      const timeoutMs = args.timeout_ms ?? 30000;
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 120000) {
        throw new ToolError('unsupported', 'timeout_ms 须在 1000 至 120000 内。');
      }
      const config = getConfig();
      const useSandbox = process.platform === 'win32' && isElfBinary(binary)
        ? await detectSandbox(config, execution.signal) : undefined;
      const sandboxActive = Boolean(useSandbox?.available);
      let gdb;
      if (!sandboxActive) {
        gdb = await detectGdb(config);
        if (!gdb || !path.isAbsolute(gdb)) {
          throw new ToolError('dependency', '配置本机 GDB 的绝对路径，或启用 Docker/WSL2 Linux 沙箱内的 GDB。');
        }
      }
      const sandboxRel = abs => './' + path.relative(location.cwd, abs).replaceAll('\\', '/');
      const targetBinary = sandboxActive ? sandboxRel(binary) : binary;
      const runGdb = (commandArgs, { ptrace = false, killTree = false } = {}) => sandboxActive
        ? runSandboxCommand(['gdb', ...commandArgs], {
          cwd: location.cwd, config, signal: execution.signal, timeoutMs, ptrace, detected: useSandbox,
        })
        : spawnCapture(gdb, commandArgs, {
          cwd: location.cwd, timeoutMs, maxBytes: MAX_TEXT_OUTPUT / 2, signal: execution.signal, killTree,
        });

      if (args.action === 'inspect') {
        const command = args.kind === 'sections' ? 'maintenance info sections' : 'info files';
        const result = await runGdb(['-q', '-batch', '-nx', '-nh', '-iex', 'set auto-load off',
          '-iex', 'set debuginfod enabled off', '--se=' + targetBinary, '-ex', command]);
        return { action: 'inspect', status: result.timedOut ? 'timeout' : result.code === 0 ? 'ok' : 'failed',
          ...(sandboxActive ? { backend: result.backend, target: result.target } : { backend: 'host' }),
          exit_code: result.code, stdout: truncate(result.stdout), stderr: truncate(result.stderr) };
      }
      const commands = validatedGdbCommands(args.commands);
      const progArgs = validatedGdbArgs(args.args);
      let stdinFile;
      if (args.stdin_file !== undefined) {
        if (typeof args.stdin_file !== 'string' || args.stdin_file.length === 0 || args.stdin_file.length > 1024) {
          throw new ToolError('unsupported', 'stdin_file 须为工作区内的相对文件路径。');
        }
        if (!commands.some(command => command.toLowerCase() === 'run')) {
          throw new ToolError('unsupported', '传入 stdin_file 时 commands 必须包含 run。');
        }
        const resolvedStdin = await access.input(location, args.stdin_file);
        stdinFile = sandboxActive ? sandboxRel(resolvedStdin) : resolvedStdin;
      }
      const effectiveCommands = commands.map(command => command.toLowerCase() === 'run' && stdinFile
        ? 'run < ' + quoteGdbPath(stdinFile) : command);
      const commandArgs = ['-q', '-batch', '-nx', '-nh', '-iex', 'set auto-load off',
        '-iex', 'set debuginfod enabled off', '-e', targetBinary, '-ex', 'set confirm off'];
      if (progArgs.length > 0) {
        const posix = sandboxActive || process.platform !== 'win32';
        commandArgs.push('-ex', 'set args ' + progArgs.map(item => quoteGdbArg(item, posix)).join(' '));
      }
      for (const command of effectiveCommands) commandArgs.push('-ex', command);
      const result = await runGdb(commandArgs, { ptrace: true, killTree: true });
      return { action: 'debug', status: result.timedOut ? 'timeout' : result.code === 0 ? 'ok' : 'failed',
        ...(sandboxActive ? { backend: result.backend, target: result.target } : { backend: 'host' }),
        binary: args.file_path, ...(args.stdin_file === undefined ? {} : { stdin_file: args.stdin_file }),
        ...(progArgs.length > 0 ? { args: progArgs } : {}),
        commands: effectiveCommands, exit_code: result.code,
        stdout: truncate(result.stdout), stderr: truncate(result.stderr) };
    },
    ['file_path', 'action'],
  );

  register('archive_crack',
    '检查 ZIP 结构并尝试破解 ZipCrypto 口令（字典/掩码/弱口令），命中后校验 CRC。',
    {
      action: { type: 'string', enum: ['info', 'crack'] },
      wordlist: { type: 'string' },
      mask: { type: 'string', description: '掩码，如 ?l?l?l?d。' },
      passwords: { type: 'array', items: { type: 'string' }, maxItems: 256 },
      min_length: { type: 'integer', minimum: 0, maximum: 64 },
      max_length: { type: 'integer', minimum: 1, maximum: 64 },
      timeout_ms: { type: 'integer', minimum: 1000, maximum: 120000 },
    },
    async (args, execution) => {
      if (!['info', 'crack'].includes(args.action)) throw new ToolError('unsupported', 'action 须为 info 或 crack。');
      const location = await access.location(execution);
      await access.input(location, args.file_path);
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
      let wordlistText;
      if (typeof args.wordlist === 'string') {
        const { bytes: wordlistBytes } = await access.read(location, args.wordlist, 64 * 1024 * 1024);
        wordlistText = wordlistBytes.toString('utf8');
      }
      const result = await crackZip(buffer, target, args, wordlistText, execution.signal);
      return { ...result, entry: { name: target.name, method: target.method }, timeout_ms: args.timeout_ms ?? 30000 };
    },
    ['file_path', 'action'],
  );

  register('stego_audio',
    'WAV（8/16/24 位 PCM）元数据、选段/声道 LSB 提取与 FFT 时频谱 PNG 渲染。',
    {
      action: { type: 'string', enum: ['info', 'lsb', 'spectrum'] },
      bit_index: { type: 'integer', minimum: 0, maximum: 23 },
      bit_order: { type: 'string', enum: ['lsb_first', 'msb_first'] },
      max_bytes: { type: 'integer', minimum: 1, maximum: 65536 },
      start_seconds: { type: 'number', minimum: 0, maximum: 86400 },
      duration_seconds: { type: 'number', exclusiveMinimum: 0, maximum: 86400 },
      start_frame: { type: 'integer', minimum: 0 },
      frame_count: { type: 'integer', minimum: 1 },
      channels: { type: 'array', minItems: 1, maxItems: 32, uniqueItems: true, items: { type: 'integer', minimum: 0, maximum: 31 } },
      sample_offset: { type: 'integer', minimum: 0 },
      fft_size: { type: 'integer', minimum: 256, maximum: 8192 },
      path: { type: 'string' },
    },
    async (args, execution) => {
      const location = await access.location(execution);
      const { bytes: buffer } = await access.read(location, args.file_path, MAX_INPUT_BYTES);
      const wav = parseWav(buffer);
      const inputHash = createHash('sha256').update(buffer).digest('hex');
      const selection = args.action === 'info' && wav.frames === 0
        ? { start: 0, count: 0, end: 0, channels: Array.from({ length: wav.fmt.channels }, (_, index) => index), sampleOffset: 0 }
        : audioSelection(wav, args);
      const base = {
        input_sha256: inputHash, format: 'wav', channels: wav.fmt.channels, sample_rate: wav.fmt.sampleRate,
        bits_per_sample: wav.fmt.bitsPerSample, frames: wav.frames,
        duration_s: Number((wav.frames / wav.fmt.sampleRate).toFixed(3)),
        selected_channels: selection.channels, start_frame: selection.start, end_frame: selection.end,
        selected_duration_s: Number((selection.count / wav.fmt.sampleRate).toFixed(3)),
        tags: wav.tags, chunks: wav.chunks.map(chunk => ({ id: chunk.id, size: chunk.size, offset: chunk.dataOffset })),
      };
      if (args.action === 'info') return { status: 'ok', ...base };
      if (args.action === 'lsb') {
        const bitIndex = args.bit_index ?? 0;
        const bitOrder = args.bit_order ?? 'lsb_first';
        if (!['lsb_first', 'msb_first'].includes(bitOrder)) throw new ToolError('unsupported', 'bit_order 须为 lsb_first 或 msb_first。');
        const maxBytes = Math.min(Math.max(args.max_bytes ?? 4096, 1), 65536);
        if (bitIndex >= wav.fmt.bitsPerSample) throw new ToolError('unsupported', `bit_index 超出 ${wav.fmt.bitsPerSample} 位采样范围。`);
        const bits = [];
        const totalSamples = selection.count * selection.channels.length;
        const sampleEnd = Math.min(totalSamples, selection.sampleOffset + maxBytes * 8);
        for (let logical = selection.sampleOffset; logical < sampleEnd; logical += 1) {
          const frame = selection.start + Math.floor(logical / selection.channels.length);
          const channel = selection.channels[logical % selection.channels.length];
          bits.push((rawSampleAt(buffer, wav, frame, channel) >> bitIndex) & 1);
        }
        const bytes = [];
        for (let index = 0; index + 8 <= bits.length; index += 8) {
          let value = 0;
          if (bitOrder === 'lsb_first') {
            for (let offset = 0; offset < 8; offset += 1) value |= bits[index + offset] << offset;
          } else {
            for (let offset = 0; offset < 8; offset += 1) value = (value << 1) | bits[index + offset];
          }
          bytes.push(value);
        }
        const data = Buffer.from(bytes);
        const printable = data.toString('utf8').replace(/[^\x20-\x7e\u4e00-\u9fff]/gu, '.');
        return {
          status: 'ok', ...base, input_sha256: inputHash, bit_index: bitIndex, bits_read: bits.length, bytes: data.length,
          sample_offset: selection.sampleOffset, next_sample_offset: sampleEnd < totalSamples ? sampleEnd - (sampleEnd % 8) : null,
          padding_bits: bits.length % 8,
          total_samples: totalSamples, artifact_sha256: createHash('sha256').update(data).digest('hex'),
          hex: data.toString('hex'), text: truncate(printable, 4096),
          sha256: createHash('sha256').update(data).digest('hex'), __artifact_bytes: data,
        };
      }
      if (args.action === 'spectrum') {
        requireWritable(ctx, execution);
        const fftSize = args.fft_size ?? 2048;
        if (!Number.isInteger(fftSize) || fftSize < 256 || fftSize > 8192 || (fftSize & (fftSize - 1)) !== 0) {
          throw new ToolError('unsupported', 'fft_size 须为 256 至 8192 内的 2 的幂。');
        }
        if (selection.count === 0) throw new ToolError('unsupported', '所选 WAV 范围没有完整 PCM 帧。');
        const maxWindows = 192;
        const hopSize = Math.max(fftSize / 4, Math.ceil(Math.max(0, selection.count - fftSize) / (maxWindows - 1)));
        const windowCount = 1 + Math.ceil(Math.max(0, selection.count - fftSize) / hopSize);
        const coefficients = Float64Array.from({ length: fftSize }, (_, index) =>
          0.5 - 0.5 * Math.cos((2 * Math.PI * index) / (fftSize - 1)));
        const windows = [];
        for (let column = 0; column < windowCount; column += 1) {
          execution.signal?.throwIfAborted();
          const mono = new Float64Array(fftSize);
          const localStart = column * hopSize;
          for (let index = 0; index < fftSize && localStart + index < selection.count; index += 1) {
            let sum = 0;
            for (const channel of selection.channels) sum += sampleAt(buffer, wav, selection.start + localStart + index, channel);
            mono[index] = sum / selection.channels.length * coefficients[index];
          }
          windows.push(fftMagnitudes(mono));
          if (column % 8 === 7) await new Promise(resolve => setImmediate(resolve));
        }
        const fileOut = await access.output(location, args.path ?? ('spectrum-' + Date.now() + '.png'));
        const rendered = renderSpectrum(fileOut, windows, wav.fmt.sampleRate, fftSize, hopSize);
        return { status: 'ok', ...rendered, input_sha256: inputHash, sha256: createHash('sha256').update(readFileSync(fileOut)).digest('hex'),
          start_frame: selection.start, end_frame: selection.end, selected_channels: selection.channels,
          selected_duration_s: Number((selection.count / wav.fmt.sampleRate).toFixed(3)) };
      }
      throw new ToolError('unsupported', `未知操作：${args.action}。`);
    },
    ['file_path', 'action'],
  );

  if (access.extendedAudit !== false) {
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
          const result = await spawnCapture(command.bin, command.args, { cwd, signal: execution.signal, timeoutMs: 60000 });
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
  }

  register('crypto_solver',
    '检查 Python 密码库（check）、生成求解脚手架（template）或直接执行内置无依赖求解（solve：JWT/Flask Session/LCG/MT19937）。',
    {
      action: { type: 'string', enum: ['check', 'template', 'solve'] },
      kind: { type: 'string', enum: ['z3_bitvec', 'coppersmith', 'lattice', 'aes_mode'] },
      operation: { type: 'string', enum: CRYPTO_SOLVE_OPERATIONS },
      token: { type: 'string', maxLength: 32768 },
      salt: { type: 'string', maxLength: 256 },
      crack: { type: 'boolean' },
      passwords: { type: 'array', maxItems: 512, items: { type: 'string', maxLength: 256 } },
      wordlist: { type: 'string', maxLength: 1024 },
      outputs: { type: 'array', maxItems: 624, items: { anyOf: [{ type: 'string', maxLength: 512 }, { type: 'integer' }] } },
      modulus: { anyOf: [{ type: 'string', maxLength: 512 }, { type: 'integer' }] },
      predict_count: { type: 'integer', minimum: 1, maximum: 64 },
      timeout_ms: { type: 'integer', minimum: 1000, maximum: 120000 },
    },
    async (args, execution) => {
      if (args.action === 'solve') {
        const readWordlist = async rel => {
          const location = await access.location(execution);
          await access.input(location, rel);
          return (await access.read(location, rel, 16 * 1024 * 1024)).bytes.toString('utf8');
        };
        return runCryptoSolve(args, { readWordlist, signal: execution.signal });
      }
      if (args.action === 'check') {
        const python = await access.python(execution.signal);
        const probe = async imports => {
          const code = imports.map(name => `import ${name}`).join('; ');
          try {
            const result = await spawnCapture(python, ['-E', '-P', '-B', '-c', `${code}; print("ok")`], {
              timeoutMs: 8000, signal: execution.signal,
            });
            return { ok: /ok/u.test(result.stdout), exit_code: result.code };
          } catch (error) {
            return { ok: false, error: describeToolError(error).kind };
          }
        };
        const [z3, fpylll, crypto, sympy] = await Promise.all([
          probe(['z3']), probe(['fpylll']), probe(['Crypto']), probe(['sympy']),
        ]);
        const modules = { z3, fpylll, pycryptodome: crypto, sympy };
        const missing = Object.entries(modules).filter(([, state]) => !state.ok).map(([name]) => name);
        let sandboxFallback;
        if (missing.length > 0) {
          const sb = await detectSandbox(getConfig(), execution.signal);
          sandboxFallback = sb.available
            ? {
              available: true,
              backend: sb.backend,
              target: sb.image ?? sb.distro,
              missing_on_host: missing,
              hint: `宿主机 Python 缺少 ${missing.join('、')}；可直接改用 ctf_sandbox(action: "exec", script_path: "...") 在 ${sb.backend} 沙箱中运行求解脚本。`,
            }
            : {
              available: false,
              missing_on_host: missing,
              hint: `宿主机 Python 缺少 ${missing.join('、')} 且 Linux 沙箱不可用；可先在宿主机安装依赖或构建 dsh-ctf-sandbox:latest 镜像。`,
            };
        }
        return { status: 'ok', python, modules, ...(sandboxFallback ? { sandbox_fallback: sandboxFallback } : {}) };
      }
      if (args.action === 'template') {
        const kind = args.kind;
        if (typeof kind !== 'string' || !Object.hasOwn(TEMPLATES, kind)) throw new ToolError('unsupported', `未知模板：${kind}。`);
        requireWritable(ctx, execution);
        const location = await access.location(execution);
        const file = await access.output(location, '.ctf-templates/' + kind + '.py');
        writeFileSync(file, TEMPLATES[kind], { flag: 'wx' });
        return { status: 'ok', file, kind, preview: TEMPLATES[kind].split('\n').slice(0, 6).join('\n') };
      }
      throw new ToolError('unsupported', `未知操作：${args.action}。`);
    },
    ['action'],
  );
}
