import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const WORKER = fileURLToPath(new URL('rev-disasm-worker.py', import.meta.url));
const WORKER_TIMEOUT = 15_000;
const MAX_WORKER_OUTPUT = 4 * 1024 * 1024;
const MAX_FILE_SIZE = 64 * 1024 * 1024;
const DEFAULT_COUNT = 100;
const MIN_COUNT = 20;
const MAX_COUNT = 400;
const DEFAULT_MAX_BLOCKS = 64;
const MIN_MAX_BLOCKS = 1;
const MAX_MAX_BLOCKS = 256;
const DEFAULT_MAX_INSTRUCTIONS = 512;
const MIN_MAX_INSTRUCTIONS = 32;
const MAX_MAX_INSTRUCTIONS = 2048;
const DEFAULT_MIN_LENGTH = 6;
const MIN_MIN_LENGTH = 4;
const MAX_MIN_LENGTH = 64;

/**
 * rev_query 的结构化输入。外层 required 与工具注册保持一致，由 registerTool 补充。
 */
export const REV_QUERY_PROPERTIES = {
  operation: { type: 'string', enum: ['disassemble', 'cfg', 'strings', 'triage'], description: 'disassemble/cfg/strings/triage（triage 无需 capstone）。' },
  file_path: { type: 'string', description: '相对 ELF/PE 路径。' },
  symbol: { type: 'string' },
  address: { type: 'string' },
  count: { type: 'integer', minimum: MIN_COUNT, maximum: MAX_COUNT },
  max_blocks: { type: 'integer', minimum: MIN_MAX_BLOCKS, maximum: MAX_MAX_BLOCKS },
  max_instructions: { type: 'integer', minimum: MIN_MAX_INSTRUCTIONS, maximum: MAX_MAX_INSTRUCTIONS },
  min_length: { type: 'integer', minimum: MIN_MIN_LENGTH, maximum: MAX_MIN_LENGTH },
  section: { type: 'string' },
  python_path: { type: 'string' },
};

class WorkerUnavailableError extends Error {
  constructor(message) {
    super(message);
    this.name = 'WorkerUnavailableError';
  }
}

function requireText(value, label, maximum = 512) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`${label} 必须是非空字符串。`);
  }
  if (value.length > maximum) throw new Error(`${label} 过长。`);
  if (/[\0\r\n]/u.test(value)) throw new Error(`${label} 包含不允许的控制字符。`);
  return value;
}

function normalizeFilePath(value) {
  const raw = requireText(value, 'file_path', 1024).replaceAll('\\', '/');
  if (raw.startsWith('/') || /^[A-Za-z]:/u.test(raw)) {
    throw new Error('file_path 必须是相对会话工作目录的路径，不能是绝对路径。');
  }
  const parts = raw.split('/').filter((part) => part !== '' && part !== '.');
  if (parts.length === 0) throw new Error('file_path 不能为空。');
  if (parts.some((part) => part === '..')) {
    throw new Error('file_path 不能包含 ".."，不能越出会话工作目录。');
  }
  if (parts.some((part) => /[. ]$/u.test(part))) {
    throw new Error('file_path 的路径段不能以点或空格结尾。');
  }
  if (parts.some((part) => part.includes(':'))) {
    throw new Error('file_path 不能包含 ":"。');
  }
  return parts.join('/');
}

function optionalName(value, label, maximum) {
  if (value === undefined || value === null) return undefined;
  return requireText(value, label, maximum);
}

function normalizeAddress(value) {
  if (typeof value === 'bigint') {
    if (value < 0n || value > 0xffffffffffffffffn) {
      throw new Error('address 超出 64 位地址范围。');
    }
    return `0x${value.toString(16)}`;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error('address 必须是非负整数或 0x 开头的十六进制字符串。');
    }
    return `0x${value.toString(16)}`;
  }
  const text = requireText(value, 'address', 32).trim();
  if (!/^(?:0[xX][0-9a-fA-F]+|[0-9]+)$/u.test(text)) {
    throw new Error('address 必须是 0x 开头的十六进制数或十进制数。');
  }
  const parsed = BigInt(text);
  if (parsed > 0xffffffffffffffffn) throw new Error('address 超出 64 位地址范围。');
  return `0x${parsed.toString(16)}`;
}

function integerInRange(value, fallback, minimum, maximum, label) {
  if (value === undefined || value === null) return fallback;
  if (!Number.isInteger(value)) throw new Error(`${label} 必须是整数。`);
  if (value < minimum || value > maximum) {
    throw new Error(`${label} 必须在 ${minimum} 到 ${maximum} 之间。`);
  }
  return value;
}

function explicitPython(input, options) {
  const value = options.pythonPath ?? input.python_path;
  if (value === undefined || value === null) return undefined;
  const text = requireText(value, 'python_path', 1024).trim();
  if (!path.isAbsolute(text)) {
    throw new Error('python_path 必须是 Python 解释器的绝对路径。');
  }
  return text;
}

function pythonCandidates(pythonPath) {
  if (pythonPath !== undefined) return [{ command: pythonPath, prefix: [] }];
  if (process.platform === 'win32') {
    return [
      { command: 'py', prefix: ['-3'] },
      { command: 'python', prefix: [] },
      { command: 'python3', prefix: [] },
    ];
  }
  return [
    { command: 'python3', prefix: [] },
    { command: 'python', prefix: [] },
  ];
}

async function digestFile(absolutePath, display) {
  const hash = createHash('sha256');
  try {
    for await (const chunk of createReadStream(absolutePath)) hash.update(chunk);
  } catch {
    throw new Error(`无法读取文件 ${display}。`);
  }
  return hash.digest('hex');
}

function spawnWorker(candidate, request, options) {
  return new Promise((resolve, reject) => {
    const args = [
      ...candidate.prefix,
      '-E',
      '-P',
      '-X',
      'utf8',
      '-B',
      '-u',
      WORKER,
    ];
    let child;
    try {
      child = spawn(candidate.command, args, {
        cwd: path.dirname(WORKER),
        shell: false,
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch {
      reject(new WorkerUnavailableError(
        `无法启动 Python 解释器 ${candidate.command}。`,
      ));
      return;
    }

    let stdout = '';
    let settled = false;
    let timer;

    const cleanup = () => {
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', onAbort);
    };
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error) reject(error);
      else resolve(result);
    };
    const kill = () => {
      try {
        child.kill('SIGKILL');
      } catch {
        // 进程可能已经退出。
      }
    };
    const onAbort = () => {
      finish(new Error('反汇编查询已取消。'));
      kill();
    };

    if (options.signal?.aborted) {
      finish(new Error('反汇编查询已取消。'));
      kill();
      return;
    }
    options.signal?.addEventListener('abort', onAbort, { once: true });

    timer = setTimeout(() => {
      finish(new Error('反汇编工作台响应超时（15 秒），已终止 Python 进程。'));
      kill();
    }, WORKER_TIMEOUT);

    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      if (Buffer.byteLength(stdout, 'utf8') > MAX_WORKER_OUTPUT) {
        finish(new Error('反汇编工作台的输出超出限制。'));
        kill();
      }
    });
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', () => {
      // stderr 只用于诊断，不影响 JSON 协议；这里消费掉避免阻塞管道。
    });
    child.on('error', (error) => {
      if (error.code === 'ENOENT') {
        finish(new WorkerUnavailableError(
          `未找到 Python 解释器 ${candidate.command}。`,
        ));
        return;
      }
      finish(new Error(`无法启动 Python 反汇编工作台（${error.code ?? '未知错误'}）。`));
    });
    child.on('close', (code) => {
      if (settled) return;
      const lines = stdout.split(/\r?\n/u).filter((line) => line.trim() !== '');
      const line = lines.at(-1);
      if (line === undefined) {
        finish(new WorkerUnavailableError(
          code === 0
            ? '反汇编工作台没有返回任何结果。'
            : `反汇编工作台异常退出（代码 ${code}）。`,
        ));
        return;
      }
      let reply;
      try {
        reply = JSON.parse(line);
      } catch {
        finish(new Error('反汇编工作台返回了无法解析的响应。'));
        return;
      }
      if (reply === null || typeof reply !== 'object' || Array.isArray(reply)) {
        finish(new Error('反汇编工作台返回了无法解析的响应。'));
        return;
      }
      if (reply.ok !== true) {
        const message = typeof reply.error === 'string' && reply.error !== ''
          ? reply.error
          : '反汇编工作台报告了未知错误。';
        finish(new Error(message));
        return;
      }
      const { ok: _ok, ...report } = reply;
      finish(undefined, report);
    });
    child.stdin.on('error', () => {
      // 子进程提前退出时由 close 统一报错。
    });
    child.stdin.end(`${JSON.stringify(request)}\n`, 'utf8');
  });
}

async function runWorker(request, pythonPath, options) {
  const candidates = pythonCandidates(pythonPath);
  let lastError;
  for (const candidate of candidates) {
    try {
      return await spawnWorker(candidate, request, options);
    } catch (error) {
      if (!(error instanceof WorkerUnavailableError)) throw error;
      lastError = error;
      if (pythonPath !== undefined) break;
    }
  }
  if (pythonPath !== undefined) {
    throw new Error(`${lastError?.message ?? 'Python 解释器不可用。'}请检查 python_path。`);
  }
  throw new Error(
    `未找到可用的 Python 解释器（${lastError?.message ?? '均启动失败'}）。`
    + '请通过 python_path 指定本机 Python 3.11 或更高版本的绝对路径。',
  );
}

/**
 * 对工作区内的 ELF 文件执行反汇编或字符串扫描。
 *
 * @param {object} input
 * @param {{ pythonPath?: string, cwd?: string, signal?: AbortSignal }} [options]
 * @returns {Promise<object>} 可直接并入工具报告的对象
 */
export async function runRevQuery(input, options = {}) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('rev_query 参数必须是 JSON 对象。');
  }
  if (options === null || typeof options !== 'object') options = {};
  const operation = input.operation;
  if (operation !== 'disassemble' && operation !== 'cfg' && operation !== 'strings' && operation !== 'triage') {
    throw new Error('operation 必须是 disassemble、cfg、strings 或 triage。');
  }

  const file = normalizeFilePath(input.file_path);
  const cwd = options.cwd === undefined ? process.cwd() : path.resolve(String(options.cwd));
  const absolute = path.resolve(cwd, file);
  const relative = path.relative(cwd, absolute);
  if (relative === '' || relative === '..'
    || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error('file_path 不能越出会话工作目录。');
  }

  let info;
  try {
    info = await stat(absolute);
  } catch {
    throw new Error(`无法读取文件 ${file}。`);
  }
  if (!info.isFile()) throw new Error(`${file} 不是普通文件。`);
  if (info.size > MAX_FILE_SIZE) {
    throw new Error(`${file} 超过 64 MiB，反汇编查询最多处理 64 MiB。`);
  }

  const request = { file: absolute, operation };
  const symbol = optionalName(input.symbol, 'symbol', 256);
  const address = input.address === undefined || input.address === null
    ? undefined
    : normalizeAddress(input.address);
  const section = optionalName(input.section, 'section', 128);
  if (operation === 'disassemble') {
    if (address !== undefined && symbol !== undefined) {
      throw new Error('address 与 symbol 不能同时指定。');
    }
    if (symbol !== undefined) request.symbol = symbol;
    if (address !== undefined) request.address = address;
    if (section !== undefined) request.section = section;
    request.count = integerInRange(
      input.count, DEFAULT_COUNT, MIN_COUNT, MAX_COUNT, 'count',
    );
  } else if (operation === 'cfg') {
    if (address !== undefined && symbol !== undefined) {
      throw new Error('cfg 的 address 与 symbol 不能同时指定。');
    }
    if (address === undefined && symbol === undefined) {
      throw new Error('cfg 必须指定 symbol 或 address。');
    }
    if (section !== undefined) {
      throw new Error('cfg 不接受 section；请指定函数 symbol 或 address。');
    }
    if (symbol !== undefined) request.symbol = symbol;
    if (address !== undefined) request.address = address;
    request.max_blocks = integerInRange(
      input.max_blocks, DEFAULT_MAX_BLOCKS, MIN_MAX_BLOCKS, MAX_MAX_BLOCKS, 'max_blocks',
    );
    request.max_instructions = integerInRange(
      input.max_instructions, DEFAULT_MAX_INSTRUCTIONS,
      MIN_MAX_INSTRUCTIONS, MAX_MAX_INSTRUCTIONS, 'max_instructions',
    );
  } else if (operation === 'strings') {
    if (symbol !== undefined || address !== undefined) {
      throw new Error('strings 查询不接受 symbol 或 address。');
    }
    if (section !== undefined) request.section = section;
    request.min_length = integerInRange(
      input.min_length, DEFAULT_MIN_LENGTH, MIN_MIN_LENGTH, MAX_MIN_LENGTH, 'min_length',
    );
  } else {
    if (symbol !== undefined || address !== undefined || section !== undefined) {
      throw new Error('triage 查询不接受 symbol、address 或 section。');
    }
  }

  const pythonPath = explicitPython(input, options);
  const report = await runWorker(request, pythonPath, {
    signal: options.signal,
  });
  return {
    file,
    size: info.size,
    sha256: await digestFile(absolute, file),
    ...report,
  };
}
