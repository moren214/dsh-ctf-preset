import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { createInterface } from 'node:readline';
import { createWorkbenchEnvironment } from './workbench-config.js';

const MAX_ITEMS = 8;
const MAX_INPUT_CHARACTERS = 8192;
const MAX_LINE_BYTES = 512 * 1024;
const REQUEST_MS = 10000;
const IDLE_MS = 60000;
const OPERATIONS = ['encode', 'decode'];
const ENCODINGS = ['utf8', 'hex'];
const SCRIPT = readFileSync(new URL('./workbench-base100-worker.py', import.meta.url), 'utf8');
const ITEM_PROPERTIES = {
  operation: { type: 'string', enum: OPERATIONS },
  input: { type: 'string', maxLength: MAX_INPUT_CHARACTERS, description: '待编码的 UTF-8 或 Hex，或待解码的 Base100 字符串。' },
  input_encoding: { type: 'string', enum: ENCODINGS, description: '仅编码时可指定，默认为 utf8。' },
};

export const WORKBENCH_BASE100_PROPERTIES = {
  items: {
    type: 'array', minItems: 1, maxItems: MAX_ITEMS,
    items: {
      type: 'object', additionalProperties: false, required: ['operation', 'input'],
      properties: ITEM_PROPERTIES,
    },
  },
};

function batch(items) {
  if (!Array.isArray(items) || items.length < 1 || items.length > MAX_ITEMS) {
    throw new Error('请给出 1 至 8 项 Base100 操作。');
  }
  const keys = Object.keys(ITEM_PROPERTIES);
  return items.map(item => {
    if (!item || typeof item !== 'object' || Array.isArray(item) || !Object.keys(item).every(key => keys.includes(key))
      || !OPERATIONS.includes(item.operation) || typeof item.input !== 'string'
      || item.input.length > 2 * MAX_INPUT_CHARACTERS || [...item.input].length > MAX_INPUT_CHARACTERS
      || /\p{Cs}/u.test(item.input)) {
      throw new Error('Base100 仅接受编码或解码操作和不超过 8192 字符的有效文本。');
    }
    if (item.input_encoding !== undefined
      && (item.operation !== 'encode' || !ENCODINGS.includes(item.input_encoding))) {
      throw new Error('仅编码时可指定 utf8 或 hex 输入。');
    }
    return { operation: item.operation, input: item.input, input_encoding: item.input_encoding };
  });
}

export class Base100Workbench {
  #worker;
  #tail = Promise.resolve();
  #disposed = false;
  #environment;

  constructor(environment = createWorkbenchEnvironment()) {
    this.#environment = environment;
  }

  run(items, signal) {
    const operations = batch(items);
    const request = this.#tail.then(() => this.#exchange(operations, signal));
    this.#tail = request.catch(() => {});
    return request;
  }

  dispose() {
    this.#disposed = true;
    if (this.#worker) this.#stop(this.#worker, new Error('CTF 插件已关闭。'));
  }

  async #start(signal) {
    const { source, sha256 } = this.#environment.base100();
    const python = await this.#environment.resolvePython(signal);
    signal?.throwIfAborted();
    if (this.#disposed) throw new Error('CTF 插件已关闭。');
    const child = spawn(python, ['-I', '-B', '-u', '-c', SCRIPT, source, sha256], {
      cwd: dirname(python), shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'],
    });
    const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
    const worker = { child, lines, pending: undefined, idle: undefined };
    this.#worker = worker;

    const connectionLost = () => this.#stop(worker, new Error('Base100 工作台进程已退出。请检查本机 Python 和工作台源码路径。'));
    child.on('error', connectionLost);
    child.once('exit', connectionLost);
    child.stdin.on('error', connectionLost);
    child.stdout.on('error', connectionLost);
    lines.on('line', line => {
      if (worker !== this.#worker) return;
      let reply;
      try {
        if (line.length > MAX_LINE_BYTES) throw new Error('超长响应');
        reply = JSON.parse(line);
      } catch {
        this.#stop(worker, new Error('Base100 工作台返回了无法读取的响应。'));
        return;
      }
      if (typeof reply?.startup_error === 'string') {
        this.#stop(worker, new Error(reply.startup_error));
        return;
      }
      const pending = worker.pending;
      if (!pending || !Array.isArray(reply?.results) || reply.results.length !== pending.length
        || !reply.results.every(item => item?.status === 'ok' || item?.status === 'error')
        || !Number.isFinite(reply.workbench_ms)) {
        this.#stop(worker, new Error('Base100 工作台的返回格式与请求不匹配。'));
        return;
      }
      pending.finish(undefined, reply);
    });
    return worker;
  }

  #stop(worker, error = new Error('Base100 工作台已关闭。')) {
    if (worker !== this.#worker) return;
    this.#worker = undefined;
    clearTimeout(worker.idle);
    worker.pending?.finish(error);
    worker.lines.close();
    worker.child.stdin.destroy();
    worker.child.kill();
  }

  async #exchange(operations, signal) {
    signal?.throwIfAborted();
    if (this.#disposed) throw new Error('CTF 插件已关闭。');
    const started = performance.now();
    const reused = this.#worker !== undefined;
    let worker;
    try {
      worker = this.#worker ?? await this.#start(signal);
    } catch (error) {
      if (signal?.aborted) throw new Error('Base100 调用已取消。');
      throw error;
    }
    if (signal?.aborted) {
      const error = new Error('Base100 调用已取消。');
      this.#stop(worker, error);
      throw error;
    }
    clearTimeout(worker.idle);

    return new Promise((resolve, reject) => {
      const abort = () => this.#stop(worker, new Error('Base100 调用已取消。'));
      const timer = setTimeout(() => this.#stop(worker, new Error('本地 Base100 工作台响应超时。')), REQUEST_MS);
      timer.unref();
      worker.pending = {
        length: operations.length,
        finish: (error, reply) => {
          clearTimeout(timer);
          signal?.removeEventListener('abort', abort);
          worker.pending = undefined;
          if (error) {
            reject(error);
            return;
          }
          worker.idle = setTimeout(() => this.#stop(worker), IDLE_MS);
          worker.idle.unref();
          resolve({
            status: reply.results.every(item => item.status === 'ok') ? 'ok' : 'incomplete',
            worker_reused: reused,
            elapsed_ms: Number((performance.now() - started).toFixed(3)),
            ...reply,
          });
        },
      };
      signal?.addEventListener('abort', abort, { once: true });
      try {
        worker.child.stdin.write(JSON.stringify({ items: operations }) + '\n');
      } catch {
        this.#stop(worker, new Error('无法发送 Base100 请求。'));
      }
    });
  }
}
