import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { MAX_ATTACHMENT_BYTES } from './attachment-layout.js';
import { WorkbenchDependencyError } from './workbench-config.js';

const SCRIPT = readFileSync(new URL('./compressed-stream-worker.py', import.meta.url), 'utf8');
const TIMEOUT_MS = 15000;
const BZIP2_SIGNATURE = Buffer.from('425a68', 'hex');
const XZ_SIGNATURE = Buffer.from('fd377a585a00', 'hex');

export function compressedStreamFormat(bytes) {
  if (bytes.length >= 4 && bytes.subarray(0, 3).equals(BZIP2_SIGNATURE) && bytes[3] >= 0x31 && bytes[3] <= 0x39) return 'bzip2';
  if (bytes.length >= XZ_SIGNATURE.length && bytes.subarray(0, XZ_SIGNATURE.length).equals(XZ_SIGNATURE)) return 'xz';
  return undefined;
}

export async function decompressCompressedStream(bytes, format, signal, workbench) {
  if (!['bzip2', 'xz'].includes(format)) return { status: 'unsupported', reason: '不支持的压缩格式。' };
  if (bytes.length > MAX_ATTACHMENT_BYTES) return { status: 'size', reason: '压缩附件原件超过 32 MiB。' };
  let interpreter;
  try {
    interpreter = await workbench.resolvePython(signal);
  } catch (error) {
    if (error instanceof WorkbenchDependencyError) {
      return { status: 'dependency_missing', reason: error.message + ' bzip2/xz 解压需要 Python 3.11 或更新版本。' };
    }
    throw error;
  }
  signal?.throwIfAborted();
  const python = spawn(interpreter, ['-I', '-S', '-B', '-c', SCRIPT, format], {
    cwd: dirname(interpreter), shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'],
  });
  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    let finished = false;
    const finish = (error, result) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      if (error) {
        python.stdin.destroy();
        python.kill();
        reject(error);
      } else resolve(result);
    };
    const abort = () => finish(signal?.reason ?? new Error('压缩附件读取已取消。'));
    const timer = setTimeout(() => {
      python.kill();
      finish(undefined, { status: 'timeout', reason: '压缩附件解压超过 15 秒。' });
    }, TIMEOUT_MS);
    signal?.addEventListener('abort', abort, { once: true });
    python.once('error', () => finish(undefined, { status: 'dependency_missing', reason: '无法启动本机 Python 解压器。' }));
    python.stdin.on('error', error => {
      if (error.code !== 'EPIPE') finish(undefined, { status: 'unsupported', reason: '无法将附件交给本机解压器。' });
    });
    python.stdout.on('data', chunk => {
      length += chunk.length;
      if (length > MAX_ATTACHMENT_BYTES) {
        python.kill();
        finish(undefined, { status: 'size', reason: '解压后的内容超过 32 MiB。' });
      } else chunks.push(chunk);
    });
    python.once('close', code => {
      if (finished) return;
      if (code === 0) return finish(undefined, { status: 'ok', bytes: Buffer.concat(chunks, length) });
      if (code === 2) return finish(undefined, { status: 'size', reason: '压缩附件或解压后的内容超过 32 MiB。' });
      if (code === 4) return finish(undefined, { status: 'dependency_missing', reason: '当前 Python 缺少 bz2 或 lzma 标准库模块。' });
      finish(undefined, { status: 'unsupported', reason: '压缩流无效、不完整或校验失败。' });
    });
    python.stdin.end(bytes);
  });
}
