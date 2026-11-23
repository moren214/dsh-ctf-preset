import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { label, MAX_ARCHIVE_MEMBER_BYTES, MAX_MEMBER_NAME, page } from './attachment-layout.js';
import { windowLength } from './byte-window.js';
import { WorkbenchDependencyError } from './workbench-config.js';

const SCRIPT = readFileSync(new URL('./archive-directory-worker.py', import.meta.url), 'utf8');
const RESPONSE_LIMIT = 256 * 1024;
const TIMEOUT_MS = 15000;
const SIGNATURES = [
  { format: '7z', variant: '7z', signature: Buffer.from('377abcaf271c', 'hex') },
  { format: 'RAR', variant: 'RAR4', signature: Buffer.from('526172211a0700', 'hex') },
  { format: 'RAR', variant: 'RAR5', signature: Buffer.from('526172211a070100', 'hex') },
];

export function nativeArchiveFormat(bytes) {
  return SIGNATURES.find(({ signature }) => signature.equals(bytes.subarray(0, signature.length)));
}

async function readArchive(bytes, [variant, offset, limit, memberIndex], signal, workbench) {
  let interpreter;
  let library;
  try {
    library = workbench.library();
    interpreter = await workbench.resolvePython(signal);
  } catch (error) {
    if (!(error instanceof WorkbenchDependencyError)) throw error;
    return { status: 'dependency_missing', reason: error.message + ' 可用 read_binary_range 查看归档字节。' };
  }
  signal?.throwIfAborted();
  const args = [variant, String(offset), String(limit), library];
  if (memberIndex !== undefined) args.push(String(memberIndex));
  const python = spawn(interpreter, ['-I', '-S', '-B', '-c', SCRIPT, ...args],
    { cwd: dirname(interpreter), shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'] });
  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    let finished = false;
    function finish(error, result) {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      if (error) {
        python.stdin.destroy();
        python.kill();
        reject(error);
      } else {
        resolve(result);
      }
    }
    const abort = () => finish(new Error('归档目录检查已取消。'));
    const timer = setTimeout(() => finish(new Error('归档目录检查响应超时。')), TIMEOUT_MS);
    signal?.addEventListener('abort', abort, { once: true });
    python.once('error', () => finish(new Error('无法启动本机归档读取器。')));
    python.stdin.on('error', error => {
      if (error.code !== 'EPIPE') finish(new Error('无法将原件内容送入归档读取器。'));
    });
    python.stdout.on('error', () => finish(new Error('无法读取本机归档目录。')));
    python.stdout.on('data', chunk => {
      length += chunk.length;
      if (length > RESPONSE_LIMIT) finish(new Error('本机归档读取器的响应过长。'));
      else chunks.push(chunk);
    });
    python.once('close', code => {
      if (finished) return;
      if (code !== 0) return finish(new Error('本机归档读取器异常退出。'));
      try {
        finish(undefined, JSON.parse(Buffer.concat(chunks, length).toString('utf8')));
      } catch {
        finish(new Error('本机归档读取器返回了无效响应。'));
      }
    });
    python.stdin.end(bytes);
  });
}

export async function inspectNativeArchive(bytes, { format, variant }, paging, signal, workbench) {
  const result = await readArchive(bytes, [variant, paging.offset, paging.limit], signal, workbench);
  const { rows, total, detail, ...header } = result;
  if (result.status !== 'ok') return { format, variant, ...header, ...(detail ? { detail: label(detail) } : {}) };
  if (!Array.isArray(rows) || !Number.isSafeInteger(total) || total < 0 || rows.length !== Math.min(paging.limit, Math.max(0, total - paging.offset))) {
    throw new Error('本机归档读取器返回了无效的分页数据。');
  }
  const displayed = rows.map((row, index) => ({
    member_index: paging.offset + index, ...row, name: row.name === null ? null : label(row.name, MAX_MEMBER_NAME),
  }));
  return { format, variant, ...header, layout: page('members', total, displayed, paging.offset) };
}

export async function readNativeArchiveMember(bytes, { format, variant }, memberIndex, window, signal, workbench) {
  const result = await readArchive(bytes, [variant, window.offset, window.length, memberIndex], signal, workbench);
  if (result.status === 'dependency_missing') return { format, variant, ...result };
  if (result.status !== 'ok') throw new Error(result.reason ?? '无法读取归档成员。');
  const { member_size: size, member_sha256: sha256, name, preview } = result;
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_ARCHIVE_MEMBER_BYTES || !/^[a-f0-9]{64}$/u.test(sha256)
    || typeof preview !== 'string') throw new Error('本机归档读取器返回了无效的成员数据。');
  const chunk = Buffer.from(preview, 'base64');
  if (chunk.length !== windowLength(size, window) || chunk.toString('base64') !== preview) {
    throw new Error('本机归档读取器返回了无效的成员片段。');
  }
  return { format, variant, name: typeof name === 'string' ? label(name, MAX_MEMBER_NAME) : null, size, sha256, chunk };
}
