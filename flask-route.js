import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decodeEvidenceText } from './evidence.js';
import { WorkbenchDependencyError } from './workbench-config.js';

export const MAX_FLASK_SOURCE_BYTES = 256 * 1024;
const MAX_RELATED_FILES = 7;
const WORKER = fileURLToPath(new URL('./flask-route-worker.py', import.meta.url));
const METHOD = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}$/u;
const PATH = /^\/[^\u0000-\u0020\u007f\\?#<>\p{Cs}]*$/u;
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/u;

export const FLASK_ROUTE_PROPERTIES = {
  source_root: { type: 'string', description: '相对于当前目录的 Flask 源码根目录。入口及模块路径相对于该目录。' },
  entry_file: { type: 'string', description: '源码根目录内声明 Flask 应用或工厂的 Python 文件。' },
  entrypoint: { type: 'string', default: 'app', description: '入口变量或工厂函数名，如 app 或 create_app。' },
  source_files: {
    type: 'array', maxItems: MAX_RELATED_FILES,
    items: { type: 'string' }, description: '与所选路由有关的本地 Python 模块路径，最多 7 个。',
  },
  request: {
    type: 'object', additionalProperties: false, required: ['method', 'path'],
    properties: {
      method: { type: 'string', maxLength: 32, description: '要定位的已知方法，如 GET。' },
      path: { type: 'string', maxLength: 2048, description: '已知请求的实际路径，如 /jobs/42，省略查询串。' },
    },
  },
};

async function runParser(input, signal, workbench) {
  const python = await workbench.resolvePython(signal);
  signal?.throwIfAborted();
  return new Promise((resolve, reject) => {
    const child = execFile(python, ['-I', '-S', '-B', '-X', 'utf8', WORKER], {
      cwd: dirname(python), signal, windowsHide: true, timeout: 10000, maxBuffer: 128 * 1024, encoding: 'utf8',
    }, (error, stdout) => {
      if (error) return reject(new Error(signal?.aborted ? 'Flask 源码核对已取消。' : '本机 Flask 源码读取器未返回有效结果。'));
      try {
        const parsed = JSON.parse(stdout);
        if (!['matched', 'not_found', 'ambiguous', 'incomplete'].includes(parsed.status)) throw new Error('invalid status');
        resolve(parsed);
      } catch {
        reject(new Error('本机 Flask 源码读取器返回了无效结果。'));
      }
    });
    child.stdin.on('error', () => {
      // execFile reports the failed worker through its completion callback.
    });
    child.stdin.end(JSON.stringify(input));
  });
}

export async function traceFlaskRoute(args, files, signal, workbench) {
  const request = args.request;
  if (!request || typeof request !== 'object' || Object.keys(request).some(key => !['method', 'path'].includes(key))
    || typeof request.method !== 'string' || !METHOD.test(request.method)
    || typeof request.path !== 'string' || request.path.length > 2048 || !PATH.test(request.path)) {
    throw new Error('请提供已知的 HTTP 方法和不带查询串的 / 路径。');
  }
  const entrypoint = args.entrypoint ?? 'app';
  if (typeof entrypoint !== 'string' || !IDENTIFIER.test(entrypoint)) throw new Error('entrypoint 须为 Flask 入口变量或工厂的简单名称。');
  const related = args.source_files ?? [];
  if (!Array.isArray(related) || related.length > MAX_RELATED_FILES) throw new Error('除入口文件外最多提供 7 个相关模块。');

  const sourceRoot = args.source_root === undefined || args.source_root === '.' ? undefined : files.normalizePath(args.source_root);
  const paths = [args.entry_file, ...related].map(files.normalizePath);
  if (paths.some(path => !path.endsWith('.py'))) throw new Error('请提供源码根目录内的 .py 文件。');
  const entries = [];
  const hashes = new Map();
  const keys = new Set();
  for (const module_path of paths) {
    signal?.throwIfAborted();
    const file_path = sourceRoot === undefined ? module_path : files.normalizePath(`${sourceRoot}/${module_path}`);
    const { bytes, targetKey } = await files.read(file_path);
    const key = targetKey ?? file_path;
    if (keys.has(key)) throw new Error('每个 Flask 源码文件只能引用一次。');
    keys.add(key);
    const source = decodeEvidenceText(bytes);
    entries.push({ file_path, module_path, source });
    hashes.set(file_path, createHash('sha256').update(bytes).digest('hex'));
  }

  let report;
  try {
    report = await runParser({ entrypoint, request, files: entries }, signal, workbench);
  } catch (error) {
    if (!(error instanceof WorkbenchDependencyError)) throw error;
    report = { status: 'incomplete', reason: `Flask 源码语法分析不可用。${error.message} 可用 read_ctf_files 查看源码。` };
  }
  const trace = report.trace;
  const locations = [trace?.route, trace?.handler?.definition, ...(trace?.mounts ?? []).map(item => item.registration),
    ...[...(trace?.hooks ?? []), ...(trace?.response_hooks ?? [])].map(item => item.registration), report.entry];
  const unrelated = new Set((report.unrelated_source_issues ?? []).map(issue => issue.source.file_path));
  const sources = [...hashes].filter(([file_path]) => !unrelated.has(file_path)).map(([file_path, sha256]) => ({
    file_path, sha256, line: locations.find(location => location?.file_path === file_path)?.line,
  }));
  return { ...report, request, source_root: sourceRoot, sources };
}
