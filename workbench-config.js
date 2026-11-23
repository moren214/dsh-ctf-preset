import { execFile } from 'node:child_process';
import { accessSync, constants, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, delimiter, dirname, isAbsolute, join } from 'node:path';

const WINDOWS = process.platform === 'win32';
const PROBE = 'import json, sys; print(json.dumps(sys.executable)) if sys.version_info >= (3, 11) else sys.exit(1)';
const AUTO_INSTALL_SETTINGS = new Set(['PYLAUNCHER_ALLOW_INSTALL', 'PYLAUNCHER_ALWAYS_INSTALL', 'PYTHON_MANAGER_AUTOMATIC_INSTALL']);

export class WorkbenchDependencyError extends Error {}

export const CONFIG_PATH_FIELDS = ['pythonPath', 'gdbPath', 'browserPath', 'base100Source', 'libarchivePath'];
export const CONFIG_TEXT_FIELDS = ['base100Sha256', 'platformUrl', 'platformTokenEnv', 'platformInstancesPath',
  'platformSubmitPath', 'platformLeaderboardPath', 'platformTeamId'];
export const CONFIG_LIST_FIELDS = ['networkOrigins', 'tcpTargets', 'attachmentImportRoots'];
const CONFIG_FIELDS = [...CONFIG_PATH_FIELDS, ...CONFIG_TEXT_FIELDS, ...CONFIG_LIST_FIELDS];

function configuredValues(source) {
  return Object.fromEntries(CONFIG_FIELDS.filter(key => source[key] !== undefined).map(key => [key, source[key]]));
}

function dshHome() {
  return isLocalWorkbenchPath(process.env.DSH_HOME) ? process.env.DSH_HOME : join(homedir(), '.dsh');
}

function readWorkbenchConfig(file = join(dshHome(), 'ctf-workbench.json')) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return {};
    throw new WorkbenchDependencyError('无法读取 DSH 用户目录中的 ctf-workbench.json。');
  }
  try {
    const value = JSON.parse(text.replace(/^\uFEFF/u, ''));
    if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  } catch {
    // Invalid settings affect only the tools that use them.
  }
  throw new WorkbenchDependencyError('DSH 用户目录中的 ctf-workbench.json 须是有效的 JSON 对象。');
}

export function isLocalWorkbenchPath(path) {
  return typeof path === 'string' && isAbsolute(path) && !/^[\\/]{2}|[\x00-\x1f]/u.test(path)
    && (!WINDOWS || /^[A-Za-z]:[\\/]/u.test(path));
}

function executable(path) {
  if (!isLocalWorkbenchPath(path) || (WINDOWS && (!/\.exe$/iu.test(path) || /[\\/]WindowsApps[\\/]/iu.test(path)))) return false;
  try {
    accessSync(path, constants.X_OK);
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function pythonCandidates(configured) {
  if (configured !== undefined) return [[configured, []]];
  const pathDirs = (process.env.PATH ?? '').split(delimiter).filter(isLocalWorkbenchPath);
  const names = WINDOWS
    ? [['py.exe', ['-3']], ['python3.exe', []], ['python.exe', []]]
    : [['python3', []], ['python', []]];
  const candidates = names.flatMap(([name, args]) => pathDirs.map(dir => [join(dir, name), args]));
  if (WINDOWS && isLocalWorkbenchPath(process.env.SystemRoot)) candidates.unshift([join(process.env.SystemRoot, 'py.exe'), ['-3']]);
  const bundled = join(dshHome(), 'dsh-runtimes', 'dsh-primary-runtime', 'dependencies', 'python', WINDOWS ? 'python.exe' : 'bin/python3');
  candidates.push([bundled, []]);
  return candidates;
}

function probePython(path, prefix, signal) {
  const env = WINDOWS
    ? { ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !AUTO_INSTALL_SETTINGS.has(key.toUpperCase()))),
      PYTHON_MANAGER_AUTOMATIC_INSTALL: 'false' }
    : process.env;
  return new Promise(resolve => {
    execFile(path, [...prefix, '-I', '-S', '-B', '-c', PROBE], {
      cwd: dirname(path), env, encoding: 'utf8', windowsHide: true, timeout: 3000, maxBuffer: 4096, signal,
    }, (error, stdout) => {
      if (error) return resolve(undefined);
      try {
        const python = JSON.parse(stdout);
        resolve(executable(python) ? python : undefined);
      } catch {
        resolve(undefined);
      }
    });
  });
}

export function createWorkbenchEnvironment(overrides = {}, configFile) {
  let config;
  let python;
  let configIssue;
  const settings = () => {
    if (config !== undefined) return config;
    let user = {};
    try { user = configuredValues(readWorkbenchConfig(configFile)); }
    catch (error) { configIssue = error.message; }
    config = { ...user, ...configuredValues(overrides) };
    return config;
  };
  return {
    presetConfig() {
      return { ...settings() };
    },
    configurationIssue() {
      settings();
      return configIssue;
    },
    async resolvePython(signal) {
      signal?.throwIfAborted();
      if (python !== undefined) return python;
      const configured = settings().pythonPath;
      const tried = new Set();
      for (const [path, args] of pythonCandidates(configured)) {
        const key = WINDOWS && typeof path === 'string' ? path.toLowerCase() : path;
        if (tried.has(key) || !executable(path)) continue;
        tried.add(key);
        const result = await probePython(path, args, signal);
        signal?.throwIfAborted();
        if (result !== undefined) {
          python = result;
          return python;
        }
      }
      const message = configured === undefined ? '没有探测到 Python 3.11 或更新版本。' : '配置的 pythonPath 无法运行 Python 3.11 或更新版本。';
      throw new WorkbenchDependencyError(message + ' 可在 DSH 用户目录的 ctf-workbench.json 指定 Python 可执行文件。');
    },
    base100() {
      const { base100Source: source, base100Sha256: sha256 } = settings();
      if (!isLocalWorkbenchPath(source) || basename(source) !== 'ctf_extra_ops.py'
        || typeof sha256 !== 'string' || !/^[0-9a-f]{64}$/iu.test(sha256)) {
        throw new WorkbenchDependencyError('Base100 工作台尚未配置。请填写 ctf-workbench.json 的 base100Source 和 base100Sha256。');
      }
      try {
        accessSync(source, constants.R_OK);
        if (!statSync(source).isFile()) throw new Error('not a file');
      } catch {
        throw new WorkbenchDependencyError('Base100 工作台源码不可读取。请检查 ctf-workbench.json 的 base100Source。');
      }
      return { source, sha256: sha256.toLowerCase() };
    },
    library() {
      const path = settings().libarchivePath;
      if (path !== undefined && !isLocalWorkbenchPath(path)) {
        throw new WorkbenchDependencyError('ctf-workbench.json 的 libarchivePath 须为本机归档库的绝对路径。');
      }
      return path ?? '';
    },
  };
}
