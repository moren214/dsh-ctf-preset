// CTF preset 的扩展工具：浏览器会话、gdb 调试、压缩包口令、音频隐写、APK 检查、
// 云元数据探测、密码学模板。能力实现已下沉至 core/capabilities/*，执行由统一 executor 托管。
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { statSync } from 'node:fs';
import { stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { BROWSER_TIMEOUT_MS, createBrowserSession } from './browser-session.js';
import { CRYPTO_TEMPLATES } from './core/capabilities/crypto-templates.js';
import {
  isElfBinary,
  quoteGdbArg,
  quoteGdbInputPath,
  sandboxRelativePath,
  validatedGdbArgs,
  validatedGdbCommands,
} from './core/capabilities/gdb-driver.js';
import {
  buildSandboxApkDecompileScript,
  buildSandboxApkSignatureScript,
  defaultApkOutDir,
  inspectApkInfo,
} from './core/capabilities/mobile-apk.js';
import { runStegoAudio } from './core/capabilities/stego-audio.js';
import { crackZip, parseZipEntries } from './core/capabilities/zip-crack.js';
import { createGdbSessionManager } from './core/sandbox/gdb-session.js';
import { buildDockerArgs, detectSandbox, resolveExecutionPlan, runSandboxCommand } from './sandbox-runner.js';
import { CRYPTO_SOLVE_OPERATIONS, runCryptoSolve } from './crypto-toolbox.js';
import { describeToolError, ToolError } from './tool-errors.js';
import { isLocalWorkbenchPath } from './workbench-config.js';

export { quoteGdbInputPath };

const MAX_INPUT_BYTES = 256 * 1024 * 1024;
const MAX_TEXT_OUTPUT = 64 * 1024;
const SOURCE_RESULT_SCHEMA = {
  type: 'string',
  pattern: '^[a-f0-9]{64}$',
  description: '可选：引用先前工具结果返回的 result_id（从持久化 Artifact 零拷贝物化输入）。',
};

function childEnvironment() {
  const keys = new Set(['path', 'systemroot', 'systemdrive', 'windir', 'temp', 'tmp', 'home', 'userprofile',
    'programfiles', 'programfiles(x86)', 'localappdata', 'appdata', 'comspec', 'pathext', 'lang', 'lc_all', 'java_home']);
  return Object.fromEntries(Object.entries(process.env).filter(([key]) => keys.has(key.toLowerCase())));
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
      reject(signal.reason ?? new ToolError('abort', '子进程已取消。'));
      return;
    }
    let child;
    try {
      child = spawn(command, args, {
        cwd,
        env,
        windowsHide: true,
        ...(killTree && process.platform !== 'win32' ? { detached: true } : {}),
        ...(!killTree && signal ? { signal } : {}),
        stdio: ['ignore', 'pipe', 'pipe'],
      });
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
          } catch { /* ignore */ }
        } else {
          try { process.kill(-child.pid, 'SIGKILL'); } catch { /* ignore */ }
        }
      }
      try { child.kill(); } catch { /* ignore */ }
    };
    const abort = () => {
      abortReason = signal?.reason ?? new ToolError('abort', '子进程已取消。');
      terminate();
    };
    if (killTree && signal) signal.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(() => {
      timedOut = true;
      terminate();
    }, timeoutMs);
    const append = (chunk, target) => (target.length >= maxBytes ? target : target + chunk.toString('utf8').slice(0, maxBytes - target.length));
    child.stdout?.on('data', chunk => { stdout = append(chunk, stdout); });
    child.stderr?.on('data', chunk => { stderr = append(chunk, stderr); });
    child.on('error', error => {
      clearTimeout(timer);
      if (killTree && signal) signal.removeEventListener('abort', abort);
      if (!settled) {
        settled = true;
        reject(error);
      }
    });
    child.on('close', code => {
      clearTimeout(timer);
      if (killTree && signal) signal.removeEventListener('abort', abort);
      if (!settled) {
        settled = true;
        if (abortReason) reject(abortReason);
        else resolve({ code: code ?? -1, timedOut, stdout, stderr });
      }
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

function findJavaTool(names) {
  const envRoots = [process.env.ANDROID_HOME, process.env.ANDROID_SDK_ROOT, process.env.JAVA_HOME].filter(Boolean);
  const roots = [
    ...envRoots.map(root => path.join(root, 'bin')),
    ...envRoots.map(root => path.join(root, 'build-tools')),
  ];
  for (const name of names) {
    const hit = findOnPath(name);
    if (hit && isLocalWorkbenchPath(hit)) return { name, path: hit };
    for (const root of roots) {
      const direct = path.join(root, name);
      try {
        if (statSync(direct).isFile() && isLocalWorkbenchPath(direct)) return { name, path: direct };
      } catch { /* ignore */ }
    }
  }
  return undefined;
}

function browserCandidates() {
  if (process.platform === 'win32') {
    const bases = [process.env.PROGRAMFILES, process.env['PROGRAMFILES(X86)'], process.env.LOCALAPPDATA].filter(Boolean);
    return [
      process.env.CHROME_PATH,
      ...bases.flatMap(base => [
        path.join(base, 'Google', 'Chrome', 'Application', 'chrome.exe'),
        path.join(base, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      ]),
    ].filter(Boolean);
  }
  return [
    process.env.CHROME_PATH,
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  ].filter(Boolean);
}

export function detectBrowser(config) {
  return firstLocalFile(config?.browserPath ? [config.browserPath] : browserCandidates());
}

export function detectGdb(config) {
  const configured = config?.gdbPath || process.env.GDB;
  return configured ? firstLocalFile([configured]) : findOnPathAsync('gdb');
}

export function registerExtraTools(_compat, configSource, access) {
  const getConfig = typeof configSource === 'function' ? configSource : () => configSource ?? {};
  const requireWritable = execution => access.requireWritable?.(execution);
  const gdbSessions = access.gdbSessions ?? createGdbSessionManager();
  access.onDispose?.(() => gdbSessions.disposeAll?.());

  const register = (toolName, description, properties, run, required = ['file_path'], { workspace = true } = {}) => {
    if (typeof access.register !== 'function') {
      throw new ToolError('unsupported', '缺少工具注册回调 access.register。');
    }
    const schemaProps = required.includes('file_path') && !Object.hasOwn(properties, 'file_path')
      ? { file_path: { type: 'string', description: '本题工作区内的相对附件路径。' }, ...properties }
      : properties;
    access.register(toolName, description, schemaProps, (args, execution, location) => run(args, execution, location), required, workspace);
  };

  const browsers = access.browserSessions ?? new WeakMap();
  const activeBrowsers = access.browsers ?? new Set();
  access.onDispose?.(() => Promise.allSettled([...activeBrowsers].map(browser => browser.close())));
  function getBrowser(session, key, execution, location) {
    let byWorkspace = browsers.get(session);
    if (byWorkspace === undefined) {
      byWorkspace = new Map();
      browsers.set(session, byWorkspace);
    }
    let browser = byWorkspace.get(key);
    if (browser === undefined) {
      browser = createBrowserSession({
        resolveBinary: () => detectBrowser(getConfig()),
        authorize: (url, signal) => access.authorize(url, signal, execution, location),
        environment: childEnvironment,
        allowInsecureTls: () => getConfig()?.allowInsecureBrowserTls === true,
        inContainer: getConfig()?.browserInContainer === true,
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
    '隔离 Chrome/Edge 会话：open/dom/screenshot/cookies/storage/network/console/dialogs 及可写交互（click/fill/select/press/wait_for/evaluate/set_cookie/set_headers/upload_file）。',
    {
      action: { type: 'string', enum: ['open', 'dom', 'screenshot', 'cookies', 'title', 'close', 'status', 'list', 'click', 'fill', 'select', 'press', 'wait_for', 'storage', 'network', 'console', 'dialogs', 'evaluate', 'set_cookie', 'set_headers', 'upload_file'] },
      url: { type: 'string' },
      selector: { type: 'string', maxLength: 1024 },
      value: { type: 'string', maxLength: 16384 },
      expression: { type: 'string', maxLength: 4096, description: 'evaluate 执行的页面 JS 表达式。' },
      name: { type: 'string', maxLength: 256, description: 'set_cookie 的 Cookie 名称。' },
      http_only: { type: 'boolean' },
      secure: { type: 'boolean' },
      same_site: { type: 'string', enum: ['Strict', 'Lax', 'None'] },
      headers: { type: 'object', maxProperties: 16, additionalProperties: { type: 'string', maxLength: 2048 }, description: 'set_headers 附加请求头。' },
      file_path: { type: 'string', maxLength: 1024, description: 'upload_file 工作区内待上传文件相对路径。' },
      key: { type: 'string', enum: ['Enter', 'Tab', 'Escape', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Space', 'Backspace', 'Delete'] },
      storage_type: { type: 'string', enum: ['local', 'session'] },
      include_values: { type: 'boolean', default: true },
      request_id: { type: 'string', maxLength: 256, description: 'network 读指定请求响应体。' },
      clear_logs: { type: 'boolean', default: false },
      wait_ms: { type: 'integer', minimum: 250, maximum: 30000 },
      path: { type: 'string' },
      timeout_ms: { type: 'integer', minimum: 1000, maximum: 60000 },
    },
    async (args, execution, resolvedLocation) => {
      const location = resolvedLocation ?? await access.location(execution);
      const action = args.action;
      if (['click', 'fill', 'select', 'press', 'evaluate', 'set_cookie', 'set_headers', 'upload_file'].includes(action)) {
        requireWritable(execution);
      }
      if (args.selector !== undefined && (typeof args.selector !== 'string' || args.selector.length === 0 || args.selector.length > 1024)) {
        throw new ToolError('unsupported', 'selector 须为不超过 1024 字符的 CSS 选择器。');
      }
      if (['click', 'fill', 'select', 'press', 'wait_for', 'upload_file'].includes(action)
        && (typeof args.selector !== 'string' || args.selector.length === 0)) {
        throw new ToolError('unsupported', `${action} 需要非空 CSS selector。`);
      }
      if (args.value !== undefined && (typeof args.value !== 'string' || args.value.length > 16384)) {
        throw new ToolError('unsupported', 'value 须为不超过 16384 字符的字符串。');
      }
      if (['fill', 'select'].includes(action) && typeof args.value !== 'string') {
        throw new ToolError('unsupported', `${action} 需要字符串 value。`);
      }
      if (action === 'press' && typeof args.key !== 'string') {
        throw new ToolError('unsupported', 'press 需要指定按键 key。');
      }
      const waitMs = args.wait_ms ?? 5000;
      if (!Number.isSafeInteger(waitMs) || waitMs < 250 || waitMs > 30000) {
        throw new ToolError('unsupported', 'wait_ms 须在 250 至 30000 内。');
      }
      const storageType = args.storage_type ?? 'local';
      if (args.storage_type !== undefined && !['local', 'session'].includes(storageType)) {
        throw new ToolError('unsupported', 'storage_type 须为 local 或 session。');
      }
      if (args.include_values !== undefined && typeof args.include_values !== 'boolean') {
        throw new ToolError('unsupported', 'include_values 必须是布尔值。');
      }
      if (args.clear_logs !== undefined && typeof args.clear_logs !== 'boolean') {
        throw new ToolError('unsupported', 'clear_logs 必须是布尔值。');
      }
      if (action === 'evaluate' && (typeof args.expression !== 'string' || args.expression.trim().length === 0 || args.expression.length > 4096)) {
        throw new ToolError('unsupported', 'evaluate 需要非空且不超过 4096 字符的 expression。');
      }
      if (action === 'set_cookie') {
        if (typeof args.url !== 'string' || args.url.length === 0) throw new ToolError('unsupported', 'set_cookie 需要 url。');
        if (typeof args.name !== 'string' || args.name.trim().length === 0 || args.name.length > 256 || /[=;\r\n]/u.test(args.name)) {
          throw new ToolError('unsupported', 'set_cookie 的 name 不合法。');
        }
        if (typeof args.value !== 'string' || /[\r\n]/u.test(args.value)) {
          throw new ToolError('unsupported', 'set_cookie 的 value 不合法。');
        }
      }
      if (action === 'set_headers') {
        if (!args.headers || typeof args.headers !== 'object' || Array.isArray(args.headers)) {
          throw new ToolError('unsupported', 'set_headers 需要 headers 对象。');
        }
        for (const [k, v] of Object.entries(args.headers)) {
          if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u.test(k)) {
            throw new ToolError('unsupported', `header ${k} 名称不合法。`);
          }
          if (typeof v !== 'string' || v.length > 2048 || /[\r\n\0]/u.test(v)) {
            throw new ToolError('unsupported', `header ${k} 含非法控制字符或超长。`);
          }
        }
      }
      if (action === 'upload_file' && (typeof args.file_path !== 'string' || args.file_path.length === 0)) {
        throw new ToolError('unsupported', 'upload_file 需要工作区内 file_path。');
      }
      if (args.request_id !== undefined && (typeof args.request_id !== 'string' || args.request_id.length === 0 || args.request_id.length > 256)) {
        throw new ToolError('unsupported', 'request_id 须为非空字符串。');
      }
      const browser = getBrowser(execution.agent.session, location.directoryKey, execution, location);
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
          if (args.url !== 'about:blank') await access.authorize(args.url, signal, execution, location);
          const target = await browser.ensure(signal);
          return { status: 'opened', ...await browser.navigate(target, args.url, signal) };
        }
        if (action === 'screenshot') requireWritable(execution);
        if (action === 'cookies' && args.url !== undefined) await access.authorize(args.url, signal, execution, location);
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
          return {
            status: 'cookies',
            include_values: includeValues,
            cookies: cookies.map(cookie => ({
              name: cookie.name,
              ...(includeValues ? {
                value: hide(String(cookie.value ?? '').slice(0, 4096)),
                ...(String(cookie.value ?? '').length > 4096 ? { value_truncated: true } : {}),
              } : {}),
              domain: cookie.domain,
              path: cookie.path,
              secure: cookie.secure,
              httpOnly: cookie.httpOnly,
              ...(cookie.sameSite ? { sameSite: cookie.sameSite } : {}),
              ...(typeof cookie.expires === 'number' && cookie.expires > 0 ? { expires: cookie.expires } : {}),
            })),
          };
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
        if (action === 'dialogs') {
          const entries = browser.dialogs(target, args.clear_logs === true);
          return { status: 'dialogs', count: entries.length, entries };
        }
        if (action === 'evaluate') return { ...(await browser.evaluateUser(target, args.expression, signal)) };
        if (action === 'set_cookie') {
          await access.authorize(args.url, signal, execution, location);
          const cookie = {
            name: args.name.trim(),
            value: args.value,
            url: args.url,
            ...(args.http_only !== undefined ? { httpOnly: args.http_only } : {}),
            ...(args.secure !== undefined ? { secure: args.secure } : {}),
            ...(args.same_site !== undefined ? { sameSite: args.same_site } : {}),
          };
          const res = await browser.setCookie(target, cookie, signal);
          return { status: res.success ? 'cookie_set' : 'failed', name: cookie.name, url: args.url };
        }
        if (action === 'set_headers') {
          const res = await browser.setExtraHeaders(target, args.headers, signal);
          return { status: 'headers_set', ...res };
        }
        if (action === 'upload_file') {
          const absFile = await access.input(location, args.file_path);
          const res = await browser.uploadFile(target, args.selector, absFile, signal);
          if (res.status === 'match_count') throw new ToolError('missing', `CSS selector 匹配 ${res.count} 个元素，upload_file 要求恰好一个。`);
          return { ...res, selector: args.selector, file_path: args.file_path };
        }
        if (action === 'list') return { status: 'targets', targets: await browser.list(target, signal) };
        throw new ToolError('unsupported', `未知操作：${action}。`);
      });
    },
    ['action'],
    { workspace: false },
  );

  register('gdb_driver',
    '用 GDB 检查或调试工作区二进制（支持持久化交互会话 session_start/session_cmd/session_close 及 Docker/WSL2 Linux GDB）；严格只读白名单。',
    {
      action: { type: 'string', enum: ['inspect', 'debug', 'session_start', 'session_cmd', 'session_close'] },
      file_path: { type: 'string', description: '工作区内目标二进制相对路径（inspect/debug/session_start 必填）。' },
      source_result_id: SOURCE_RESULT_SCHEMA,
      kind: { type: 'string', enum: ['files', 'sections'] },
      commands: { type: 'array', minItems: 1, maxItems: 24, items: { type: 'string', maxLength: 256 }, description: 'GDB 白名单命令列表。' },
      args: { type: 'array', maxItems: 16, items: { type: 'string', maxLength: 256 }, description: '程序命令行参数。' },
      stdin_file: { type: 'string', maxLength: 1024 },
      session_id: { type: 'string', maxLength: 64, description: 'session_cmd/session_close 的会话标识。' },
      timeout_ms: { type: 'integer', minimum: 1000, maximum: 120000 },
    },
    async (args, execution, resolvedLocation) => {
      const action = args.action;
      if (action === 'session_close') {
        if (typeof args.session_id !== 'string' || !args.session_id.trim()) {
          throw new ToolError('unsupported', 'session_close 需要 session_id。');
        }
        return gdbSessions.close(args.session_id.trim());
      }
      if (action === 'session_cmd') {
        requireWritable(execution);
        if (typeof args.session_id !== 'string' || !args.session_id.trim()) {
          throw new ToolError('unsupported', 'session_cmd 需要 session_id。');
        }
        const timeoutMs = args.timeout_ms ?? 20000;
        return gdbSessions.execCommands(args.session_id.trim(), args.commands, { timeoutMs, signal: execution.signal });
      }

      if (typeof args.file_path !== 'string' || !args.file_path.trim()) {
        throw new ToolError('unsupported', `${action} 需要提供工作区内的 file_path 或 source_result_id。`);
      }
      if (action === 'inspect' && !['files', 'sections'].includes(args.kind ?? 'files')) {
        throw new ToolError('unsupported', 'inspect 的 kind 须为 files 或 sections。');
      }
      if (action === 'debug' || action === 'session_start') requireWritable(execution);

      const location = resolvedLocation ?? await access.location(execution);
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
      const targetBinary = sandboxActive ? sandboxRelativePath(location.cwd, binary) : binary;

      if (action === 'session_start') {
        const baseFlags = ['-q', '-nx', '-nh', '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off', `--se=${targetBinary}`];
        if (sandboxActive && useSandbox.backend === 'docker') {
          const dockerBin = useSandbox.dockerBin ?? 'docker';
          const dockerArgs = buildDockerArgs(
            ['bash', '-c', 'GDB_BIN="$(command -v gdb-multiarch || command -v gdb || true)"; [ -n "$GDB_BIN" ] || exit 127; exec "$GDB_BIN" "$@"', '_', ...baseFlags],
            { cwd: location.cwd, targetImage: useSandbox.image, ptrace: true, readOnlyWork: false },
          ).filter(arg => arg !== '--rm');
          const interactiveArgs = ['run', '--rm', '-i', ...dockerArgs.slice(2)];
          return gdbSessions.start({
            command: dockerBin,
            args: interactiveArgs,
            cwd: location.cwd,
            binary: args.file_path,
            timeoutMs,
            signal: execution.signal,
          });
        }
        return gdbSessions.start({
          command: gdb,
          args: baseFlags,
          cwd: location.cwd,
          binary: args.file_path,
          timeoutMs,
          signal: execution.signal,
        });
      }

      const runGdb = (commandArgs, { ptrace = false, killTree = false } = {}) => sandboxActive
        ? runSandboxCommand(['bash', '-c', 'GDB_BIN="$(command -v gdb-multiarch || command -v gdb || true)"; [ -n "$GDB_BIN" ] || exit 127; exec "$GDB_BIN" "$@"', '_', ...commandArgs], {
          cwd: location.cwd, config, signal: execution.signal, timeoutMs, ptrace, requiresIsolation: true, detected: useSandbox,
        })
        : spawnCapture(gdb, commandArgs, {
          cwd: location.cwd, timeoutMs, maxBytes: MAX_TEXT_OUTPUT / 2, signal: execution.signal, killTree,
        });

      if (action === 'inspect') {
        const command = args.kind === 'sections' ? 'maintenance info sections' : 'info files';
        const result = await runGdb(['-q', '-batch', '-nx', '-nh', '-iex', 'set auto-load off',
          '-iex', 'set debuginfod enabled off', '--se=' + targetBinary, '-ex', command]);
        return {
          action: 'inspect',
          status: result.timedOut ? 'timeout' : result.code === 0 ? 'ok' : 'failed',
          ...(sandboxActive ? { backend: result.backend, target: result.target } : { backend: 'host' }),
          exit_code: result.code,
          stdout: truncate(result.stdout),
          stderr: truncate(result.stderr),
        };
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
        stdinFile = sandboxActive ? sandboxRelativePath(location.cwd, resolvedStdin) : resolvedStdin;
      }
      const effectiveCommands = commands.map(command => command.toLowerCase() === 'run' && stdinFile
        ? 'run < ' + quoteGdbInputPath(stdinFile, sandboxActive || process.platform !== 'win32') : command);
      const commandArgs = ['-q', '-batch', '-nx', '-nh', '-iex', 'set auto-load off',
        '-iex', 'set debuginfod enabled off', '--se=' + targetBinary, '-ex', 'set confirm off'];
      if (progArgs.length > 0) {
        const posix = sandboxActive || process.platform !== 'win32';
        commandArgs.push('-ex', 'set args ' + progArgs.map(item => quoteGdbArg(item, posix)).join(' '));
      }
      for (const command of effectiveCommands) commandArgs.push('-ex', command);
      const result = await runGdb(commandArgs, { ptrace: true, killTree: true });
      return {
        action: 'debug',
        status: result.timedOut ? 'timeout' : result.code === 0 ? 'ok' : 'failed',
        ...(sandboxActive ? { backend: result.backend, target: result.target } : { backend: 'host' }),
        binary: args.file_path,
        ...(args.stdin_file === undefined ? {} : { stdin_file: args.stdin_file }),
        ...(progArgs.length > 0 ? { args: progArgs } : {}),
        commands: effectiveCommands,
        exit_code: result.code,
        stdout: truncate(result.stdout),
        stderr: truncate(result.stderr),
      };
    },
    ['action'],
  );

  register('archive_crack',
    '检查 ZIP 结构并尝试破解 ZipCrypto 口令（字典/掩码/弱口令），命中后校验 CRC。',
    {
      action: { type: 'string', enum: ['info', 'crack'] },
      source_result_id: SOURCE_RESULT_SCHEMA,
      wordlist: { type: 'string' },
      mask: { type: 'string', description: '掩码，如 ?l?l?l?d。' },
      passwords: { type: 'array', items: { type: 'string' }, maxItems: 256 },
      min_length: { type: 'integer', minimum: 0, maximum: 64 },
      max_length: { type: 'integer', minimum: 1, maximum: 64 },
      timeout_ms: { type: 'integer', minimum: 1000, maximum: 120000 },
    },
    async (args, execution, resolvedLocation) => {
      if (!['info', 'crack'].includes(args.action)) throw new ToolError('unsupported', 'action 须为 info 或 crack。');
      const location = resolvedLocation ?? await access.location(execution);
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
      source_result_id: SOURCE_RESULT_SCHEMA,
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
    async (args, execution, resolvedLocation) => {
      if (args.action === 'spectrum') requireWritable(execution);
      const location = resolvedLocation ?? await access.location(execution);
      const { bytes: buffer } = await access.read(location, args.file_path, MAX_INPUT_BYTES);
      return runStegoAudio(buffer, args, {
        signal: execution.signal,
        writeOutput: async (relPath, pngBuffer) => {
          const fileOut = await access.output(location, relPath);
          await writeFile(fileOut, pngBuffer, { flag: 'wx' });
          return fileOut;
        },
      });
    },
    ['file_path', 'action'],
  );

  if (access.extendedAudit !== false || access.domainSelection?.allowedTools?.has('mobile_apk') || access.domainSelection?.active) {
    register('mobile_apk',
      '检查 APK 结构（manifest、dex、ABI、签名块），或在安装 apktool/jadx 时反编译，在安装 apksigner/jarsigner 时校验签名（支持自动桥接重型沙箱）。',
      {
        action: { type: 'string', enum: ['info', 'decompile', 'signature'], description: '操作类型。' },
        backend: { type: 'string', enum: ['auto', 'host', 'docker'], description: '执行后端，默认 auto；传 docker 可强制使用重型沙箱隔离执行。' },
        source_result_id: SOURCE_RESULT_SCHEMA,
        output_dir: { type: 'string', description: 'decompile 输出目录，默认工作区 .apk-<文件名>。' },
        timeout_ms: { type: 'integer', minimum: 1000, maximum: 300000, description: '反编译上限，默认 120000。' },
      },
      async (args, execution, resolvedLocation) => {
        const location = resolvedLocation ?? await access.location(execution);
        const cwd = location.cwd;
        const backendMode = args.backend ?? 'auto';
        const file = await access.input(location, args.file_path);
        const { bytes: buffer } = await access.read(location, args.file_path, MAX_INPUT_BYTES);
        if (args.action === 'info') {
          return inspectApkInfo(buffer, {
            apktool: Boolean(findJavaTool(['apktool', 'apktool.bat'])),
            jadx: Boolean(findJavaTool(['jadx', 'jadx.bat'])),
            apksigner: Boolean(findJavaTool(['apksigner', 'apksigner.bat'])),
            jarsigner: Boolean(findJavaTool(['jarsigner'])),
          });
        }
        if (args.action === 'decompile') {
          requireWritable(execution);
          const output = await access.output(location, args.output_dir ?? defaultApkOutDir(file), true);
          const timeoutMs = Math.min(Math.max(args.timeout_ms ?? 120000, 1000), 300000);
          if (backendMode !== 'docker') {
            const jadx = findJavaTool(['jadx', 'jadx.bat']);
            const apktool = findJavaTool(['apktool', 'apktool.bat']);
            if (jadx || apktool) {
              const command = jadx
                ? { bin: jadx.path, args: ['-d', output, '--no-res', file] }
                : { bin: apktool.path, args: ['d', '-f', '-o', output, file] };
              const result = await spawnCapture(command.bin, command.args, { cwd, signal: execution.signal, timeoutMs });
              return {
                status: result.timedOut ? 'timeout' : (result.code === 0 ? 'ok' : 'failed'),
                backend: 'host',
                tool: jadx ? 'jadx' : 'apktool',
                output_dir: output,
                exit_code: result.code,
                stdout: truncate(result.stdout),
                stderr: truncate(result.stderr),
              };
            }
            if (backendMode === 'host') {
              throw new ToolError('dependency', '宿主机未找到 jadx 或 apktool。', '安装本机 jadx/apktool，或改用 backend: "docker" / "auto"。');
            }
          }
          const config = getConfig();
          const effectiveConfig = backendMode === 'docker' ? { ...config, sandboxBackend: 'docker' } : config;
          const detected = await detectSandbox(effectiveConfig, execution.signal);
          if (!detected.available) {
            throw new ToolError('dependency', '宿主机与沙箱均未找到 jadx 或 apktool。', '安装本机 jadx/apktool，或构建重型镜像：docker build -f docker/Dockerfile.heavy -t dsh-ctf-sandbox:heavy docker/。');
          }
          const plan = resolveExecutionPlan(detected, { preferDocker: true, preferHeavy: true, heavyReasons: ['apk_workload'] }, 'auto');
          const relApk = path.relative(cwd, file).replaceAll('\\', '/');
          const relOut = path.relative(cwd, output).replaceAll('\\', '/');
          const result = await runSandboxCommand(['bash', '-c', buildSandboxApkDecompileScript(), '_', relApk, relOut], {
            cwd, config: effectiveConfig, signal: execution.signal, timeoutMs, requiresIsolation: true, detected, image: plan.image, profile: plan.profile,
          });
          if (result.code === 127) {
            throw new ToolError('dependency', `沙箱（${result.backend}:${result.target}）内未安装 jadx 或 apktool。`, '请构建重型镜像：docker build -f docker/Dockerfile.heavy -t dsh-ctf-sandbox:heavy docker/。');
          }
          const toolHit = /^__TOOL=(jadx|apktool)\r?\n?/u.exec(result.stdout);
          const cleanStdout = toolHit ? result.stdout.slice(toolHit[0].length) : result.stdout;
          return {
            status: result.timedOut ? 'timeout' : (result.code === 0 ? 'ok' : 'failed'),
            backend: result.backend,
            target: result.target,
            profile: result.profile,
            ...(plan.profileFallbackReason ? { profile_fallback_reason: plan.profileFallbackReason } : {}),
            tool: toolHit ? toolHit[1] : 'sandbox',
            output_dir: output,
            exit_code: result.code,
            stdout: truncate(cleanStdout),
            stderr: truncate(result.stderr),
          };
        }
        if (args.action === 'signature') {
          if (backendMode !== 'docker') {
            const apksigner = findJavaTool(['apksigner', 'apksigner.bat']);
            const jarsigner = findJavaTool(['jarsigner']);
            if (apksigner || jarsigner) {
              const command = apksigner
                ? { bin: apksigner.path, args: ['verify', '--print-certs', file] }
                : { bin: jarsigner.path, args: ['-verify', '-verbose', '-certs', file] };
              const result = await spawnCapture(command.bin, command.args, { cwd, signal: execution.signal, timeoutMs: 60000 });
              return {
                status: result.code === 0 ? 'ok' : 'failed',
                backend: 'host',
                tool: apksigner ? 'apksigner' : 'jarsigner',
                exit_code: result.code,
                stdout: truncate(result.stdout),
                stderr: truncate(result.stderr),
              };
            }
            if (backendMode === 'host') {
              throw new ToolError('dependency', '宿主机未找到 apksigner 或 jarsigner。', '安装 JDK / Android SDK，或改用 backend: "docker" / "auto"。');
            }
          }
          const config = getConfig();
          const effectiveConfig = backendMode === 'docker' ? { ...config, sandboxBackend: 'docker' } : config;
          const detected = await detectSandbox(effectiveConfig, execution.signal);
          if (!detected.available) {
            throw new ToolError('dependency', '宿主机与沙箱均未找到 apksigner、jarsigner 或 keytool。', '安装 JDK / Android SDK 或构建重型镜像 dsh-ctf-sandbox:heavy。');
          }
          const plan = resolveExecutionPlan(detected, { preferDocker: true, preferHeavy: true, heavyReasons: ['apk_signature'] }, 'auto');
          const relApk = path.relative(cwd, file).replaceAll('\\', '/');
          const result = await runSandboxCommand(['bash', '-c', buildSandboxApkSignatureScript(), '_', relApk], {
            cwd, config: effectiveConfig, signal: execution.signal, timeoutMs: 60000, requiresIsolation: true, detected, image: plan.image, profile: plan.profile, readOnlyWork: true,
          });
          if (result.code === 127) {
            throw new ToolError('dependency', `沙箱（${result.backend}:${result.target}）内未找到 apksigner、jarsigner 或证书签名文件。`);
          }
          const toolHit = /^__TOOL=(apksigner|jarsigner|keytool)\r?\n?/u.exec(result.stdout);
          const cleanStdout = toolHit ? result.stdout.slice(toolHit[0].length) : result.stdout;
          return {
            status: result.timedOut ? 'timeout' : (result.code === 0 ? 'ok' : 'failed'),
            backend: result.backend,
            target: result.target,
            profile: result.profile,
            tool: toolHit ? toolHit[1] : 'sandbox',
            exit_code: result.code,
            stdout: truncate(cleanStdout),
            stderr: truncate(result.stderr),
          };
        }
        throw new ToolError('unsupported', `未知操作：${args.action}。`);
      },
      ['file_path', 'action'],
    );
  }

  if (access.extendedAudit !== false) {
    register('cloud_metadata',
      '保留旧工具入口，提示使用工作区中的脱敏日志。',
      { action: { type: 'string', description: '旧入口操作。' } },
      async () => { throw new ToolError('unsupported', '宿主元数据与凭据探测已关闭。可读取题目目录里的脱敏记录。'); },
      ['action'],
      { workspace: false },
    );
  }

  register('crypto_solver',
    '检查 Python 密码库（check）、生成求解脚手架（template）或直接执行内置无依赖求解（solve：JWT/Flask Session/LCG/MT19937）。',
    {
      action: { type: 'string', enum: ['check', 'template', 'solve'] },
      kind: { type: 'string', enum: ['z3_bitvec', 'coppersmith', 'lattice', 'aes_mode', 'ecc_weak', 'padding_oracle', 'hash_ext'] },
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
    async (args, execution, resolvedLocation) => {
      if (args.action === 'solve') {
        const readWordlist = async rel => {
          const location = resolvedLocation ?? await access.location(execution);
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
        if (typeof kind !== 'string' || !Object.hasOwn(CRYPTO_TEMPLATES, kind)) throw new ToolError('unsupported', `未知模板：${kind}。`);
        requireWritable(execution);
        const location = resolvedLocation ?? await access.location(execution);
        const relTemplate = '.ctf-templates/' + kind + '.py';
        const file = await access.output(location, relTemplate);
        await writeFile(file, CRYPTO_TEMPLATES[kind], { flag: 'wx' });
        return { status: 'ok', file, kind, preview: CRYPTO_TEMPLATES[kind].split('\n').slice(0, 6).join('\n') };
      }
      throw new ToolError('unsupported', `未知操作：${args.action}。`);
    },
    ['action'],
    { workspace: true },
  );
}
