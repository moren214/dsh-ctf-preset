import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as wait } from 'node:timers/promises';
import { browserGateway } from './browser-gateway.js';
import { httpRequest } from './http-client.js';

const PROFILE_PREFIX = 'dsh-ctf-browser-';
export const BROWSER_TIMEOUT_MS = 15000;

async function removeProfile(profile, root) {
  if (!profile) return true;
  try {
    const item = await lstat(profile);
    const resolved = await realpath(profile);
    if (!item.isDirectory() || item.isSymbolicLink() || path.dirname(resolved) !== root
      || !path.basename(resolved).startsWith(PROFILE_PREFIX)) return false;
    await rm(resolved, { recursive: true, force: true, maxRetries: 6, retryDelay: 60 });
    return true;
  } catch (error) {
    return error.code === 'ENOENT';
  }
}

export function createBrowserSession({ resolveBinary, authorize, environment, onStart, onStop }) {
  let state;
  let active;
  let cleanup;

  async function timedExit(browser, milliseconds) {
    return browser.exit === undefined || Promise.race([browser.exit.then(() => true), wait(milliseconds, false)]);
  }

  function shutdown() {
    if (cleanup) return cleanup;
    const browser = state;
    state = undefined;
    if (browser === undefined) {
      onStop();
      return Promise.resolve({ process_exited: true, profile_removed: true });
    }
    cleanup = (async () => {
      browser.gateway?.dispose();
      if (browser.socket?.readyState === 1 && !browser.exited) {
        void send(browser, 'Browser.close', {}, AbortSignal.timeout(500), null).catch(() => {});
        await timedExit(browser, 650);
      }
      if (!browser.exited && browser.child) {
        try { browser.child.kill(); } catch { /* already closed */ }
      }
      try { browser.socket?.close(); } catch { /* already closed */ }
      const exited = await timedExit(browser, 1200);
      const removed = await removeProfile(browser.profile, browser.root);
      return { process_exited: exited, profile_removed: removed };
    })().finally(() => {
      cleanup = undefined;
      onStop();
    });
    return cleanup;
  }

  function connect(browser, url, signal) {
    signal.throwIfAborted();
    return new Promise((resolve, reject) => {
      const socket = new WebSocket(url);
      browser.socket = socket;
      const cleanupConnection = () => {
        signal.removeEventListener('abort', abort);
        socket.removeEventListener('open', ready);
        socket.removeEventListener('error', failed);
      };
      const abort = () => { cleanupConnection(); reject(signal.reason); };
      const ready = () => { cleanupConnection(); resolve(); };
      const failed = () => { cleanupConnection(); reject(new Error('无法连接浏览器的调试端口。')); };
      signal.addEventListener('abort', abort, { once: true });
      socket.addEventListener('open', ready, { once: true });
      socket.addEventListener('error', failed, { once: true });
      socket.addEventListener('close', () => {
        failed();
        for (const entry of browser.pending.values()) entry.finish(new Error('浏览器调试连接已关闭。'));
      });
      socket.addEventListener('message', event => {
        let payload;
        try { payload = JSON.parse(event.data); } catch { return; }
        browser.pending.get(payload.id)?.finish(payload.error ? new Error('浏览器调试调用失败。') : undefined, payload.result);
      });
      if (signal.aborted) abort();
    });
  }

  function send(browser, method, params, signal, sessionId = browser.sessionId) {
    signal.throwIfAborted();
    if (browser.socket?.readyState !== 1) throw new Error('浏览器会话未建立。');
    const id = ++browser.nextId;
    return new Promise((resolve, reject) => {
      const finish = (error, result) => {
        browser.pending.delete(id);
        signal.removeEventListener('abort', abort);
        if (error) reject(error);
        else resolve(result);
      };
      const abort = () => finish(signal.reason);
      signal.addEventListener('abort', abort, { once: true });
      browser.pending.set(id, { finish });
      try { browser.socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) })); }
      catch (error) { finish(error); }
      if (signal.aborted) abort();
    });
  }

  async function ensure(signal) {
    if (state?.sessionId && state.socket?.readyState === 1) return state;
    const binary = await resolveBinary();
    signal.throwIfAborted();
    if (!binary || !path.isAbsolute(binary)) throw new Error('缺少可用的本机 Chrome/Edge 浏览器绝对路径。');
    if (typeof WebSocket !== 'function') throw new Error('当前 DSH 的 Node 运行时缺少 WebSocket。');
    if (state) await shutdown();
    onStart();
    const browser = { pending: new Map(), nextId: 0, exited: false };
    state = browser;
    try {
      browser.gateway = await browserGateway(authorize);
      signal.throwIfAborted();
      browser.root = await realpath(tmpdir());
      browser.profile = await mkdtemp(path.join(browser.root, PROFILE_PREFIX));
      signal.throwIfAborted();
      browser.child = spawn(binary, [
        '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
        '--disable-extensions', '--mute-audio', '--remote-debugging-port=0', '--disable-background-networking',
        '--disable-quic', '--dns-prefetch-disable', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
        '--proxy-server=' + browser.gateway.address, '--proxy-bypass-list=<-loopback>',
        '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1',
        '--user-data-dir=' + browser.profile, 'about:blank',
      ], { stdio: 'ignore', windowsHide: true, env: environment() });
      browser.exit = new Promise(resolve => {
        const exited = () => {
          browser.exited = true;
          resolve();
          if (state === browser && !active) void shutdown();
        };
        browser.child.once('exit', exited);
        browser.child.once('error', exited);
      });
      const portFile = path.join(browser.profile, 'DevToolsActivePort');
      let contents;
      while (contents === undefined && !browser.exited) {
        signal.throwIfAborted();
        try { contents = await readFile(portFile, { encoding: 'utf8', signal }); }
        catch (error) {
          if (error.code !== 'ENOENT' && error.code !== 'EBUSY' && error.code !== 'EACCES') throw error;
          await wait(50, undefined, { signal });
        }
      }
      if (!contents) throw new Error('Chrome/Edge 启动失败。');
      const port = contents.split(/\r?\n/u)[0];
      if (!/^\d{1,5}$/u.test(port) || Number(port) < 1 || Number(port) > 65535) throw new Error('调试端口无效。');
      const reply = await httpRequest({ url: 'http://127.0.0.1:' + port + '/json/version',
        timeout_ms: 3000, follow_redirects: false }, { signal });
      if (reply.status !== 200 || !reply.body_complete) throw new Error('无法读取本机浏览器的调试配置。');
      const debuggerUrl = new URL(JSON.parse(reply.body).webSocketDebuggerUrl);
      if (debuggerUrl.protocol !== 'ws:' || debuggerUrl.hostname !== '127.0.0.1' || debuggerUrl.port !== port
        || debuggerUrl.username || debuggerUrl.password) throw new Error('调试连接超出本机浏览器。');
      await connect(browser, debuggerUrl.href, signal);
      const { targetId } = await send(browser, 'Target.createTarget', { url: 'about:blank' }, signal, null);
      const attached = await send(browser, 'Target.attachToTarget', { targetId, flatten: true }, signal, null);
      browser.targetId = targetId;
      browser.sessionId = attached.sessionId;
      return browser;
    } catch (error) {
      await shutdown();
      throw error;
    }
  }

  async function evaluate(browser, expression, signal) {
    const result = await send(browser, 'Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, signal);
    if (result.exceptionDetails) throw new Error('无法读取页面的所选内容。');
    return result.result?.value;
  }

  return {
    async run(timeoutMs, parent, operation) {
      if (active || cleanup) throw new Error('此浏览器会话正忙。');
      const deadline = AbortSignal.timeout(timeoutMs);
      const controller = new AbortController();
      const signal = AbortSignal.any([deadline, controller.signal, ...(parent ? [parent] : [])]);
      let finish;
      const complete = new Promise(resolve => { finish = resolve; });
      active = { controller, complete };
      try {
        signal.throwIfAborted();
        return await operation(signal);
      } catch (error) {
        if (signal.aborted || state?.exited) await shutdown();
        if (deadline.aborted && !parent?.aborted) throw new Error('浏览器操作超时（' + timeoutMs + ' ms）。');
        if (signal.aborted) throw new Error('浏览器操作已取消。');
        throw error;
      } finally {
        active = undefined;
        finish();
      }
    },
    ensure,
    async status(signal) {
      const browser = state;
      if (!browser?.sessionId || browser.exited) return { running: false };
      return { running: true, target: browser.targetId, url: await evaluate(browser, 'location.href', signal) };
    },
    async navigate(browser, url, signal) {
      const navigation = await send(browser, 'Page.navigate', { url }, signal);
      if (navigation.errorText || navigation.isDownload) throw new Error('页面打开失败，或者目标返回了下载。');
      while (await evaluate(browser, 'document.readyState', signal) !== 'complete') await wait(75, undefined, { signal });
      const current = await evaluate(browser, 'location.href', signal);
      if (current !== 'about:blank') await authorize(current, signal);
      return { url: current, title: await evaluate(browser, 'document.title', signal) };
    },
    evaluate,
    async screenshot(browser, file, signal) {
      const { data } = await send(browser, 'Page.captureScreenshot', { format: 'png' }, signal);
      const bytes = Buffer.from(data, 'base64');
      signal.throwIfAborted();
      await writeFile(file, bytes, { flag: 'wx' });
      return { bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
    },
    async cookies(browser, url, signal) {
      const result = await send(browser, 'Network.getCookies', { urls: url ? [url] : [] }, signal);
      return result.cookies ?? [];
    },
    async list(browser, signal) {
      const result = await send(browser, 'Target.getTargets', {}, signal, null);
      return (result.targetInfos ?? []).filter(item => item.type === 'page').map(({ targetId, url, title }) => ({ id: targetId, url, title }));
    },
    async close() {
      const operation = active;
      if (operation) {
        operation.controller.abort();
        await operation.complete;
      }
      return shutdown();
    },
  };
}
