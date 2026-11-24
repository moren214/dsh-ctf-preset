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
const MAX_CAPTURE_LOGS = 64;
const MAX_RESPONSE_BODY_CHARS = 64 * 1024;
const INTERESTING_RESPONSE_HEADERS = new Set(['content-type', 'location', 'set-cookie', 'www-authenticate', 'x-powered-by', 'server']);

function formatConsoleArg(arg) {
  if (!arg || typeof arg !== 'object') return '';
  if (arg.type === 'string' || arg.type === 'number' || arg.type === 'boolean') return String(arg.value);
  if (arg.type === 'undefined') return 'undefined';
  if (arg.subtype === 'null') return 'null';
  return String(arg.description ?? arg.value ?? `[${arg.type}]`);
}

function pushBounded(list, item) {
  if (list.length >= MAX_CAPTURE_LOGS) list.shift();
  list.push(item);
}

function handleCdpEvent(browser, payload) {
  if (!payload || typeof payload.method !== 'string') return;
  if (browser.sessionId && payload.sessionId && payload.sessionId !== browser.sessionId) return;
  const { method, params = {} } = payload;
  if (method === 'Network.requestWillBeSent') {
    const id = params.requestId;
    const req = params.request ?? {};
    if (typeof id !== 'string') return;
    const entry = {
      request_id: id,
      url: String(req.url ?? '').slice(0, 2048),
      method: String(req.method ?? 'GET'),
      resource_type: params.type ?? null,
      ...(typeof req.postData === 'string' && req.postData.length > 0 ? {
        post_data: req.postData.slice(0, 512),
        post_data_truncated: req.postData.length > 512,
      } : {}),
      status: null,
      mime_type: null,
      headers: {},
      failed: false,
    };
    browser.networkById.set(id, entry);
    if (browser.networkLogs.length >= MAX_CAPTURE_LOGS) {
      const removed = browser.networkLogs.shift();
      if (removed) browser.networkById.delete(removed.request_id);
    }
    browser.networkLogs.push(entry);
  } else if (method === 'Network.responseReceived') {
    const entry = browser.networkById.get(params.requestId);
    const res = params.response ?? {};
    if (!entry) return;
    entry.status = typeof res.status === 'number' ? res.status : null;
    entry.status_text = String(res.statusText ?? '').slice(0, 128);
    entry.mime_type = typeof res.mimeType === 'string' ? res.mimeType : null;
    const picked = {};
    for (const [key, value] of Object.entries(res.headers ?? {})) {
      const lower = key.toLowerCase();
      if (INTERESTING_RESPONSE_HEADERS.has(lower)) picked[lower] = String(value).slice(0, 1024);
    }
    entry.headers = picked;
  } else if (method === 'Network.loadingFailed') {
    const entry = browser.networkById.get(params.requestId);
    if (!entry) return;
    entry.failed = true;
    entry.error = String(params.errorText ?? 'loading failed').slice(0, 256);
  } else if (method === 'Runtime.consoleAPICalled') {
    const text = (params.args ?? []).map(formatConsoleArg).join(' ');
    pushBounded(browser.consoleLogs, {
      type: String(params.type ?? 'log'),
      text: text.slice(0, 1024),
      truncated: text.length > 1024,
      at: new Date().toISOString(),
    });
  } else if (method === 'Runtime.exceptionThrown') {
    const detail = params.exceptionDetails ?? {};
    const description = detail.exception?.description ?? detail.text ?? 'Uncaught exception';
    pushBounded(browser.consoleLogs, {
      type: 'exception',
      text: String(description).slice(0, 1024),
      ...(detail.url ? { url: String(detail.url).slice(0, 512) } : {}),
      ...(typeof detail.lineNumber === 'number' ? { line: detail.lineNumber + 1 } : {}),
      at: new Date().toISOString(),
    });
  }
}
const BROWSER_KEYS = Object.freeze({
  Enter: { key: 'Enter', code: 'Enter', value: 13, text: '\r' },
  Tab: { key: 'Tab', code: 'Tab', value: 9, text: '\t' },
  Escape: { key: 'Escape', code: 'Escape', value: 27 },
  ArrowUp: { key: 'ArrowUp', code: 'ArrowUp', value: 38 },
  ArrowDown: { key: 'ArrowDown', code: 'ArrowDown', value: 40 },
  ArrowLeft: { key: 'ArrowLeft', code: 'ArrowLeft', value: 37 },
  ArrowRight: { key: 'ArrowRight', code: 'ArrowRight', value: 39 },
  Space: { key: ' ', code: 'Space', value: 32, text: ' ' },
  Backspace: { key: 'Backspace', code: 'Backspace', value: 8 },
  Delete: { key: 'Delete', code: 'Delete', value: 46 },
});

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
        if (payload.id !== undefined) {
          browser.pending.get(payload.id)?.finish(payload.error ? new Error('浏览器调试调用失败。') : undefined, payload.result);
        } else {
          handleCdpEvent(browser, payload);
        }
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
    const browser = { pending: new Map(), nextId: 0, exited: false, networkLogs: [], networkById: new Map(), consoleLogs: [] };
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
      await send(browser, 'Network.enable', { maxTotalBufferSize: 4 * 1024 * 1024, maxResourceBufferSize: 512 * 1024 }, signal);
      await send(browser, 'Runtime.enable', {}, signal);
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
    async interact(browser, action, selector, value, signal) {
      const query = JSON.stringify(selector);
      let operation;
      if (action === 'click') {
        operation = `if (node.disabled) return {status:'disabled'}; const label=(node.innerText||node.getAttribute('aria-label')||node.value||'').trim().slice(0,200); node.click(); return {status:'clicked',tag:node.tagName,label};`;
      } else if (action === 'fill') {
        const text = JSON.stringify(value);
        operation = `if (node.disabled||node.readOnly) return {status:'not_editable'}; if (node instanceof HTMLInputElement) { if (['button','submit','reset','image','hidden','file','checkbox','radio'].includes(node.type)) return {status:'not_text_input'}; const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set; setter.call(node,${text}); } else if (node instanceof HTMLTextAreaElement) { const setter=Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set; setter.call(node,${text}); } else if (node.isContentEditable) { node.textContent=${text}; } else return {status:'not_editable'}; node.dispatchEvent(new Event('input',{bubbles:true,composed:true})); node.dispatchEvent(new Event('change',{bubbles:true,composed:true})); return {status:'filled',tag:node.tagName,type:node.type||undefined};`;
      } else if (action === 'select') {
        const text = JSON.stringify(value);
        operation = `if (!(node instanceof HTMLSelectElement)) return {status:'not_select'}; if (node.disabled) return {status:'disabled'}; if (!Array.from(node.options).some(option=>option.value===${text})) return {status:'option_not_found'}; const setter=Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set; setter.call(node,${text}); node.dispatchEvent(new Event('input',{bubbles:true,composed:true})); node.dispatchEvent(new Event('change',{bubbles:true,composed:true})); return {status:'selected',value:node.value};`;
      } else throw new Error('不支持的浏览器交互操作。');
      const expression = `(() => { let nodes; try { nodes=Array.from(document.querySelectorAll(${query})); } catch { return {status:'invalid_selector'}; } if (nodes.length!==1) return {status:'match_count',count:nodes.length}; const node=nodes[0]; ${operation} })()`;
      return evaluate(browser, expression, signal);
    },
    async press(browser, selector, key, signal) {
      const query = JSON.stringify(selector);
      const expression = `(() => { let nodes; try { nodes=Array.from(document.querySelectorAll(${query})); } catch { return {status:'invalid_selector'}; } if (nodes.length!==1) return {status:'match_count',count:nodes.length}; const node=nodes[0]; if(typeof node.focus!=='function') return {status:'not_focusable'}; node.focus(); return document.activeElement===node ? {status:'focused',tag:node.tagName} : {status:'not_focusable'}; })()`;
      const focused = await evaluate(browser, expression, signal);
      if (focused.status !== 'focused') return focused;
      const keyInfo = BROWSER_KEYS[key];
      if (keyInfo === undefined) return { status: 'unsupported_key' };
      const params = { key: keyInfo.key, code: keyInfo.code,
        windowsVirtualKeyCode: keyInfo.value, nativeVirtualKeyCode: keyInfo.value,
        ...(keyInfo.text === undefined ? {} : { text: keyInfo.text }) };
      await send(browser, 'Input.dispatchKeyEvent', { type: 'keyDown', ...params }, signal);
      await send(browser, 'Input.dispatchKeyEvent', { type: 'keyUp', ...params }, signal);
      return { status: 'pressed', tag: focused.tag, key };
    },
    async waitFor(browser, selector, waitMs, signal) {
      const query = JSON.stringify(selector);
      const expression = `(() => { try { const node=document.querySelector(${query}); return node ? {status:'found',tag:node.tagName,text:(node.innerText||node.textContent||'').trim().slice(0,200)} : {status:'waiting'}; } catch { return {status:'invalid_selector'}; } })()`;
      const end = Date.now() + waitMs;
      while (true) {
        signal.throwIfAborted();
        const result = await evaluate(browser, expression, signal);
        if (result.status !== 'waiting') return result;
        if (Date.now() >= end) return { status: 'not_found' };
        await wait(Math.min(100, Math.max(1, end - Date.now())), undefined, { signal });
      }
    },
    async storage(browser, kind, signal) {
      const property = kind === 'session' ? 'sessionStorage' : 'localStorage';
      const expression = `(() => { try { const store=window[${JSON.stringify(property)}]; const count=store.length; const entries=[]; let truncated=count>32; for(let i=0;i<Math.min(count,32);i++){ const key=store.key(i); const value=store.getItem(key)||''; entries.push({key:key.slice(0,256),value:value.slice(0,2048),value_truncated:value.length>2048}); if(key.length>256||value.length>2048) truncated=true; } return {status:'ok',count,entries,truncated}; } catch { return {status:'unavailable',count:0,entries:[],truncated:false}; } })()`;
      return evaluate(browser, expression, signal);
    },
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
    network(browser, clear = false) {
      const entries = browser.networkLogs.map(item => ({ ...item, headers: { ...item.headers } }));
      if (clear) {
        browser.networkLogs.length = 0;
        browser.networkById.clear();
      }
      return entries;
    },
    async responseBody(browser, requestId, signal) {
      const result = await send(browser, 'Network.getResponseBody', { requestId }, signal);
      const raw = String(result?.body ?? '');
      return {
        request_id: requestId,
        base64_encoded: Boolean(result?.base64Encoded),
        body: raw.slice(0, MAX_RESPONSE_BODY_CHARS),
        truncated: raw.length > MAX_RESPONSE_BODY_CHARS,
      };
    },
    console(browser, clear = false) {
      const entries = browser.consoleLogs.map(item => ({ ...item }));
      if (clear) browser.consoleLogs.length = 0;
      return entries;
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
