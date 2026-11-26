import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { ToolError } from '../contracts/errors.js';
import { validatedGdbCommands } from '../capabilities/gdb-driver.js';

const MAX_GDB_SESSIONS = 8;
const IDLE_MS = 10 * 60 * 1000;

export function createGdbSessionManager() {
  const sessions = new Map();

  function pruneIdle() {
    const now = Date.now();
    for (const [id, entry] of sessions) {
      if (!entry.busy && now - entry.lastUsedAt > IDLE_MS) {
        void close(id);
      }
    }
  }

  async function sendLine(entry, cmd, timeoutMs = 15000, signal) {
    if (entry.closed) throw new ToolError('conflict', 'GDB 会话已关闭。');
    if (entry.busy) throw new ToolError('conflict', 'GDB 会话正在执行其他命令，请勿并发调用。');
    entry.busy = true;
    entry.lastUsedAt = Date.now();
    const token = Math.floor(Math.random() * 1e9) + 1;
    const marker = `__DSH_GDB_DONE_${token}__`;
    let buffer = '';
    try {
      return await new Promise((resolve, reject) => {
        const cleanup = () => {
          clearTimeout(timer);
          signal?.removeEventListener('abort', onAbort);
          entry.child.stdout?.off('data', onData);
          entry.child.off('exit', onExit);
        };
        const onAbort = () => {
          cleanup();
          reject(new ToolError('abort', 'GDB 会话命令已取消。'));
        };
        const onExit = code => {
          cleanup();
          entry.closed = true;
          sessions.delete(entry.id);
          reject(new ToolError('conflict', `GDB 会话进程已退出（${code ?? -1}）。`));
        };
        const onData = chunk => {
          buffer += chunk.toString('utf8');
          const idx = buffer.indexOf(marker);
          if (idx >= 0) {
            const out = buffer.slice(0, idx).trim();
            cleanup();
            resolve(out);
          }
        };
        const timer = setTimeout(() => {
          cleanup();
          reject(new ToolError('timeout', `GDB 命令执行超时（${timeoutMs} ms）。`));
        }, timeoutMs);
        signal?.addEventListener('abort', onAbort, { once: true });
        if (signal?.aborted) return onAbort();
        entry.child.stdout.on('data', onData);
        entry.child.once('exit', onExit);
        try {
          entry.child.stdin.write(`${cmd}\nprintf "${marker}\\n"\n`);
        } catch (err) {
          cleanup();
          reject(new ToolError('dependency', `写入 GDB 会话失败：${err.message}`));
        }
      });
    } finally {
      entry.busy = false;
      entry.lastUsedAt = Date.now();
    }
  }

  async function start({ command, args, cwd, binary, timeoutMs = 20000, signal }) {
    pruneIdle();
    if (sessions.size >= MAX_GDB_SESSIONS) {
      throw new ToolError('conflict', `持久化 GDB 会话数已达上限 ${MAX_GDB_SESSIONS}，请先关闭不用的会话。`);
    }
    const id = `gdb-${randomUUID().slice(0, 10)}`;
    const child = spawn(command, args, { cwd, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    let stderr = '';
    child.stderr?.on('data', c => {
      if (stderr.length < 8192) stderr += c.toString('utf8');
    });
    const entry = { id, child, binary, closed: false, busy: false, lastUsedAt: Date.now() };
    sessions.set(id, entry);
    child.once('exit', () => {
      entry.closed = true;
      sessions.delete(id);
    });
    try {
      const initOut = await sendLine(entry, 'set confirm off', timeoutMs, signal);
      return { status: 'started', session_id: id, binary, output: initOut, stderr: stderr.trim() };
    } catch (error) {
      await close(id);
      throw error;
    }
  }

  async function execCommands(sessionId, commands, { timeoutMs = 20000, signal } = {}) {
    const entry = sessions.get(sessionId);
    if (!entry || entry.closed) throw new ToolError('missing', `GDB 会话不存在或已关闭：${sessionId}`);
    const validated = validatedGdbCommands(commands);
    const outputs = [];
    for (const cmd of validated) {
      const out = await sendLine(entry, cmd, timeoutMs, signal);
      outputs.push({ command: cmd, output: out });
    }
    return { status: 'ok', session_id: sessionId, binary: entry.binary, results: outputs };
  }

  async function close(sessionId) {
    const entry = sessions.get(sessionId);
    if (!entry) return { status: 'not_found', session_id: sessionId };
    sessions.delete(sessionId);
    entry.closed = true;
    try { entry.child.stdin?.write('quit\n'); } catch { /* ignore */ }
    try { entry.child.kill('SIGKILL'); } catch { /* ignore */ }
    return { status: 'closed', session_id: sessionId };
  }

  async function dispose() {
    const ids = [...sessions.keys()];
    await Promise.allSettled(ids.map(id => close(id)));
  }

  return {
    start,
    execCommands,
    close,
    dispose,
    disposeAll: dispose,
    list: () => [...sessions.values()].map(s => ({ session_id: s.id, binary: s.binary, busy: s.busy })),
  };
}
