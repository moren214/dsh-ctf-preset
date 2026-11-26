import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { ToolError } from '../contracts/errors.js';

const DEFAULT_IDLE_TTL_MS = 10 * 60 * 1000;

const POOL_WORKER_SCRIPT = [
  'import base64, json, subprocess, sys',
  'for line in sys.stdin:',
  '    line = line.strip()',
  '    if not line: continue',
  '    req = None',
  '    try:',
  '        req = json.loads(line)',
  '        argv = req["argv"]',
  '        timeout_s = max(0.5, float(req.get("timeout_ms", 60000)) / 1000.0)',
  '        max_bytes = int(req.get("max_bytes", 131072))',
  '        proc = subprocess.run(argv, cwd="/work", capture_output=True, timeout=timeout_s)',
  '        out = proc.stdout[:max_bytes]',
  '        err = proc.stderr[:max_bytes]',
  '        resp = {',
  '            "id": req["id"],',
  '            "code": proc.returncode,',
  '            "stdout_b64": base64.b64encode(out).decode("ascii"),',
  '            "stderr_b64": base64.b64encode(err).decode("ascii"),',
  '            "stdout_truncated": len(proc.stdout) > max_bytes,',
  '            "stderr_truncated": len(proc.stderr) > max_bytes,',
  '            "timed_out": False,',
  '        }',
  '    except subprocess.TimeoutExpired as exc:',
  '        out = (exc.stdout or b"")[:max_bytes]',
  '        err = (exc.stderr or b"")[:max_bytes]',
  '        resp = {',
  '            "id": req.get("id") if isinstance(req, dict) else None,',
  '            "code": -1,',
  '            "stdout_b64": base64.b64encode(out).decode("ascii"),',
  '            "stderr_b64": base64.b64encode(err).decode("ascii"),',
  '            "stdout_truncated": len(exc.stdout or b"") > max_bytes,',
  '            "stderr_truncated": len(exc.stderr or b"") > max_bytes,',
  '            "timed_out": True,',
  '        }',
  '    except Exception as exc:',
  '        resp = {',
  '            "id": req.get("id") if isinstance(req, dict) else None,',
  '            "code": -1,',
  '            "stdout_b64": "",',
  '            "stderr_b64": base64.b64encode(str(exc).encode("utf-8", "replace")).decode("ascii"),',
  '            "stdout_truncated": False,',
  '            "stderr_truncated": False,',
  '            "timed_out": False,',
  '        }',
  '    sys.stdout.write(json.dumps(resp) + "\\n")',
  '    sys.stdout.flush()',
].join('\n');

function killContainerBestEffort(containerName) {
  try {
    const killer = spawn('docker', ['rm', '-f', containerName], { windowsHide: true, stdio: 'ignore' });
    killer.on('error', () => {});
    killer.unref?.();
  } catch {
    // ignore
  }
}

export function createSandboxPool({ idleTtlMs = DEFAULT_IDLE_TTL_MS } = {}) {
  const slots = new Map();
  let gcTimer;

  function ensureGc() {
    if (gcTimer) return;
    gcTimer = setInterval(() => { void pruneExpired(); }, 60_000);
    gcTimer.unref?.();
  }

  function setSlotRef(entry, active) {
  const method = active ? 'ref' : 'unref';
  try { entry.child[method]?.(); } catch { /* ignore */ }
  try { entry.child.stdin?.[method]?.(); } catch { /* ignore */ }
  try { entry.child.stdout?.[method]?.(); } catch { /* ignore */ }
  try { entry.child.stderr?.[method]?.(); } catch { /* ignore */ }
}

function destroyEntry(key, entry, reason) {
    if (key && slots.get(key) === entry) slots.delete(key);
    if (entry.closed) return;
    entry.closed = true;
    const pending = entry.pending;
    entry.pending = null;
    if (pending) pending.fail(reason ?? new ToolError('timeout', '沙箱常驻容器已关闭。'));
    try { entry.child.stdin?.end(); } catch { /* ignore */ }
    try { entry.child.kill('SIGKILL'); } catch { /* ignore */ }
    killContainerBestEffort(entry.containerName);
  }

  async function pruneExpired() {
    const now = Date.now();
    for (const [key, entry] of slots.entries()) {
      if (!entry.busy && now - entry.lastUsedAt > idleTtlMs) {
        destroyEntry(key, entry);
      }
    }
  }

  function spawnWorkerSlot(key, spec) {
    const {
      cwd,
      targetImage,
      isHeavy = false,
      network = 'none',
      ptrace = false,
      readOnlyWork = false,
      extraDockerArgs = [],
      buildArgsFn,
    } = spec;
    const containerName = 'dsh-ctf-pool-' + randomUUID().slice(0, 12);
    const runArgs = buildArgsFn(['python3', '-u', '-c', POOL_WORKER_SCRIPT], {
      cwd, containerName, targetImage, isHeavy, network, ptrace, readOnlyWork, extraArgs: extraDockerArgs,
    });
    const interactiveArgs = ['run', '-i', ...runArgs.slice(1)];
    const child = spawn('docker', interactiveArgs, { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    const entry = {
      key,
      containerName,
      child,
      buf: '',
      errBuf: '',
      nextId: 1,
      busy: false,
      closed: false,
      lastUsedAt: Date.now(),
      pending: null,
    };

    child.stderr?.on('data', chunk => {
      if (entry.errBuf.length < 4096) entry.errBuf += chunk.toString('utf8');
    });
    child.stdout?.on('data', chunk => {
      entry.buf += chunk.toString('utf8');
      let nl = entry.buf.indexOf('\n');
      while (nl >= 0) {
        const line = entry.buf.slice(0, nl).trim();
        entry.buf = entry.buf.slice(nl + 1);
        if (line && entry.pending) {
          try {
            const msg = JSON.parse(line);
            if (msg.id === entry.pending.id) {
              const p = entry.pending;
              entry.pending = null;
              p.ok(msg);
            }
          } catch {
            // ignore non-json noise
          }
        }
        nl = entry.buf.indexOf('\n');
      }
    });
    child.once('error', err => destroyEntry(key, entry, err));
    child.once('close', code => {
      const detail = entry.errBuf.trim();
      destroyEntry(key, entry, new ToolError('dependency', detail || `常驻沙箱退出（code=${code ?? -1}）。`));
    });
    if (key) {
      slots.set(key, entry);
      ensureGc();
    }
    setSlotRef(entry, false);
    return entry;
  }

  function runOnSlot(entry, key, argv, { timeoutMs = 60000, signal, maxBytes = 131072 } = {}) {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) {
        reject(signal.reason ?? new ToolError('abort', '沙箱调用已取消。'));
        return;
      }
      if (entry.closed || !entry.child.stdin?.writable) {
        reject(new ToolError('dependency', '常驻沙箱通道已关闭。'));
        return;
      }
      setSlotRef(entry, true);
      entry.busy = true;
      entry.lastUsedAt = Date.now();
      const id = entry.nextId++;
      let settled = false;

      const cleanup = () => {
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
        setSlotRef(entry, false);
      };
      const onAbort = () => {
        if (settled) return;
        settled = true;
        cleanup();
        const reason = signal?.reason ?? new ToolError('abort', '沙箱调用已取消。');
        destroyEntry(key, entry, reason);
        reject(reason);
      };
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        cleanup();
        destroyEntry(key, entry);
        resolve({
          code: -1,
          stdoutBuf: Buffer.alloc(0),
          stderrBuf: Buffer.alloc(0),
          stdout: '',
          stderr: '',
          stdoutTruncated: false,
          stderrTruncated: false,
          timedOut: true,
        });
      }, timeoutMs + 5000);

      signal?.addEventListener('abort', onAbort, { once: true });

      entry.pending = {
        id,
        ok(msg) {
          if (settled) return;
          settled = true;
          cleanup();
          entry.busy = false;
          entry.lastUsedAt = Date.now();
          const stdoutBuf = Buffer.from(msg.stdout_b64 || '', 'base64');
          const stderrBuf = Buffer.from(msg.stderr_b64 || '', 'base64');
          resolve({
            code: msg.code ?? -1,
            stdoutBuf,
            stderrBuf,
            stdout: stdoutBuf.toString('utf8'),
            stderr: stderrBuf.toString('utf8'),
            stdoutTruncated: Boolean(msg.stdout_truncated),
            stderrTruncated: Boolean(msg.stderr_truncated),
            timedOut: Boolean(msg.timed_out),
          });
        },
        fail(err) {
          if (settled) return;
          settled = true;
          cleanup();
          entry.busy = false;
          reject(err);
        },
      };

      try {
        entry.child.stdin.write(JSON.stringify({ id, argv, timeout_ms: timeoutMs, max_bytes: maxBytes }) + '\n');
      } catch (error) {
        entry.pending = null;
        settled = true;
        cleanup();
        destroyEntry(key, entry, error);
        reject(error);
      }
    });
  }

  async function exec(spec, argv, { timeoutMs = 60000, signal, maxBytes = 131072 } = {}) {
    const key = JSON.stringify([
      spec.cwd,
      spec.targetImage,
      Boolean(spec.isHeavy),
      spec.network ?? 'none',
      Boolean(spec.ptrace),
      Boolean(spec.readOnlyWork),
      spec.extraDockerArgs ?? [],
    ]);
    let entry = slots.get(key);
    let reused = false;
    if (entry && !entry.closed && !entry.busy && entry.child.stdin?.writable) {
      reused = true;
    } else if (!entry || entry.closed) {
      entry = spawnWorkerSlot(key, spec);
      reused = false;
    } else {
      // Slot is currently busy; spawn an unkeyed ephemeral worker without blocking or corrupting the pooled slot.
      entry = spawnWorkerSlot(null, spec);
      reused = false;
      try {
        const res = await runOnSlot(entry, null, argv, { timeoutMs, signal, maxBytes });
        return { ...res, reused: false };
      } finally {
        destroyEntry(null, entry);
      }
    }

    const res = await runOnSlot(entry, key, argv, { timeoutMs, signal, maxBytes });
    return { ...res, reused };
  }

  async function dispose() {
    if (gcTimer) {
      clearInterval(gcTimer);
      gcTimer = undefined;
    }
    const items = [...slots.entries()];
    slots.clear();
    for (const [key, entry] of items) {
      destroyEntry(key, entry);
    }
  }

  return {
    exec,
    pruneExpired,
    dispose,
    disposeAll: dispose,
    size: () => slots.size,
  };
}
