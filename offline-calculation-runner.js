import { Worker } from 'node:worker_threads';

const workerFile = new URL('./offline-calculation-worker.js', import.meta.url);
const MAX_RUNNING = 2;

export function createCalculationRunner({ budgetMs = 5000 } = {}) {
  const running = new Set();
  let disposed = false;
  return {
    async run(steps, signal) {
      signal?.throwIfAborted();
      if (disposed) throw new Error('CTF 计算器已关闭。');
      if (running.size >= MAX_RUNNING) return { status: 'busy', reason: '当前有两项计算在运行。' };
      const worker = new Worker(workerFile, {
        workerData: steps,
        execArgv: [],
        resourceLimits: { maxOldGenerationSizeMb: 64 },
      });
      running.add(worker);
      try {
        return await new Promise((resolve, reject) => {
          let settled = false;
          const complete = (error, result) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            signal?.removeEventListener('abort', abort);
            if (error === undefined) resolve(result);
            else reject(error);
          };
          const abort = () => complete(signal.reason ?? new Error('计算已取消。'));
          const timer = setTimeout(() => complete(undefined, {
            status: 'timeout', budget_ms: budgetMs, reason: '计算达到时间上限，未返回部分结果。',
          }), budgetMs);
          worker.on('error', error => complete(error));
          worker.once('exit', () => complete(new Error('CTF 计算进程已结束。')));
          worker.once('message', ({ report, error }) => complete(error === undefined ? undefined : new Error(error), report));
          signal?.addEventListener('abort', abort, { once: true });
          if (signal?.aborted) abort();
        });
      } finally {
        try {
          await worker.terminate();
        } finally {
          running.delete(worker);
        }
      }
    },
    dispose() {
      disposed = true;
      for (const worker of running) void worker.terminate().catch(() => {});
    },
  };
}
