import { createHash, randomBytes } from 'node:crypto';
import { Worker } from 'node:worker_threads';
import { CALCULATION_RESUME_ID, calculationReport, supportsCalculationReplay } from './offline-calculation.js';

const workerFile = new URL('./offline-calculation-worker.js', import.meta.url);
const MAX_RUNNING = 2;
const MAX_CHECKPOINTS = 8;
const CHECKPOINT_TTL_MS = 15 * 60 * 1000;

function requestDigest(steps, candidates, inputs) {
  const plan = JSON.stringify({ steps, candidates }, (_key, value) =>
    value !== null && typeof value === 'object' && !Array.isArray(value)
      ? Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]]))
      : value);
  const digest = createHash('sha256').update(plan);
  for (const input of inputs ?? []) digest.update(createHash('sha256').update(input).digest());
  return digest.digest('hex');
}

function startWorker(workerData) {
  return new Worker(workerFile, {
    workerData, execArgv: [], resourceLimits: { maxOldGenerationSizeMb: 64 },
  });
}

export function createCalculationRunner({ budgetMs = 5000, createWorker = startWorker } = {}) {
  const running = new Set();
  const checkpoints = new Map();
  let disposed = false;
  return {
    async run(steps, signal, resolvedInputs, { candidates, resumeId, session, directoryKey } = {}) {
      signal?.throwIfAborted();
      if (disposed) throw new Error('CTF 计算器已关闭。');
      if (running.size >= MAX_RUNNING) return { status: 'busy', reason: '当前有两项计算在运行。' };
      for (const [id, checkpoint] of checkpoints) {
        if (checkpoint.expires <= Date.now() || checkpoint.session.deref() === undefined) checkpoints.delete(id);
      }
      const canReplay = supportsCalculationReplay(steps);
      const sessionPresent = session !== null && typeof session === 'object';
      let completed = [];
      if (resumeId !== undefined) {
        const checkpoint = typeof resumeId === 'string' && CALCULATION_RESUME_ID.test(resumeId) ? checkpoints.get(resumeId) : undefined;
        if (!canReplay || !checkpoint || !sessionPresent || checkpoint.session.deref() !== session
          || checkpoint.directoryKey !== directoryKey || checkpoint.digest !== requestDigest(steps, candidates, resolvedInputs)) {
          throw new Error('续算编号失效或计算参数已变化。请使用同一会话和原计算参数，或重新开始。');
        }
        completed = [...checkpoint.completed];
      }
      const worker = createWorker({ steps, resolvedInputs, candidates, completed, trackProgress: canReplay });
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
          const timer = setTimeout(() => {
            try {
              if (completed.length > 0 && completed.length === steps.length) {
                if (resumeId !== undefined) checkpoints.delete(resumeId);
                complete(undefined, calculationReport(completed, candidates));
                return;
              }
              let id;
              if (completed.length > 0 && sessionPresent && !disposed) {
                id = resumeId ?? randomBytes(16).toString('hex');
                checkpoints.delete(id);
                checkpoints.set(id, {
                  session: new WeakRef(session), directoryKey, completed,
                  digest: requestDigest(steps, candidates, resolvedInputs),
                  expires: Date.now() + CHECKPOINT_TTL_MS,
                });
                if (checkpoints.size > MAX_CHECKPOINTS) checkpoints.delete(checkpoints.keys().next().value);
              }
              const partial = completed.length ? calculationReport(completed, candidates) : {};
              complete(undefined, {
                ...partial, status: 'timeout', budget_ms: budgetMs, completed_steps: completed.length,
                next_step: completed.length + 1, reason: '计算达到时间上限。',
                ...(id === undefined ? {} : { resume_id: id }),
              });
            } catch (error) {
              complete(error);
            }
          }, budgetMs);
          worker.on('error', error => complete(error));
          worker.once('exit', () => complete(new Error('CTF 计算进程已结束。')));
          worker.on('message', ({ report, error, step }) => {
            if (settled) return;
            if (step !== undefined) {
              completed.push(step);
              return;
            }
            if (error === undefined && resumeId !== undefined) checkpoints.delete(resumeId);
            complete(error === undefined ? undefined : new Error(error), report);
          });
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
      checkpoints.clear();
      for (const worker of running) void worker.terminate().catch(() => {});
    },
  };
}
