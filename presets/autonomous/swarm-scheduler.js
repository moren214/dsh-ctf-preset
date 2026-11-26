import { manageGraphInStore } from '../../ctf-graph.js';
import { ToolError } from '../../core/contracts/errors.js';

/**
 * Multi-agent Best-of-N Swarm scheduler built on SQLite StateStore (atomic WAL + leases).
 */
export function createSwarmScheduler(stateStore, { defaultOwner = 'swarm' } = {}) {
  if (!stateStore) {
    throw new ToolError('dependency', 'createSwarmScheduler 需要有效 StateStore 实例。');
  }

  return {
    async planRace({ challenge, race_id, branches, budget_minutes = 15, owner }) {
      return manageGraphInStore({
        action: 'start_race',
        challenge,
        race_id,
        branches,
        budget_minutes,
        owner: owner ?? defaultOwner,
      }, stateStore, { defaultOwner });
    },

    async claimBranch({ challenge, intent_id, owner, budget_minutes }) {
      return manageGraphInStore({
        action: 'claim_intent',
        ...(intent_id ? { intent_id } : { next: true, challenge }),
        owner: owner ?? defaultOwner,
        ...(budget_minutes ? { budget_minutes } : {}),
      }, stateStore, { defaultOwner });
    },

    async completeBranch({ intent_id, lease_id, owner, outcome = 'done', summary, produced_facts }) {
      return manageGraphInStore({
        action: 'finish_intent',
        intent_id,
        lease_id,
        owner: owner ?? defaultOwner,
        outcome,
        summary,
        ...(produced_facts ? { produced_facts } : {}),
      }, stateStore, { defaultOwner });
    },

    async cancelLosers({ race_id, winner_intent_id, reason = 'superseded_by_winner' }) {
      return manageGraphInStore({
        action: 'cancel_race_siblings',
        race_id,
        ...(winner_intent_id ? { winner_intent_id } : {}),
        outcome: reason,
      }, stateStore, { defaultOwner });
    },

    async board({ challenge, summary_only = false } = {}) {
      return manageGraphInStore({
        action: 'board',
        ...(challenge ? { challenge } : {}),
        summary_only,
      }, stateStore, { defaultOwner });
    },

    checkBudget({ steps = 0, maxSteps = 24, elapsedMs = 0, timeoutMs = 180000 } = {}) {
      const stepsExhausted = steps >= maxSteps;
      const timedOut = elapsedMs >= timeoutMs;
      return {
        ok: !stepsExhausted && !timedOut,
        steps,
        max_steps: maxSteps,
        remaining_steps: Math.max(0, maxSteps - steps),
        elapsed_ms: elapsedMs,
        timeout_ms: timeoutMs,
        remaining_ms: Math.max(0, timeoutMs - elapsedMs),
        reason: timedOut ? 'timeout' : stepsExhausted ? 'step_budget_exhausted' : 'within_budget',
      };
    },

    async runParallelBranches(branches, workerFn, { concurrency = 3, signal } = {}) {
      const list = Array.isArray(branches) ? branches : [];
      const results = new Array(list.length);
      let nextIdx = 0;
      let winner = null;
      const controller = new AbortController();
      const combined = signal ? AbortSignal.any([signal, controller.signal]) : controller.signal;

      async function workerLoop() {
        while (nextIdx < list.length && !combined.aborted) {
          const i = nextIdx++;
          const branch = list[i];
          try {
            const res = await workerFn(branch, combined);
            results[i] = res;
            if (res?.verified === true && !winner) {
              winner = { index: i, branch, result: res };
              controller.abort(new ToolError('abort', 'Best-of-N winner verified'));
              return;
            }
          } catch (error) {
            results[i] = { ok: false, error: error?.message ?? String(error) };
          }
        }
      }

      const workers = Array.from({ length: Math.min(Math.max(1, concurrency), list.length || 1) }, () => workerLoop());
      await Promise.allSettled(workers);
      return { winner, results };
    },
  };
}
