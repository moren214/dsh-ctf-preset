import { ToolError } from '../../core/contracts/errors.js';
import { apply as applyAdapter, Config as AdapterConfig } from '../../dsh-adapter/apply.js';
import { workspaceLocation } from '../../dsh-adapter/filesystem.js';
import { verifyExitCondition } from './exit-verifier.js';
import { buildAutonomousSystemPrompt } from './persona.js';
import { createSwarmScheduler } from './swarm-scheduler.js';

export const name = 'ctf-autonomous';
export const inject = ['tools', 'fs', 'workingDirectory', 'sandboxPolicy'];
export const Config = AdapterConfig;

/**
 * Autonomous / Multi-Agent Swarm preset entrypoint (isolated from presets/copilot/).
 */
export function apply(ctx, config = {}) {
  const effectiveConfig = () => {
    const resolved = typeof config === 'function' ? config() : (config ?? {});
    return {
      toolDomain: resolved.toolDomain ?? 'triage',
      skillMode: 'modular',
      ...resolved,
    };
  };

  const state = applyAdapter(ctx, effectiveConfig);
  const schedulerForCwd = cwd => createSwarmScheduler(state.runtime.getStateStore(cwd, { readOnly: false }));

  ctx.tools.register({
    name: 'ctf_swarm',
    description: '全自动赛马与多智能体调度器：创建 Best-of-N 赛马分支（plan_race）、互斥认领（claim）、赢家淘汰（cancel_losers）与预算检查（budget_check）。',
    parameters: {
      type: 'object',
      additionalProperties: false,
      required: ['action'],
      properties: {
        action: { type: 'string', enum: ['plan_race', 'claim', 'cancel_losers', 'status', 'budget_check'] },
        challenge: { type: 'string', maxLength: 120 },
        race_id: { type: 'string', maxLength: 64 },
        winner_intent_id: { type: 'string', maxLength: 32 },
        owner: { type: 'string', maxLength: 120 },
        budget_minutes: { type: 'integer', minimum: 1, maximum: 240 },
        steps: { type: 'integer', minimum: 0 },
        max_steps: { type: 'integer', minimum: 1 },
        elapsed_ms: { type: 'integer', minimum: 0 },
        timeout_ms: { type: 'integer', minimum: 1000 },
        branches: {
          type: 'array',
          minItems: 1,
          maxItems: 8,
          items: {
            type: 'object',
            additionalProperties: false,
            required: ['branch_id', 'title'],
            properties: {
              branch_id: { type: 'string', maxLength: 64 },
              title: { type: 'string', maxLength: 200 },
              priority: { type: 'integer', minimum: 1, maximum: 5 },
              hypothesis: { type: 'string', maxLength: 1000 },
            },
          },
        },
      },
    },
    output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: v }] },
    async execute(args, execution) {
      try {
        if (args.action === 'budget_check') {
          return JSON.stringify({
            status: 'ok',
            steps: args.steps ?? 0,
            max_steps: args.max_steps ?? 24,
            elapsed_ms: args.elapsed_ms ?? 0,
            timeout_ms: args.timeout_ms ?? 180000,
            ok: (args.steps ?? 0) < (args.max_steps ?? 24) && (args.elapsed_ms ?? 0) < (args.timeout_ms ?? 180000),
          });
        }
        const location = await workspaceLocation(ctx, execution);
        const scheduler = schedulerForCwd(location.cwd);
        if (args.action === 'plan_race') {
          if (!args.challenge || !args.race_id || !Array.isArray(args.branches)) {
            throw new ToolError('unsupported', 'plan_race 需要 challenge、race_id 与 branches。');
          }
          return JSON.stringify(await scheduler.planRace(args));
        }
        if (args.action === 'claim') {
          return JSON.stringify(await scheduler.claimBranch(args));
        }
        if (args.action === 'cancel_losers') {
          if (!args.race_id) throw new ToolError('unsupported', 'cancel_losers 需要 race_id。');
          return JSON.stringify(await scheduler.cancelLosers(args));
        }
        if (args.action === 'status') {
          return JSON.stringify(await scheduler.board({ challenge: args.challenge, summary_only: true }));
        }
        throw new ToolError('unsupported', `未知 action：${args.action}。`);
      } catch (error) {
        return JSON.stringify({ ok: false, error: { kind: error?.kind ?? 'other', message: error?.message ?? String(error) } });
      }
    },
  });

  ctx.tools.register({
    name: 'ctf_verify_exit',
    description: '全自动赛道机器可验证退出检查：校验 flag 非空/格式、证据来源及可选平台/本地复现结果，禁止未验证提前退出。',
    parameters: {
      type: 'object',
      additionalProperties: false,
      required: ['flag'],
      properties: {
        flag: { type: 'string', maxLength: 512 },
        pattern: { type: 'string', maxLength: 200 },
        source: { type: 'string', maxLength: 512 },
        evidence_ids: { type: 'array', maxItems: 32, items: { type: 'string', maxLength: 64 } },
        require_submission: { type: 'boolean' },
        submit_verdict: { type: 'string', enum: ['accepted', 'duplicate', 'rejected', 'unknown', 'rejected_local'] },
      },
    },
    output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: v }] },
    async execute(args) {
      try {
        const res = await verifyExitCondition({
          flag: args.flag,
          pattern: args.pattern,
          source: args.source,
          evidenceIds: args.evidence_ids,
          requireSubmission: args.require_submission === true,
          ...(args.submit_verdict ? { submitResult: { verdict: args.submit_verdict } } : {}),
        });
        return JSON.stringify(res);
      } catch (error) {
        return JSON.stringify({ ok: false, done: false, exit_code: 2, error: { kind: error?.kind ?? 'other', message: error?.message ?? String(error) } });
      }
    },
  });

  const prompt = ctx.get?.('systemPrompt');
  if (prompt && typeof prompt.context === 'function') {
    try {
      prompt.context({
        name: 'ctf-autonomous-persona',
        order: 890,
        text: buildAutonomousSystemPrompt(state.domainRouter.activeDomains(), { includeSkill: false }),
      });
    } catch {
      // Optional on older hosts.
    }
  }

  return { ...state, mode: 'autonomous' };
}
