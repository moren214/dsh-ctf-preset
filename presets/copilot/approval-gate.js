import { describeToolError, ToolError } from '../../core/contracts/errors.js';

const ALWAYS_GUARDED = new Set(['submit_flag']);

/**
 * Evaluate whether a tool call requires explicit human confirmation (`confirm: true`).
 */
export function evaluateApprovalGate(toolName, args = {}) {
  let actionLabel;
  if (ALWAYS_GUARDED.has(toolName)) {
    actionLabel = `正式提交 flag（challenge=${args.challenge ?? '默认'}）`;
  } else if (toolName === 'ctf_arena' && args?.action === 'submit') {
    actionLabel = `向竞赛平台提交 flag（challenge_id=${args.challenge_id ?? args.challenge ?? '未知'}）`;
  } else if (toolName === 'ctf_instance' && ['delete', 'rotate'].includes(args?.action)) {
    actionLabel = `变更或销毁靶机实例（action=${args.action}, id=${args.id ?? '默认'}）`;
  } else if (toolName === 'ctf_sandbox' && args?.network === 'bridge') {
    actionLabel = `开启沙箱 bridge 网络访问（command/script=${args.command ? 'inline' : args.script_path ?? 'n/a'}）`;
  }

  if (!actionLabel) return { guarded: false };
  if (args?.confirm === true) return { guarded: true, approved: true, preview: actionLabel };
  return { guarded: true, approved: false, preview: actionLabel };
}

/**
 * Enforce approval synchronously; throws structured ToolError('permission') when unconfirmed.
 */
export function assertApproved(toolName, args = {}, { requireApproval = true } = {}) {
  const verdict = evaluateApprovalGate(toolName, args);
  if (!requireApproval || !verdict.guarded || verdict.approved) return verdict;
  throw new ToolError(
    'permission',
    `Copilot 审批门拦截：${verdict.preview}。请先向人类确认风险与参数，再附带 confirm: true 重新调用。`,
    '向人类展示操作摘要并确认后，传 confirm: true 重新执行。',
  );
}

/**
 * Wrap a tool definition with Copilot human-confirmation gating on high-impact operations.
 */
export function wrapWithApprovalGate(toolDef, { requireApproval = true, getConfig } = {}) {
  const isMaybeGuarded = ALWAYS_GUARDED.has(toolDef.name)
    || ['ctf_arena', 'ctf_instance', 'ctf_sandbox'].includes(toolDef.name);
  if (!isMaybeGuarded) return toolDef;

  const baseProps = toolDef.parameters?.properties ?? {};
  const wrappedParams = {
    ...(toolDef.parameters ?? { type: 'object', additionalProperties: false, required: [] }),
    properties: {
      ...baseProps,
      confirm: {
        type: 'boolean',
        description: 'Copilot 高风险操作人类确认开关（正式提交/销毁实例/沙箱联网须明确传 true）。',
      },
    },
  };

  const origExecute = toolDef.execute;
  return {
    ...toolDef,
    parameters: wrappedParams,
    async execute(args, execution) {
      const enabled = typeof getConfig === 'function' ? getConfig()?.requireApproval !== false : requireApproval;
      const verdict = evaluateApprovalGate(toolDef.name, args);
      if (enabled && verdict.guarded && !verdict.approved) {
        const err = new ToolError(
          'permission',
          `Copilot 审批门拦截：${verdict.preview}。请向用户确认后附带 confirm: true 重试。`,
          '确认后传 confirm: true 重试。',
        );
        return JSON.stringify({
          ok: false,
          approval_required: true,
          tool: toolDef.name,
          preview: verdict.preview,
          error: describeToolError(err),
        });
      }
      if (args && typeof args === 'object' && Object.hasOwn(args, 'confirm')) {
        const { confirm: _stripped, ...forwardArgs } = args;
        return origExecute(forwardArgs, execution);
      }
      return origExecute(args, execution);
    },
  };
}
