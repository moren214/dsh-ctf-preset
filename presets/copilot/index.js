import { join } from 'node:path';
import { apply as applyAdapter, Config as AdapterConfig } from '../../dsh-adapter/apply.js';
import { pathParts, readWorkspaceFile, workspaceLocation } from '../../dsh-adapter/filesystem.js';
import { wrapWithApprovalGate } from './approval-gate.js';
import { buildCopilotSystemPrompt } from './persona.js';
import { buildTriageCard } from './triage-card.js';

export const name = 'ctf-copilot';
export const inject = ['tools', 'fs', 'workingDirectory', 'sandboxPolicy'];
export const Config = AdapterConfig;

/**
 * Human-AI Copilot preset entrypoint (isolated from presets/autonomous/).
 */
export function apply(ctx, config = {}) {
  const effectiveConfig = () => {
    const resolved = typeof config === 'function' ? config() : (config ?? {});
    return { skillMode: 'modular', ...resolved };
  };

  const getConfig = effectiveConfig;
  const wrappedCtx = {
    ...ctx,
    tools: {
      ...ctx.tools,
      register(toolDef) {
        return ctx.tools.register(wrapWithApprovalGate(toolDef, {
          requireApproval: getConfig()?.requireApproval !== false,
          getConfig,
        }));
      },
    },
  };

  const state = applyAdapter(wrappedCtx, effectiveConfig);

  ctx.tools.register({
    name: 'triage_card',
    description: 'Human-AI 协同首轮快速情报卡：检查魔数/SHA-256/ELF/领域分类并生成 3 条可接管下一步建议。',
    parameters: {
      type: 'object',
      additionalProperties: false,
      required: [],
      properties: {
        file_path: { type: 'string', description: '工作区目标附件相对路径。' },
        title: { type: 'string', maxLength: 300 },
        description: { type: 'string', maxLength: 4000 },
        url: { type: 'string', maxLength: 1024 },
        connection_info: { type: 'string', maxLength: 512 },
        files: { type: 'array', maxItems: 64, items: { type: 'string', maxLength: 260 } },
      },
    },
    output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: v }] },
    async execute(args = {}, execution) {
      const location = await workspaceLocation(ctx, execution);
      const card = await buildTriageCard({
        filePath: args.file_path,
        title: args.title,
        description: args.description,
        url: args.url,
        connectionInfo: args.connection_info,
        files: args.files,
        readFileBytes: async rel => (await readWorkspaceFile(ctx, pathParts(rel), location, 16 * 1024 * 1024)).bytes,
      });
      return JSON.stringify({ ...card, cwd: join(location.cwd) }, null, getConfig()?.compact === false ? 2 : 0);
    },
  });

  const prompt = ctx.get?.('systemPrompt');
  if (prompt && typeof prompt.context === 'function') {
    try {
      prompt.context({
        name: 'ctf-copilot-persona',
        order: 890,
        text: buildCopilotSystemPrompt(state.domainRouter.activeDomains(), { includeSkill: false }),
      });
    } catch {
      // Optional on older hosts.
    }
  }

  return { ...state, mode: 'copilot' };
}
