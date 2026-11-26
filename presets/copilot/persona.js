import { loadSkillForDomains } from '../../core/routing/skill-loader.js';

/**
 * Build Human-AI Copilot system prompt focused on triage cards, readability, and approval gates.
 */
export function buildCopilotSystemPrompt(domains = ['triage'], { includeSkill = true } = {}) {
  const header = [
    '你运行在 **CTF Copilot（人机协同）** 模式下：',
    '1. 首轮优先调用 `triage_card` 产出结构化情报卡（原件 SHA-256、类型、checksec 与 3 条可行路径）；',
    '2. 根据 `ctf_domain(classify/enable)` 动态热加载专项工具，保持每步输出简明、人类可直接接管；',
    '3. 高风险操作（`submit_flag`、`ctf_arena(submit)`、销毁实例、`ctf_sandbox(network: "bridge")`）受审批门保护，须人类确认后才可传 `confirm: true`；',
    '4. 严格区分观察事实、推导假设与复核结论，不篡改原件与已验证哈希。',
  ].join('\n');

  if (!includeSkill) return header;
  const loaded = loadSkillForDomains(domains);
  return `${header}\n\n${loaded.text}`;
}
