import { createRangeInspector } from '../attachment-ranges.js';
import { ToolError } from '../core/contracts/errors.js';
import { createToolExecutor } from '../core/runtime/tool-executor.js';
import { createCtfRuntime } from '../core/runtime/create-runtime.js';
import { createDomainRouter, resolveToolDomainSelection, shouldRegisterTool } from '../core/routing/ctf-router.js';
import { loadSkillForDomains } from '../core/routing/skill-loader.js';
import { platformCredential } from '../platform-request.js';
import { registerExtraTools } from '../extra-tools.js';
import { CONFIG_BOOLEAN_FIELDS, CONFIG_LIST_FIELDS, CONFIG_PATH_FIELDS, CONFIG_TEXT_FIELDS } from '../workbench-config.js';
import {
  checkedOutput,
  networkScopeFor,
  openWorkspaceFile,
  pathParts,
  persistResult,
  readWorkspaceFile,
  rewriteInputPaths,
  workspaceLocation,
} from './filesystem.js';
import { compactJson, registerCoreTools, resultSources } from './register-tools.js';
import { join } from 'node:path';

export const name = 'ctf-attachment-tools';
export const inject = ['tools', 'fs', 'workingDirectory', 'sandboxPolicy'];
export const Config = {
  '~standard': {
    version: 1,
    vendor: 'ctf-preset',
    validate(input) {
      const value = input ?? {};
      if (typeof value !== 'object' || Array.isArray(value)) return { issues: [{ message: 'CTF 配置须是对象。' }] };
      for (const field of CONFIG_PATH_FIELDS) {
        if (value[field] !== undefined && typeof value[field] !== 'string') {
          return { issues: [{ message: `${field} 须是本机路径。`, path: [field] }] };
        }
      }
      for (const field of CONFIG_TEXT_FIELDS) {
        if (value[field] !== undefined && typeof value[field] !== 'string') {
          return { issues: [{ message: `${field} 须是字符串。`, path: [field] }] };
        }
      }
      for (const field of CONFIG_LIST_FIELDS) {
        if (value[field] !== undefined && (!Array.isArray(value[field])
          || value[field].some(item => typeof item !== 'string' || item.length === 0))) {
          return { issues: [{ message: field + ' 须是字符串数组。', path: [field] }] };
        }
      }
      for (const field of CONFIG_BOOLEAN_FIELDS) {
        if (value[field] !== undefined && typeof value[field] !== 'boolean') {
          return { issues: [{ message: `${field} 须是布尔值。`, path: [field] }] };
        }
      }
      return { value };
    },
  },
};

export function apply(ctx, config) {
  const runtime = createCtfRuntime({ config });
  const workbench = runtime.workbench;
  const currentConfig = runtime.getConfig;
  const domainSelection = resolveToolDomainSelection(currentConfig());
  const domainRouter = createDomainRouter({ initialDomain: currentConfig().toolDomain ?? 'all' });
  const inspectRanges = createRangeInspector(ctx.fs);

  const deferredToolDefs = new Map();
  const registeredToolNames = new Set();
  const registerToolDef = def => {
    if (registeredToolNames.has(def.name)) return false;
    registeredToolNames.add(def.name);
    ctx.tools.register(def);
    return true;
  };
  const deferToolDef = def => {
    if (!registeredToolNames.has(def.name)) deferredToolDefs.set(def.name, def);
  };

  const prompt = ctx.get?.('systemPrompt');
  const buildPromptText = domains => {
    const baseText = '本题工作区可能有 .ctf-graph/（优先用 ctf_graph board 查共享事实与待办任务）、notes.md（续接记录）、handoff.md（接替简报）、.ctf-status.json（时间盒心跳）和 .ctf-submissions.jsonl（提交回执）：开始或接手时先读它们，再决定下一步。';
    if (currentConfig().skillMode === 'modular') {
      return `${baseText}\n\n${loadSkillForDomains(domains).text}`;
    }
    return baseText;
  };

  function expandDomains(domainInput) {
    const res = domainRouter.enableDomain(domainInput);
    const newlyRegistered = [];
    for (const [toolName, def] of deferredToolDefs.entries()) {
      if (domainRouter.isToolAllowed(toolName) && registerToolDef(def)) {
        deferredToolDefs.delete(toolName);
        newlyRegistered.push(toolName);
      }
    }
    if (prompt && typeof prompt.context === 'function' && currentConfig().skillMode === 'modular') {
      try {
        prompt.context({
          name: 'ctf-resume-hint',
          order: 900,
          text: buildPromptText(domainRouter.activeDomains()),
        });
      } catch {
        // Older hosts may not expose mutable prompt context updates.
      }
    }
    return {
      status: 'ok',
      active_domains: res.domains,
      added_domains: res.added_domains,
      registered_tools: newlyRegistered,
      total_registered_tools: registeredToolNames.size,
      skill_loaded: loadSkillForDomains(res.domains).files,
    };
  }

  const executor = createToolExecutor({
    runtime,
    shouldRegisterTool: toolName => domainRouter.isToolAllowed(toolName),
    normalizePath: value => pathParts(value).join('/'),
    resolveLocation: execution => workspaceLocation(ctx, execution),
    rewriteInputPaths: (args, location, execution) => rewriteInputPaths(ctx, args, location, execution, currentConfig()),
    persistResult: (location, execution, resultId, result) => persistResult(ctx, location, execution, resultId, result),
    resultSources,
    compactJson,
    registerTarget: registerToolDef,
    deferTarget: deferToolDef,
  });
  ctx.effect(() => () => runtime.dispose(), 'CTF Core Runtime disposal');

  const extendedAudit = currentConfig().enableExtendedAudit === true;
  const regState = registerCoreTools({
    ctx,
    runtime,
    executor,
    domainSelection,
    domainRouter,
    expandDomains,
    registeredToolNames,
    workbench,
    inspectRanges,
    extendedAudit,
  });

  registerExtraTools(undefined, currentConfig, {
    extendedAudit,
    domainSelection,
    gdbSessions: runtime.gdbSessions,
    browserSessions: runtime.browserSessions,
    browsers: runtime.browsers,
    onDispose: fn => ctx.effect?.(() => fn, 'CTF extra tool resource'),
    requireWritable(execution) {
      const policy = ctx.sandboxPolicy?.resolve?.({ session: execution?.agent?.session });
      if (policy?.mode === 'read-only') throw new ToolError('permission', '当前会话是只读权限，无法写入文件。');
    },
    register(toolName, description, properties, run, required, workspace = true) {
      const binding = workspace
        ? (['gdb_driver', 'archive_crack', 'stego_audio', 'mobile_apk'].includes(toolName)
          ? regState.fileMatResults
          : regState.fileResults)
        : regState.sessionResults;
      return executor(toolName, description, properties, run, required, binding);
    },
    location: execution => workspaceLocation(ctx, execution),
    async input(location, inputPath) {
      const parts = pathParts(inputPath);
      await openWorkspaceFile(ctx, parts, location);
      return join(location.cwd, ...parts);
    },
    read: (location, inputPath, limit) => readWorkspaceFile(ctx, pathParts(inputPath), location, limit),
    output: (location, inputPath, directory) => checkedOutput(ctx, location, inputPath, directory),
    python: signal => workbench.resolvePython(signal),
    authorize: (url, signal, execution, location) => runtime.networkBoundary.http(url, signal,
      networkScopeFor(execution, location ?? { directoryKey: undefined })),
    platformToken: () => platformCredential(currentConfig()).token,
  });

  if (prompt && typeof prompt.context === 'function') {
    try {
      prompt.context({
        name: 'ctf-resume-hint',
        order: 900,
        text: buildPromptText(domainRouter.activeDomains()),
      });
    } catch {
      // Older hosts may not expose the system prompt service; SKILL.md carries the same rule.
    }
  }

  return { runtime, domainRouter, expandDomains, registeredToolNames, deferredToolDefs };
}
