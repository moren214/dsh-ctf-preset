import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import path, { resolve } from 'node:path';
import { createCtfRuntime } from '../core/runtime/create-runtime.js';
import { ToolError, describeToolError } from '../core/contracts/errors.js';
import { classifyChallengeDomain, createDomainRouter } from '../core/routing/ctf-router.js';
import { runSandbox, SANDBOX_PROPERTIES } from '../core/sandbox/sandbox-runner.js';
import { inspectAttachment } from '../attachment.js';
import { inspectElf } from '../elf.js';
import { runCryptoSolve } from '../crypto-toolbox.js';
import { cyclicPattern, PWN_PATTERN_PROPERTIES } from '../pwn-pattern.js';
import { buildPwnPayload, PWN_PAYLOAD_PROPERTIES } from '../pwn-payload.js';
import { GRAPH_PROPERTIES, manageGraphInStore } from '../ctf-graph.js';
import { verifyExitCondition } from '../presets/autonomous/exit-verifier.js';
import { createSwarmScheduler } from '../presets/autonomous/swarm-scheduler.js';

function resolveInside(rootDir, relPath) {
  if (typeof relPath !== 'string' || !relPath.trim()) {
    throw new ToolError('path', '必须提供非空相对文件路径。');
  }
  const absRoot = resolve(rootDir);
  const absTarget = resolve(absRoot, relPath);
  const rel = path.relative(absRoot, absTarget);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new ToolError('path', `路径越界：${relPath} 超出题目工作区。`);
  }
  return absTarget;
}

/**
 * Cordis-free headless tool registry powering the Autonomous Competition Runner.
 */
export function createHeadlessToolRegistry({ challengeDir, config = {}, verifyFlag } = {}) {
  if (!challengeDir || !existsSync(challengeDir)) {
    throw new ToolError('missing', `题目工作目录不存在：${challengeDir}`);
  }
  const absDir = resolve(challengeDir);
  const runtime = createCtfRuntime({
    config: () => ({
      sandboxBackend: process.env.CTF_SANDBOX_BACKEND ?? config.sandboxBackend ?? 'auto',
      ...config,
    }),
  });
  const router = createDomainRouter({ initialDomain: config.toolDomain ?? 'triage' });
  const activeTools = new Map();
  const deferredTools = new Map();
  const evidenceLedger = new Map();

  function register(name, description, parameters, handler) {
    const def = { name, description, parameters, handler };
    if (router.isToolAllowed(name) || ['ctf_swarm', 'ctf_verify_exit'].includes(name)) {
      activeTools.set(name, def);
    } else {
      deferredTools.set(name, def);
    }
  }

  register('ctf_domain', 'Query, classify, or dynamically enable challenge domains.', {
    type: 'object',
    required: ['action'],
    properties: {
      action: { type: 'string', enum: ['status', 'classify', 'enable'] },
      domain: { anyOf: [{ type: 'string' }, { type: 'array', items: { type: 'string' } }] },
      title: { type: 'string' },
      description: { type: 'string' },
      files: { type: 'array', items: { type: 'string' } },
      url: { type: 'string' },
    },
  }, async args => {
    if (args.action === 'status') return { status: 'ok', ...router.status(), registered_tools: activeTools.size };
    if (args.action === 'classify') return { status: 'ok', ...classifyChallengeDomain(args) };
    if (args.action === 'enable') {
      const res = router.enableDomain(args.domain);
      const added = [];
      for (const [k, def] of deferredTools.entries()) {
        if (router.isToolAllowed(k)) {
          deferredTools.delete(k);
          activeTools.set(k, def);
          added.push(k);
        }
      }
      return { status: 'ok', active_domains: res.domains, added_domains: res.added_domains, registered_tools: added };
    }
    throw new ToolError('unsupported', `未知 action: ${args.action}`);
  });

  register('inspect_attachment', 'Inspect attachment structure, type, and SHA-256.', {
    type: 'object',
    required: ['file_path'],
    properties: { file_path: { type: 'string' } },
  }, async args => {
    const target = resolveInside(absDir, args.file_path);
    const bytes = await readFile(target);
    return inspectAttachment(bytes, { size: bytes.length, filePath: args.file_path });
  });

  register('read_binary_range', 'Read byte window from a workspace file (UTF-8 / Hex preview).', {
    type: 'object',
    required: ['file_path'],
    properties: {
      file_path: { type: 'string' },
      byte_offset: { type: 'integer', minimum: 0 },
      byte_length: { type: 'integer', minimum: 1, maximum: 65536 },
      encoding: { type: 'string', enum: ['utf8', 'hex', 'base64'] },
    },
  }, async args => {
    const target = resolveInside(absDir, args.file_path);
    const bytes = await readFile(target);
    const off = args.byte_offset ?? 0;
    const len = Math.min(args.byte_length ?? 4096, Math.max(0, bytes.length - off));
    const slice = bytes.subarray(off, off + len);
    const enc = args.encoding ?? 'utf8';
    return {
      status: 'ok',
      file: args.file_path,
      byte_offset: off,
      byte_length: slice.length,
      total_size: bytes.length,
      text: slice.toString(enc === 'hex' ? 'hex' : enc === 'base64' ? 'base64' : 'utf8'),
    };
  });

  register('inspect_elf', 'Inspect ELF headers, checksec, imports, PLT/GOT, and symbols.', {
    type: 'object',
    required: ['file_path'],
    properties: { file_path: { type: 'string' } },
  }, async args => {
    const target = resolveInside(absDir, args.file_path);
    const bytes = await readFile(target);
    return inspectElf(bytes);
  });

  register('pwn_cyclic', 'Generate or locate pwntools De Bruijn pattern.', {
    type: 'object',
    required: ['operation'],
    properties: PWN_PATTERN_PROPERTIES,
  }, async args => cyclicPattern(args));

  register('pwn_payload', 'Build bounded x86-64 ROP / ret2libc payload.', {
    type: 'object',
    required: ['operation'],
    properties: PWN_PAYLOAD_PROPERTIES,
  }, async args => buildPwnPayload(args));

  register('crypto_solver', 'Built-in zero-dependency CTF crypto solver (JWT/Flask/LCG/MT19937).', {
    type: 'object',
    required: ['operation'],
    properties: {
      operation: { type: 'string' },
      token: { type: 'string' },
      salt: { type: 'string' },
      crack: { type: 'boolean' },
      passwords: { type: 'array', items: { type: 'string' } },
      outputs: { type: 'array', items: { anyOf: [{ type: 'string' }, { type: 'integer' }] } },
      modulus: { anyOf: [{ type: 'string' }, { type: 'integer' }] },
      predict_count: { type: 'integer' },
    },
  }, async args => runCryptoSolve({ action: 'solve', ...args }, { signal: undefined }));

  register('ctf_sandbox', 'Execute isolated scripts/commands or ELF decompilation inside Linux sandbox.', {
    type: 'object',
    required: ['action'],
    properties: SANDBOX_PROPERTIES,
  }, async (args, execCtx) => {
    const store = runtime.getStateStore(absDir, { readOnly: false });
    return runSandbox(args, {
      cwd: absDir,
      config: runtime.getConfig(),
      signal: execCtx?.signal,
      writable: true,
      sandboxPool: runtime.sandboxPool,
      detectCache: runtime.detectCache,
      networkBoundary: runtime.networkBoundary,
      networkScope: { session: { id: 'runner' }, workspaceKey: absDir, stateStore: store },
    });
  });

  register('ctf_graph', 'SQLite-backed Fact-Intent graph & Best-of-N race coordination.', {
    type: 'object',
    required: ['action'],
    properties: GRAPH_PROPERTIES,
  }, async args => {
    const store = runtime.getStateStore(absDir, { readOnly: false });
    return manageGraphInStore(args, store, { defaultOwner: 'runner' });
  });

  register('ctf_swarm', 'Autonomous Best-of-N swarm branch scheduler.', {
    type: 'object',
    required: ['action'],
    properties: {
      action: { type: 'string', enum: ['plan_race', 'claim', 'cancel_losers', 'status'] },
      challenge: { type: 'string' },
      race_id: { type: 'string' },
      winner_intent_id: { type: 'string' },
      owner: { type: 'string' },
      branches: { type: 'array', items: { type: 'object' } },
    },
  }, async args => {
    const scheduler = createSwarmScheduler(runtime.getStateStore(absDir, { readOnly: false }));
    if (args.action === 'plan_race') return scheduler.planRace(args);
    if (args.action === 'claim') return scheduler.claimBranch(args);
    if (args.action === 'cancel_losers') return scheduler.cancelLosers(args);
    if (args.action === 'status') return scheduler.board({ challenge: args.challenge, summary_only: true });
    throw new ToolError('unsupported', `未知 swarm action: ${args.action}`);
  });

  register('ctf_verify_exit', 'Verify candidate flag format and provenance before exiting.', {
    type: 'object',
    required: ['flag'],
    properties: {
      flag: { type: 'string' },
      pattern: { type: 'string' },
      source: { type: 'string' },
      evidence_ids: { type: 'array', items: { type: 'string', pattern: '^[a-f0-9]{64}$' } },
    },
  }, async (args, execCtx) => verifyExitCondition({
    flag: args.flag,
    pattern: args.pattern,
    source: args.source,
    evidenceIds: args.evidence_ids,
    resolveEvidence: id => evidenceLedger.get(id),
    ...(typeof verifyFlag === 'function' ? {
      localVerifyFn: flag => verifyFlag(flag, { challengeDir: absDir, signal: execCtx?.signal }),
    } : {}),
  }));

  async function executeTool(name, args = {}, { signal } = {}) {
    const tool = activeTools.get(name);
    if (!tool) {
      return {
        ok: false,
        error: describeToolError(new ToolError('missing', `工具 ${name} 尚未加载（当前激活域：${router.activeDomains().join(', ')}）。请先调用 ctf_domain(enable) 激活对应域。`)),
      };
    }
    try {
      const result = await tool.handler(args ?? {}, { signal });
      if (name === 'ctf_verify_exit') return result;
      const serialized = JSON.stringify(result);
      const resultId = createHash('sha256').update(name).update('\0').update(serialized ?? 'undefined').digest('hex');
      evidenceLedger.set(resultId, { tool: name, report: result });
      while (evidenceLedger.size > 128) evidenceLedger.delete(evidenceLedger.keys().next().value);
      return result !== null && typeof result === 'object' && !Array.isArray(result)
        ? { ...result, result_id: resultId }
        : { result_id: resultId, result };
    } catch (error) {
      return { ok: false, error: describeToolError(error) };
    }
  }

  return {
    runtime,
    router,
    activeTools,
    deferredTools,
    listToolSchemas: () => [...activeTools.values()].map(t => ({
      type: 'function',
      function: { name: t.name, description: t.description, parameters: t.parameters },
    })),
    executeTool,
    resolveEvidence: id => evidenceLedger.get(id),
    dispose: () => runtime.dispose(),
  };
}
