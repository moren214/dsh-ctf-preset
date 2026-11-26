import { appendFile, writeFile } from 'node:fs/promises';
import { ToolError, describeToolError } from '../core/contracts/errors.js';
import { verifyExitCondition } from '../presets/autonomous/exit-verifier.js';
import { buildAutonomousSystemPrompt } from '../presets/autonomous/persona.js';
import { createHeadlessToolRegistry } from './tool-registry.js';

async function traceEvent(tracePath, event) {
  if (!tracePath) return;
  await appendFile(tracePath, JSON.stringify({ at: new Date().toISOString(), ...event }) + '\n', 'utf8');
}

async function callChatCompletions({ baseUrl, apiKey, model, messages, tools, signal }) {
  const endpoint = `${baseUrl.replace(/\/$/u, '')}/chat/completions`;
  const res = await fetch(endpoint, {
    method: 'POST',
    signal,
    headers: {
      'content-type': 'application/json',
      ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}),
    },
    body: JSON.stringify({
      model,
      messages,
      tools,
      tool_choice: 'auto',
    }),
  });
  const text = await res.text();
  if (!res.ok) {
    throw new ToolError('network', `LLM 接口返回 HTTP ${res.status}: ${text.slice(0, 500)}`, '检查 --base-url、--model 与 API Key。', { status: res.status });
  }
  return JSON.parse(text);
}

/**
 * Run headless Autonomous CTF solver loop (supports live OpenAI-compatible APIs and offline mockPlan).
 */
export async function runAutonomousSolver({
  challengeDir,
  prompt = 'Solve this CTF challenge and verify the flag.',
  model = process.env.CTF_MODEL ?? 'deepseek-chat',
  baseUrl = process.env.OPENAI_BASE_URL ?? 'https://api.deepseek.com/v1',
  apiKey = process.env.OPENAI_API_KEY ?? process.env.DEEPSEEK_API_KEY,
  maxSteps = 24,
  timeoutMs = 180_000,
  mockPlan,
  tracePath,
  outputPath,
  signal,
  config = {},
} = {}) {
  const startedAt = Date.now();
  const timeoutCtrl = new AbortController();
  const timer = setTimeout(() => timeoutCtrl.abort(new ToolError('timeout', `Runner 超时（${timeoutMs}ms）。`)), timeoutMs);
  const runSignal = signal ? AbortSignal.any([signal, timeoutCtrl.signal]) : timeoutCtrl.signal;

  const registry = createHeadlessToolRegistry({ challengeDir, config });
  let steps = 0;

  const finalize = async result => {
    clearTimeout(timer);
    if (outputPath) {
      await writeFile(outputPath, JSON.stringify(result, null, 2) + '\n', 'utf8').catch(() => {});
    }
    await registry.dispose().catch(() => {});
    return result;
  };

  try {
    if (Array.isArray(mockPlan)) {
      let lastFlagCandidate;
      let lastSource = 'mock_plan';
      for (const action of mockPlan) {
        if (runSignal.aborted) throw runSignal.reason ?? new ToolError('timeout', 'Runner aborted');
        if (steps >= maxSteps) {
          return await finalize({
            status: 'budget_exhausted',
            exit_code: 2,
            steps,
            elapsed_ms: Date.now() - startedAt,
            active_domains: registry.router.activeDomains(),
          });
        }
        if (action.tool) {
          steps += 1;
          const out = await registry.executeTool(action.tool, action.args ?? {}, { signal: runSignal });
          await traceEvent(tracePath, { step: steps, tool: action.tool, args: action.args, out });
          if (action.tool === 'ctf_verify_exit' && out?.done === true) {
            return await finalize({
              status: 'solved',
              exit_code: 0,
              flag: out.verified_flag,
              verified_flag_sha256: out.verified_flag_sha256,
              verified: true,
              steps,
              elapsed_ms: Date.now() - startedAt,
              active_domains: registry.router.activeDomains(),
              ...(tracePath ? { trace_path: tracePath } : {}),
            });
          }
          if (typeof out?.flag === 'string') lastFlagCandidate = out.flag;
          if (typeof action.args?.flag === 'string') lastFlagCandidate = action.args.flag;
        } else if (action.finish) {
          const check = await verifyExitCondition({
            flag: action.finish.flag ?? lastFlagCandidate,
            pattern: action.finish.pattern,
            source: action.finish.source ?? lastSource,
            evidenceIds: action.finish.evidence_ids,
          });
          await traceEvent(tracePath, { step: steps, finish: check });
          return await finalize({
            status: check.done ? 'solved' : 'unverified',
            exit_code: check.done ? 0 : 2,
            ...(check.done ? { flag: check.verified_flag } : {}),
            verified: check.done,
            checks: check.checks,
            reason: check.reason,
            steps,
            elapsed_ms: Date.now() - startedAt,
            active_domains: registry.router.activeDomains(),
            ...(tracePath ? { trace_path: tracePath } : {}),
          });
        }
      }
      return await finalize({
        status: 'unverified',
        exit_code: 2,
        verified: false,
        steps,
        elapsed_ms: Date.now() - startedAt,
        active_domains: registry.router.activeDomains(),
      });
    }

    if (!apiKey) {
      throw new ToolError('dependency', '未配置 OPENAI_API_KEY / DEEPSEEK_API_KEY，且未提供 --mock-plan。');
    }

    const messages = [
      { role: 'system', content: buildAutonomousSystemPrompt(registry.router.activeDomains()) },
      { role: 'user', content: `Workspace: ${challengeDir}\nTask: ${prompt}` },
    ];

    while (steps < maxSteps) {
      if (runSignal.aborted) throw runSignal.reason ?? new ToolError('timeout', 'Runner aborted');
      steps += 1;
      const completion = await callChatCompletions({
        baseUrl,
        apiKey,
        model,
        messages,
        tools: registry.listToolSchemas(),
        signal: runSignal,
      });
      const msg = completion?.choices?.[0]?.message;
      if (!msg) throw new ToolError('network', 'LLM 响应缺少 choices[0].message。');
      messages.push(msg);

      const toolCalls = Array.isArray(msg.tool_calls) ? msg.tool_calls : [];
      if (toolCalls.length === 0) {
        const candidateMatch = /[A-Za-z0-9_]{1,24}\{[^{}\r\n]{4,256}\}/u.exec(msg.content ?? '');
        const check = await verifyExitCondition({ flag: candidateMatch?.[0], source: 'llm_final_message' });
        await traceEvent(tracePath, { step: steps, final_check: check });
        if (check.done) {
          return await finalize({
            status: 'solved',
            exit_code: 0,
            flag: check.verified_flag,
            verified_flag_sha256: check.verified_flag_sha256,
            verified: true,
            steps,
            elapsed_ms: Date.now() - startedAt,
            active_domains: registry.router.activeDomains(),
          });
        }
        return await finalize({
          status: 'unverified',
          exit_code: 2,
          verified: false,
          reason: check.reason,
          steps,
          elapsed_ms: Date.now() - startedAt,
          active_domains: registry.router.activeDomains(),
        });
      }

      for (const tc of toolCalls) {
        let parsedArgs = {};
        try { parsedArgs = JSON.parse(tc.function?.arguments || '{}'); } catch { /* ignore */ }
        const out = await registry.executeTool(tc.function?.name, parsedArgs, { signal: runSignal });
        await traceEvent(tracePath, { step: steps, tool: tc.function?.name, args: parsedArgs, out });
        messages.push({ role: 'tool', tool_call_id: tc.id, content: JSON.stringify(out) });
        if (tc.function?.name === 'ctf_verify_exit' && out?.done === true) {
          return await finalize({
            status: 'solved',
            exit_code: 0,
            flag: out.verified_flag,
            verified_flag_sha256: out.verified_flag_sha256,
            verified: true,
            steps,
            elapsed_ms: Date.now() - startedAt,
            active_domains: registry.router.activeDomains(),
          });
        }
      }
    }

    return await finalize({
      status: 'budget_exhausted',
      exit_code: 2,
      verified: false,
      steps,
      elapsed_ms: Date.now() - startedAt,
      active_domains: registry.router.activeDomains(),
    });
  } catch (error) {
    const desc = describeToolError(error);
    return await finalize({
      status: desc.kind === 'timeout' ? 'timeout' : 'error',
      exit_code: desc.kind === 'timeout' ? 2 : 1,
      verified: false,
      error: desc,
      steps,
      elapsed_ms: Date.now() - startedAt,
      active_domains: registry.router.activeDomains(),
    });
  }
}
