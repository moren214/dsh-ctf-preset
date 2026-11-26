import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { apply as applyCopilot } from '../presets/copilot/index.js';
import { buildTriageCard } from '../presets/copilot/triage-card.js';
import { apply as applyAutonomous } from '../presets/autonomous/index.js';
import { verifyExitCondition } from '../presets/autonomous/exit-verifier.js';
import { createSwarmScheduler } from '../presets/autonomous/swarm-scheduler.js';
import { createStateStore } from '../core/index.js';

function makeMockCtx(cwd) {
  const tools = new Map();
  const base = cwd.replaceAll('\\', '/').replace(/\/$/u, '');
  const resolveTarget = (name, opts = {}) => {
    const clean = name.replaceAll('\\', '/').replace(/\/$/u, '');
    if (opts.cwd === undefined && clean === base) return { targetKey: base, displayPath: base };
    const root = (opts.cwd ?? cwd).replaceAll('\\', '/').replace(/\/$/u, '');
    return { targetKey: `${root}/${clean}`, displayPath: name };
  };
  const fsSync = import('node:fs/promises');
  const prompts = [];
  const ctx = {
    tools: { register(def) { tools.set(def.name, def); } },
    effect() {},
    emit() {},
    get(svc) {
      if (svc === 'systemPrompt') return { context(entry) { prompts.push(entry); } };
      return undefined;
    },
    workingDirectory: { async ensure() { return cwd; } },
    sandboxPolicy: { resolve() { return { mode: 'workspace-write' }; } },
    fs: {
      async resolve(name, opts) { return resolveTarget(name, opts); },
      contains(a, b) { return b.targetKey.startsWith(a.targetKey); },
      async lstat(name, opts) {
        const rel = resolveTarget(name, opts).targetKey.slice(base.length + 1);
        const { lstat } = await fsSync;
        try { const s = await lstat(join(cwd, rel)); return { type: s.isDirectory() ? 'directory' : 'file' }; } catch { return undefined; }
      },
      async stat(target) {
        const rel = target.targetKey.slice(base.length + 1);
        const { stat } = await fsSync;
        try { const s = await stat(join(cwd, rel)); return { type: s.isDirectory() ? 'directory' : 'file', size: s.size, version: String(s.mtimeMs) }; } catch { return null; }
      },
      async readBytes(target) { return readFile(join(cwd, target.targetKey.slice(base.length + 1))); },
      async writeText(target, text) {
        const rel = target.targetKey.slice(base.length + 1);
        const { mkdir } = await fsSync;
        const abs = join(cwd, rel);
        await mkdir(join(abs, '..'), { recursive: true });
        await writeFile(abs, text, 'utf8');
        return { version: String(Date.now()) };
      },
    },
  };
  return {
    ctx,
    tools,
    prompts,
    execution: { signal: new AbortController().signal, agent: { session: { id: 'preset-test', header: { cwd } } } },
  };
}

test('CTF Copilot preset: registers triage_card and enforces approval-gate on dangerous tools', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'ctf-copilot-'));
  let state;
  try {
    await writeFile(join(cwd, 'vuln.bin'), Buffer.from('\x7fELF\x02\x01\x01\x00' + '\0'.repeat(56), 'latin1'));
    const { ctx, tools, execution } = makeMockCtx(cwd);
    state = applyCopilot(ctx, {});
    assert.equal(state.mode, 'copilot');
    assert.ok(tools.has('triage_card'));

    const card = JSON.parse(await tools.get('triage_card').execute({
      file_path: 'vuln.bin',
      title: 'EzStack',
      description: 'stack overflow pwn with libc.so.6',
      connection_info: 'nc pwn.ctf.local 1337',
    }, execution));
    assert.equal(card.status, 'ok');
    assert.equal(card.primary_domain, 'pwn');
    assert.equal(card.magic, 'elf');
    assert.match(card.markdown, /情报卡/u);

    const standalone = await buildTriageCard({
      filePath: 'login.php',
      title: 'Web Login',
      url: 'http://127.0.0.1:8080',
      readFileBytes: () => Buffer.from('<?php echo 1;'),
    });
    assert.equal(standalone.primary_domain, 'web');

    // submit_flag without confirm: true must be blocked by Copilot approval-gate
    const blocked = JSON.parse(await tools.get('submit_flag').execute({
      flag: 'flag{copilot_gate_test}',
      source: 'test-script',
    }, execution));
    assert.equal(blocked.ok, false);
    assert.equal(blocked.approval_required, true);
    assert.equal(blocked.error.kind, 'permission');

    // With confirm: true, request passes through approval-gate cleanly to normal validation (platform missing -> dependency)
    const confirmed = JSON.parse(await tools.get('submit_flag').execute({
      flag: 'flag{copilot_gate_test}',
      source: 'test-script',
      confirm: true,
    }, execution));
    assert.equal(confirmed.approval_required, undefined);
    assert.equal(confirmed.error?.kind, 'dependency');
  } finally {
    await state?.runtime?.dispose?.();
    await rm(cwd, { recursive: true, force: true });
  }
});

test('CTF Autonomous preset: starts in triage, supports hot ctf_domain expansion, swarm race, and exit verification', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'ctf-auto-'));
  let state;
  try {
    const { ctx, tools, execution } = makeMockCtx(cwd);
    state = applyAutonomous(ctx, {});
    assert.equal(state.mode, 'autonomous');
    assert.deepEqual(state.domainRouter.activeDomains(), ['triage']);
    assert.ok(tools.has('ctf_swarm'));
    assert.ok(tools.has('ctf_verify_exit'));
    assert.equal(tools.has('pwn_cyclic'), false);

    // Hot expansion via ctf_domain
    const expanded = JSON.parse(await tools.get('ctf_domain').execute({ action: 'enable', domain: 'pwn' }, execution));
    assert.equal(expanded.status, 'ok');
    assert.equal(tools.has('pwn_cyclic'), true);

    // Swarm Best-of-N race + parallel runner
    const race = JSON.parse(await tools.get('ctf_swarm').execute({
      action: 'plan_race',
      challenge: 'bof1',
      race_id: 'r1',
      branches: [
        { branch_id: 'b1', title: 'branch 1', priority: 5 },
        { branch_id: 'b2', title: 'branch 2', priority: 4 },
      ],
    }, execution));
    assert.equal(race.status, 'ok');

    const store = createStateStore(cwd);
    const sched = createSwarmScheduler(store);
    const par = await sched.runParallelBranches(['a', 'b', 'c'], async item => (
      item === 'b' ? { verified: true, flag: 'flag{parallel_winner_2026}' } : { verified: false }
    ), { concurrency: 2 });
    assert.equal(par.winner.branch, 'b');

    // Machine-verifiable exit condition
    const badExit = await verifyExitCondition({ flag: 'invalid', source: '' });
    assert.equal(badExit.done, false);
    assert.equal(badExit.exit_code, 2);

    const sourceOnlyExit = JSON.parse(await tools.get('ctf_verify_exit').execute({
      flag: 'flag{verified_autonomous_2026}',
      source: 'exploit.py',
      submit_verdict: 'accepted',
    }, execution));
    assert.equal(sourceOnlyExit.done, false, '自由文本来源和调用方自报 verdict 不能证明 Flag 正确');
    assert.equal(sourceOnlyExit.exit_code, 2);

    const verifiedByOracle = await verifyExitCondition({
      flag: 'flag{verified_autonomous_2026}',
      localVerifyFn: flag => flag === 'flag{verified_autonomous_2026}',
    });
    assert.equal(verifiedByOracle.done, true, '可信宿主验证器通过时可产生机器终态');
    assert.ok(verifiedByOracle.checks.every(check => check.ok), 'done=true 时所有必需检查应为通过');

    const flagHash = createHash('sha256').update('flag{verified_autonomous_2026}').digest('hex');
    const platformReceipt = await verifyExitCondition({
      flag: 'flag{verified_autonomous_2026}',
      evidenceIds: ['a'.repeat(64)],
      requireSubmission: true,
      resolveEvidence: async () => ({
        tool: 'submit_flag',
        report: { status: 'submitted', verdict: 'accepted', flag_sha256: flagHash },
      }),
    });
    assert.equal(platformReceipt.done, true, '真实提交工具回执匹配候选 Flag 后可通过');
    assert.ok(platformReceipt.checks.every(check => check.ok), '平台回执通过后不能残留失败的可选检查');
    const fakeArenaReceipt = await verifyExitCondition({
      flag: 'flag{verified_autonomous_2026}',
      evidenceIds: ['b'.repeat(64)],
      requireSubmission: true,
      resolveEvidence: async () => ({
        tool: 'ctf_arena',
        report: { action: 'detail', status: 'accepted', flag: 'flag{verified_autonomous_2026}', flag_sha256: flagHash },
      }),
    });
    assert.equal(fakeArenaReceipt.done, false, 'ctf_arena detail 结果不能冒充提交回执');
  } finally {
    await state?.runtime?.dispose?.();
    await rm(cwd, { recursive: true, force: true });
  }
});

test('cordis.patch.yml declares dual presets CTF Copilot & CTF Autonomous cleanly', async () => {
  const yml = await readFile(new URL('../cordis.patch.yml', import.meta.url), 'utf8');
  assert.match(yml, /id:\s*preset-ctf-copilot/u);
  assert.match(yml, /name:\s*'@local\/dsh-ctf-preset\/copilot'/u);
  assert.match(yml, /id:\s*preset-ctf-autonomous/u);
  assert.match(yml, /name:\s*'@local\/dsh-ctf-preset\/autonomous'/u);
  assert.doesNotMatch(yml, /id:\s*preset-ctf$/mu);
  assert.equal(existsSync(new URL('../presets/copilot/index.js', import.meta.url)), true);
  assert.equal(existsSync(new URL('../presets/autonomous/index.js', import.meta.url)), true);
});
