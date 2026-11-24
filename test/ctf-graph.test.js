import assert from 'node:assert/strict';
import test from 'node:test';
import { apply } from '../ctf-tools.js';
import { GRAPH_BACKUP, GRAPH_BOARD, GRAPH_FILE, manageGraph } from '../ctf-graph.js';

function createCasMemoryFiles({ canWrite = true } = {}) {
  const store = new Map();
  let seq = 0;
  return {
    store,
    canWrite,
    async read(name) {
      await Promise.resolve();
      const entry = store.get(name);
      if (!entry) return { name, target: name, text: '', version: undefined };
      return { name, target: name, text: entry.text, version: entry.version };
    },
    async write(document, body) {
      await Promise.resolve();
      const current = store.get(document.name);
      if (document.version === undefined) {
        if (current !== undefined) throw new Error('CAS conflict: already exists');
      } else if (!current || current.version !== document.version) {
        throw new Error('CAS conflict: stale version');
      }
      seq += 1;
      store.set(document.name, { text: body, version: `v${seq}` });
    },
  };
}

test('ctf_graph: add_fact 派生任务、dedupe_key 去重、board 轻量索引与 expand 按需展开', async () => {
  const files = createCasMemoryFiles();
  const bigEvidence = 'EVIDENCE_PAYLOAD_' + 'X'.repeat(500);

  const added = await manageGraph({
    action: 'add_fact',
    challenge: 'web-01',
    kind: 'vuln',
    title: '发现 /login SQL 注入点',
    summary: 'username 参数未做参数化查询',
    evidence: bigEvidence,
    source: 'http_request:abc',
    dedupe_key: 'web-01:login-sqli',
    spawn_intents: [
      { title: '提取数据库表名与管理员哈希', priority: 5, budget_minutes: 10 },
      { title: '检查文件读取权限', priority: 2, budget_minutes: 15 },
    ],
  }, files, { defaultOwner: 'lead' });

  assert.equal(added.status, 'ok');
  assert.equal(added.fact.id, 'F-1');
  assert.equal(added.spawned_intents.length, 2);
  assert.deepEqual(added.spawned_intents[0].parent_fact_ids, ['F-1']);

  // dedupe_key 去重
  const dup = await manageGraph({
    action: 'add_fact',
    challenge: 'web-01',
    kind: 'vuln',
    title: '重复写入不应新增',
    dedupe_key: 'web-01:login-sqli',
  }, files);
  assert.equal(dup.status, 'deduplicated');
  assert.equal(dup.fact.id, 'F-1');

  // board 第一层不应泄漏大段 evidence / summary，同时返回按题汇总与来源标识
  const board = await manageGraph({ action: 'board' }, files);
  assert.equal(board.counts.facts, 1);
  assert.equal(board.counts.open, 2);
  assert.equal(board.counts.challenges, 1);
  assert.equal(board.challenges[0].challenge, 'web-01');
  assert.equal(board.challenges[0].open, 2);
  assert.equal(board.challenges[0].has_flag, false);
  assert.equal(JSON.stringify(board).includes(bigEvidence), false);
  assert.equal(board.facts[0].title, '发现 /login SQL 注入点');
  assert.equal(board.facts[0].source, 'http_request:abc');
  assert.equal(board.facts[0].has_evidence, true);

  // 标记一条 dead（已排除路径），确认 board.ruled_out 与 BOARD.md 分区渲染正确
  await manageGraph({
    action: 'finish_intent', intent_id: 'I-2', status: 'dead', outcome: '账号无 FILE 权限，排除读文件路线',
  }, files);
  const boardWithDead = await manageGraph({ action: 'board' }, files);
  assert.equal(boardWithDead.counts.dead, 1);
  assert.equal(boardWithDead.ruled_out.length, 1);
  assert.equal(boardWithDead.ruled_out[0].id, 'I-2');
  assert.match(boardWithDead.ruled_out[0].outcome, /无 FILE 权限/u);

  // expand 返回二/三层完整详情
  const expanded = await manageGraph({ action: 'expand', fact_ids: ['F-1', 'F-999'], intent_ids: ['I-1'] }, files);
  assert.equal(expanded.facts.length, 1);
  assert.equal(expanded.facts[0].evidence, bigEvidence);
  assert.deepEqual(expanded.missing_fact_ids, ['F-999']);
  assert.equal(expanded.intents[0].id, 'I-1');

  // BOARD.md 投影与恢复副本均已同步生成
  assert.ok(files.store.has(GRAPH_BACKUP));
  const boardMd = files.store.get(GRAPH_BOARD)?.text ?? '';
  assert.match(boardMd, /## Overview/u);
  assert.match(boardMd, /\| web-01 \| - \| 1 \| 1 \| 0 \| 0 \| 1 \| 0 \|/u);
  assert.match(boardMd, /## web-01/u);
  assert.match(boardMd, /`F-1`.*\[src: http_request:abc\]/u);
  assert.match(boardMd, /### Active & Open Intents/u);
  assert.match(boardMd, /`I-1`.*\[from F-1\]/u);
  assert.match(boardMd, /### Completed & Ruled Out/u);
  assert.match(boardMd, /\[-\] `I-2`.*ruled-out.*无 FILE 权限/u);
});

test('ctf_graph: Promise.all 并发 claim_intent 严格互斥，且 next:true 按优先级分配不撞车', async () => {
  const files = createCasMemoryFiles();
  await manageGraph({
    action: 'add_fact',
    challenge: 'pwn-01',
    kind: 'binary',
    title: '64-bit PIE+NX 关闭',
    spawn_intents: [
      { title: '低优任务', priority: 1 },
      { title: '最高优任务', priority: 5 },
      { title: '中优任务', priority: 3 },
    ],
  }, files);

  // 5 个代理同时抢同一条 I-1：只能恰好 1 个成功，其余 4 个 conflict
  const sameRace = await Promise.all(
    ['sub-1', 'sub-2', 'sub-3', 'sub-4', 'sub-5'].map(owner =>
      manageGraph({ action: 'claim_intent', intent_id: 'I-1', owner }, files),
    ),
  );
  const winners = sameRace.filter(r => r.status === 'claimed');
  const conflicts = sameRace.filter(r => r.status === 'conflict');
  assert.equal(winners.length, 1);
  assert.equal(conflicts.length, 4);

  // 剩余 I-2（P5）和 I-3（P3）：3 个代理并发 next: true，2 个分别抢到不同任务，1 个 empty
  const nextRace = await Promise.all(
    ['w-a', 'w-b', 'w-c'].map(owner =>
      manageGraph({ action: 'claim_intent', next: true, owner }, files),
    ),
  );
  const claimedIds = nextRace.filter(r => r.status === 'claimed').map(r => r.intent.id).sort();
  const empties = nextRace.filter(r => r.status === 'empty');
  assert.deepEqual(claimedIds, ['I-2', 'I-3']);
  assert.equal(empties.length, 1);
});

test('ctf_graph: 超时 overdue 检测、steal_overdue 接管、finish_intent 原子产出与损坏恢复', async () => {
  const files = createCasMemoryFiles();
  let clock = Date.parse('2026-11-24T00:00:00Z');
  const now = () => clock;

  await manageGraph({
    action: 'add_intent', challenge: 'rev-01', title: '逆向主校验函数', priority: 4, budget_minutes: 10,
  }, files, { now });
  await manageGraph({ action: 'claim_intent', intent_id: 'I-1', owner: 'worker-1' }, files, { now });

  // 5 分钟后未超时，无法接管
  clock += 5 * 60000;
  const notYet = await manageGraph({
    action: 'claim_intent', intent_id: 'I-1', owner: 'worker-2', steal_overdue: true,
  }, files, { now });
  assert.equal(notYet.status, 'conflict');
  assert.equal(notYet.overdue, false);

  // 12 分钟后超时，board 标 overdue 且允许 steal_overdue 接管
  clock += 7 * 60000;
  const board = await manageGraph({ action: 'board' }, files, { now });
  assert.equal(board.counts.overdue, 1);
  assert.equal(board.intents[0].overdue, true);

  const stolen = await manageGraph({
    action: 'claim_intent', intent_id: 'I-1', owner: 'worker-2', steal_overdue: true,
  }, files, { now });
  assert.equal(stolen.status, 'stolen');
  assert.equal(stolen.previous_owner, 'worker-1');
  assert.equal(stolen.intent.owner, 'worker-2');

  // 滞后的旧持有者 worker-1 不能越权结案，且不递增 revision
  const staleFinish = await manageGraph({
    action: 'finish_intent',
    intent_id: 'I-1',
    owner: 'worker-1',
    status: 'dead',
    outcome: '滞后超时结果不应覆盖 worker-2',
  }, files, { now });
  assert.equal(staleFinish.status, 'conflict');
  assert.equal(staleFinish.owner, 'worker-2');
  assert.equal(staleFinish.attempted_owner, 'worker-1');
  assert.equal(staleFinish.revision, stolen.revision);

  // finish_intent 原子产出新 Fact 与后续 Intent
  const finished = await manageGraph({
    action: 'finish_intent',
    intent_id: 'I-1',
    owner: 'worker-2',
    status: 'done',
    outcome: '已定位 RC4 变形与固定密钥',
    facts: [{ kind: 'crypto', title: '密钥为 s3cr3t_rc4', evidence: '0x402010' }],
    spawn_intents: [{ title: '解密密文验证 flag', priority: 5 }],
  }, files, { now });
  assert.equal(finished.status, 'ok');
  assert.equal(finished.intent.status, 'done');
  assert.equal(finished.produced_facts[0].id, 'F-1');
  assert.equal(finished.spawned_intents[0].id, 'I-2');
  assert.deepEqual(finished.spawned_intents[0].parent_fact_ids, ['F-1']);

  // 已结案的终态 Intent 不允许重复结案覆盖
  const repeatFinish = await manageGraph({
    action: 'finish_intent',
    intent_id: 'I-1',
    owner: 'worker-2',
    status: 'dead',
    outcome: '重复覆盖尝试',
  }, files, { now });
  assert.equal(repeatFinish.status, 'closed');
  assert.equal(repeatFinish.intent_status, 'done');
  assert.equal(repeatFinish.outcome, '已定位 RC4 变形与固定密钥');
  assert.equal(repeatFinish.revision, finished.revision);

  // 破坏主文件 graph.json，验证从 graph.saved.json 自动恢复
  const curPrimary = files.store.get(GRAPH_FILE);
  files.store.set(GRAPH_FILE, { text: '{broken json', version: curPrimary.version });
  const recoveredBoard = await manageGraph({ action: 'board' }, files, { now });
  assert.equal(recoveredBoard.recovered, true);
  assert.equal(recoveredBoard.counts.facts, 1);
  assert.equal(recoveredBoard.counts.done, 1);
  assert.equal(recoveredBoard.counts.open, 1);

  // 只读权限下允许 board/expand，禁止写入
  const readonlyFiles = createCasMemoryFiles({ canWrite: false });
  assert.equal((await manageGraph({ action: 'board' }, readonlyFiles)).status, 'ok');
  await assert.rejects(
    manageGraph({ action: 'add_fact', challenge: 'c', title: 't' }, readonlyFiles),
    error => error.kind === 'permission',
  );
});

test('ctf_graph 通过 apply 注册工具端到端运行', async () => {
  const cwd = 'D:/mock-graph-ws';
  const entries = new Map();
  let seq = 0;
  const tools = new Map();
  const resolveTarget = (name, options = {}) => {
    const base = (options.cwd ?? cwd).replace(/[\\/]$/u, '');
    const targetKey = options.cwd ? `${base}/${name}` : name;
    return { targetKey, displayPath: targetKey };
  };
  const ctx = {
    tools: { register(tool) { tools.set(tool.name, tool); } },
    effect() {},
    emit() {},
    workingDirectory: { async ensure() { return cwd; } },
    sandboxPolicy: { resolve() { return { mode: 'workspace-write' }; } },
    fs: {
      async resolve(name, options) { return resolveTarget(name, options); },
      contains(parent, child) { return child.targetKey === parent.targetKey || child.targetKey.startsWith(parent.targetKey + '/'); },
      async lstat(name, options) {
        const rel = resolveTarget(name, options).targetKey.slice(cwd.length + 1);
        if (entries.has(rel)) return { type: 'file' };
        if (rel === '.ctf-graph' || [...entries.keys()].some(k => k.startsWith(rel + '/'))) return { type: 'directory' };
        return undefined;
      },
      async stat(target) {
        const rel = target.targetKey.slice(cwd.length + 1);
        const item = entries.get(rel);
        return item ? { type: 'file', size: item.bytes.length, version: item.version } : null;
      },
      async readBytes(target) {
        const rel = target.targetKey.slice(cwd.length + 1);
        return entries.get(rel)?.bytes;
      },
      async writeText(target, text, intent) {
        const rel = target.targetKey.slice(cwd.length + 1);
        const prev = entries.get(rel);
        if (intent.kind === 'createIfAbsent' && prev !== undefined) throw new Error('exists');
        if (intent.kind === 'replaceIfVersion' && prev?.version !== intent.version) throw new Error('conflict');
        seq += 1;
        entries.set(rel, { bytes: Buffer.from(text, 'utf8'), version: `v${seq}` });
        return { version: `v${seq}` };
      },
    },
  };
  apply(ctx, {});
  const execution = { signal: new AbortController().signal, agent: { session: { header: { cwd }, id: 'main-agent' } } };
  const added = JSON.parse(await tools.get('ctf_graph').execute({
    action: 'add_fact', challenge: 'misc-1', kind: 'recon', title: '附件为伪加密 ZIP',
  }, execution));
  assert.equal(added.status, 'ok');
  assert.equal(added.fact.created_by, 'main-agent');

  const board = JSON.parse(await tools.get('ctf_graph').execute({ action: 'board', challenge: 'misc-1' }, execution));
  assert.equal(board.counts.facts, 1);
});

test('ctf_graph: dispatch_plan 按优先级分派不同题目、避开进行中题目并列出超时回收清单', async () => {
  const files = createCasMemoryFiles();
  let clock = Date.parse('2026-11-24T04:00:00Z');
  const now = () => clock;

  await manageGraph({
    action: 'add_fact', challenge: 'web-a', kind: 'recon', title: 'Web A', dedupe_key: 'k-a',
    spawn_intents: [
      { title: 'Web A 任务1', priority: 5, budget_minutes: 10 },
      { title: 'Web A 任务2', priority: 4, budget_minutes: 10 },
    ],
  }, files, { now });
  // 重复 dedupe_key 即使带 spawn_intents 也不应重复派生任务
  const dup = await manageGraph({
    action: 'add_fact', challenge: 'web-a', kind: 'recon', title: 'Web A dup', dedupe_key: 'k-a',
    spawn_intents: [{ title: '不应派生', priority: 5 }],
  }, files, { now });
  assert.equal(dup.status, 'deduplicated');
  assert.equal(dup.spawned_intents.length, 0);

  await manageGraph({
    action: 'add_fact', challenge: 'pwn-b', kind: 'binary', title: 'Pwn B',
    spawn_intents: [{ title: 'Pwn B 利用', priority: 4, budget_minutes: 10 }],
  }, files, { now });
  await manageGraph({
    action: 'add_fact', challenge: 'crypto-c', kind: 'crypto', title: 'Crypto C',
    spawn_intents: [{ title: 'Crypto C 求解', priority: 3, budget_minutes: 10 }],
  }, files, { now });

  // worker-old 认领 pwn-b 且超时
  await manageGraph({ action: 'claim_intent', intent_id: 'I-3', owner: 'worker-old' }, files, { now });
  clock += 15 * 60000;

  // worker-live 正在做 web-a（未超时）
  await manageGraph({ action: 'claim_intent', intent_id: 'I-1', owner: 'worker-live' }, files, { now });

  const plan = await manageGraph({ action: 'dispatch_plan', max_workers: 3 }, files, { now });
  assert.equal(plan.status, 'ok');
  assert.deepEqual(plan.active_challenges, ['web-a']);
  // 默认避开正在做的 web-a，只分派 crypto-c（I-4）
  assert.deepEqual(plan.assignments.map(a => a.intent_id), ['I-4']);
  assert.match(plan.assignments[0].recommended_prompt, /claim_intent/u);
  assert.equal(plan.overdue_recovery.length, 1);
  assert.equal(plan.overdue_recovery[0].intent_id, 'I-3');

  // allow_same_challenge: true 时把 web-a 的 I-2 也纳入分派
  const sameAllowed = await manageGraph({
    action: 'dispatch_plan', max_workers: 3, allow_same_challenge: true,
  }, files, { now });
  assert.deepEqual(sameAllowed.assignments.map(a => a.intent_id), ['I-2', 'I-4']);
});

test('ctf_graph: board 分页/状态过滤/summary_only 与 export_writeup 导出', async () => {
  const files = createCasMemoryFiles();
  let clock = Date.parse('2026-11-24T01:00:00Z');
  const now = () => clock;

  await manageGraph({
    action: 'add_fact', challenge: 'web-01', kind: 'vuln', title: '发现登录接口 SSTI 注入点',
    detail: '模板参数 name 未转义，{{7*7}} 返回 49', evidence: 'http_request:R-1',
    spawn_intents: [
      { title: '构造 Jinja2 RCE payload', priority: 5, budget_minutes: 10 },
      { title: '检查备用接口', priority: 2, budget_minutes: 10 },
    ],
  }, files, { now });
  await manageGraph({
    action: 'add_fact', challenge: 'pwn-01', kind: 'binary', title: '栈溢出偏移 72 字节',
    spawn_intents: [{ title: '泄露 libc 并打 ret2libc', priority: 4, budget_minutes: 10 }],
  }, files, { now });

  // 认领并完成 I-1，让 I-2 超时，I-3 保持 open
  await manageGraph({ action: 'claim_intent', intent_id: 'I-1', owner: 'w1' }, files, { now });
  await manageGraph({
    action: 'finish_intent', intent_id: 'I-1', owner: 'w1', status: 'done',
    outcome: '成功读取 /flag 得到 flag{graph_export_ok}',
    facts: [{ kind: 'flag', title: 'flag{graph_export_ok}', evidence: 'http_request:R-2' }],
  }, files, { now });
  await manageGraph({ action: 'claim_intent', intent_id: 'I-2', owner: 'w2' }, files, { now });
  clock += 15 * 60000;

  // status_filter: active / overdue / done
  const activeBoard = await manageGraph({ action: 'board', status_filter: 'active' }, files, { now });
  assert.deepEqual(activeBoard.intents.map(i => i.id).sort(), ['I-2', 'I-3']);
  const overdueBoard = await manageGraph({ action: 'board', status_filter: 'overdue' }, files, { now });
  assert.deepEqual(overdueBoard.intents.map(i => i.id), ['I-2']);
  const doneBoard = await manageGraph({ action: 'board', status_filter: 'done' }, files, { now });
  assert.deepEqual(doneBoard.intents.map(i => i.id), ['I-1']);

  // 分页 limit + offset
  const page1 = await manageGraph({ action: 'board', limit: 2, offset: 0 }, files, { now });
  assert.equal(page1.facts.length, 2);
  assert.equal(page1.intents.length, 2);
  assert.equal(page1.paging.total_facts, 3);
  assert.equal(page1.paging.total_intents, 3);
  assert.equal(page1.paging.has_more_facts, true);
  assert.equal(page1.paging.next_offset, 2);

  const page2 = await manageGraph({ action: 'board', limit: 2, offset: 2 }, files, { now });
  assert.equal(page2.facts.length, 1);
  assert.equal(page2.paging.has_more_facts, false);
  assert.equal(page2.paging.next_offset, undefined);

  // summary_only 省略列表细节
  const summary = await manageGraph({ action: 'board', summary_only: true }, files, { now });
  assert.equal(summary.summary_only, true);
  assert.equal(summary.facts, undefined);
  assert.equal(summary.intents, undefined);
  assert.equal(summary.counts.facts, 3);
  assert.equal(summary.counts.done, 1);

  // export_writeup：按单题导出并允许只读权限
  const readonlyFiles = createCasMemoryFiles({ canWrite: false });
  readonlyFiles.store.set(GRAPH_FILE, files.store.get(GRAPH_FILE));
  const exported = await manageGraph({ action: 'export_writeup', challenge: 'web-01' }, readonlyFiles, { now });
  assert.equal(exported.status, 'ok');
  assert.equal(exported.challenge, 'web-01');
  assert.equal(exported.fact_count, 2);
  assert.equal(exported.intent_count, 2);
  assert.match(exported.markdown, /# web-01 题解草稿/u);
  assert.match(exported.markdown, /flag\{graph_export_ok\}/u);
  assert.match(exported.markdown, /`I-1`/u);
  assert.ok(!exported.markdown.includes('pwn-01'));
});
