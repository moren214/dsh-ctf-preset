import { randomUUID } from 'node:crypto';
import { classifyChallengeDomain } from './ctf-router.js';
import { ToolError } from './tool-errors.js';

export const GRAPH_DIR = '.ctf-graph';
export const GRAPH_FILE = '.ctf-graph/graph.json';
export const GRAPH_BACKUP = '.ctf-graph/graph.saved.json';
export const GRAPH_BOARD = '.ctf-graph/BOARD.md';

const SCHEMA_VERSION = 1;
const MAX_FACTS = 5000;
const MAX_INTENTS = 5000;
const ATTEMPTS = 24;
const mutationQueues = new Map();
const DEFAULT_PRIORITY = 3;
const DEFAULT_BUDGET_MINUTES = 15;
const FACT_KINDS = ['recon', 'vuln', 'credential', 'crypto', 'binary', 'flag', 'note'];

export const GRAPH_PROPERTIES = {
  action: {
    type: 'string',
    enum: ['board', 'expand', 'add_fact', 'add_intent', 'claim_intent', 'finish_intent', 'dispatch_plan', 'export_writeup'],
    description: 'board 查索引（支持分页与 summary_only）；expand 展开；add_fact/add_intent 写入；claim_intent 互斥认领；finish_intent 结案；dispatch_plan 生成并行计划；export_writeup 导出题解草稿。',
  },
  challenge: { type: 'string', maxLength: 120 },
  status_filter: { type: 'string', enum: ['all', 'active', 'open', 'claimed', 'done', 'dead', 'overdue'], description: 'board 按状态筛选 Intent（active=open+claimed）。' },
  limit: { type: 'integer', minimum: 1, maximum: 500, description: 'board 每页最多返回的 Fact/Intent 条数（默认 50）。' },
  offset: { type: 'integer', minimum: 0, maximum: 5000, description: 'board 分页起始偏移（默认 0）。' },
  summary_only: { type: 'boolean', default: false, description: 'board 仅返回按题汇总、统计与超时预警，不展开单条列表。' },
  fact_ids: { type: 'array', maxItems: 32, items: { type: 'string', maxLength: 32 } },
  intent_ids: { type: 'array', maxItems: 32, items: { type: 'string', maxLength: 32 } },
  kind: { type: 'string', enum: FACT_KINDS },
  title: { type: 'string', maxLength: 200 },
  summary: { type: 'string', maxLength: 2000 },
  evidence: { type: 'string', maxLength: 4000 },
  source: { type: 'string', maxLength: 400 },
  dedupe_key: { type: 'string', maxLength: 120 },
  parent_fact_ids: { type: 'array', maxItems: 16, items: { type: 'string', maxLength: 32 } },
  hypothesis: { type: 'string', maxLength: 1000 },
  priority: { type: 'integer', minimum: 1, maximum: 5, default: DEFAULT_PRIORITY },
  budget_minutes: { type: 'integer', minimum: 1, maximum: 240, default: DEFAULT_BUDGET_MINUTES },
  intent_id: { type: 'string', maxLength: 32 },
  next: { type: 'boolean' },
  owner: { type: 'string', maxLength: 120 },
  lease_id: { type: 'string', maxLength: 64, description: 'finish_intent 使用 claim_intent 返回的租约 ID，阻止过期代理结案。' },
  steal_overdue: { type: 'boolean', default: false },
  max_workers: { type: 'integer', minimum: 1, maximum: 8, default: 3 },
  allow_same_challenge: { type: 'boolean', default: false },
  status: { type: 'string', enum: ['done', 'dead'] },
  outcome: { type: 'string', maxLength: 2000 },
  facts: {
    type: 'array', maxItems: 10,
    items: {
      type: 'object', additionalProperties: false, required: ['title'],
      properties: {
        kind: { type: 'string', enum: FACT_KINDS },
        title: { type: 'string', maxLength: 200 },
        summary: { type: 'string', maxLength: 2000 },
        evidence: { type: 'string', maxLength: 4000 },
        source: { type: 'string', maxLength: 400 },
        dedupe_key: { type: 'string', maxLength: 120 },
      },
    },
  },
  spawn_intents: {
    type: 'array', maxItems: 10,
    items: {
      type: 'object', additionalProperties: false, required: ['title'],
      properties: {
        title: { type: 'string', maxLength: 200 },
        hypothesis: { type: 'string', maxLength: 1000 },
        priority: { type: 'integer', minimum: 1, maximum: 5 },
        budget_minutes: { type: 'integer', minimum: 1, maximum: 240 },
        parent_fact_ids: { type: 'array', maxItems: 16, items: { type: 'string', maxLength: 32 } },
      },
    },
  },
};

function emptyGraph(nowIso) {
  return { schema_version: SCHEMA_VERSION, revision: 0, updated_at: nowIso, facts: [], intents: [] };
}

function parseGraphDocument(document) {
  if (document.version === undefined) return emptyGraph(new Date().toISOString());
  try {
    const parsed = JSON.parse(document.text);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      && parsed.schema_version === SCHEMA_VERSION
      && Number.isSafeInteger(parsed.revision) && parsed.revision >= 0
      && Array.isArray(parsed.facts) && Array.isArray(parsed.intents)) {
      return parsed;
    }
  } catch {
    // Corrupted primary copy falls back to saved backup.
  }
  return undefined;
}

async function readGraph(files) {
  const document = await files.read(GRAPH_FILE);
  const parsed = parseGraphDocument(document);
  if (parsed !== undefined && document.version !== undefined) {
    return { document, graph: parsed, recovered: false };
  }
  const backup = await files.read(GRAPH_BACKUP);
  if (backup.version !== undefined) {
    const saved = parseGraphDocument(backup);
    if (saved !== undefined) return { document, graph: saved, recovered: true };
  }
  if (parsed !== undefined) return { document, graph: parsed, recovered: false };
  throw new ToolError('encoding', '图谱主文件与恢复副本均已损坏。');
}

function nextId(items, prefix) {
  let max = 0;
  for (const item of items) {
    const match = typeof item?.id === 'string' ? new RegExp(`^${prefix}-([0-9]+)$`, 'u').exec(item.id) : null;
    if (match) {
      const n = Number(match[1]);
      if (Number.isSafeInteger(n) && n > max) max = n;
    }
  }
  return `${prefix}-${max + 1}`;
}

function cleanText(value, field, maxLength, { required = false, singleLine = false } = {}) {
  if (value === undefined) {
    if (required) throw new ToolError('unsupported', `${field} 不能为空。`);
    return undefined;
  }
  if (typeof value !== 'string') throw new ToolError('unsupported', `${field} 须为字符串。`);
  const trimmed = value.trim();
  if (required && trimmed.length === 0) throw new ToolError('unsupported', `${field} 不能为空。`);
  if (trimmed.length > maxLength) throw new ToolError('unsupported', `${field} 不能超过 ${maxLength} 字符。`);
  if (singleLine && /[\r\n]/u.test(trimmed)) throw new ToolError('unsupported', `${field} 须为单行文本。`);
  return trimmed.length > 0 ? trimmed : undefined;
}

function cleanIdList(value, field, maxItems) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > maxItems
    || value.some(item => typeof item !== 'string' || item.trim().length === 0 || item.length > 32)) {
    throw new ToolError('unsupported', `${field} 须为不超过 ${maxItems} 项的 ID 数组。`);
  }
  return [...new Set(value.map(item => item.trim()))];
}

function cleanPriority(value) {
  const n = value ?? DEFAULT_PRIORITY;
  if (!Number.isSafeInteger(n) || n < 1 || n > 5) throw new ToolError('unsupported', 'priority 须为 1 至 5 的整数。');
  return n;
}

function cleanBudget(value) {
  const n = value ?? DEFAULT_BUDGET_MINUTES;
  if (!Number.isSafeInteger(n) || n < 1 || n > 240) throw new ToolError('unsupported', 'budget_minutes 须为 1 至 240 的整数。');
  return n;
}

function isIntentOverdue(intent, nowMs) {
  if (intent.status !== 'claimed' || !intent.claimed_at) return false;
  const claimedMs = Date.parse(intent.claimed_at);
  if (!Number.isFinite(claimedMs)) return false;
  const budget = Number.isFinite(intent.budget_minutes) ? intent.budget_minutes : DEFAULT_BUDGET_MINUTES;
  return (nowMs - claimedMs) >= budget * 60000;
}

function elapsedMinutes(iso, nowMs) {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return 0;
  return Math.max(0, Math.round((nowMs - ms) / 60000));
}

function buildFact(graph, input, challenge, owner, nowIso) {
  if (graph.facts.length >= MAX_FACTS) throw new ToolError('size', `图谱 Fact 数量已达上限（${MAX_FACTS}）。`);
  const title = cleanText(input.title, 'title', 200, { required: true, singleLine: true });
  const kind = input.kind ?? 'note';
  if (!FACT_KINDS.includes(kind)) throw new ToolError('unsupported', `kind 须为 ${FACT_KINDS.join('、')} 之一。`);
  const dedupeKey = cleanText(input.dedupe_key, 'dedupe_key', 120, { singleLine: true });
  if (dedupeKey) {
    const existing = graph.facts.find(f => f.challenge === challenge && f.dedupe_key === dedupeKey);
    if (existing) return { fact: existing, deduplicated: true };
  }
  const fact = {
    id: nextId(graph.facts, 'F'),
    challenge,
    kind,
    title,
    ...(cleanText(input.summary, 'summary', 2000) ? { summary: cleanText(input.summary, 'summary', 2000) } : {}),
    ...(cleanText(input.evidence, 'evidence', 4000) ? { evidence: cleanText(input.evidence, 'evidence', 4000) } : {}),
    ...(cleanText(input.source, 'source', 400, { singleLine: true }) ? { source: cleanText(input.source, 'source', 400, { singleLine: true }) } : {}),
    ...(owner ? { created_by: owner } : {}),
    ...(dedupeKey ? { dedupe_key: dedupeKey } : {}),
    created_at: nowIso,
  };
  graph.facts.push(fact);
  return { fact, deduplicated: false };
}

function buildIntent(graph, input, challenge, defaultParents, nowIso) {
  if (graph.intents.length >= MAX_INTENTS) throw new ToolError('size', `图谱 Intent 数量已达上限（${MAX_INTENTS}）。`);
  const title = cleanText(input.title, 'title', 200, { required: true, singleLine: true });
  const parents = input.parent_fact_ids !== undefined
    ? cleanIdList(input.parent_fact_ids, 'parent_fact_ids', 16)
    : defaultParents;
  const hypothesis = cleanText(input.hypothesis, 'hypothesis', 1000);
  const intent = {
    id: nextId(graph.intents, 'I'),
    challenge,
    title,
    parent_fact_ids: parents,
    ...(hypothesis ? { hypothesis } : {}),
    priority: cleanPriority(input.priority),
    budget_minutes: cleanBudget(input.budget_minutes),
    status: 'open',
    owner: null,
    claim_lease: null,
    claimed_at: null,
    finished_at: null,
    outcome: null,
    produced_fact_ids: [],
    created_at: nowIso,
  };
  graph.intents.push(intent);
  return intent;
}

function challengeMetrics(graph, challengeFilter, nowMs) {
  const facts = challengeFilter ? graph.facts.filter(f => f.challenge === challengeFilter) : graph.facts;
  const intents = challengeFilter ? graph.intents.filter(i => i.challenge === challengeFilter) : graph.intents;
  const map = new Map();
  const ensure = name => {
    let entry = map.get(name);
    if (!entry) {
      entry = { challenge: name, facts: 0, open: 0, claimed: 0, done: 0, dead: 0, overdue: 0, has_flag: false };
      map.set(name, entry);
    }
    return entry;
  };
  for (const f of facts) {
    const entry = ensure(f.challenge);
    entry.facts += 1;
    if (f.kind === 'flag') entry.has_flag = true;
  }
  for (const i of intents) {
    const entry = ensure(i.challenge);
    if (i.status === 'open' || i.status === 'claimed' || i.status === 'done' || i.status === 'dead') {
      entry[i.status] += 1;
    }
    if (isIntentOverdue(i, nowMs)) entry.overdue += 1;
  }
  return [...map.values()].sort((a, b) => a.challenge.localeCompare(b.challenge));
}

function formatBoardIntent(intent, nowMs) {
  const overdue = isIntentOverdue(intent, nowMs);
  const box = intent.status === 'done' ? '[x]' : intent.status === 'dead' ? '[-]' : intent.status === 'claimed' ? '[~]' : '[ ]';
  const meta = [`P${intent.priority}`, `${intent.budget_minutes}m`];
  if (intent.status === 'claimed') {
    const elapsed = intent.claimed_at ? elapsedMinutes(intent.claimed_at, nowMs) : 0;
    meta.push(`owner=${intent.owner ?? 'unknown'}`, `${elapsed}/${intent.budget_minutes}m`);
    if (overdue) meta.push('OVERDUE');
  } else if (intent.status === 'dead') {
    meta.push('ruled-out');
  } else if (intent.status !== 'open') {
    meta.push(intent.status);
  }
  const parents = intent.parent_fact_ids?.length ? ` [from ${intent.parent_fact_ids.join(',')}]` : '';
  const tail = intent.outcome ? ` — ${intent.outcome.replace(/\s+/gu, ' ').slice(0, 140)}` : '';
  return `- ${box} \`${intent.id}\` (${meta.join(', ')}) ${intent.title}${parents}${tail}`;
}

export function renderBoardMarkdown(graph, nowMs = Date.now()) {
  const summary = challengeMetrics(graph, undefined, nowMs);
  const lines = [
    `# CTF Fact-Intent Board (rev ${graph.revision})`,
    '',
    `Updated: ${graph.updated_at} | Challenges: ${summary.length} | Facts: ${graph.facts.length} | Intents: ${graph.intents.length}`,
  ];
  if (summary.length === 0) {
    lines.push('', '_暂无记录。使用 `ctf_graph(action: "add_fact")` 记录首条事实。_', '');
    return lines.join('\n');
  }
  lines.push(
    '',
    '## Overview',
    '',
    '| Challenge | Flag | Facts | Open | Claimed | Done | Ruled Out | Overdue |',
    '|---|---:|---:|---:|---:|---:|---:|---:|',
    ...summary.map(row => `| ${row.challenge} | ${row.has_flag ? 'YES' : '-'} | ${row.facts} | ${row.open} | ${row.claimed} | ${row.done} | ${row.dead} | ${row.overdue} |`),
  );
  for (const row of summary) {
    const ch = row.challenge;
    lines.push('', `## ${ch}`, '', '### Facts');
    const chFacts = graph.facts.filter(f => f.challenge === ch);
    if (chFacts.length === 0) lines.push('- (none)');
    for (const f of chFacts) {
      const src = f.source ? ` [src: ${f.source}]` : '';
      lines.push(`- \`${f.id}\` (${f.kind}) ${f.title}${src}`);
    }
    const chIntents = graph.intents.filter(i => i.challenge === ch);
    const activeIntents = chIntents
      .filter(i => i.status === 'claimed' || i.status === 'open')
      .sort((a, b) => (a.status === 'claimed' ? -1 : 1) - (b.status === 'claimed' ? -1 : 1) || (b.priority - a.priority));
    const closedIntents = chIntents.filter(i => i.status === 'done' || i.status === 'dead');

    lines.push('', '### Active & Open Intents');
    if (activeIntents.length === 0) lines.push('- (none)');
    for (const intent of activeIntents) {
      lines.push(formatBoardIntent(intent, nowMs));
    }
    if (closedIntents.length > 0) {
      lines.push('', '### Completed & Ruled Out');
      for (const intent of closedIntents) {
        lines.push(formatBoardIntent(intent, nowMs));
      }
    }
  }
  lines.push('');
  return lines.join('\n');
}

async function preserveSidecar(files, filePath, body, latestPrimaryBody) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const doc = await files.read(filePath);
    if (doc.text === body) return;
    if (latestPrimaryBody !== undefined && (await files.read(GRAPH_FILE)).text !== latestPrimaryBody) return;
    try {
      await files.write(doc, body);
      return;
    } catch (error) {
      const current = await files.read(filePath);
      const transientLock = ['EBUSY', 'EPERM'].includes(error?.code ?? error?.cause?.code);
      if (attempt === 2 || (current.version === doc.version && !transientLock)) throw error;
      await new Promise(resolve => setTimeout(resolve, Math.min(250, 8 * (2 ** attempt)) + Math.random() * 12));
    }
  }
}

async function withMutationQueue(lockKey, task) {
  if (!lockKey) return task();
  const previous = mutationQueues.get(lockKey) ?? Promise.resolve();
  let release;
  const current = new Promise(resolve => { release = resolve; });
  const tail = previous.then(() => current, () => current);
  mutationQueues.set(lockKey, tail);
  await previous.catch(() => {});
  try {
    return await task();
  } finally {
    release();
    if (mutationQueues.get(lockKey) === tail) {
      mutationQueues.delete(lockKey);
    }
  }
}

async function commitMutation(files, nowMs, mutate) {
  let lockKey = null;
  try {
    const probe = await files.read(GRAPH_FILE);
    if (typeof probe?.target === 'string' && probe.target !== '' && probe.target !== GRAPH_FILE) {
      lockKey = probe.target;
    }
  } catch {
    // Fall back to unqueued CAS loop if probe fails.
  }
  return withMutationQueue(lockKey, async () => {
    const nowIso = new Date(nowMs).toISOString();
    for (let attempt = 0; attempt < ATTEMPTS; attempt += 1) {
      const { document, graph, recovered } = await readGraph(files);
      const cloned = structuredClone(graph);
      const outcome = mutate(cloned, nowIso, nowMs);
      if (outcome.skipWrite) {
        return { ...outcome.response, revision: cloned.revision, recovered };
      }
      cloned.revision += 1;
      cloned.updated_at = nowIso;
      const body = JSON.stringify(cloned, null, 2) + '\n';
      try {
        await files.write(document, body);
      } catch (error) {
        const current = await files.read(GRAPH_FILE);
        const transientLock = ['EBUSY', 'EPERM'].includes(error?.code ?? error?.cause?.code);
        if (current.version === document.version && !transientLock) throw error;
        if (attempt + 1 === ATTEMPTS) {
          if (current.version === document.version) throw error;
          throw new ToolError('conflict', '图谱正被其他代理并发更新，CAS 重试次数已用完，请重试。');
        }
        await new Promise(resolve => setTimeout(resolve, Math.min(180, Math.round(6 * (1.5 ** attempt))) + Math.random() * 15));
        continue;
      }
      const warnings = [];
      try {
        await preserveSidecar(files, GRAPH_BACKUP, body, body);
      } catch {
        warnings.push('图谱已提交，恢复副本尚未刷新。');
      }
      try {
        await preserveSidecar(files, GRAPH_BOARD, renderBoardMarkdown(cloned, nowMs), body);
      } catch {
        warnings.push('图谱已提交，BOARD.md 看板尚未刷新。');
      }
      return {
        ...outcome.response,
        revision: cloned.revision,
        recovered,
        ...(warnings.length > 0 ? { warnings } : {}),
      };
    }
  });
}

const BOARD_STATUS_FILTERS = ['all', 'active', 'open', 'claimed', 'done', 'dead', 'overdue'];
const DEFAULT_BOARD_LIMIT = 50;

function matchesBoardStatus(intent, statusFilter, nowMs) {
  if (statusFilter === 'all') return true;
  if (statusFilter === 'active') return intent.status === 'open' || intent.status === 'claimed';
  if (statusFilter === 'overdue') return isIntentOverdue(intent, nowMs);
  return intent.status === statusFilter;
}

function summarizeBoard(graph, challengeFilter, nowMs, { statusFilter = 'all', limit = DEFAULT_BOARD_LIMIT, offset = 0, summaryOnly = false } = {}) {
  const allFacts = (challengeFilter ? graph.facts.filter(f => f.challenge === challengeFilter) : graph.facts)
    .map(f => ({
      id: f.id,
      challenge: f.challenge,
      kind: f.kind,
      title: f.title,
      ...(f.source ? { source: f.source } : {}),
      ...(f.evidence ? { has_evidence: true } : {}),
    }));
  const scopedIntents = challengeFilter
    ? graph.intents.filter(i => i.challenge === challengeFilter)
    : graph.intents;
  let overdueCount = 0;
  const counts = { open: 0, claimed: 0, done: 0, dead: 0 };
  const ruledOut = [];
  const matchedIntents = [];
  for (const i of scopedIntents) {
    counts[i.status] = (counts[i.status] ?? 0) + 1;
    const overdue = isIntentOverdue(i, nowMs);
    if (overdue) overdueCount += 1;
    if (i.status === 'dead') {
      ruledOut.push({
        id: i.id,
        challenge: i.challenge,
        title: i.title,
        ...(i.outcome ? { outcome: i.outcome.replace(/\s+/gu, ' ').slice(0, 160) } : {}),
      });
    }
    if (matchesBoardStatus(i, statusFilter, nowMs)) {
      matchedIntents.push({
        id: i.id,
        challenge: i.challenge,
        title: i.title,
        priority: i.priority,
        status: i.status,
        ...(i.owner ? { owner: i.owner } : {}),
        budget_minutes: i.budget_minutes,
        ...(i.status === 'claimed' && i.claimed_at ? { claimed_minutes: elapsedMinutes(i.claimed_at, nowMs) } : {}),
        ...(overdue ? { overdue: true } : {}),
      });
    }
  }
  const challenges = challengeMetrics(graph, challengeFilter, nowMs);
  const base = {
    action: 'board',
    status: 'ok',
    revision: graph.revision,
    ...(challengeFilter ? { challenge: challengeFilter } : {}),
    ...(statusFilter !== 'all' ? { status_filter: statusFilter } : {}),
    counts: { challenges: challenges.length, facts: allFacts.length, ...counts, overdue: overdueCount },
    challenges,
  };
  if (summaryOnly) {
    return {
      ...base,
      summary_only: true,
      ...(ruledOut.length > 0 ? { ruled_out: ruledOut.slice(0, 20), ...(ruledOut.length > 20 ? { ruled_out_truncated: true } : {}) } : {}),
      ...(overdueCount > 0 ? { hint: `有 ${overdueCount} 条已认领 Intent 超过时间预算；可核对进展或用 claim_intent(steal_overdue: true) 接管止损。` } : {}),
    };
  }
  const facts = allFacts.slice(offset, offset + limit);
  const intents = matchedIntents.slice(offset, offset + limit);
  const hasMoreFacts = offset + facts.length < allFacts.length;
  const hasMoreIntents = offset + intents.length < matchedIntents.length;
  const ruledOutPage = ruledOut.slice(offset, offset + limit);
  const hasMoreRuledOut = offset + ruledOutPage.length < ruledOut.length;
  const truncated = hasMoreFacts || hasMoreIntents || hasMoreRuledOut;
  return {
    ...base,
    facts,
    intents,
    ...(truncated || offset > 0 ? {
      paging: {
        offset,
        limit,
        total_facts: allFacts.length,
        total_intents: matchedIntents.length,
        total_ruled_out: ruledOut.length,
        has_more_facts: hasMoreFacts,
        has_more_intents: hasMoreIntents,
        has_more_ruled_out: hasMoreRuledOut,
        ...(truncated ? { next_offset: offset + limit } : {}),
      },
    } : {}),
    ...(ruledOut.length > 0 ? { ruled_out: ruledOutPage, ...(hasMoreRuledOut ? { ruled_out_truncated: true } : {}) } : {}),
    ...(overdueCount > 0 ? { hint: `有 ${overdueCount} 条已认领 Intent 超过时间预算；可核对进展或用 claim_intent(steal_overdue: true) 接管止损。` } : {}),
  };
}

export function renderWriteupMarkdown(graph, challengeFilter) {
  const challenges = challengeMetrics(graph, challengeFilter, Date.now());
  const lines = [
    challengeFilter ? `# ${challengeFilter} 题解草稿` : '# CTF 共享图谱题解草稿',
    '',
    `> 来源：\`.ctf-graph/graph.json\`（rev ${graph.revision}，更新于 ${graph.updated_at}）`,
  ];
  if (challenges.length === 0) {
    lines.push('', '_当前图谱无匹配题目记录。_', '');
    return { markdown: lines.join('\n'), challengeCount: 0, factCount: 0, intentCount: 0 };
  }
  let totalFacts = 0;
  let totalIntents = 0;
  for (const row of challenges) {
    const ch = row.challenge;
    const chFacts = graph.facts.filter(f => f.challenge === ch);
    const chIntents = graph.intents.filter(i => i.challenge === ch);
    totalFacts += chFacts.length;
    totalIntents += chIntents.length;
    const flags = chFacts.filter(f => f.kind === 'flag');
    const otherFacts = chFacts.filter(f => f.kind !== 'flag');
    const doneIntents = chIntents.filter(i => i.status === 'done');
    const deadIntents = chIntents.filter(i => i.status === 'dead');
    const openIntents = chIntents.filter(i => i.status === 'open' || i.status === 'claimed');

    lines.push('', `## ${ch}`);
    lines.push('', '### 结论与 Flag');
    if (flags.length === 0) {
      lines.push('- （尚未记录 `kind: flag` 事实）');
    } else {
      for (const f of flags) {
        const src = f.source ? `（来源：\`${f.source}\`）` : '';
        lines.push(`- **${f.title}**${src}`);
        if (f.summary) lines.push(`  - 摘要：${f.summary}`);
        if (f.evidence) lines.push(`  - 证据：${f.evidence.replace(/\r?\n/gu, ' ').slice(0, 400)}`);
      }
    }

    lines.push('', '### 观察与关键事实');
    if (otherFacts.length === 0) {
      lines.push('- （无）');
    } else {
      for (const f of otherFacts) {
        const src = f.source ? ` [src: \`${f.source}\`]` : '';
        lines.push(`- \`${f.id}\` (${f.kind}) ${f.title}${src}`);
        if (f.summary) lines.push(`  - ${f.summary}`);
        if (f.evidence) lines.push(`  - 证据：${f.evidence.replace(/\r?\n/gu, ' ').slice(0, 400)}`);
      }
    }

    lines.push('', '### 已完成分析路径');
    if (doneIntents.length === 0) {
      lines.push('- （无）');
    } else {
      for (const i of doneIntents) {
        const owner = i.owner ? ` [${i.owner}]` : '';
        lines.push(`- \`${i.id}\` ${i.title}${owner}：${i.outcome ?? ''}`);
      }
    }

    if (deadIntents.length > 0) {
      lines.push('', '### 已排除路径');
      for (const i of deadIntents) {
        lines.push(`- \`${i.id}\` ${i.title}：${i.outcome ?? ''}`);
      }
    }

    if (openIntents.length > 0) {
      lines.push('', '### 待核实与未完成事项');
      for (const i of openIntents) {
        lines.push(`- \`${i.id}\` (${i.status}, P${i.priority}) ${i.title}`);
      }
    }
  }
  lines.push('');
  return { markdown: lines.join('\n'), challengeCount: challenges.length, factCount: totalFacts, intentCount: totalIntents };
}

function buildDispatchPlan(graph, { challengeFilter, maxWorkers, allowSameChallenge, nowMs }) {
  const factMap = new Map(graph.facts.map(f => [f.id, f]));
  const scoped = challengeFilter
    ? graph.intents.filter(i => i.challenge === challengeFilter)
    : graph.intents;
  const activeChallenges = new Set();
  const overdueRecovery = [];
  for (const intent of scoped) {
    if (intent.status !== 'claimed') continue;
    if (isIntentOverdue(intent, nowMs)) {
      overdueRecovery.push({
        intent_id: intent.id,
        challenge: intent.challenge,
        title: intent.title,
        previous_owner: intent.owner,
        claimed_minutes: elapsedMinutes(intent.claimed_at, nowMs),
        budget_minutes: intent.budget_minutes,
        recommended_action: `ctf_graph(action: "claim_intent", intent_id: "${intent.id}", steal_overdue: true)`,
      });
    } else {
      activeChallenges.add(intent.challenge);
    }
  }
  const open = scoped
    .filter(i => i.status === 'open')
    .sort((a, b) => (b.priority - a.priority) || a.created_at.localeCompare(b.created_at));
  const assignments = [];
  const chosenChallenges = new Set(allowSameChallenge ? [] : activeChallenges);
  for (const intent of open) {
    if (assignments.length >= maxWorkers) break;
    if (!allowSameChallenge && chosenChallenges.has(intent.challenge)) continue;
    chosenChallenges.add(intent.challenge);
    const parentFacts = (intent.parent_fact_ids ?? [])
      .map(id => factMap.get(id))
      .filter(Boolean)
      .map(f => ({ id: f.id, kind: f.kind, title: f.title }));
    const slot = `worker-${assignments.length + 1}-${randomUUID()}`;
    const route = classifyChallengeDomain({
      challenge: intent.challenge,
      title: `${intent.title} ${parentFacts.map(f => f.title).join(' ')}`,
      description: intent.hypothesis ?? '',
    });
    assignments.push({
      worker_slot: slot,
      intent_id: intent.id,
      challenge: intent.challenge,
      title: intent.title,
      priority: intent.priority,
      budget_minutes: intent.budget_minutes,
      recommended_domain: route.primary,
      recommended_domains: route.domains,
      ...(intent.hypothesis ? { hypothesis: intent.hypothesis } : {}),
      parent_facts: parentFacts,
      recommended_prompt: `你是 ${slot}。先执行 ctf_graph(action: "claim_intent", intent_id: "${intent.id}", owner: "${slot}") 认领任务（若返回 conflict 立即停止），保存返回的 lease_id；用 ctf_graph(action: "expand", intent_ids: ["${intent.id}"]${parentFacts.length ? `, fact_ids: ${JSON.stringify(parentFacts.map(f => f.id))}` : ''}) 读完整上下文；在 ${intent.budget_minutes} 分钟预算内完成「${intent.challenge} — ${intent.title}」，结束后用 ctf_graph(action: "finish_intent", intent_id: "${intent.id}", lease_id: "<claim 返回值>", status: "done"|"dead", outcome: "...", facts: [...], spawn_intents: [...]) 原子写回结论与证据。`,
    });
  }
  return {
    action: 'dispatch_plan',
    status: 'ok',
    revision: graph.revision,
    ...(challengeFilter ? { challenge: challengeFilter } : {}),
    max_workers: maxWorkers,
    active_challenges: [...activeChallenges].sort(),
    assignments,
    overdue_recovery: overdueRecovery,
    remaining_open: Math.max(0, open.length - assignments.length),
  };
}

export async function manageGraph(args, files, { now = () => Date.now(), defaultOwner } = {}) {
  const action = args.action;
  const nowMs = now();

  if (action === 'board') {
    const challenge = cleanText(args.challenge, 'challenge', 120, { singleLine: true });
    const statusFilter = args.status_filter ?? 'all';
    if (!BOARD_STATUS_FILTERS.includes(statusFilter)) {
      throw new ToolError('unsupported', `status_filter 须为 ${BOARD_STATUS_FILTERS.join('、')} 之一。`);
    }
    const limit = args.limit ?? DEFAULT_BOARD_LIMIT;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) {
      throw new ToolError('unsupported', 'limit 须为 1 至 500 的整数。');
    }
    const offset = args.offset ?? 0;
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > 5000) {
      throw new ToolError('unsupported', 'offset 须为 0 至 5000 的整数。');
    }
    const summaryOnly = args.summary_only === true;
    const { graph, recovered } = await readGraph(files);
    return { ...summarizeBoard(graph, challenge, nowMs, { statusFilter, limit, offset, summaryOnly }), recovered };
  }

  if (action === 'export_writeup') {
    const challenge = cleanText(args.challenge, 'challenge', 120, { singleLine: true });
    const { graph, recovered } = await readGraph(files);
    const rendered = renderWriteupMarkdown(graph, challenge);
    return {
      action: 'export_writeup',
      status: 'ok',
      revision: graph.revision,
      recovered,
      ...(challenge ? { challenge } : {}),
      challenge_count: rendered.challengeCount,
      fact_count: rendered.factCount,
      intent_count: rendered.intentCount,
      markdown: rendered.markdown,
    };
  }

  if (action === 'dispatch_plan') {
    const challengeFilter = cleanText(args.challenge, 'challenge', 120, { singleLine: true });
    const maxWorkers = args.max_workers ?? 3;
    if (!Number.isSafeInteger(maxWorkers) || maxWorkers < 1 || maxWorkers > 8) {
      throw new ToolError('unsupported', 'max_workers 须为 1 至 8 的整数。');
    }
    const allowSameChallenge = args.allow_same_challenge === true;
    const { graph, recovered } = await readGraph(files);
    return { ...buildDispatchPlan(graph, { challengeFilter, maxWorkers, allowSameChallenge, nowMs }), recovered };
  }

  if (action === 'expand') {
    const factIds = cleanIdList(args.fact_ids, 'fact_ids', 32);
    const intentIds = cleanIdList(args.intent_ids, 'intent_ids', 32);
    if (factIds.length === 0 && intentIds.length === 0) {
      throw new ToolError('unsupported', 'expand 至少需要提供 fact_ids 或 intent_ids 之一。');
    }
    const { graph, recovered } = await readGraph(files);
    const factMap = new Map(graph.facts.map(f => [f.id, f]));
    const intentMap = new Map(graph.intents.map(i => [i.id, i]));
    const facts = [];
    const missingFacts = [];
    for (const id of factIds) {
      const hit = factMap.get(id);
      if (hit) facts.push(hit);
      else missingFacts.push(id);
    }
    const intents = [];
    const missingIntents = [];
    for (const id of intentIds) {
      const hit = intentMap.get(id);
      if (hit) {
        const { claim_lease: _hiddenLease, ...publicIntent } = hit;
        intents.push({ ...publicIntent, overdue: isIntentOverdue(hit, nowMs) });
      } else missingIntents.push(id);
    }
    return {
      action: 'expand',
      status: 'ok',
      revision: graph.revision,
      recovered,
      facts,
      intents,
      ...(missingFacts.length > 0 ? { missing_fact_ids: missingFacts } : {}),
      ...(missingIntents.length > 0 ? { missing_intent_ids: missingIntents } : {}),
    };
  }

  if (!files.canWrite) {
    throw new ToolError('permission', `当前会话为只读权限，无法执行 ${action}。`);
  }

  const actor = cleanText(args.owner, 'owner', 120, { singleLine: true }) ?? defaultOwner ?? 'agent';

  if (action === 'add_fact') {
    const challenge = cleanText(args.challenge, 'challenge', 120, { required: true, singleLine: true });
    if (args.spawn_intents !== undefined && (!Array.isArray(args.spawn_intents) || args.spawn_intents.length > 10)) {
      throw new ToolError('unsupported', 'spawn_intents 须为不超过 10 项的数组。');
    }
    return commitMutation(files, nowMs, (graph, nowIso) => {
      const { fact, deduplicated } = buildFact(graph, args, challenge, actor, nowIso);
      if (deduplicated) {
        return {
          skipWrite: true,
          response: { action: 'add_fact', status: 'deduplicated', fact, spawned_intents: [] },
        };
      }
      const spawned = [];
      if (Array.isArray(args.spawn_intents)) {
        for (const spec of args.spawn_intents) {
          if (!spec || typeof spec !== 'object' || Array.isArray(spec)) {
            throw new ToolError('unsupported', 'spawn_intents 每项须为对象。');
          }
          spawned.push(buildIntent(graph, spec, challenge, [fact.id], nowIso));
        }
      }
      return {
        skipWrite: false,
        response: {
          action: 'add_fact',
          status: 'ok',
          fact,
          spawned_intents: spawned,
        },
      };
    });
  }

  if (action === 'add_intent') {
    const challenge = cleanText(args.challenge, 'challenge', 120, { required: true, singleLine: true });
    return commitMutation(files, nowMs, (graph, nowIso) => {
      const intent = buildIntent(graph, args, challenge, [], nowIso);
      return { skipWrite: false, response: { action: 'add_intent', status: 'ok', intent } };
    });
  }

  if (action === 'claim_intent') {
    const intentId = cleanText(args.intent_id, 'intent_id', 32, { singleLine: true });
    const pickNext = args.next === true;
    if (Boolean(intentId) === pickNext) {
      throw new ToolError('unsupported', 'claim_intent 须在 intent_id 与 next: true 中二选一。');
    }
    const challengeFilter = cleanText(args.challenge, 'challenge', 120, { singleLine: true });
    const stealOverdue = args.steal_overdue === true;

    return commitMutation(files, nowMs, (graph, nowIso, ts) => {
      let target;
      if (intentId) {
        target = graph.intents.find(i => i.id === intentId);
        if (!target) throw new ToolError('missing', `未找到 Intent ${intentId}。`);
        if (target.status === 'done' || target.status === 'dead') {
          return {
            skipWrite: true,
            response: { action: 'claim_intent', status: 'closed', intent_id: target.id, intent_status: target.status, outcome: target.outcome },
          };
        }
        if (target.status === 'claimed') {
          const overdue = isIntentOverdue(target, ts);
          if (!stealOverdue || !overdue) {
            return {
              skipWrite: true,
              response: {
                action: 'claim_intent',
                status: 'conflict',
                intent_id: target.id,
                owner: target.owner,
                claimed_at: target.claimed_at,
                overdue,
                message: overdue
                  ? `Intent ${target.id} 已被 ${target.owner} 认领但已超时，传 steal_overdue: true 可接管。`
                  : `Intent ${target.id} 正由 ${target.owner} 处理中。`,
              },
            };
          }
        }
      } else {
        const candidates = graph.intents.filter(i => {
          if (challengeFilter && i.challenge !== challengeFilter) return false;
          if (i.status === 'open') return true;
          if (stealOverdue && i.status === 'claimed' && isIntentOverdue(i, ts)) return true;
          return false;
        });
        if (candidates.length === 0) {
          return {
            skipWrite: true,
            response: { action: 'claim_intent', status: 'empty', message: '当前没有可认领的 Intent。' },
          };
        }
        candidates.sort((a, b) => (b.priority - a.priority)
          || (a.status === 'open' ? -1 : 1) - (b.status === 'open' ? -1 : 1)
          || a.created_at.localeCompare(b.created_at));
        target = candidates[0];
      }

      const previousOwner = target.status === 'claimed' ? target.owner : null;
      target.status = 'claimed';
      target.owner = actor;
      target.claimed_at = nowIso;
      target.claim_lease = randomUUID();
      if (args.budget_minutes !== undefined) target.budget_minutes = cleanBudget(args.budget_minutes);
      return {
        skipWrite: false,
        response: {
          action: 'claim_intent',
          status: previousOwner ? 'stolen' : 'claimed',
          ...(previousOwner ? { previous_owner: previousOwner } : {}),
          lease_id: target.claim_lease,
          intent: target,
        },
      };
    });
  }

  if (action === 'finish_intent') {
    const intentId = cleanText(args.intent_id, 'intent_id', 32, { required: true, singleLine: true });
    const finalStatus = args.status;
    if (finalStatus !== 'done' && finalStatus !== 'dead') {
      throw new ToolError('unsupported', 'finish_intent 的 status 须为 done 或 dead。');
    }
    const outcome = cleanText(args.outcome, 'outcome', 2000, { required: true });
    if (args.facts !== undefined && (!Array.isArray(args.facts) || args.facts.length > 10)) {
      throw new ToolError('unsupported', 'facts 须为不超过 10 项的数组。');
    }
    if (args.spawn_intents !== undefined && (!Array.isArray(args.spawn_intents) || args.spawn_intents.length > 10)) {
      throw new ToolError('unsupported', 'spawn_intents 须为不超过 10 项的数组。');
    }

    return commitMutation(files, nowMs, (graph, nowIso) => {
      const target = graph.intents.find(i => i.id === intentId);
      if (!target) throw new ToolError('missing', `未找到 Intent ${intentId}。`);
      if (target.status === 'done' || target.status === 'dead') {
        return {
          skipWrite: true,
          response: {
            action: 'finish_intent',
            status: 'closed',
            intent_id: target.id,
            intent_status: target.status,
            owner: target.owner,
            outcome: target.outcome,
            message: `Intent ${target.id} 已处于终态 ${target.status}，不能重复结案。`,
          },
        };
      }
      if (target.status !== 'claimed') {
        return {
          skipWrite: true,
          response: {
            action: 'finish_intent',
            status: 'conflict',
            intent_id: target.id,
            intent_status: target.status,
            attempted_owner: actor,
            message: `Intent ${target.id} 尚未认领；请先用 claim_intent 获取租约，再提交结论。`,
          },
        };
      }
      if (target.status === 'claimed' && target.owner && target.owner !== actor) {
        return {
          skipWrite: true,
          response: {
            action: 'finish_intent',
            status: 'conflict',
            intent_id: target.id,
            owner: target.owner,
            attempted_owner: actor,
            claimed_at: target.claimed_at,
            message: `Intent ${target.id} 当前由 ${target.owner} 持有，${actor} 不能越权结案；如已超时请先用 claim_intent(steal_overdue: true) 接管。`,
          },
        };
      }
      if (target.status === 'claimed' && target.claim_lease && args.lease_id !== target.claim_lease) {
        return {
          skipWrite: true,
          response: {
            action: 'finish_intent',
            status: 'conflict',
            intent_id: target.id,
            owner: target.owner,
            attempted_owner: actor,
            claimed_at: target.claimed_at,
            message: `Intent ${target.id} 的租约已变化或缺失；请使用最近一次 claim_intent 返回的 lease_id。`,
          },
        };
      }
      target.status = finalStatus;
      target.outcome = outcome;
      target.finished_at = nowIso;
      target.claim_lease = null;
      if (!target.owner) target.owner = actor;

      const producedFacts = [];
      if (Array.isArray(args.facts)) {
        for (const spec of args.facts) {
          if (!spec || typeof spec !== 'object' || Array.isArray(spec)) {
            throw new ToolError('unsupported', 'facts 每项须为对象。');
          }
          const { fact } = buildFact(graph, spec, target.challenge, actor, nowIso);
          producedFacts.push(fact);
          if (!target.produced_fact_ids.includes(fact.id)) {
            target.produced_fact_ids.push(fact.id);
          }
        }
      }

      const defaultParents = producedFacts.length > 0 ? producedFacts.map(f => f.id) : target.parent_fact_ids;
      const spawned = [];
      if (Array.isArray(args.spawn_intents)) {
        for (const spec of args.spawn_intents) {
          if (!spec || typeof spec !== 'object' || Array.isArray(spec)) {
            throw new ToolError('unsupported', 'spawn_intents 每项须为对象。');
          }
          spawned.push(buildIntent(graph, spec, target.challenge, defaultParents, nowIso));
        }
      }

      return {
        skipWrite: false,
        response: {
          action: 'finish_intent',
          status: 'ok',
          intent: target,
          produced_facts: producedFacts,
          spawned_intents: spawned,
        },
      };
    });
  }

  throw new ToolError('unsupported', `未知 action：${action}。`);
}
