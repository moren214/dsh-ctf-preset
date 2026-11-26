import { provenanceUrl } from './attachment-transfer.js';
import { classifyChallengeDomain } from './ctf-router.js';
import { webUrl } from './network-boundary.js';
import { platformBase, platformCredential, platformRequest } from './platform-request.js';
import { handleSubmission } from './submission.js';
import { ToolError } from './tool-errors.js';

export const ARENA_ADAPTERS = ['auto', 'ctfd', 'gzctf', 'generic'];
const SAFE_ID = /^[A-Za-z0-9._-]{1,120}$/u;

export const ARENA_PROPERTIES = {
  action: {
    type: 'string',
    enum: ['status', 'games', 'challenges', 'detail', 'sync_graph', 'fetch_files', 'container', 'submit'],
    description: 'CTFd/GZCTF/通用平台统一入口：challenges 拉题单；detail 查题情并授权靶机；sync_graph 导入 ctf_graph；fetch_files 拉附件；container 启删靶机；submit 校验并提交。',
  },
  platform_type: { type: 'string', enum: ARENA_ADAPTERS },
  game_id: { type: 'string', maxLength: 120, description: 'GZCTF 比赛 ID。' },
  challenge_id: { type: 'string', maxLength: 120 },
  category: { type: 'string', maxLength: 120 },
  unsolved_only: { type: 'boolean', default: true },
  limit: { type: 'integer', minimum: 1, maximum: 200, default: 20 },
  offset: { type: 'integer', minimum: 0, maximum: 5000, default: 0, description: '分页起始偏移（支持超过 50 题的大型赛场）。' },
  container_action: { type: 'string', enum: ['create', 'delete', 'extend'] },
  flag: { type: 'string', maxLength: 512 },
  pattern: { type: 'string', maxLength: 200 },
  source: { type: 'string', maxLength: 400 },
  dynamic: { type: 'boolean' },
  instance: { type: 'string', maxLength: 200 },
  refreshed_at: { type: 'string', maxLength: 40 },
  retry_unknown: { type: 'boolean', description: '上次提交为 unknown/pending（如 429/超时）时允许重提。' },
};

function safeId(value, label) {
  const text = typeof value === 'number' && Number.isSafeInteger(value) ? String(value) : String(value ?? '').trim();
  if (!SAFE_ID.test(text) || text === '.' || text === '..') {
    throw new ToolError('unsupported', `${label} 须为合法的标识字符（1-120 字符，不含路径分隔符）。`);
  }
  return text;
}

function parseJsonBody(response) {
  if (!response || typeof response.body !== 'string' || response.body.trim() === '') return undefined;
  try {
    return JSON.parse(response.body);
  } catch {
    return response.body.trim();
  }
}

function okHttp(response) {
  return Boolean(response && response.status >= 200 && response.status < 300 && !response.body_error);
}

function adapterConfig(config, adapter) {
  if (config?.platformAuthHeader !== undefined || config?.platformAuthScheme !== undefined) {
    return config;
  }
  if (adapter === 'ctfd') {
    return { ...config, platformAuthScheme: 'Token' };
  }
  if (adapter === 'gzctf') {
    const { token } = platformCredential(config);
    if (token) {
      if (/(?:^|;\s*)GZCTF_Token=/u.test(token)) {
        return { ...config, platformAuthHeader: 'Cookie', platformAuthScheme: '' };
      }
      if (!token.includes('=')) {
        return { ...config, platformAuthHeader: 'Cookie', platformAuthScheme: 'GZCTF_Token=' };
      }
    }
  }
  return config;
}

export async function resolveAdapter(config, requestedType, gameId, signal, requestFn = platformRequest) {
  const configured = requestedType ?? config?.platformType ?? 'auto';
  if (!ARENA_ADAPTERS.includes(configured)) {
    throw new ToolError('unsupported', `platform_type 须为 ${ARENA_ADAPTERS.join('、')} 之一。`);
  }
  if (configured !== 'auto') return configured;
  const checkProbeAuth = response => {
    if ([401, 403].includes(Number(response?.status))) {
      throw new ToolError('permission', '平台自动探测收到认证拒绝，请核对平台凭据及权限。');
    }
    return response;
  };
  if (gameId) {
    const gz = checkProbeAuth(await requestFn(adapterConfig(config, 'gzctf'), signal, 'GET', `/api/game/${encodeURIComponent(gameId)}/details`));
    if (okHttp(gz)) return 'gzctf';
  }
  const ctfd = checkProbeAuth(await requestFn(adapterConfig(config, 'ctfd'), signal, 'GET', '/api/v1/challenges'));
  const ctfdBody = parseJsonBody(ctfd);
  if (okHttp(ctfd) && ctfdBody && typeof ctfdBody === 'object' && ctfdBody.success === true && Array.isArray(ctfdBody.data)) {
    return 'ctfd';
  }
  const gz = checkProbeAuth(await requestFn(adapterConfig(config, 'gzctf'), signal, 'GET', '/api/game'));
  const gzBody = parseJsonBody(gz);
  if (okHttp(gz) && (Array.isArray(gzBody) || Array.isArray(gzBody?.data))) return 'gzctf';
  return 'generic';
}

function normalizeChallengeItem(raw, fallbackCategory = 'Misc') {
  if (!raw || typeof raw !== 'object') return undefined;
  const id = raw.id ?? raw.challenge_id;
  if (id === undefined || id === null) return undefined;
  return {
    id: String(id),
    name: String(raw.name ?? raw.title ?? `challenge-${id}`).trim(),
    category: String(raw.category ?? raw.tag ?? fallbackCategory).trim() || fallbackCategory,
    value: Number.isFinite(Number(raw.value ?? raw.score ?? raw.points)) ? Number(raw.value ?? raw.score ?? raw.points) : 0,
    solved: Boolean(raw.solved_by_me ?? raw.solved ?? raw.isSolved),
    ...(Number.isFinite(Number(raw.solves ?? raw.solvedCount)) ? { solves: Number(raw.solves ?? raw.solvedCount) } : {}),
  };
}

export function normalizeChallengeList(adapter, body) {
  const items = [];
  if (adapter === 'ctfd') {
    const rows = Array.isArray(body?.data) ? body.data : Array.isArray(body) ? body : [];
    for (const row of rows) {
      const norm = normalizeChallengeItem(row);
      if (norm) items.push(norm);
    }
    return items;
  }
  if (adapter === 'gzctf') {
    const source = body?.challenges ?? body?.data?.challenges ?? body?.data ?? body;
    if (Array.isArray(source)) {
      for (const row of source) {
        const norm = normalizeChallengeItem(row);
        if (norm) items.push(norm);
      }
    } else if (source && typeof source === 'object') {
      for (const [cat, list] of Object.entries(source)) {
        if (!Array.isArray(list)) continue;
        for (const row of list) {
          const norm = normalizeChallengeItem(row, cat);
          if (norm) items.push(norm);
        }
      }
    }
    return items;
  }
  const rows = Array.isArray(body) ? body : Array.isArray(body?.data) ? body.data : Array.isArray(body?.challenges) ? body.challenges : [];
  for (const row of rows) {
    const norm = normalizeChallengeItem(row);
    if (norm) items.push(norm);
  }
  return items;
}

function resolveFileUrl(base, rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.trim() === '') return undefined;
  try {
    const resolved = new URL(rawUrl.trim(), base.endsWith('/') ? base : base + '/');
    if (resolved.protocol === 'http:' || resolved.protocol === 'https:') return resolved.toString();
  } catch { /* ignore invalid */ }
  return undefined;
}

export function normalizeChallengeDetail(adapter, base, rawBody) {
  const d = rawBody?.data && typeof rawBody.data === 'object' && !Array.isArray(rawBody.data) ? rawBody.data : rawBody;
  if (!d || typeof d !== 'object') throw new ToolError('unsupported', '平台返回的题目详情格式无法解析。');
  const summary = normalizeChallengeItem(d) ?? { id: String(d.id ?? ''), name: String(d.name ?? d.title ?? ''), category: 'Misc', value: 0, solved: false };
  const rawFiles = [];
  if (Array.isArray(d.files)) rawFiles.push(...d.files);
  if (d.attachment?.url) rawFiles.push(d.attachment.url);
  if (d.context?.attachment?.url) rawFiles.push(d.context.attachment.url);
  const files = [...new Set(rawFiles.map(item => {
    const href = typeof item === 'string' ? item : item?.url ?? item?.href;
    return resolveFileUrl(base, href);
  }).filter(Boolean))];
  const hints = Array.isArray(d.hints)
    ? d.hints.map(h => (typeof h === 'string' ? h : String(h?.content ?? h?.text ?? '').trim())).filter(Boolean)
    : [];
  const connectionInfo = typeof d.connection_info === 'string' && d.connection_info.trim()
    ? d.connection_info.trim()
    : typeof d.context?.entry === 'string' && d.context.entry.trim()
      ? d.context.entry.trim()
      : typeof d.context?.url === 'string' && d.context.url.trim()
        ? d.context.url.trim()
        : undefined;
  return {
    adapter,
    ...summary,
    description: String(d.description ?? d.content ?? '').slice(0, 16384),
    ...(connectionInfo ? { connection_info: connectionInfo } : {}),
    files,
    ...(hints.length > 0 ? { hints } : {}),
    ...(d.context && typeof d.context === 'object' ? { container: d.context } : {}),
  };
}

function normalizeSubmitResponse(adapter, response) {
  if (adapter !== 'gzctf' || !response) return response;
  const parsed = parseJsonBody(response);
  const label = typeof parsed === 'string' ? parsed : String(parsed?.data ?? parsed?.status ?? parsed?.result ?? '');
  const lower = label.trim().toLowerCase();
  let mapped;
  if (['accepted', 'correct'].includes(lower)) mapped = { status: 'accepted', raw: label };
  else if (['wronganswer', 'wrong', 'incorrect', 'rejected', 'invalid'].includes(lower)) mapped = { status: 'rejected', raw: label };
  else if (['flagsubmitted', 'alreadysolved', 'duplicate'].includes(lower)) mapped = { status: 'duplicate', raw: label };
  return mapped ? { ...response, body: JSON.stringify(mapped) } : response;
}

function priorityForChallenge(item, allItems) {
  if (allItems.length === 0) return 3;
  // 综合分值（低分优先）与解出人数（高解出优先）：开赛初期所有题目初始分相同时按 solves 精准排序
  const ordered = [...allItems].sort((a, b) => {
    const scoreDiff = (a.value ?? 0) - (b.value ?? 0);
    if (scoreDiff !== 0) return scoreDiff;
    const solvesA = Number.isFinite(a.solves) ? a.solves : -1;
    const solvesB = Number.isFinite(b.solves) ? b.solves : -1;
    return solvesB - solvesA;
  });
  const key = entry => `${entry.value ?? 0}:${Number.isFinite(entry.solves) ? entry.solves : -1}`;
  const itemKey = key(item);
  const idx = ordered.findIndex(entry => key(entry) === itemKey);
  const ratio = ordered.length <= 1 ? 0.5 : Math.max(0, idx) / (ordered.length - 1);
  if (ratio <= 0.2) return 5;
  if (ratio <= 0.45) return 4;
  if (ratio <= 0.7) return 3;
  if (ratio <= 0.9) return 2;
  return 1;
}

function extractEndpointsFromText(text) {
  const http = [];
  const tcp = [];
  if (typeof text !== 'string' || text.trim() === '') return { http, tcp };
  for (const m of text.matchAll(/https?:\/\/[^\s"'<>)]+/giu)) {
    http.push(m[0].replace(/[.,;]+$/u, ''));
  }
  for (const m of text.matchAll(/\b(?:nc|ncat|netcat)\s+(?:-[A-Za-z0-9]+\s+)*(\[[^\]]+\]|[A-Za-z0-9.-]+)\s+(\d{1,5})\b/giu)) {
    const port = Number(m[2]);
    if (port >= 1 && port <= 65535) tcp.push({ host: m[1], port });
  }
  for (const m of text.matchAll(/(?:^|\s)(\[[^\]]+\]|[A-Za-z0-9.-]+\.[A-Za-z0-9.-]+|\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})(?:\s|$)/gu)) {
    const port = Number(m[2]);
    if (port >= 1 && port <= 65535) tcp.push({ host: m[1], port });
  }
  return { http, tcp };
}

export async function runArena(args, {
  config = {},
  signal,
  writable,
  network,
  networkScope,
  authorizeResponse,
  revokeTargets,
  recordInstance,
  lookupInstance,
  requestFn = platformRequest,
  syncGraphFact,
  fetchFile,
  submissionFiles,
}) {
  const action = args.action;
  const base = platformBase(config);
  const { tokenEnv, token } = platformCredential(config);
  const gameId = args.game_id !== undefined ? safeId(args.game_id, 'game_id')
    : (typeof config?.platformGameId === 'string' && config.platformGameId.trim() !== '' ? safeId(config.platformGameId, 'platformGameId') : undefined);

  if (action === 'status') {
    const configuredType = args.platform_type ?? config?.platformType ?? 'auto';
    let detected = configuredType;
    if (base && configuredType === 'auto') {
      detected = await resolveAdapter(config, 'auto', gameId, signal, requestFn);
    }
    return {
      action: 'status',
      status: base ? 'ok' : 'unconfigured',
      configured: base !== '',
      base: base ? provenanceUrl(webUrl(base)) : null,
      platform_type: configuredType,
      detected_adapter: base ? detected : null,
      ...(gameId ? { game_id: gameId } : {}),
      token_env: tokenEnv,
      token_present: token !== '',
    };
  }

  if (!base) {
    throw new ToolError('dependency', '未配置比赛平台 platformUrl。请在 ~/.dsh/ctf-workbench.json 设置 platformUrl 及令牌环境变量。');
  }

  const adapter = await resolveAdapter(config, args.platform_type, gameId, signal, requestFn);
  const cfg = adapterConfig(config, adapter);

  if (action === 'games') {
    if (adapter !== 'gzctf') {
      return { action: 'games', adapter, status: 'not_applicable', note: '仅 GZCTF 平台按 game_id 组织比赛；当前平台可直接调用 challenges。' };
    }
    const res = await requestFn(cfg, signal, 'GET', '/api/game');
    if (!okHttp(res)) return { action: 'games', adapter, status: 'failed', request: res };
    const body = parseJsonBody(res);
    const list = Array.isArray(body) ? body : Array.isArray(body?.data) ? body.data : [];
    return {
      action: 'games',
      adapter,
      status: 'ok',
      count: list.length,
      games: list.slice(0, 32).map(g => ({
        id: String(g?.id ?? ''),
        title: String(g?.title ?? g?.name ?? ''),
        ...(g?.start ? { start: g.start } : {}),
        ...(g?.end ? { end: g.end } : {}),
      })),
    };
  }

  const requireGzGame = () => {
    if (adapter === 'gzctf' && !gameId) {
      throw new ToolError('unsupported', 'GZCTF 平台操作需要提供 game_id（或在配置中设 platformGameId；可先调用 games 查询）。');
    }
    return gameId;
  };

  async function fetchChallengeList() {
    let route;
    if (adapter === 'ctfd') route = '/api/v1/challenges';
    else if (adapter === 'gzctf') route = `/api/game/${encodeURIComponent(requireGzGame())}/details`;
    else route = config?.platformChallengesPath ?? '/challenges';
    const res = await requestFn(cfg, signal, 'GET', route);
    if (!okHttp(res)) return { ok: false, request: res };
    const rawBody = parseJsonBody(res);
    let allRaw = normalizeChallengeList(adapter, rawBody);
    // Support generic REST pagination when the platform returns a same-origin `next` path.
    if (adapter === 'generic' && rawBody && typeof rawBody === 'object' && typeof rawBody.next === 'string') {
      const seenRoutes = new Set([route]);
      let nextRoute = rawBody.next;
      for (let page = 0; page < 10 && typeof nextRoute === 'string' && nextRoute.startsWith('/') && !seenRoutes.has(nextRoute); page += 1) {
        seenRoutes.add(nextRoute);
        const pageRes = await requestFn(cfg, signal, 'GET', nextRoute);
        if (!okHttp(pageRes)) break;
        const pageBody = parseJsonBody(pageRes);
        const pageItems = normalizeChallengeList(adapter, pageBody);
        if (pageItems.length === 0) break;
        allRaw = allRaw.concat(pageItems);
        nextRoute = pageBody && typeof pageBody === 'object' && typeof pageBody.next === 'string' ? pageBody.next : '';
      }
    }
    const totalRaw = allRaw.length;
    let challenges = allRaw;
    if (typeof args.category === 'string' && args.category.trim() !== '') {
      const wanted = args.category.trim().toLowerCase();
      challenges = challenges.filter(c => c.category.toLowerCase() === wanted);
    }
    if (args.unsolved_only === true) {
      challenges = challenges.filter(c => !c.solved);
    }
    return { ok: true, totalRaw, challenges };
  }

  if (action === 'challenges') {
    const listed = await fetchChallengeList();
    if (!listed.ok) return { action: 'challenges', adapter, status: 'failed', request: listed.request };
    const offset = Number.isSafeInteger(args.offset) && args.offset >= 0 ? args.offset : 0;
    const limit = Math.min(Number.isSafeInteger(args.limit) && args.limit >= 1 ? args.limit : 20, 200);
    const shown = listed.challenges.slice(offset, offset + limit);
    const hasMore = offset + shown.length < listed.challenges.length;
    return {
      action: 'challenges',
      adapter,
      status: 'ok',
      total: listed.challenges.length,
      total_raw: listed.totalRaw,
      total_matched: listed.challenges.length,
      offset,
      shown: shown.length,
      has_more: hasMore,
      ...(hasMore ? { next_offset: offset + shown.length } : {}),
      challenges: shown,
    };
  }

  async function fetchChallengeDetail(challengeId) {
    let route;
    if (adapter === 'ctfd') route = `/api/v1/challenges/${encodeURIComponent(challengeId)}`;
    else if (adapter === 'gzctf') route = `/api/game/${encodeURIComponent(requireGzGame())}/challenges/${encodeURIComponent(challengeId)}`;
    else route = `${(config?.platformChallengesPath ?? '/challenges').replace(/\/$/u, '')}/${encodeURIComponent(challengeId)}`;
    const res = await requestFn(cfg, signal, 'GET', route);
    if (!okHttp(res)) return { ok: false, request: res };
    const detail = normalizeChallengeDetail(adapter, base, parseJsonBody(res));
    const leaseScope = networkScope ? { ...networkScope, leaseId: `challenge:${challengeId}` } : undefined;
    // Only the platform's designated connection field can describe a target.
    // The raw response includes free-form description text and is not authorization.
    const fromText = extractEndpointsFromText(detail.connection_info ?? '');
    const grantedHttp = [...new Set([
      ...fromText.http.map(u => network?.grantHttp(u, leaseScope)).filter(Boolean),
    ])];
    const grantedTcp = [...new Set([
      ...fromText.tcp.map(({ host, port }) => network?.grantTcp(host, port, leaseScope)).filter(Boolean),
    ])];
    return {
      ok: true,
      detail,
      ...(grantedHttp.length || grantedTcp.length ? { authorized_targets: { http: grantedHttp, tcp: grantedTcp } } : {}),
    };
  }

  if (action === 'detail') {
    const id = safeId(args.challenge_id, 'challenge_id');
    const fetched = await fetchChallengeDetail(id);
    if (!fetched.ok) return { action: 'detail', adapter, status: 'failed', request: fetched.request };
    const route = classifyChallengeDomain({
      category: fetched.detail.category,
      title: fetched.detail.name,
      description: fetched.detail.description,
      connection_info: fetched.detail.connection_info,
      files: fetched.detail.files,
    });
    return {
      action: 'detail',
      status: 'ok',
      ...fetched.detail,
      recommended_domain: route.primary,
      recommended_domains: route.domains,
      recommended_tools: route.recommended_tools,
      ...(fetched.authorized_targets ? { authorized_targets: fetched.authorized_targets } : {}),
    };
  }

  if (!writable) {
    throw new ToolError('permission', `当前会话为只读权限，无法执行平台写操作 ${action}。`);
  }

  if (action === 'sync_graph') {
    const listed = await fetchChallengeList();
    if (!listed.ok) return { action: 'sync_graph', adapter, status: 'failed', request: listed.request };
    const offset = Number.isSafeInteger(args.offset) && args.offset >= 0 ? args.offset : 0;
    const limit = Math.min(Number.isSafeInteger(args.limit) && args.limit >= 1 ? args.limit : 20, 200);
    const slice = listed.challenges.slice(offset, offset + limit);
    const hasMore = offset + slice.length < listed.challenges.length;
    const imported = [];
    let deduplicated = 0;
    for (const item of slice) {
      const priority = priorityForChallenge(item, slice);
      const challengeKey = `${item.category.toLowerCase()}-${item.name}`.replace(/[^\w\u4e00-\u9fff.-]+/gu, '-').slice(0, 80);
      const res = await syncGraphFact({
        action: 'add_fact',
        challenge: challengeKey,
        kind: 'recon',
        title: `[${item.category}/${item.value}pt] ${item.name} (#${item.id})`,
        summary: `平台 ${adapter} 题目 #${item.id}（分类 ${item.category}，分值 ${item.value}${item.solves !== undefined ? `，解出 ${item.solves}` : ''}）。`,
        source: `ctf_arena:${adapter}:${item.id}`,
        dedupe_key: `arena:${adapter}:${item.id}`,
        spawn_intents: item.solved ? [] : [{
          title: `查题情/拉附件并开题（#${item.id}）`,
          hypothesis: `调用 ctf_arena(detail/fetch_files, challenge_id: "${item.id}") 获取题面与附件后开展分析。`,
          priority,
          budget_minutes: 15,
        }],
      });
      if (res.status === 'deduplicated' || res.status === 'deduplicated_with_spawn') {
        deduplicated += 1;
      } else {
        imported.push({ challenge: challengeKey, challenge_id: item.id, fact_id: res.fact?.id, intent_id: res.spawned_intents?.[0]?.id, priority });
      }
    }
    return {
      action: 'sync_graph',
      adapter,
      status: 'ok',
      total: listed.challenges.length,
      offset,
      scanned: slice.length,
      has_more: hasMore,
      ...(hasMore ? { next_offset: offset + slice.length } : {}),
      imported_count: imported.length,
      deduplicated_count: deduplicated,
      imported,
      hint: '可立即调用 ctf_graph(action: "dispatch_plan") 为多个并行子代理生成分工简报。',
    };
  }

  if (action === 'fetch_files') {
    const id = safeId(args.challenge_id, 'challenge_id');
    const fetched = await fetchChallengeDetail(id);
    if (!fetched.ok) return { action: 'fetch_files', adapter, status: 'failed', request: fetched.request };
    const allFiles = fetched.detail.files;
    const files = allFiles.slice(0, 8);
    if (files.length === 0) {
      return { action: 'fetch_files', adapter, status: 'ok', challenge_id: id, downloaded: [], note: '该题目未提供附件下载链接。' };
    }
    const downloaded = [];
    for (const url of files) {
      downloaded.push(await fetchFile(url, cfg));
    }
    return {
      action: 'fetch_files',
      adapter,
      status: files.length < allFiles.length ? 'partial' : 'ok',
      challenge_id: id,
      challenge_name: fetched.detail.name,
      total_files: allFiles.length,
      omitted_file_count: allFiles.length - files.length,
      downloaded,
      ...(files.length < allFiles.length ? { note: '本次最多下载 8 个附件；请从 detail 返回的 URL 中选择其余附件并逐个调用 fetch_attachment。' } : {}),
    };
  }

  if (action === 'container') {
    const id = safeId(args.challenge_id, 'challenge_id');
    const op = args.container_action;
    if (op !== 'create' && op !== 'delete' && op !== 'extend') {
      throw new ToolError('unsupported', 'container 需要指定 container_action 为 create、delete 或 extend。');
    }
    if (adapter !== 'gzctf') {
      throw new ToolError('unsupported', `当前平台适配器 ${adapter} 不支持题目级容器启删/续期，请使用 ctf_instance 管理实例。`);
    }
    const baseRoute = `/api/game/${encodeURIComponent(requireGzGame())}/challenges/${encodeURIComponent(id)}/container`;
    const route = op === 'extend' ? `${baseRoute}/extend` : baseRoute;
    const method = op === 'delete' ? 'DELETE' : 'POST';
    const res = await requestFn(cfg, signal, method, route, op === 'delete' ? undefined : {});
    if (!okHttp(res)) return { action: 'container', container_action: op, adapter, status: 'failed', request: res };
    const leaseId = `container:${id}`;
    const authorized = op !== 'delete' ? authorizeResponse?.(res, leaseId) : undefined;
    if (op === 'delete') revokeTargets?.(leaseId);
    const statusLabel = op === 'create' ? 'created' : op === 'extend' ? 'extended' : 'deleted';
    const instanceId = `container:${id}`;
    const instanceRecorded = recordInstance ? await recordInstance(instanceId, op === 'delete' ? 'deleted' : 'created') : undefined;
    return {
      action: 'container',
      container_action: op,
      adapter,
      status: instanceRecorded === false ? 'partial' : statusLabel,
      challenge_id: id,
      ...(instanceRecorded !== undefined ? { instance_id: instanceId, instance_recorded: instanceRecorded } : {}),
      container: parseJsonBody(res),
      ...(authorized ? { authorized_targets: authorized } : {}),
      ...(instanceRecorded === false ? { note: '平台容器操作已完成，但实例账本写入失败；动态 flag 提交前请重试容器刷新并确认 instance_recorded。' } : {}),
    };
  }

  if (action === 'submit') {
    const id = safeId(args.challenge_id, 'challenge_id');
    if (typeof args.flag !== 'string' || args.flag.trim() === '') {
      throw new ToolError('unsupported', 'submit 需要提供非空 flag。');
    }
    let refreshedAt = args.refreshed_at;
    if (args.dynamic === true) {
      const instanceId = typeof args.instance === 'string' ? args.instance.trim() : '';
      const record = instanceId && lookupInstance ? await lookupInstance(instanceId) : undefined;
      const age = record?.state === 'created' ? Date.now() - Date.parse(record.observed_at ?? '') : Infinity;
      if (!Number.isFinite(age) || age < -5 * 60000 || age > 30 * 60000) {
        return {
          action: 'submit', adapter, challenge_id: id, status: 'rejected', verdict: 'rejected_local',
          reason: '动态 flag 需要 30 分钟内由 ctf_instance 或 ctf_arena 容器操作写入的实例记录；调用方提供的 refreshed_at 不作为可信刷新时间。',
        };
      }
      refreshedAt = record.observed_at;
    }
    const submitArgs = {
      flag: args.flag,
      challenge: id,
      ...(args.pattern !== undefined ? { pattern: args.pattern } : {}),
      ...(args.source !== undefined ? { source: args.source } : {}),
      ...(args.dynamic !== undefined ? { dynamic: args.dynamic } : {}),
      ...(args.instance !== undefined ? { instance: args.instance } : {}),
      ...(refreshedAt !== undefined ? { refreshed_at: refreshedAt } : {}),
      ...(args.retry_unknown === true ? { retry_unknown: true } : {}),
    };
    const outcome = await handleSubmission(submitArgs, submissionFiles, async () => {
      if (adapter === 'ctfd') {
        const numeric = /^\d+$/u.test(id) ? Number(id) : id;
        return requestFn(cfg, signal, 'POST', '/api/v1/challenges/attempt', { challenge_id: numeric, submission: args.flag.trim() });
      }
      if (adapter === 'gzctf') {
        const raw = await requestFn(cfg, signal, 'POST', `/api/game/${encodeURIComponent(requireGzGame())}/challenges/${encodeURIComponent(id)}`, { flag: args.flag.trim() });
        return normalizeSubmitResponse(adapter, raw);
      }
      return requestFn(cfg, signal, 'POST', cfg?.platformSubmitPath ?? '/submissions', { challenge: id, flag: args.flag.trim() });
    }, base, signal);
    return { action: 'submit', adapter, challenge_id: id, ...outcome };
  }

  throw new ToolError('unsupported', `未知 action：${action}。`);
}
