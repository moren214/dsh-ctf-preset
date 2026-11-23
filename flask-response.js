import { createHash } from 'node:crypto';
import { RESULT_HASH } from './ctf-result-values.js';
import { decodeEvidenceText, parseEvidenceJson } from './evidence.js';
import { httpTextRows, pathFromTarget, statusCode } from './http-evidence.js';

const MAX_REPORTED_SITES = 12;
export const FLASK_RESPONSE_PROPERTIES = {
  http_result_id: { type: 'string', description: '本会话 verify_http_evidence 返回的完整 result_id。' },
  observation_index: { type: 'integer', minimum: 0, description: '要核对的实际响应在 observations 中的索引，从 0 开始。' },
  trace_result_id: { type: 'string', description: '本会话同一路由的 trace_flask_route 结果编号。' },
  file_path: { type: 'string', description: '题目目录内的应用事件 JSONL 日志。' },
};

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

async function priorReport(files, id, tool) {
  const result = typeof id === 'string' && RESULT_HASH.test(id) ? await files.result(id) : undefined;
  if (result?.tool !== tool) throw new Error(`请提供当前会话和目录中 ${tool} 返回的完整结果编号。`);
  return result.report;
}

function siteKey({ file_path, line }) {
  return JSON.stringify([file_path, line]);
}

function statusSites(functions, expected) {
  const bySite = new Map();
  for (const fn of functions) {
    for (const site of fn.status_sites) {
      if (site.status_code !== expected) continue;
      bySite.set(siteKey(site.source), { ...site, scope: fn.scope, function: fn.name, ...(fn.hook ? { hook: fn.hook } : {}) });
    }
  }
  return bySite;
}

function returnSite(row, status, sites, knownSites, hashByFile, normalizePath) {
  const recorded = statusCode(row.status);
  if (recorded === undefined) return { missing: 'event_status_unavailable' };
  if (recorded !== status) return { disagree: 'event_status_differs' };
  if (typeof row.source?.file_path !== 'string' || !Number.isSafeInteger(row.source.line) || row.source.line < 1) {
    return { missing: 'event_source_unavailable' };
  }
  let file_path;
  try {
    file_path = normalizePath(row.source.file_path);
  } catch {
    return { disagree: 'event_source_outside_trace' };
  }
  const key = siteKey({ file_path, line: row.source.line });
  const candidate = sites.get(key);
  if (!candidate) {
    if (knownSites.has(key)) return { disagree: 'event_source_status_differs' };
    return { missing: 'event_source_not_statically_verified' };
  }
  const revision = row.source.sha256;
  if (revision !== undefined) {
    if (typeof revision !== 'string' || !RESULT_HASH.test(revision.toLowerCase())) return { missing: 'event_source_hash_invalid' };
    if (hashByFile.get(file_path) !== revision.toLowerCase()) return { disagree: 'event_source_hash_differs' };
  }
  return { key, candidate, recorded_source_hash: revision === undefined ? 'unavailable' : 'matches' };
}

function scanEvents(text, request, observation, sites, knownSites, hashByFile, normalizePath) {
  const origins = new Map();
  const problems = [];
  let matchingEvents = 0;
  let returnEvents = 0;
  let problemsCount = 0;
  let disagree = false;
  let excludedEvents = 0;
  const observedAt = Date.parse(observation.recorded_at ?? '');
  function recordProblem(reason, location, conflict = false) {
    problemsCount++;
    disagree ||= conflict;
    if (problems.length < MAX_REPORTED_SITES) problems.push({ reason, location });
  }
  for (const { content, location } of httpTextRows(text)) {
    const row = parseEvidenceJson(content);
    if (!row || typeof row !== 'object' || Array.isArray(row)) {
      recordProblem('event_record_unreadable', location);
      continue;
    }
    if (row.request_id !== request.request_id) continue;
    const path = pathFromTarget(row.path);
    if (row.event === 'response_returned' && (typeof row.method !== 'string' || !path)) {
      recordProblem('event_request_unavailable', location);
      continue;
    }
    if (row.method !== request.method || path !== request.path) continue;
    const eventAt = Date.parse(row.timestamp ?? '');
    if (Number.isFinite(observedAt) && Number.isFinite(eventAt) && Math.abs(eventAt - observedAt) > 5 * 60_000) {
      excludedEvents++;
      continue;
    }
    matchingEvents++;
    if (row.event !== 'response_returned') continue;
    returnEvents++;
    const proof = returnSite(row, observation.status_code, sites, knownSites, hashByFile, normalizePath);
    if (proof.missing || proof.disagree) {
      recordProblem(proof.missing ?? proof.disagree, location, proof.disagree !== undefined);
      continue;
    }
    const previous = origins.get(proof.key);
    if (!previous || (previous.recorded_source_hash !== 'matches' && proof.recorded_source_hash === 'matches')) {
      origins.set(proof.key, { ...proof.candidate, recorded_source_hash: proof.recorded_source_hash, event_location: location });
    }
  }
  return { origins: [...origins.values()], matchingEvents, returnEvents, problems, problemsCount, disagree, excludedEvents };
}

export async function verifyFlaskResponse(args, files) {
  const [http, flask] = await Promise.all([
    priorReport(files, args.http_result_id, 'verify_http_evidence'),
    priorReport(files, args.trace_result_id, 'trace_flask_route'),
  ]);
  const index = args.observation_index;
  const observation = Number.isSafeInteger(index) && index >= 0 ? http.observations[index] : undefined;
  if (http.correlation !== 'request_id' || observation?.match !== 'matched' || observation.format === 'expectations_jsonl') {
    throw new Error('请选择按请求 ID 唯一定位的实际响应记录。');
  }
  const { request } = http;
  if (flask.request.method !== request.method || flask.request.path !== request.path) {
    throw new Error('HTTP 观测和 Flask 源码结果须对应同一方法与路径。');
  }
  const file_path = files.normalizePath(args.file_path);
  const sources = [observation.source, ...flask.sources];
  const responseReview = flask.route_identified === true && flask.response_review_pending === true
    && flask.review_count > 0;
  const report = {
    request, observation: { ...observation, result_id: args.http_result_id, index }, trace_result_id: args.trace_result_id,
    sources, ...(responseReview ? { response_processing_unverified: true } : {}),
  };
  if ((flask.status !== 'matched' && !responseReview) || flask.match_count !== 1) {
    return { ...report, status: 'insufficient', reason: 'route_trace_incomplete' };
  }

  const { bytes } = await files.readEvent(file_path);
  const event = { file_path, sha256: sha256(bytes) };
  const text = decodeEvidenceText(bytes);
  if (text === null) throw new Error(`应用事件日志须使用有效的 UTF-8 文本。${file_path}`);
  const checkedHashes = new Map([[file_path, event.sha256]]);
  for (const source of sources) {
    if (!checkedHashes.has(source.file_path)) {
      const original = await files.readSource(source.file_path);
      checkedHashes.set(source.file_path, original === null ? null : sha256(original.bytes));
    }
    if (checkedHashes.get(source.file_path) !== source.sha256) {
      const reason = checkedHashes.get(source.file_path) === null ? 'source_unavailable' : 'source_changed';
      return { ...report, status: 'insufficient', reason, affected_source: source.file_path };
    }
  }

  const trace = flask.trace;
  const responseHooks = trace.response_hooks ?? [];
  const functions = [...trace.hooks, ...responseHooks, { ...trace.handler, scope: 'handler' }];
  const sites = statusSites(functions, observation.status_code);
  const knownSites = new Set(functions.flatMap(fn => fn.status_sites.map(site => siteKey(site.source))));
  const normalizeSource = path => {
    const relative = files.normalizePath(path);
    return flask.source_root ? files.normalizePath(`${flask.source_root}/${relative}`) : relative;
  };
  const { origins, matchingEvents, returnEvents, problems, problemsCount, disagree, excludedEvents } = scanEvents(
    text, request, observation, sites, knownSites, checkedHashes, normalizeSource,
  );
  const truncated = trace.hook_count > trace.hooks.length || (trace.response_hook_count ?? 0) > responseHooks.length
    || functions.some(fn => fn.status_site_count > fn.status_sites.length);
  const summary = {
    ...report, candidates: [...sites.values()].slice(0, MAX_REPORTED_SITES), candidate_count: sites.size,
    candidate_list_incomplete: truncated || sites.size > MAX_REPORTED_SITES,
    event_log: event, matching_events: matchingEvents, return_events: returnEvents,
    excluded_events_by_time: excludedEvents,
    ...(trace.framework_response === undefined ? {} : { framework_response: trace.framework_response }),
    sources: [...sources, event],
  };
  if (problemsCount) return { ...summary, status: disagree ? 'inconsistent' : 'insufficient', problems, problem_count: problemsCount };
  if (origins.length > 1) return { ...summary, status: 'ambiguous', origins: origins.slice(0, MAX_REPORTED_SITES), origin_count: origins.length };
  if (origins.length === 0) {
    if (responseReview) return { ...summary, status: 'insufficient', reason: 'response_processing_requires_return_event' };
    if (trace.framework_response?.status_code === observation.status_code) {
      return { ...summary, status: 'candidates', reason: 'framework_response_requires_event' };
    }
    return sites.size ? { ...summary, status: 'candidates', reason: 'no_matching_return_event' }
      : { ...summary, status: 'insufficient', reason: 'no_explicit_status_site' };
  }
  const [origin] = origins;
  const eventSource = { ...event, ...origin.event_location };
  summary.sources = [observation.source, ...flask.sources.map(source => source.file_path === origin.source.file_path
    ? { ...source, line: origin.source.line } : source), eventSource];
  return { ...summary, status: 'correlated', origin: { ...origin, event_source: eventSource } };
}
