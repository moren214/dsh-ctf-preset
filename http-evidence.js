import { createHash } from 'node:crypto';
import { decodeEvidenceText, locatedTextRows, parseEvidenceJson } from './evidence.js';

export const MAX_HTTP_BYTES = 8 * 1024 * 1024;
const MAX_RECORDS = 50000;
const MAX_SOURCES = 6;
const MAX_PATH = 2048;
const FORMATS = ['har', 'access_jsonl', 'access_combined', 'expectations_jsonl'];
const METHOD = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}$/u;
const PATH = /^\/[^\u0000-\u0020\u007f\\?#\p{Cs}]*$/u;
const REQUEST_ID = /^[A-Za-z0-9_.:@-]{1,128}$/u;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;
const COMBINED = /^\S+ \S+ \S+ \[(\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\] "([^ "\t]+) ([^ "\t]+) HTTP\/\d+(?:\.\d+)?" ([\d-]+) (?:\d+|-)(?=\s|$)/u;
const MEDIA_TYPE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+\/[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u;

export const HTTP_EVIDENCE_PROPERTIES = {
  request: {
    type: 'object', additionalProperties: false, required: ['method', 'path'],
    properties: {
      method: { type: 'string', maxLength: 32, description: '按记录原样匹配的方法，如 GET。' },
      path: { type: 'string', maxLength: MAX_PATH, description: '已知的请求路径，从 / 开始，省略查询串。' },
      request_id: { type: 'string', maxLength: 128, description: '记录中已知的请求 ID。HAR 取 X-Request-ID。' },
    },
  },
  sources: {
    type: 'array', minItems: 1, maxItems: MAX_SOURCES,
    items: {
      type: 'object', additionalProperties: false, required: ['file_path', 'format'],
      properties: {
        file_path: { type: 'string', description: '题目目录内的本地附件路径。' },
        format: { type: 'string', enum: FORMATS, description: 'HAR、JSONL 访问日志、Common/Combined 访问日志或 JSONL 预期状态表。' },
      },
    },
  },
};

function hasKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).every(key => keys.includes(key));
}

function given(value, pattern) {
  return typeof value === 'string' && pattern.test(value);
}

function validPath(value) {
  return typeof value === 'string' && value.length <= MAX_PATH && PATH.test(value);
}

function parseRequest(request) {
  if (!hasKeys(request, ['method', 'path', 'request_id']) || !given(request.method, METHOD) || !validPath(request.path)
    || (request.request_id !== undefined && !given(request.request_id, REQUEST_ID))) {
    throw new Error('请提供已知的请求方法和不带查询串的 / 路径，可附已记录的 request_id。');
  }
  return request;
}

export function pathFromTarget(target, absolute = false) {
  if (typeof target !== 'string') return undefined;
  if (absolute) {
    const authority = /^https?:\/\/[^\s/?#\\]+(?=[/?#]|$)/iu.exec(target);
    if (!authority) return undefined;
    target = target.slice(authority[0].length);
    if (target === '' || /^[?#]/u.test(target)) return '/';
  }
  const path = target.split(/[?#]/u, 1)[0];
  return validPath(path) ? path : undefined;
}

export function statusCode(value) {
  if (given(value, /^[1-5]\d\d$/u)) return Number(value);
  return Number.isInteger(value) && value >= 100 && value <= 599 ? value : undefined;
}

function recordedAt(value) {
  return given(value, ISO_TIME) && Number.isFinite(Date.parse(value)) ? value : undefined;
}

function headerValues(headers, name) {
  if (!Array.isArray(headers)) return [];
  return headers.flatMap(header => typeof header?.name === 'string' && header.name.toLowerCase() === name && typeof header.value === 'string'
    ? [header.value.trim()] : []);
}

function parseHar(row, index) {
  const path = pathFromTarget(row?.request?.url, true);
  const method = row?.request?.method;
  if (!path || !given(method, METHOD)) return undefined;
  const headers = row.response?.headers;
  const requestIds = [...new Set([
    ...headerValues(row.request.headers, 'x-request-id'),
    ...headerValues(headers, 'x-request-id'),
  ])];
  const types = [...new Set(headerValues(headers, 'content-type').map(value => value.split(';', 1)[0].trim().toLowerCase()))];
  return {
    path, method, status: row.response?.status, requestIds, time: recordedAt(row.startedDateTime),
    headers: Array.isArray(headers) ? {
      media_type: types.length === 1 && types[0].length <= 128 && MEDIA_TYPE.test(types[0]) ? types[0] : undefined,
      location_present: headerValues(headers, 'location').length > 0,
      set_cookie_present: headerValues(headers, 'set-cookie').length > 0,
    } : undefined,
    location: { json_pointer: `/log/entries/${index}/response/status` },
  };
}

function parseJsonl(text) {
  const row = parseEvidenceJson(text);
  const path = pathFromTarget(row?.path);
  if (!path || !given(row.method, METHOD)) return undefined;
  return {
    path, method: row.method, status: row.status,
    requestIds: given(row.request_id, REQUEST_ID) ? [row.request_id] : [], time: recordedAt(row.timestamp),
  };
}

function parseCombined(text) {
  const entry = COMBINED.exec(text);
  if (!entry) return undefined;
  const [, time, method, target, status] = entry;
  const path = pathFromTarget(target);
  return path && given(method, METHOD) ? { path, method, status, time, requestIds: [] } : undefined;
}

export function httpTextRows(text) {
  return locatedTextRows(text, MAX_RECORDS, '每份 Web 原件');
}

function* traceRows(text, format) {
  if (format === 'har') {
    const entries = parseEvidenceJson(text)?.log?.entries;
    if (!Array.isArray(entries)) throw new Error('HAR 需要有效的 log.entries 数组。');
    if (entries.length > MAX_RECORDS) throw new Error('每份 Web 原件最多检查 50000 条记录。');
    for (const [index, entry] of entries.entries()) yield parseHar(entry, index);
    return;
  }
  const parse = format === 'access_combined' ? parseCombined : parseJsonl;
  for (const { content, location } of httpTextRows(text)) {
    const row = parse(content);
    yield row ? { ...row, location } : undefined;
  }
}

function locateTrace(text, format, request) {
  const requireId = request.request_id !== undefined && format !== 'expectations_jsonl';
  if (requireId && format === 'access_combined') return { match: 'request_id_unavailable', matches: 0 };
  let chosen;
  let matches = 0;
  let malformed = 0;
  let unidentified = 0;
  let conflictingId = false;
  for (const row of traceRows(text, format)) {
    if (!row) {
      malformed++;
      continue;
    }
    if (row.method !== request.method || row.path !== request.path) continue;
    if (requireId) {
      if (row.requestIds.length === 0) unidentified++;
      if (!row.requestIds.includes(request.request_id)) continue;
      if (row.requestIds.length > 1) conflictingId = true;
    }
    matches++;
    if (matches === 1) chosen = row;
  }
  const summary = { matches, malformed_records: malformed, unidentified_records: unidentified };
  if (matches > 1 || conflictingId) return { ...summary, match: 'ambiguous' };
  if (malformed > 0) return { ...summary, match: 'partial' };
  if (!chosen) return { ...summary, match: unidentified ? 'request_id_unavailable' : 'not_found' };
  const status_code = statusCode(chosen.status);
  if (status_code === undefined) return { ...summary, match: 'status_unavailable' };
  return { ...summary, match: 'matched', status_code, recorded_at: chosen.time, headers: chosen.headers, location: chosen.location };
}

export async function verifyHttpEvidence(args, files) {
  const request = parseRequest(args.request);
  if (!Array.isArray(args.sources) || args.sources.length < 1 || args.sources.length > MAX_SOURCES) {
    throw new Error('请选择 1 至 6 份独立的本地 Web 证据。');
  }
  const sources = args.sources.map(source => {
    if (!hasKeys(source, ['file_path', 'format']) || !FORMATS.includes(source.format)) throw new Error('请提供原件路径和支持的 Web 格式。');
    return { ...source, file_path: files.normalizePath(source.file_path) };
  });
  if (sources.every(source => source.format === 'expectations_jsonl')) throw new Error('至少需要一份实际请求记录。');

  const seen = new Set();
  const observations = [];
  for (const { file_path, format } of sources) {
    const { bytes, targetKey } = await files.read(file_path);
    const key = targetKey ?? file_path;
    if (seen.has(key)) throw new Error('每个 Web 证据文件只能引用一次。');
    seen.add(key);
    const text = decodeEvidenceText(bytes);
    if (text === null) throw new Error(`Web 证据须使用有效的 UTF-8 文本。${file_path}`);
    const { location, ...observation } = locateTrace(text, format, request);
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    observations.push({ format, ...observation, source: { file_path, sha256, ...location } });
  }
  const complete = observations.every(observation => observation.match === 'matched');
  let status = 'insufficient';
  if (complete) {
    const codes = new Set(observations.map(observation => observation.status_code));
    status = observations.length === 1 ? 'observed' : codes.size === 1 ? 'consistent' : 'conflict';
  }
  return { status, correlation: request.request_id === undefined ? 'method_and_path' : 'request_id', request, observations };
}
