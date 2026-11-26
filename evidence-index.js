import { createHash } from 'node:crypto';
import { isResultPointer, isResultScalar, RESULT_HASH, summarize } from './ctf-result-values.js';
import { ToolError } from './tool-errors.js';

const INDEX_LIMIT = 4 * 1024 * 1024;
const ENTRY_LIMIT = 128 * 1024;
const MAX_ENTRIES = 128;
const FULL_REPORTS = new Set(['verify_http_evidence', 'trace_flask_route', 'verify_rev_machine']);
const RANGE_REPORTS = new Set(['read_binary_range', 'read_log_range']);
const HASH = text => createHash('sha256').update(text).digest('hex');

function copySources(sources) {
  if (!Array.isArray(sources) || sources.length === 0 || sources.length > 64) return undefined;
  if (!sources.every(source => source !== null && typeof source === 'object' && typeof source.file_path === 'string'
    && RESULT_HASH.test(source.sha256 ?? ''))) return undefined;
  return sources;
}

export function encodeEvidenceEntry(id, result) {
  const sources = copySources(result?.sources);
  if (!RESULT_HASH.test(id) || !sources) return undefined;
  const record = { id, tool: result.tool, sources };
  if (result.summary) {
    record.fields = [...result.summary.fields]
      .filter(([pointer]) => !/(?:^|\/)(?:password|token|cookie|authorization|flag_preview|payload_hex)(?:\/|$)/iu.test(pointer));
  } else if (FULL_REPORTS.has(result.tool)) {
    record.report = result.report;
    record.full = true;
  } else {
    record.fields = [...summarize(result, 64 * 1024).fields]
      .filter(([pointer]) => !/(?:^|\/)(?:password|token|cookie|authorization|flag_preview|payload_hex)(?:\/|$)/iu.test(pointer));
    if (RANGE_REPORTS.has(result.tool)) {
      const { file, sha256, range_sha256, byte_offset, byte_length } = result.report;
      record.report = { file, sha256, range_sha256, byte_offset, byte_length };
    }
  }
  const payload = JSON.stringify(record);
  return Buffer.byteLength(payload) <= ENTRY_LIMIT ? { payload, digest: HASH(payload) } : undefined;
}

function decodeEntry(wrapper) {
  if (typeof wrapper?.payload !== 'string' || wrapper.digest !== HASH(wrapper.payload)) return undefined;
  const record = JSON.parse(wrapper.payload);
  const { id, tool, sources, report, fields, full } = record;
  if (!RESULT_HASH.test(id ?? '') || !copySources(sources) || typeof tool !== 'string') return undefined;
  if (full && HASH(tool + '\0' + JSON.stringify(report)) !== id) return undefined;
  if (fields !== undefined && (!Array.isArray(fields) || !fields.every(item => Array.isArray(item)
    && isResultPointer(item[0]) && isResultScalar(item[1]?.value)))) return undefined;
  return [id, { tool, sources, report, persisted: true, full: full === true,
    ...(fields === undefined ? {} : { summary: { fields: new Map(fields) } }) }];
}

function records(text) {
  if (!text) return [];
  const content = JSON.parse(text);
  if (content.version !== 1 || !Array.isArray(content.entries) || content.entries.length > MAX_ENTRIES
    || Buffer.byteLength(text) > INDEX_LIMIT) throw new ToolError('encoding', '证据索引格式或大小无效。');
  return content.entries;
}

export function decodeEvidenceIndex(text) {
  return new Map(records(text).flatMap(wrapper => {
    try {
      const record = decodeEntry(wrapper);
      return record ? [record] : [];
    } catch { return []; }
  }));
}

export function appendEvidenceIndex(text, id, entry) {
  const entries = records(text);
  if (entries.some(wrapper => {
    try { return decodeEntry(wrapper)?.[0] === id; } catch { return false; }
  })) return text;
  const next = [...entries, entry].slice(-MAX_ENTRIES);
  let serialized = JSON.stringify({ version: 1, entries: next }) + '\n';
  while (Buffer.byteLength(serialized) > INDEX_LIMIT && next.length > 1) {
    next.shift();
    serialized = JSON.stringify({ version: 1, entries: next }) + '\n';
  }
  return serialized;
}
