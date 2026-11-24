import { createHash } from 'node:crypto';

const SESSION_RESULT_LIMIT = 48;
const EVIDENCE_RESULT_LIMIT = 128;
const WORKSPACE_LIMIT = 8;
const MAX_RESULT_BYTES = 64 * 1024;
const MAX_BUCKET_BYTES = 4 * 1024 * 1024;
const MAX_SUMMARY_CONTAINERS = 4096;
const MAX_DERIVED_ARTIFACTS = 32;
const MAX_DERIVED_ARTIFACT_BYTES = 16 * 1024 * 1024;
const MAX_DERIVED_ARTIFACT_ITEM_BYTES = 12 * 1024 * 1024;
const POINTER = /^(?:\/(?:[^~/\r\n\0]|~[01])*)+$/u;
export const RESULT_HASH = /^[a-f0-9]{64}$/u;
export const MAX_VALUE_LENGTH = 256;
export const OFFLINE_RESULT_SCOPE = Symbol('offline results');

export function isResultPointer(value) {
  return typeof value === 'string' && value.length <= 256 && POINTER.test(value);
}

export function isResultScalar(value) {
  return value === null || typeof value === 'boolean' || Number.isFinite(value)
    || (typeof value === 'string' && value.length <= MAX_VALUE_LENGTH && !/\p{Cs}/u.test(value));
}

function resultField(report, pointer) {
  let value = report;
  for (const segment of pointer.slice(1).split('/')) {
    const key = segment.replace(/~[01]/gu, escape => escape === '~0' ? '~' : '/');
    if (value === null || typeof value !== 'object' || !Object.hasOwn(value, key)
      || (Array.isArray(value) && !/^(?:0|[1-9][0-9]*)$/u.test(key))) return undefined;
    value = value[key];
  }
  return value;
}

export function resultValue(report, pointer) {
  const value = resultField(report, pointer);
  return isResultScalar(value) ? value : undefined;
}

export function cachedResultValue(result, pointer) {
  return result.summary === undefined ? resultValue(result.report, pointer) : result.summary.fields.get(pointer)?.value;
}

function revNameReferences(report, pointer) {
  const name = /^(.*)\/(from|to)_names\/(0|[1-9][0-9]*)$/u.exec(pointer);
  const definition = /^(.*)\/(from|to)_definitions\/(0|[1-9][0-9]*)\/name$/u.exec(pointer);
  const match = name ?? definition;
  if (!match) return undefined;
  const [, prefix, direction, index] = match;
  const edge = resultField(report, prefix);
  const site = edge?.[`${direction}_definitions`]?.[index];
  if (!edge?.source || !site) return undefined;
  const { file_path, sha256 } = edge.source;
  const { line, byte_offset, byte_length } = site;
  return [edge.source, { file_path, sha256, line, byte_offset, byte_length }];
}

export function resultReferences(result, pointer) {
  if (result.summary !== undefined) return result.summary.fields.get(pointer)?.sources ?? result.sources;
  const parent = resultField(result.report, pointer.slice(0, pointer.lastIndexOf('/')));
  if (result.tool === 'trace_flask_route' && pointer.endsWith('/status_code') && parent?.source) {
    return result.sources.map(reference => reference.file_path === parent.source.file_path ? { ...reference, line: parent.source.line } : reference);
  }
  if (result.tool === 'query_rev_export') {
    const references = revNameReferences(result.report, pointer);
    if (references) return references;
  }
  if (['query_rev_export', 'map_rev_address', 'read_ctf_files'].includes(result.tool) && parent?.source) return [parent.source];
  if (result.tool === 'verify_rev_machine' && Number.isSafeInteger(parent?.rule_line)) {
    return [{ ...result.sources[0], line: parent.rule_line }];
  }
  return result.sources;
}

export function summarize(result, budget) {
  const fields = new Map();
  let bytes = 0;
  let limited = false;
  const queue = [{ pointer: '', value: result.report }];
  // Preserve shallow fields from each record before indexing deeper arrays.
  for (let index = 0; index < queue.length; index++) {
    const { pointer, value } = queue[index];
    for (const key of Object.keys(value)) {
      const path = pointer + '/' + key.replaceAll('~', '~0').replaceAll('/', '~1');
      if (!isResultPointer(path)) continue;
      const child = value[key];
      if (child !== null && typeof child === 'object') {
        if (queue.length < MAX_SUMMARY_CONTAINERS) queue.push({ pointer: path, value: child });
        else limited = true;
        continue;
      }
      if (!isResultScalar(child)) continue;
      const sources = resultReferences(result, path);
      const field = sources === result.sources ? { value: child } : { value: child, sources };
      const length = Buffer.byteLength(JSON.stringify([path, field]), 'utf8');
      if (length > budget - bytes) {
        limited = true;
        continue;
      }
      fields.set(path, field);
      bytes += length;
    }
  }
  return { fields, bytes, limited };
}

function touch(entries, key) {
  const entry = entries.get(key);
  if (entry === undefined) return undefined;
  entries.delete(key);
  entries.set(key, entry);
  return entry;
}

function bucket() {
  return { entries: new Map(), bytes: 0 };
}

function storeResult(cache, id, entry, limit) {
  const previous = cache.entries.get(id);
  if (previous !== undefined) {
    cache.entries.delete(id);
    cache.bytes -= previous.bytes;
  }
  cache.entries.set(id, entry);
  cache.bytes += entry.bytes;
  while (cache.entries.size > limit || cache.bytes > MAX_BUCKET_BYTES) {
    const oldest = cache.entries.keys().next().value;
    cache.bytes -= cache.entries.get(oldest).bytes;
    cache.entries.delete(oldest);
  }
}

export function createToolResults() {
  const sessions = new WeakMap();
  return {
    remember(session, scope, tool, report, sources) {
      if (session === null || typeof session !== 'object' || !Array.isArray(sources)) return undefined;
      const json = JSON.stringify(report);
      const reportBytes = Buffer.byteLength(json, 'utf8');
      const oversized = reportBytes > MAX_RESULT_BYTES;
      if (oversized && (typeof scope !== 'string' || sources.length === 0)) return undefined;
      const references = JSON.stringify(sources);
      const referenceBytes = Buffer.byteLength(references, 'utf8');
      if (referenceBytes > MAX_BUCKET_BYTES || (!oversized && reportBytes + referenceBytes > MAX_BUCKET_BYTES)) return undefined;
      let result = { tool, report: JSON.parse(json), sources: JSON.parse(references) };
      let bytes = reportBytes + referenceBytes;
      if (oversized) {
        const summary = summarize(result, Math.min(MAX_RESULT_BYTES, MAX_BUCKET_BYTES - referenceBytes));
        if (summary.fields.size === 0) return undefined;
        result = { tool, sources: result.sources, summary };
        bytes = referenceBytes + summary.bytes;
      }
      const id = createHash('sha256').update(tool).update('\0').update(json).digest('hex');
      let results = sessions.get(session);
      if (!results) {
        results = { workspaces: new Map(), offline: bucket(), session: bucket(), artifacts: new Map(), artifactBytes: 0 };
        sessions.set(session, results);
      }
      let cache;
      if (scope === null) cache = results.session;
      else if (scope === OFFLINE_RESULT_SCOPE) cache = results.offline;
      else {
        cache = touch(results.workspaces, scope);
        if (cache === undefined) {
          cache = bucket();
          results.workspaces.set(scope, cache);
          if (results.workspaces.size > WORKSPACE_LIMIT) results.workspaces.delete(results.workspaces.keys().next().value);
        }
      }
      storeResult(cache, id, { bytes, result, created_at: Date.now() }, scope === null ? SESSION_RESULT_LIMIT : EVIDENCE_RESULT_LIMIT);
      return id;
    },
    rememberArtifact(session, id, bytes, evidence = []) {
      if (session === null || typeof session !== 'object' || typeof id !== 'string'
        || !RESULT_HASH.test(id) || !Buffer.isBuffer(bytes) || bytes.length > MAX_DERIVED_ARTIFACT_ITEM_BYTES) return false;
      let results = sessions.get(session);
      if (!results) {
        results = { workspaces: new Map(), offline: bucket(), session: bucket(), artifacts: new Map(), artifactBytes: 0 };
        sessions.set(session, results);
      }
      const previous = results.artifacts.get(id);
      if (previous) results.artifactBytes -= previous.bytes.length;
      const artifact = { bytes: Buffer.from(bytes), evidence: Array.isArray(evidence) ? JSON.parse(JSON.stringify(evidence)) : [] };
      results.artifacts.delete(id);
      results.artifacts.set(id, artifact);
      results.artifactBytes += artifact.bytes.length;
      while (results.artifacts.size > MAX_DERIVED_ARTIFACTS || results.artifactBytes > MAX_DERIVED_ARTIFACT_BYTES) {
        const oldest = results.artifacts.keys().next().value;
        results.artifactBytes -= results.artifacts.get(oldest).bytes.length;
        results.artifacts.delete(oldest);
      }
      return results.artifacts.has(id);
    },
    getArtifact(session, id) {
      const results = sessions.get(session);
      const entry = results?.artifacts.get(id);
      if (!entry) return undefined;
      results.artifacts.delete(id);
      results.artifacts.set(id, entry);
      return { bytes: Buffer.from(entry.bytes), evidence: JSON.parse(JSON.stringify(entry.evidence)) };
    },
    list(session, scope) {
      const results = sessions.get(session);
      if (!results) return [];
      const found = new Map();
      const collect = (cache, label) => {
        for (const [id, entry] of cache.entries) {
          found.set(id, {
            result_id: id, tool: entry.result.tool, bytes: entry.bytes, scope: label, created_at: entry.created_at,
          });
        }
      };
      if (typeof scope === 'string') {
        const workspace = results.workspaces.get(scope);
        if (workspace !== undefined) collect(workspace, 'workspace');
      }
      collect(results.offline, 'offline');
      collect(results.session, 'session');
      return [...found.values()].reverse();
    },
    get(session, scope, id) {
      const results = sessions.get(session);
      if (!results) return undefined;
      const workspace = results.workspaces.get(scope);
      const entry = workspace && touch(workspace.entries, id);
      if (entry !== undefined) {
        touch(results.workspaces, scope);
        return entry.result;
      }
      return (touch(results.offline.entries, id) ?? touch(results.session.entries, id))?.result;
    },
  };
}
