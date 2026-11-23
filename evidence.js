import { createHash } from 'node:crypto';

export const MAX_EVIDENCE_SOURCES = 8;
export const MAX_EVIDENCE_TEXT = 256;

export function lineBounds(text, line, offset) {
  const breaks = /\r\n|[\r\n]/gu;
  let number = 1;
  let start = 0;
  for (;;) {
    const newline = breaks.exec(text);
    const end = newline?.index ?? text.length;
    if (line === undefined ? offset <= end : number === line) return { number, start, end };
    if (newline === null) return null;
    start = breaks.lastIndex;
    number++;
  }
}

function findObservation(text, { line, prefix, suffix }) {
  const scope = line === undefined ? { start: 0, end: text.length } : lineBounds(text, line);
  if (scope === null) return { status: 'missing', reason: '指定行超出文件范围。' };
  const anchor = text.indexOf(prefix, scope.start);
  const start = anchor + prefix.length;
  if (anchor < 0 || start > scope.end) return { status: 'missing', reason: '在选定范围内找不到前缀。' };
  const repeated = text.indexOf(prefix, anchor + 1);
  if (repeated >= 0 && repeated + prefix.length <= scope.end) {
    return { status: 'ambiguous', reason: '前缀匹配多次。请指定行号或使用更明确的前缀。' };
  }
  const bounds = line === undefined ? lineBounds(text, undefined, anchor) : scope;
  const end = suffix === undefined ? bounds.end : text.indexOf(suffix, start);
  if (end < 0 || end + (suffix?.length ?? 0) > bounds.end) {
    return { status: 'missing', reason: '在同一行的前缀之后找不到后缀。' };
  }
  const value = text.slice(start, end);
  if (value.length > 2 * MAX_EVIDENCE_TEXT || [...value].length > MAX_EVIDENCE_TEXT) {
    return { status: 'unavailable', reason: '定位到的文本值超过 256 字符。' };
  }
  return {
    status: 'observed',
    line: bounds.number,
    byte_offset: Buffer.byteLength(text.slice(0, start), 'utf8'),
    byte_length: Buffer.byteLength(value, 'utf8'),
    value,
  };
}

export function decodeEvidenceText(bytes) {
  if (bytes.includes(0)) return null;
  try {
    // Keep any UTF-8 BOM so that reported offsets address the original bytes.
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
}

export function parseEvidenceJson(text) {
  if (text === null) return undefined;
  try {
    return JSON.parse(text.replace(/^\uFEFF/u, ''));
  } catch {
    return undefined;
  }
}

export function* locatedTextRows(text, limit, subject) {
  let line = 0;
  let offset = 0;
  for (const [chunk] of text.matchAll(/[^\r\n]+(?:\r\n|\r|\n)?|\r\n|\r|\n/gu)) {
    const content = chunk.replace(/(?:\r\n|\r|\n)$/u, '');
    const location = { line: ++line, byte_offset: offset, byte_length: Buffer.byteLength(content, 'utf8') };
    offset += Buffer.byteLength(chunk, 'utf8');
    if (line > limit) throw new Error(`${subject}最多检查 ${limit} 行。`);
    if (content.trim() !== '') yield { content: line === 1 ? content.replace(/^\uFEFF/u, '') : content, location };
  }
}

function compareObservations(observations, expected, files) {
  const values = new Set(observations.filter(item => item.status === 'observed').map(item => item.value));
  if (values.size > 1 || (values.size === 1 && expected !== undefined && !values.has(expected))) {
    return { status: 'conflict', reason: '定位到的值互不一致，或与给定的期望值不同。' };
  }
  if (observations.some(item => item.status !== 'observed') || files.size < 2) {
    return { status: 'insufficient', reason: '需要至少两个不同文件，且所有选定证据都能唯一定位。' };
  }
  return { status: 'consistent', reason: '所有选定证据的文本值一致。' };
}

function rangeObservation(bytes, source) {
  const start = source.byte_offset;
  const declared = source.byte_length;
  if (!Number.isSafeInteger(start) || start < 0 || start > bytes.length) {
    return { status: 'missing', reason: '记录的字节偏移超出文件大小。' };
  }
  if (!Number.isSafeInteger(declared) || declared <= 0 || declared > bytes.length - start) {
    return { status: 'missing', reason: '记录的字节长度为空或超出文件范围。' };
  }
  const slice = bytes.subarray(start, start + declared);
  const range_sha256 = createHash('sha256').update(slice).digest('hex');
  if (source.expected_range_sha256 !== undefined && source.expected_range_sha256 !== range_sha256) {
    return { status: 'missing', range_sha256, reason: '按记录偏移取到的片段 SHA-256 不再匹配，文件可能已被修改。' };
  }
  const decoded = decodeEvidenceText(slice);
  const value = decoded === null ? slice.toString('hex') : decoded;
  if (value.length > 2 * MAX_EVIDENCE_TEXT || [...value].length > 2 * MAX_EVIDENCE_TEXT) {
    return { status: 'unavailable', reason: '片段超过可比较长度，请改用更小的读取窗口。' };
  }
  return { status: 'observed', byte_offset: start, byte_length: slice.length, range_sha256, value,
    ...(source.expected_file_sha256 || source.expected_range_sha256 ? { recomputed: true } : {}) };
}

export async function verifyEvidence(sources, expected, readFile) {
  const observations = Array(sources.length);
  const groups = new Map();
  for (const [index, source] of sources.entries()) {
    const entries = groups.get(source.file_path) ?? [];
    entries.push({ source, index });
    groups.set(source.file_path, entries);
  }

  const files = new Set();
  for (const [file, entries] of groups) {
    const snapshot = await readFile(file);
    const sha256 = snapshot ? createHash('sha256').update(snapshot.bytes).digest('hex') : undefined;
    const text = snapshot && entries.some(({ source }) => source.prefix !== undefined) ? decodeEvidenceText(snapshot.bytes) : null;
    for (const { source, index } of entries) {
      if (snapshot && source.byte_offset !== undefined && source.prefix === undefined) {
        if (source.expected_file_sha256 !== undefined && source.expected_file_sha256 !== sha256) {
          observations[index] = { file, sha256, status: 'unavailable', reason: '原件 SHA-256 与引用不同，文件已变化。' };
          continue;
        }
        const observation = rangeObservation(snapshot.bytes, source);
        observations[index] = { file, sha256, ...observation,
          ...(source.used_fallback ? { used_fallback: true, result_id: source.result_id } : {}) };
        if (observation.status === 'observed') files.add(snapshot.targetKey);
        continue;
      }
      if (text === null) {
        const reason = snapshot ? '文件不是可读取的 UTF-8 文本。' : '无法读取工作区文件。文件可能缺失、超限或不可访问。';
        observations[index] = { file, sha256, line: source.line, status: 'unavailable', reason };
        continue;
      }
      const observation = findObservation(text, source);
      observations[index] = { file, sha256, line: source.line, ...observation };
      if (observation.status === 'observed') files.add(snapshot.targetKey);
    }
  }
  const comparison = compareObservations(observations, expected, files);
  const recomputed = observations.some(item => item.recomputed) && observations.every(item => item.status === 'observed');
  return { ...comparison, expected_value: expected, observations, ...(recomputed ? { recomputed: true } : {}) };
}
