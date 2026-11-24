import { createHash } from 'node:crypto';
import { ToolError } from './tool-errors.js';
import { decodeEvidenceText, lineBounds, parseEvidenceJson } from './evidence.js';
import { EXPERIMENT_TOOLS, experimentRequestHash } from './experiment-input.js';
import {
  cachedResultValue, isResultPointer, isResultScalar, MAX_VALUE_LENGTH, RESULT_HASH, resultReferences, resultValue,
} from './ctf-result-values.js';

const MAX_ENTRIES = 24;
const MAX_EXPERIMENTS = 12;
const MAX_RESULT_SOURCES = 16;
const MAX_TEXT = 1024;
const MAX_SOURCES = 5;
const MAX_ATTACHMENTS = 64;
const HASH = /^[a-f0-9]{64}$/iu;
const TOOL_MATCH_NOTE = '工具结果一致，缺少可复核的原件引用。';
const LEGACY_VALUES_WARNING = 'notes.md 的旧标题只表示保存时的状态。以本次 value_status 为准。';
const STATE_FILE = '.ctf/state.json';
const STATE_BACKUP = '.ctf/state.previous.json';
const STATE_RECOVERY = '.ctf/state.saved.json';
const STATE_HEADER = /^<!-- machine: ([^ ]+) sha256:([a-f0-9]{64}) -->\n/u;

const SCALAR_SCHEMA = { anyOf: [{ type: 'string', maxLength: MAX_VALUE_LENGTH }, { type: 'number' }, { type: 'boolean' }, { type: 'null' }] };
const SOURCE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['file_path'],
  properties: {
    file_path: { type: 'string' },
    line: { type: 'integer', minimum: 1 },
    byte_offset: { type: 'integer', minimum: 0 },
    byte_length: { type: 'integer', minimum: 1 },
    json_pointer: { type: 'string', maxLength: 256 },
    sha256: { type: 'string' },
  },
};
const REFERENCE_PROPERTIES = SOURCE_SCHEMA.properties;
const TEXT = { type: 'string', minLength: 1, maxLength: MAX_TEXT };
const TEXT_LIST = { type: 'array', maxItems: MAX_ENTRIES, items: TEXT };
const VALUE_FIELDS = {
  label: TEXT,
  result_id: { type: 'string' },
  pointer: { type: 'string', maxLength: 256 },
  value: SCALAR_SCHEMA,
  tool: { type: 'string' },
  sources: { type: 'array', maxItems: MAX_RESULT_SOURCES, items: { type: 'object' } },
};
const VALUE_LIST = {
  type: 'array', maxItems: MAX_ENTRIES,
  items: { type: 'object', required: ['label', 'result_id', 'pointer', 'value'], properties: VALUE_FIELDS, additionalProperties: false },
};
const PROGRESS_FIELDS = {
  confirmed: {
    type: 'array', maxItems: MAX_ENTRIES,
    items: { type: 'object', required: ['text', 'sources'], additionalProperties: false, properties: { text: TEXT, sources: { type: 'array', minItems: 1, maxItems: MAX_SOURCES, items: SOURCE_SCHEMA } } },
  },
  ruled_out: TEXT_LIST,
  pending: TEXT_LIST,
  attachments: { type: 'array', maxItems: MAX_ATTACHMENTS, items: { type: 'string' } },
  commands: { type: 'array', maxItems: 16, items: { type: 'object', required: ['command'] } },
  values: { type: 'array', maxItems: MAX_ENTRIES, items: { type: 'object', required: ['label', 'result_id', 'pointer', 'value'] } },
  insights: { type: 'array', maxItems: 16, items: { type: 'object', required: ['text', 'source'] } },
  hints: { type: 'array', maxItems: 16, items: { type: 'object', required: ['hint', 'source', 'hypothesis'] } },
  experiments: { type: 'array', maxItems: MAX_EXPERIMENTS, items: { type: 'object', required: ['label', 'hypothesis', 'pointer', 'expected'] } },
};
const INSIGHT_FIELDS = { text: TEXT, source: { type: 'string', enum: ['self', 'human', 'external'] }, note: TEXT };
const HINT_FIELDS = { hint: TEXT, source: { type: 'string', enum: ['self', 'human', 'external'] }, hypothesis: TEXT, test: TEXT, verified: { type: 'boolean' } };
const EXPERIMENT_FIELDS = {
  label: TEXT, hypothesis: TEXT, pointer: VALUE_FIELDS.pointer, expected: SCALAR_SCHEMA,
  result_id: VALUE_FIELDS.result_id, actual: SCALAR_SCHEMA, tool: { type: 'string', enum: EXPERIMENT_TOOLS },
  request_sha256: { type: 'string', pattern: '^[a-f0-9]{64}$' }, sources: VALUE_FIELDS.sources,
};

export const PROGRESS_PROPERTIES = {
  action: { type: 'string', enum: ['load', 'check', 'save', 'writeup', 'handoff', 'results', 'experiments', 'repair'],
    description: 'load/handoff/results 仅传 action；check 传 claims；save 传 revision+progress(+instance)；writeup/repair 传 revision；experiments 可选 experiment_query。' },
  revision: { type: 'string', description: 'load 返回的 notes.md 版本（save/repair 必填）。' },
  claims: { ...VALUE_LIST, description: 'check 待核对的工具值列表（label/result_id/pointer/value）。' },
  experiment_query: {
    type: 'object', additionalProperties: false, required: ['tool', 'args'],
    properties: { tool: { type: 'string', enum: EXPERIMENT_TOOLS }, args: { type: 'object' } },
  },
  progress: {
    type: 'object', properties: PROGRESS_FIELDS, additionalProperties: false,
    required: ['confirmed', 'ruled_out', 'pending'],
    description: 'save 进度对象：confirmed/ruled_out/pending 必填，可选 attachments/commands/values/insights/hints/experiments。',
  },
  instance: { type: 'string', maxLength: 200, description: 'save 可选实例标识。' },
};

export const PROGRESS_ACTION_KEYS = Object.freeze({
  load: ['action'],
  check: ['action', 'claims'],
  save: ['action', 'revision', 'progress', 'instance'],
  writeup: ['action', 'revision'],
  handoff: ['action'],
  results: ['action'],
  experiments: ['action', 'experiment_query'],
  repair: ['action', 'revision'],
});

export const PROGRESS_PARAMETERS = {
  type: 'object',
  properties: PROGRESS_PROPERTIES,
  additionalProperties: false,
  required: ['action'],
};

function digest(text) {
  return createHash('sha256').update(text).digest('hex');
}

function keysMatch(value, allowed) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).every(key => allowed.includes(key));
}

function isText(value) {
  return typeof value === 'string' && value.length <= 2 * MAX_TEXT && value.trim().length > 0
    && [...value].length <= MAX_TEXT && !/[\r\n\0\p{Cs}]/u.test(value);
}

function validList(value) {
  return Array.isArray(value) && value.length <= MAX_ENTRIES && [...value].every(isText);
}

function optionalIndex(value, minimum) {
  return value === undefined || (Number.isSafeInteger(value) && value >= minimum);
}

function normalizeSource(source, normalizePath) {
  if (!keysMatch(source, Object.keys(REFERENCE_PROPERTIES)) || !optionalIndex(source.line, 1)
    || !optionalIndex(source.byte_offset, 0) || !optionalIndex(source.byte_length, 1)
    || (source.byte_length !== undefined && source.byte_offset === undefined)
    || (source.json_pointer !== undefined && (!isResultPointer(source.json_pointer) || source.line !== undefined || source.byte_offset !== undefined))
    || (source.sha256 !== undefined && (typeof source.sha256 !== 'string' || !HASH.test(source.sha256)))) {
    throw new Error('证据位置或 SHA-256 格式无效。');
  }
  return {
    file_path: normalizePath(source.file_path), line: source.line, byte_offset: source.byte_offset,
    byte_length: source.byte_length, json_pointer: source.json_pointer, sha256: source.sha256?.toLowerCase(),
  };
}

function normalizeValues(values, normalizePath) {
  if (!Array.isArray(values) || values.length > MAX_ENTRIES) throw new Error(`最多可核对 ${MAX_ENTRIES} 项工具值。`);
  const labels = new Set();
  return values.map(entry => {
    if (!keysMatch(entry, Object.keys(VALUE_FIELDS)) || !isText(entry.label) || labels.has(entry.label)
      || typeof entry.result_id !== 'string' || !RESULT_HASH.test(entry.result_id)
      || !isResultPointer(entry.pointer) || !isResultScalar(entry.value)
      || (entry.tool !== undefined && (typeof entry.tool !== 'string' || !/^[a-z_]{1,40}$/u.test(entry.tool)))
      || (entry.sources !== undefined && (!Array.isArray(entry.sources) || entry.sources.length > MAX_RESULT_SOURCES))) {
      throw new Error('工具值需要唯一标签、有效的 result_id、字段路径和标量值。');
    }
    labels.add(entry.label);
    return {
      label: entry.label, result_id: entry.result_id, pointer: entry.pointer, value: entry.value,
      tool: entry.tool, sources: entry.sources?.map(source => normalizeSource(source, normalizePath)),
    };
  });
}

function normalizeExperiments(entries, normalizePath) {
  if (!Array.isArray(entries) || entries.length > MAX_EXPERIMENTS) throw new Error('单题验证最多记录 12 项。');
  const labels = new Set();
  return entries.map(entry => {
    if (!keysMatch(entry, Object.keys(EXPERIMENT_FIELDS)) || !isText(entry.label) || labels.has(entry.label)
      || !isText(entry.hypothesis) || !isResultPointer(entry.pointer) || !isResultScalar(entry.expected)
      || (entry.result_id !== undefined && (typeof entry.result_id !== 'string' || !RESULT_HASH.test(entry.result_id)))
      || (entry.actual !== undefined && !isResultScalar(entry.actual))
      || (entry.tool !== undefined && !EXPERIMENT_TOOLS.includes(entry.tool))
      || (entry.request_sha256 !== undefined && (typeof entry.request_sha256 !== 'string' || !RESULT_HASH.test(entry.request_sha256)))
      || (entry.sources !== undefined && (!Array.isArray(entry.sources) || entry.sources.length > MAX_RESULT_SOURCES))) {
      throw new Error('验证记录需要唯一标签、假设、结果字段路径和预期标量值。');
    }
    labels.add(entry.label);
    return { ...entry, ...(entry.sources === undefined ? {} : {
      sources: entry.sources.map(source => normalizeSource(source, normalizePath)),
    }) };
  });
}

function normalizeCommands(commands) {
  if (!Array.isArray(commands) || commands.length > 16) {
    throw new Error('最多可记录 16 条命令。');
  }
  return commands.map(entry => {
    if (!keysMatch(entry, ['command', 'exit_code', 'output', 'cwd']) || !isText(entry.command)
      || (entry.exit_code !== undefined && !Number.isSafeInteger(entry.exit_code))
      || (entry.output !== undefined && !isText(entry.output))
      || (entry.cwd !== undefined && !isText(entry.cwd))) {
      throw new Error('命令记录需要单行命令，可选整数退出码、单行输出和目录。');
    }
    return { command: entry.command, exit_code: entry.exit_code, output: entry.output, cwd: entry.cwd };
  });
}

function normalizeInsights(insights) {
  if (!Array.isArray(insights) || insights.length > 16) throw new Error('关键判断来源最多记录 16 条。');
  return insights.map(entry => {
    if (!keysMatch(entry, ['text', 'source', 'note']) || !isText(entry.text)
      || !['self', 'human', 'external'].includes(entry.source)
      || (entry.note !== undefined && !isText(entry.note))) {
      throw new Error('关键判断需要单行说明和来源（self、human 或 external），可选单行备注。');
    }
    return { text: entry.text, source: entry.source, ...(entry.note === undefined ? {} : { note: entry.note }) };
  });
}

function normalizeHints(hints) {
  if (!Array.isArray(hints) || hints.length > 16) throw new Error('提示吸收记录最多 16 条。');
  return hints.map(entry => {
    if (!keysMatch(entry, ['hint', 'source', 'hypothesis', 'test', 'verified'])
      || !isText(entry.hint) || !['self', 'human', 'external'].includes(entry.source)
      || !isText(entry.hypothesis)
      || (entry.test !== undefined && !isText(entry.test))
      || (entry.verified !== undefined && typeof entry.verified !== 'boolean')) {
      throw new Error('提示吸收记录需要提示原文、来源和可证伪假设；可选最小验证和布尔 verified。');
    }
    return {
      hint: entry.hint, source: entry.source, hypothesis: entry.hypothesis,
      ...(entry.test === undefined ? {} : { test: entry.test }),
      ...(entry.verified === undefined ? {} : { verified: entry.verified }),
    };
  });
}

function normalizeProgress(progress, normalizePath) {
  if (!keysMatch(progress, Object.keys(PROGRESS_FIELDS))
    || !Array.isArray(progress.confirmed) || progress.confirmed.length > MAX_ENTRIES
    || !validList(progress.ruled_out) || !validList(progress.pending)) {
    throw new Error(`续接记录需要已核验、已排除和待补三组条目，每组最多 ${MAX_ENTRIES} 条。`);
  }
  const attachments = progress.attachments;
  if (attachments !== undefined && (!Array.isArray(attachments) || attachments.length > MAX_ATTACHMENTS)) {
    throw new Error('attachments 最多记录 64 个附件路径。');
  }
  return {
    ...(progress.insights === undefined ? {} : { insights: normalizeInsights(progress.insights) }),
    ...(progress.hints === undefined ? {} : { hints: normalizeHints(progress.hints) }),
    confirmed: [...progress.confirmed].map(entry => {
      if (!keysMatch(entry, ['text', 'sources']) || !isText(entry.text) || !Array.isArray(entry.sources)
        || entry.sources.length < 1 || entry.sources.length > MAX_SOURCES) {
        throw new Error(`每条已核验结论需要单行说明和 1 至 ${MAX_SOURCES} 个可定位的原件引用。`);
      }
      return {
        text: entry.text,
        sources: [...entry.sources].map(source => normalizeSource(source, normalizePath)),
      };
    }),
    ruled_out: [...progress.ruled_out],
    pending: [...progress.pending],
    ...(attachments === undefined ? {} : { attachments: [...new Set(attachments.map(path => normalizePath(path)))] }),
    ...(progress.commands === undefined ? {} : { commands: normalizeCommands(progress.commands) }),
    ...(progress.values === undefined ? {} : { values: normalizeValues(progress.values, normalizePath) }),
    ...(progress.experiments === undefined ? {} : { experiments: normalizeExperiments(progress.experiments, normalizePath) }),
  };
}

function markers(kind) {
  return {
    start: '<!-- dsh-ctf-' + kind + '-start:v1 -->',
    end: '<!-- dsh-ctf-' + kind + '-end:v1 -->',
  };
}

function managedBlock(text, kind, allowModified = false) {
  const { start, end } = markers(kind);
  const from = text.indexOf(start);
  const to = text.indexOf(end);
  if (from < 0 && to < 0) return null;
  if (from < 0 || to <= from || text.indexOf(start, from + start.length) >= 0
    || text.indexOf(end, to + end.length) >= 0) {
    throw new Error('文档中的 CTF 记录区不完整或有重复标记。');
  }
  const raw = text.slice(from + start.length, to).replace(/\r\n/gu, '\n');
  const match = /^\n<!-- sha256:([a-f0-9]{64}) -->\n([\s\S]*)\n$/u.exec(raw);
  if (!match || (!allowModified && digest(match[2]) !== match[1])) {
    throw new Error('CTF 记录区已有手工改动，可用 repair 重新核对并恢复。');
  }
  return { from, to: to + end.length, content: match[2] };
}

function withManagedBlock(text, kind, content, allowModified = false) {
  const existing = managedBlock(text, kind, allowModified);
  if (!allowModified && existing?.content === content) return text;
  const { start, end } = markers(kind);
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const block = [start, '<!-- sha256:' + digest(content) + ' -->', content, end].join('\n').replace(/\n/gu, eol);
  if (existing) return text.slice(0, existing.from) + block + text.slice(existing.to);
  const separation = text === '' ? '' : text.endsWith(eol + eol) ? '' : text.endsWith(eol) ? eol : eol + eol;
  return text + separation + block + eol;
}

function validateStoredProgress(progress) {
  if (progress.confirmed.some(entry => entry.sources.some(source => !source.sha256))) {
    throw new Error('续接记录中的已核验条目缺少原件 SHA-256。');
  }
  if (progress.values?.some(entry => !entry.tool || !entry.sources || entry.sources.some(source => !source.sha256))) {
    throw new Error('续接记录中的工具值缺少工具名或已核对的原件。');
  }
  return progress;
}

function inlineRecord(content, normalizePath) {
  const current = /^<!-- dsh-ctf-data-v2\n([\s\S]*?)\n-->\n/u.exec(content);
  const legacy = current ? null : /^<!-- dsh-ctf-data:([A-Za-z0-9+/=]+) -->\n/u.exec(content);
  if (!current && !legacy) throw new Error('续接记录缺少结构化数据。');
  let value;
  try {
    value = JSON.parse(current ? current[1] : Buffer.from(legacy[1], 'base64').toString('utf8'));
  } catch {
    throw new Error('续接记录中的结构化数据无法读取。');
  }
  return { progress: validateStoredProgress(normalizeProgress(value, normalizePath)), meta: {} };
}

function unpackState(document, normalizePath) {
  const value = JSON.parse(document.text);
  const progress = validateStoredProgress(normalizeProgress(value.progress ?? value, normalizePath));
  return {
    progress,
    meta: {
      ...(typeof value.session === 'string' && value.session !== '' ? { session: value.session } : {}),
      ...(typeof value.instance === 'string' && value.instance !== '' ? { instance: value.instance } : {}),
    },
  };
}

function progressRevision(notes, state) {
  if (state.version === undefined) return notes.version === undefined ? 'absent' : digest(notes.text);
  return digest(digest(state.text) + '\0' + digest(notes.text));
}

async function readStored(files, notes, state, allowModified = false) {
  const block = managedBlock(notes.text, 'notes', allowModified);
  const header = block ? STATE_HEADER.exec(block.content) : null;
  if (state.version !== undefined) {
    try {
      const record = unpackState(state, files.normalizePath);
      return { ...record, projectionStale: header?.[2] !== digest(state.text) };
    } catch {
      // Read the prior committed revision if the current state is damaged.
    }
  }
  if (state.version !== undefined || header !== null) {
    for (const name of [STATE_RECOVERY, STATE_BACKUP]) {
      const backup = await files.readDocument(name);
      if (backup.version === undefined) continue;
      try {
        return { ...unpackState(backup, files.normalizePath), projectionStale: true, recovered: backup };
      } catch {
        // Old inline data can still be used when present.
      }
    }
    if (!block || header) throw new Error('当前状态与上一份有效状态均不可读取。');
  }
  return block ? inlineRecord(block.content, files.normalizePath) : null;
}

async function mirrorState(files, body) {
  const mirror = await files.readDocument(STATE_RECOVERY);
  const current = await files.readDocument(STATE_FILE);
  if (current.text === body && mirror.text !== body) {
    await files.writeDocument({ ...mirror, name: STATE_RECOVERY }, body);
  }
}

async function retainPrevious(files, state) {
  if (state.version === undefined) return;
  try { unpackState(state, files.normalizePath); } catch { return; }
  const backup = await files.readDocument(STATE_BACKUP);
  if (backup.text === state.text) return;
  const current = await files.readDocument(STATE_FILE);
  if (current.version !== state.version) throw new Error('续接记录已被更新，请重新读取。');
  try {
    await files.writeDocument({ ...backup, name: STATE_BACKUP }, state.text);
  } catch (error) {
    if ((await files.readDocument(STATE_BACKUP)).text !== state.text) throw error;
  }
}

function refreshProjection(text, kind, content) {
  const old = managedBlock(text, kind, true);
  if (old) {
    try { return withManagedBlock(text, kind, content); }
    catch {
      // Preserve edits as Markdown outside the newly managed section.
      text = text.slice(0, old.from) + old.content + '\n' + text.slice(old.to);
    }
  }
  return withManagedBlock(text, kind, content);
}

async function writeProjection(files, name, kind, body) {
  let target = name;
  let document = await files.readDocument(target);
  let content;
  try {
    content = refreshProjection(document.text, kind, body);
  } catch {
    target = name.replace(/\.md$/u, '.ctf-generated.md');
    document = await files.readDocument(target);
    content = refreshProjection(document.text, kind, body);
  }
  if (content !== document.text) await files.writeDocument(document, content);
  return { target, revision: digest(content) };
}

function readable(value) {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replace(/[\\\x60*_[\]]/gu, '\\$&');
}

function bullets(list) {
  return list.length ? list.map(text => '- ' + readable(text)).join('\n') : '- 暂无记录。';
}

function sourcesText(sources) {
  return sources.map(source => {
    const location = [readable(source.file_path)];
    if (source.line !== undefined) location.push('第 ' + source.line + ' 行');
    if (source.byte_offset !== undefined) location.push('字节偏移 ' + source.byte_offset);
    if (source.byte_length !== undefined) location.push('长度 ' + source.byte_length + ' 字节');
    if (source.json_pointer !== undefined) location.push('JSON 字段 ' + readable(source.json_pointer));
    if (source.status === 'changed') location.push('原件已变化');
    if (source.status === 'unavailable') location.push('原件无法读取');
    if (source.status === 'invalid_location') location.push('证据位置无效');
    if (source.status === 'location_unavailable') location.push('JSON 字段未复核，请改用行号、字节范围或原件哈希');
    return '  - ' + location.join('，') + '。SHA-256 ' + source.sha256;
  }).join('\n');
}

const INSIGHT_LABELS = { self: '自行推导', human: '人工提示', external: '外部参考' };

function renderProgress(progress, heading, valueStates, includeResultIds = true) {
  const observations = progress.confirmed.map(entry => {
    const review = needsReview(entry);
    return '- ' + (review ? '**待复核** ' : '') + readable(entry.text) + '\n' + sourcesText(entry.sources);
  });
  const stateOf = entry => valueStates?.get(entry.label) ?? 'recorded';
  const needsValueReview = entry => !['reverified', 'tool_match'].includes(stateOf(entry));
  const values = progress.values?.map(entry => {
    const state = stateOf(entry);
    const recorded = needsValueReview(entry);
    const mark = state === 'tool_match' ? '**工具值一致（无原件引用）** ' : recorded ? '**未复算（待复核）** ' : '';
    const main = '- ' + mark + readable(entry.label) + ' = ' + readable(JSON.stringify(entry.value));
    const origin = '  - ' + readable(entry.tool) + ' ' + readable(entry.pointer)
      + (includeResultIds ? '。工具结果编号 ' + entry.result_id : '');
    const note = recorded
      ? ['  - ' + (state === 'review' || needsReview(entry) ? '原件引用需要复核，待复核。'
        : state === 'mismatch' ? '保存值与当前工具结果不一致，待复核。'
        : state === 'unavailable' ? '当前工具结果中找不到该字段，待复核。'
        : '记录值，本会话未重新执行该工具，待复核。')]
      : [];
    return [main, origin, ...note, sourcesText(entry.sources)].filter(Boolean).join('\n');
  });
  const reviewValues = progress.values?.filter(needsValueReview) ?? [];
  const valuesHeading = values?.length
    ? ['### ' + (reviewValues.length ? '已记录工具值（部分未复算，待复核）'
      : progress.values.some(entry => stateOf(entry) === 'tool_match') ? '工具值核对' : '已核对工具值')]
    : [];
  const reviewSection = reviewValues.length
    ? ['### 待复核', reviewValues.map(entry => '- ' + readable(entry.label) + '：本会话未复算，需重新读取或复算。').join('\n')]
    : [];
  const insights = progress.insights?.length
    ? ['### 关键判断来源', progress.insights.map(entry => '- [' + INSIGHT_LABELS[entry.source] + '] '
      + readable(entry.text) + (entry.note === undefined ? '' : '（' + readable(entry.note) + '）')).join('\n')]
    : [];
  const hints = progress.hints?.length
    ? ['### 提示吸收', progress.hints.map(entry => {
      const test = entry.test === undefined ? '' : '；最小验证：' + readable(entry.test);
      const verdict = entry.verified === true ? '已验证' : entry.verified === false ? '已验证但未通过' : '待验证';
      return '- [' + INSIGHT_LABELS[entry.source] + '] ' + readable(entry.hint) + ' → 假设：'
        + readable(entry.hypothesis) + test + '（' + verdict + '）';
    }).join('\n')]
    : [];
  const commands = progress.commands?.length
    ? ['### 已执行命令', progress.commands.map(entry => {
      const meta = [entry.exit_code !== undefined ? '退出码 ' + entry.exit_code : '',
        entry.cwd ? '目录 ' + readable(entry.cwd) : ''].filter(Boolean).join('，');
      const output = entry.output ? '\n  - 输出：' + readable(entry.output) : '';
      return '- ' + '`' + readable(entry.command) + '`' + (meta ? '（' + meta + '）' : '') + output;
    }).join('\n')]
    : [];
  const experiments = progress.experiments?.length
    ? ['### 单题验证记录', progress.experiments.map(entry => {
      const observed = entry.actual === undefined ? '待取得观测' : '已记录观测 ' + readable(JSON.stringify(entry.actual));
      return '- ' + readable(entry.label) + ' · ' + readable(entry.hypothesis)
        + '\n  - 预期 ' + readable(JSON.stringify(entry.expected)) + '，' + observed;
    }).join('\n')]
    : [];
  return [
    heading, '### 已记录结论', observations.join('\n') || '- 暂无记录。',
    ...(values?.length ? [...valuesHeading, values.join('\n')] : []),
    ...commands,
    ...reviewSection,
    '### 已排除假设', bullets(progress.ruled_out),
    '### 待补证据与待办', bullets(progress.pending),
    ...insights,
    ...hints,
    ...experiments,
  ].join('\n\n');
}

function stateBody(progress, meta) {
  const value = { version: 2, saved_at: new Date().toISOString(), ...meta, progress };
  return JSON.stringify(value, null, 2).replace(/[<>]/gu, char => char === '<' ? '\\u003c' : '\\u003e') + '\n';
}

function blockContent(stateSha, progress, valueStates) {
  return '<!-- machine: ' + STATE_FILE + ' sha256:' + stateSha + ' -->\n'
    + renderProgress(progress, '## CTF 续接记录', valueStates);
}

function needsReview(entry) {
  return entry.sources.some(source => source.status !== undefined && source.status !== 'matches');
}

function allSources(progress) {
  return [...progress.confirmed, ...(progress.values ?? [])].flatMap(entry => entry.sources);
}

function handoffContext(progress, evidenceStatus, valueChecks) {
  const manifest = new Map((progress.attachments ?? []).map(file_path => [file_path, { file_path, status: 'listed' }]));
  for (const source of allSources(progress)) {
    manifest.set(source.file_path, {
      file_path: source.file_path, sha256: source.sha256, status: evidenceStatus.get(source.file_path),
    });
  }
  const pendingValue = valueChecks.find(check => check.status !== 'reverified');
  const next_step = progress.pending[0] ?? (pendingValue ? '重新调用相应工具并核对 ' + pendingValue.label : '按题面复查已记录结论。');
  return { attachments: [...manifest.values()], next_step };
}

function textLineBounds(text, line) {
  const bounds = text === null ? null : lineBounds(text, line);
  if (bounds === null) return undefined;
  const start = Buffer.byteLength(text.slice(0, bounds.start), 'utf8');
  const end = start + Buffer.byteLength(text.slice(bounds.start, bounds.end), 'utf8');
  return { start, end };
}

function validLocation(reference, size, text, json, streamedLines) {
  if (reference.json_pointer !== undefined) return resultValue(json, reference.json_pointer) !== undefined;
  if (reference.byte_offset !== undefined && (reference.byte_offset > size
    || (reference.byte_length ?? 0) > size - reference.byte_offset)) return false;
  if (reference.line === undefined) return true;
  const bounds = streamedLines === undefined ? textLineBounds(text, reference.line) : streamedLines.get(reference.line);
  if (bounds === undefined) return false;
  if (reference.byte_offset === undefined) return true;
  const { start, end } = bounds;
  return reference.byte_offset >= start && reference.byte_offset <= end
    && (reference.byte_length ?? 0) <= end - reference.byte_offset;
}

async function verifySources(progress, readEvidence, saving) {
  const byFile = new Map();
  const checked = new Map();
  for (const reference of allSources(progress)) {
    const references = byFile.get(reference.file_path) ?? [];
    references.push(reference);
    byFile.set(reference.file_path, references);
  }
  for (const [file, references] of byFile) {
    const snapshot = await readEvidence(file, references);
    const bytes = snapshot instanceof Uint8Array ? snapshot : null;
    const hash = bytes === null ? snapshot?.sha256 ?? null : digest(bytes);
    const size = bytes?.length ?? snapshot?.size;
    const needJson = references.some(reference => reference.json_pointer !== undefined);
    const text = bytes !== null && (needJson || references.some(reference => reference.line !== undefined)) ? decodeEvidenceText(bytes) : null;
    const json = needJson ? parseEvidenceJson(text) : undefined;
    for (const reference of references) {
      let status = 'matches';
      if (hash === null) status = 'unavailable';
      else if (reference.sha256 !== undefined && reference.sha256 !== hash) status = 'changed';
      else if (bytes === null && reference.json_pointer !== undefined) status = 'location_unavailable';
      else if (!validLocation(reference, size, text, json, snapshot?.line_bounds)) status = 'invalid_location';
      if (saving && status !== 'matches') {
        const reason = {
          unavailable: '无法读取已核验引用的原件。',
          changed: '原件 SHA-256 已变化，请复核。',
          invalid_location: '证据位置或范围无效。',
          location_unavailable: '超过 32 MiB 的原件请使用行号、字节范围或原件哈希复核。',
        }[status];
        throw new Error(reason + file);
      }
      checked.set(reference, saving ? { ...reference, sha256: hash } : { ...reference, status });
    }
  }
  const rechecked = entry => ({ ...entry, sources: entry.sources.map(reference => checked.get(reference)) });
  return { ...progress, confirmed: progress.confirmed.map(rechecked),
    ...(progress.values === undefined ? {} : { values: progress.values.map(rechecked) }) };
}

function hasOriginals(sources) {
  return Array.isArray(sources) && sources.length > 0 && sources.every(source => typeof source?.file_path === 'string' && source.file_path.length > 0
    && typeof source.sha256 === 'string' && HASH.test(source.sha256));
}

function sourceKeys(sources) {
  return sources.map(({ file_path, sha256, line, byte_offset, byte_length, json_pointer }) =>
    JSON.stringify([file_path, sha256.toLowerCase(), line, byte_offset, byte_length, json_pointer])).sort();
}

function valueVerification(entry, readResult) {
  if (needsReview(entry)) return { status: 'review', note: '原件引用需要复核，待复核。' };
  const result = readResult(entry.result_id);
  if (!result || result.persisted) return { status: 'recorded', note: '记录值，本会话未重新执行该工具，待复核。' };
  const current = cachedResultValue(result, entry.pointer);
  if (current === undefined) return { status: 'unavailable', note: '当前工具结果中找不到该字段，待复核。' };
  if (current !== entry.value) return { status: 'mismatch', note: '保存值与当前工具结果不一致，待复核。', actual: current };
  const references = resultReferences(result, entry.pointer);
  if (!hasOriginals(entry.sources) || !hasOriginals(references)) return { status: 'tool_match', note: TOOL_MATCH_NOTE };
  const storedKeys = sourceKeys(entry.sources);
  const currentKeys = sourceKeys(references);
  if (storedKeys.length !== currentKeys.length || storedKeys.some((key, index) => key !== currentKeys[index])) {
    return { status: 'review', note: '保存的原件引用与当前工具结果不同，待复核。' };
  }
  return { status: 'reverified' };
}

function observedValue(claim, readResult, saved = []) {
  const result = readResult(claim.result_id);
  if (!result) {
    const previous = saved.find(entry => entry.result_id === claim.result_id && entry.pointer === claim.pointer);
    return previous ? { ...previous, label: claim.label, origin: 'recorded' } : undefined;
  }
  const value = cachedResultValue(result, claim.pointer);
  if (value === undefined) return undefined;
  const references = resultReferences(result, claim.pointer);
  return {
    label: claim.label, result_id: claim.result_id, pointer: claim.pointer, value, tool: result.tool,
    sources: hasOriginals(references) ? references : [], origin: result.persisted ? 'recorded' : 'session',
  };
}

function checkValues(claims, files, saved = []) {
  if (claims.length === 0) throw new Error('claims 至少需要一项工具值。');
  const checks = claims.map(claim => {
    const found = observedValue(claim, files.readResult, saved);
    const reference = { label: claim.label, result_id: claim.result_id, pointer: claim.pointer, expected: claim.value };
    if (!found) {
      const summary = files.readResult(claim.result_id)?.summary;
      const reason = summary === undefined ? '找不到该工具结果或标量字段。请在当前会话重新调用工具。'
        : '该字段未留在长报告的复核数据中。可缩小结果页后重新读取。';
      return { ...reference, status: 'unavailable', reason };
    }
    if (found.origin === 'recorded') {
      return { ...reference, status: claim.value === found.value ? 'recorded' : 'mismatch', actual: found.value, tool: found.tool, sources: found.sources, reason: '本会话未重新执行该工具，值来自 notes.md，待复核。' };
    }
    const status = claim.value !== found.value ? 'mismatch' : hasOriginals(found.sources) ? 'match' : 'tool_match';
    return { ...reference, status, actual: found.value, tool: found.tool, sources: found.sources,
      ...(status === 'tool_match' ? { reason: TOOL_MATCH_NOTE } : {}) };
  });
  const status = checks.some(check => check.status === 'mismatch') ? 'mismatch'
    : checks.some(check => check.status === 'unavailable') ? 'unavailable'
    : checks.some(check => check.status === 'recorded') ? 'recorded'
    : checks.some(check => check.status === 'tool_match') ? 'tool_match' : 'match';
  return { status, checks };
}

function recordExperiment(draft, files, previous) {
  const { label, hypothesis, pointer, expected, result_id } = draft;
  const prediction = { label, hypothesis, pointer, expected, ...(result_id === undefined ? {} : { result_id }) };
  if (result_id === undefined) return prediction;
  const result = files.readResult(result_id);
  if (!result || !EXPERIMENT_TOOLS.includes(result.tool)) {
    const recorded = previous?.find(entry => entry.result_id === result_id && entry.pointer === pointer);
    return recorded === undefined ? prediction : { ...recorded, ...prediction };
  }
  // A displayed page is not the full text even when the final page fits in a scalar.
  if (result.tool === 'calculate_offline' && /^\/steps\/\d+\/result$/u.test(pointer)
    && typeof cachedResultValue(result, pointer.replace(/\/result$/u, '/result_sha256')) === 'string') {
    return prediction;
  }
  const actual = cachedResultValue(result, pointer);
  const requestHash = cachedResultValue(result, '/request_sha256');
  if (actual === undefined) return prediction;
  const sources = resultReferences(result, pointer);
  return {
    ...prediction, actual, tool: result.tool,
    ...(typeof requestHash === 'string' && RESULT_HASH.test(requestHash) ? { request_sha256: requestHash } : {}),
    sources: hasOriginals(sources) ? sources.map(source => normalizeSource(source, files.normalizePath)) : [],
  };
}

async function checkExperiments(entries, files) {
  if (!entries?.length) return [];
  const { confirmed } = await verifySources({
    confirmed: entries.map(entry => ({ ...entry, sources: entry.sources ?? [] })),
  }, files.readEvidence, false);
  return confirmed.map(entry => {
    const sufficient = entry.actual !== undefined && hasOriginals(entry.sources) && !needsReview(entry);
    const observation = entry.result_id === undefined ? undefined : files.readResult(entry.result_id);
    return {
      ...entry, status: sufficient ? entry.actual === entry.expected ? 'supported' : 'refuted' : 'insufficient',
      ...(entry.actual === undefined ? {} : {
        observation_status: observation && !observation.persisted ? 'current_session' : 'recorded',
      }),
      ...(!sufficient ? { reason: needsReview(entry) ? '引用的原件已变化或不可复核。' : '缺少可复核的实际观测。' } : {}),
    };
  });
}

export async function manageProgress(args, files) {
  const { action, revision } = args;
  if (!PROGRESS_PROPERTIES.action.enum.includes(action)) throw new Error('请选择读取、核对、保存、生成题解、接替、查看结果或修复。');
  if (action === 'results') {
    if (revision !== undefined || args.progress !== undefined || args.claims !== undefined) {
      throw new Error('results 只需 action。');
    }
    return { status: 'results', file: 'notes.md', results: files.listResults?.() ?? [] };
  }
  if (action === 'experiments') {
    if (!keysMatch(args, PROGRESS_ACTION_KEYS.experiments)) throw new Error('experiments 只接受 action 和 experiment_query。');
    const { experiment_query: query } = args;
    let requestHash;
    if (query !== undefined) {
      if (!keysMatch(query, ['tool', 'args'])) throw new Error('找验证记录需要工具名和原调用参数。');
      const input = typeof query.args?.file_path === 'string'
        ? { ...query.args, file_path: files.normalizePath(query.args.file_path) } : query.args;
      requestHash = experimentRequestHash(query.tool, input);
      if (requestHash === undefined) throw new Error('无法为这组工具参数计算验证编号。');
    }
    const notes = await files.readDocument('notes.md');
    const state = await files.readDocument(STATE_FILE);
    const record = await readStored(files, notes, state);
    const saved = record?.progress.experiments ?? [];
    const entries = requestHash === undefined ? saved : saved.filter(entry => entry.request_sha256 === requestHash);
    return { status: 'experiments', experiments: await checkExperiments(entries, files) };
  }
  if (action === 'check') {
    if (revision !== undefined || args.progress !== undefined) throw new Error('check 只需 action 和 claims。');
    const notes = await files.readDocument('notes.md');
    const state = await files.readDocument(STATE_FILE);
    const record = await readStored(files, notes, state);
    return checkValues(normalizeValues(args.claims, files.normalizePath), files, record?.progress.values);
  }
  if (args.claims !== undefined) throw new Error('claims 用于 check。保存工具值时请填写 progress.values。');
  if (((action === 'load' || action === 'handoff') && revision !== undefined) || (action !== 'save' && args.progress !== undefined)) {
    throw new Error('load 和 handoff 只需 action。writeup 可附 revision，progress 用于 save。');
  }
  if ((action === 'save' || action === 'repair' || revision !== undefined)
    && (typeof revision !== 'string' || (revision !== 'absent' && !HASH.test(revision)))) {
    throw new Error('请先用 load 读取 notes.md，再传入返回的 revision。');
  }

  const draft = action === 'save' ? normalizeProgress(args.progress, files.normalizePath) : undefined;
  const notes = await files.readDocument('notes.md');
  const state = await files.readDocument(STATE_FILE);
  const current = progressRevision(notes, state);
  if (revision !== undefined && current !== revision.toLowerCase()) {
    const operation = action === 'repair' ? '修复' : action === 'save' ? '保存' : '生成题解';
    throw new ToolError('conflict', `notes.md 已被更新，请重新读取后再${operation}。`);
  }
  let record;
  try {
    record = await readStored(files, notes, state, action === 'repair');
  } catch (error) {
    if (action === 'load' || action === 'repair') {
      return {
        status: action === 'load' ? 'repair_required' : 'repair_unavailable',
        file: 'notes.md', revision: current, reason: error.message,
      };
    }
    throw error;
  }
  const stored = record?.progress;
  const storedMeta = record?.meta ?? {};
  if (action === 'save') {
    if (draft.attachments === undefined && stored?.attachments !== undefined) draft.attachments = stored.attachments;
    if (draft.experiments !== undefined) {
      draft.experiments = draft.experiments.map(entry => recordExperiment(entry, files, stored?.experiments));
    } else if (stored?.experiments !== undefined) {
      draft.experiments = stored.experiments;
    }
    const values = draft.values ?? stored?.values;
    const valueStates = new Map();
    if (values !== undefined) {
      draft.values = values.map(claim => {
        const found = observedValue(claim, files.readResult, stored?.values);
        if (!found) throw new Error('工具结果或字段无法定位。请在当前会话重新调用工具。' + claim.label);
        if (found.value !== claim.value) throw new Error('工具值与结果不一致。' + claim.label);
        valueStates.set(found.label, found.origin === 'recorded' ? 'recorded'
          : hasOriginals(found.sources) ? 'reverified' : 'tool_match');
        return {
          label: found.label, result_id: found.result_id, pointer: found.pointer, value: found.value,
          ...(found.tool === undefined ? {} : { tool: found.tool }),
          ...(found.sources === undefined ? {} : { sources: found.sources }),
        };
      });
    }
    const checkpoint = await verifySources(draft, files.readEvidence, true);
    const experimentStatus = checkpoint.experiments === undefined ? undefined : await checkExperiments(checkpoint.experiments, files);
    const instance = args.instance ?? storedMeta.instance;
    const meta = {
      ...(files.sessionId === undefined ? {} : { session: files.sessionId }),
      ...(instance === undefined ? {} : { instance }),
    };
    const body = stateBody(checkpoint, meta);
    const content = withManagedBlock(notes.text, 'notes', blockContent(digest(body), checkpoint, valueStates));
    await retainPrevious(files, state);
    await files.writeDocument({ ...state, name: STATE_FILE }, body);
    let nextNotes = { ...notes, version: 'saved', text: content };
    let warning;
    try {
      if (content !== notes.text) await files.writeDocument(notes, content);
    } catch {
      nextNotes = await files.readDocument('notes.md').catch(() => notes);
      warning = '状态已提交，notes.md 显示尚未刷新。用 load 和 repair 恢复。';
    }
    try {
      await mirrorState(files, body);
    } catch {
      warning = [warning, '最新恢复副本写入失败。'].filter(Boolean).join(' ');
    }
    return { status: 'saved', file: 'notes.md', state_file: STATE_FILE, state_sha256: digest(body),
      ...(experimentStatus === undefined ? {} : { experiment_status: experimentStatus }),
      revision: progressRevision(nextNotes, { version: 'saved', text: body }), ...(warning ? { warning } : {}) };
  }

  if (!stored) return { status: 'empty', file: 'notes.md', revision: current };
  const verified = await verifySources(stored, files.readEvidence, false);
  const evidenceStatus = new Map();
  for (const source of allSources(verified)) {
    const previous = evidenceStatus.get(source.file_path);
    if (previous === undefined || previous === 'matches') evidenceStatus.set(source.file_path, source.status);
  }
  const valueChecks = (verified.values ?? []).map(entry => {
    const check = valueVerification(entry, files.readResult);
    return { label: entry.label, status: check.status, ...(check.note ? { note: check.note } : {}) };
  });
  const valueStates = new Map(valueChecks.map(check => [check.label, check.status]));
  const legacyHeading = /^### 已核对工具值$/mu.test(notes.text)
    && valueChecks.some(check => check.status !== 'reverified');

  if (action === 'load') {
    const warnings = [];
    if (record.recovered) warnings.push('当前状态不可读取，已载入上一份有效状态。可运行 repair 提交恢复。');
    else if (record.projectionStale) warnings.push('notes.md 显示与已提交状态不同。可运行 repair 刷新显示。');
    if (storedMeta.session !== undefined && files.sessionId !== undefined && storedMeta.session !== files.sessionId) {
      warnings.push('该笔记由另一个会话（' + storedMeta.session + '）保存；先用 repair 核对差异，再继续补写。');
    }
    if (legacyHeading) warnings.push(LEGACY_VALUES_WARNING);
    return { status: 'loaded', file: 'notes.md', revision: current, progress: stored,
      ...(storedMeta.instance === undefined ? {} : { instance: storedMeta.instance }),
      evidence_status: Object.fromEntries(evidenceStatus), value_status: valueChecks,
      ...(stored.experiments === undefined ? {} : { experiment_status: await checkExperiments(stored.experiments, files) }),
      ...(warnings.length ? { warning: warnings.join(' ') } : {}) };
  }

  if (action === 'repair') {
    const body = record.recovered?.text ?? (state.version === undefined ? stateBody(stored, storedMeta) : state.text);
    const content = withManagedBlock(notes.text, 'notes', blockContent(digest(body), stored, valueStates), true);
    const stateChanged = state.version === undefined || state.text !== body;
    if (content === notes.text && !stateChanged) return { status: 'unchanged', file: 'notes.md', revision: current };
    const backupName = `notes.ctf-backup-${current.slice(0, 16)}.md`;
    const backup = await files.readDocument(backupName);
    if (backup.version === undefined) await files.writeDocument(backup, notes.text);
    else if (backup.text !== notes.text) throw new Error('修复备份路径已有不同内容。');
    if (stateChanged) await files.writeDocument({ ...state, name: STATE_FILE }, body);
    if (content !== notes.text) await files.writeDocument(notes, content);
    await mirrorState(files, body);
    return { status: 'repaired', file: 'notes.md', revision: progressRevision({ version: 'saved', text: content },
      { version: 'saved', text: body }), backup_file: backupName,
      evidence_status: Object.fromEntries(evidenceStatus), value_status: valueChecks };
  }

  if (action === 'handoff') {
    const cwd = files.cwd;
    const context = handoffContext(verified, evidenceStatus, valueChecks);
    const paths = context.attachments.map(item => item.file_path);
    const heading = ['## CTF 接替简报', ...(cwd === undefined ? [] : ['题目工作目录 ' + readable(cwd)]),
      '### 附件清单', bullets(paths), '### 下一步', readable(context.next_step)].join('\n\n');
    const briefing = heading + '\n\n' + renderProgress(verified, '### 已有进展', valueStates, false);
    const projection = files.canWrite === false ? undefined : await writeProjection(files, 'handoff.md', 'handoff', briefing);
    const persisted = projection !== undefined;
    const handoffRevision = projection?.revision;
    const warnings = [];
    if (legacyHeading) warnings.push(LEGACY_VALUES_WARNING);
    if (!persisted) warnings.push('只读会话未写入 handoff.md，只返回简报文本。');
    return { status: 'handoff', file: 'notes.md', revision: current, cwd, ...context, briefing,
      handoff_file: projection?.target ?? 'handoff.md', ...(handoffRevision === undefined ? {} : { handoff_revision: handoffRevision }),
      persisted, progress: stored,
      evidence_status: Object.fromEntries(evidenceStatus), value_status: valueChecks,
      ...(warnings.length ? { warning: warnings.join(' ') } : {}) };
  }

  const body = '续接记录版本 ' + current + '。\n\n' + renderProgress(verified, '## 题解草稿', valueStates);
  const projection = await writeProjection(files, 'writeup.md', 'writeup', body);
  const status = await files.readDocument('.ctf-status.json');
  let statusRecords = 0;
  try {
    const parsed = JSON.parse(status.text === '' ? '{}' : status.text);
    statusRecords = Array.isArray(parsed.entries) ? parsed.entries.length : 0;
  } catch {
    statusRecords = 0;
  }
  const warnings = [];
  if (statusRecords < 2) warnings.push('本题 ctf_status 记录不足 2 条：收尾前补记录卡点、已排除假设和下一步。');
  return {
    status: 'saved', file: projection.target, notes_revision: current, status_records: statusRecords,
    ...(warnings.length ? { warning: warnings.join(' ') } : {}),
  };
}
