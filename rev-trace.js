import { createHash } from 'node:crypto';
import { isResultScalar, RESULT_HASH } from './ctf-result-values.js';
import { parseEvidenceJson } from './evidence.js';
import { revText } from './rev-evidence.js';
import { ToolError } from './tool-errors.js';

const FIELDS = ['function', 'address', 'input', 'state_before', 'state', 'value_before', 'value', 'output'];

export const REV_TRACE_PROPERTIES = {
  file_path: { type: 'string', description: '已有的实际运行记录 JSONL。' },
  reference_path: { type: 'string', description: '要对照的本地参考记录 JSONL。' },
  machine_result_id: { type: 'string', description: '当前会话 verify_rev_machine 返回的编号，可作为参考记录。' },
  fields: { type: 'array', minItems: 1, maxItems: FIELDS.length, uniqueItems: true, items: { type: 'string', enum: FIELDS } },
};

function readTrace(bytes, file_path) {
  const { rows, source } = revText(bytes, file_path);
  const records = [];
  let previous = 0;
  for (const { content, location } of rows) {
    const data = parseEvidenceJson(content);
    if (!Number.isSafeInteger(data?.step) || data.step <= previous) throw new ToolError('unsupported', `${file_path} 第 ${location.line} 行须有唯一递增的正整数 step。`);
    previous = data.step;
    records.push({ data, source: { ...source, ...location } });
  }
  return { source, records };
}

async function machineTrace(id, files) {
  const cached = typeof id === 'string' && RESULT_HASH.test(id) ? await files.result(id) : undefined;
  if (cached?.tool !== 'verify_rev_machine') throw new ToolError('conflict', '请使用当前会话和目录中 verify_rev_machine 的结果编号。');
  const machine = cached.report;
  const [source] = machine.sources;
  const current = await files.snapshot(source.file_path);
  if (current === null || createHash('sha256').update(current.bytes).digest('hex') !== source.sha256) {
    return { source, reason: 'machine_source_changed' };
  }
  if (machine.status === 'incomplete') return { source, reason: 'machine_reference_incomplete' };
  return { source, records: machine.steps.map(data => ({ data, source: { ...source, line: data.rule_line } })) };
}

function usable(value) {
  return isResultScalar(value) && (!Number.isInteger(value) || Number.isSafeInteger(value));
}

function compareRows(expected, observed, fields) {
  const total = Math.max(expected.length, observed.length);
  for (let index = 0; index < total; index++) {
    const left = expected[index];
    const right = observed[index];
    if (left?.data.step !== right?.data.step) {
      const step = Math.min(left?.data.step ?? Infinity, right?.data.step ?? Infinity);
      const missing = left?.data.step === step ? 'observed' : 'reference';
      return { status: 'insufficient', matched_steps: index, first_difference: {
        step, reason: 'missing_step', missing, reference_source: left?.source, observed_source: right?.source,
      } };
    }
    for (const field of fields) {
      const a = left.data[field];
      const b = right.data[field];
      if (usable(a) && usable(b) && a === b) continue;
      const available = usable(a) && usable(b);
      return { status: available ? 'mismatch' : 'insufficient', matched_steps: index, first_difference: {
        step: left.data.step, field, reason: available ? 'different_value' : 'missing_or_unsupported_value',
        expected: usable(a) ? a : undefined, actual: usable(b) ? b : undefined,
        reference_source: left.source, observed_source: right.source,
      } };
    }
  }
  return total ? { status: 'match', matched_steps: total } : { status: 'insufficient', matched_steps: 0, reason: 'no_steps' };
}

export async function compareRevTrace(args, files) {
  const fields = args.fields;
  if (!Array.isArray(fields) || !fields.length || fields.some(field => !FIELDS.includes(field)) || new Set(fields).size !== fields.length) {
    throw new ToolError('unsupported', '请选择要核对的不同轨迹字段。');
  }
  if ((args.reference_path === undefined) === (args.machine_result_id === undefined)) {
    throw new ToolError('unsupported', '请选用参考文件或当前会话的状态机结果。');
  }
  const file_path = files.normalizePath(args.file_path);
  const input = await files.read(file_path);
  const actual = readTrace(input.bytes, file_path);
  let expected;
  if (args.reference_path !== undefined) {
    const reference = files.normalizePath(args.reference_path);
    const file = await files.read(reference);
    if ((input.targetKey ?? file_path) === (file.targetKey ?? reference)) throw new ToolError('unsupported', '请使用不同的观测和参考记录。');
    expected = readTrace(file.bytes, reference);
  } else {
    expected = await machineTrace(args.machine_result_id, files);
  }
  const result = expected.reason ? { status: 'insufficient', reason: expected.reason, matched_steps: 0 }
    : compareRows(expected.records, actual.records, fields);
  const sources = [result.first_difference?.reference_source ?? expected.source, result.first_difference?.observed_source ?? actual.source];
  return { ...result, fields, sources };
}
