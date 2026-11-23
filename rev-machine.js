import { parseEvidenceJson } from './evidence.js';
import { calculateSteps, WORD_ACCUMULATOR_OPERATIONS, WORD_WIDTHS } from './offline-calculation.js';
import { revText } from './rev-evidence.js';

const MAX_INPUT_BYTES = 64;
const STATE = /^[A-Za-z_][A-Za-z_0-9.-]{0,63}$/u;
const BYTE = /^[\da-f]{2}$/iu;
const WORD = /^[+-]?(?:\d{1,64}|0x[\da-f]{1,64})$/iu;

export const REV_MACHINE_PROPERTIES = {
  file_path: { type: 'string', description: '题目目录中明确给出的字节状态机规则 JSONL。' },
  input_hex: { type: 'string', maxLength: MAX_INPUT_BYTES * 2, description: '按从左到右的顺序消费 Hex 字节。' },
  expected_state: { type: 'string', maxLength: 64 },
  expected_value: { type: 'string', maxLength: 20, description: '期望的最终无符号十进制累加值。' },
};

function test(value, regex) {
  return typeof value === 'string' && regex.test(value);
}

function allowed(row, keys) {
  return row !== null && typeof row === 'object' && !Array.isArray(row) && Object.keys(row).every(key => keys.includes(key));
}

function transitionKey(state, input) {
  return `${state}/${input}`;
}

function readRules(rows) {
  let start;
  const rules = new Map();
  for (const { content, location } of rows) {
    const row = parseEvidenceJson(content);
    if (!start) {
      if (!allowed(row, ['kind', 'state', 'width', 'value']) || row.kind !== 'start' || !test(row.state, STATE)
        || !WORD_WIDTHS.includes(row.width) || !test(row.value, WORD)) {
        throw new Error(`第 ${location.line} 行须声明起始状态、字宽和初始整数。`);
      }
      start = { ...row, line: location.line };
      continue;
    }
    if (!allowed(row, ['kind', 'state', 'byte', 'next', 'operation', 'operand', 'emit']) || row.kind !== 'rule'
      || !test(row.state, STATE) || !test(row.next, STATE) || (row.byte !== '*' && !test(row.byte, BYTE))
      || (row.emit !== undefined && typeof row.emit !== 'boolean')) throw new Error(`第 ${location.line} 行的转换规则无效。`);
    if (row.operation !== undefined ? !WORD_ACCUMULATOR_OPERATIONS.includes(row.operation) || !(row.operand === 'input' || test(row.operand, WORD))
      : row.operand !== undefined) throw new Error(`第 ${location.line} 行的运算或操作数无效。`);
    const key = transitionKey(row.state, row.byte.toLowerCase());
    if (rules.has(key)) throw new Error(`第 ${location.line} 行与已有状态和字节规则重复。`);
    rules.set(key, { ...row, line: location.line });
  }
  if (!start || rules.size === 0) throw new Error('请提供起始状态和至少一条状态转换规则。');
  return { start, rules };
}

export function verifyRevMachine(bytes, file_path, args) {
  const { input_hex: input, expected_value: expected, expected_state: expectedState } = args;
  if (typeof input !== 'string' || input.length > MAX_INPUT_BYTES * 2 || input.length % 2 !== 0 || /[^\da-f]/iu.test(input)) {
    throw new Error('输入须为最多 64 字节的成对 Hex。');
  }
  if ((expected !== undefined && !test(expected, /^\d{1,20}$/u)) || (expectedState !== undefined && !test(expectedState, STATE))) {
    throw new Error('最终期望值须使用无符号十进制字符串，期望状态须为有效状态名称。');
  }
  const { source, rows } = revText(bytes, file_path, 512);
  const { start, rules } = readRules(rows);
  const initial = calculateSteps([{ operation: 'word_truncate', width: start.width, inputs: [start.value] }]).steps[0].result;
  const steps = [];
  const output = [];
  let state = start.state;
  let value = initial;
  let stopped;
  for (const [index, byte] of Buffer.from(input, 'hex').entries()) {
    const token = byte.toString(16).padStart(2, '0');
    const rule = rules.get(transitionKey(state, token)) ?? rules.get(transitionKey(state, '*'));
    if (!rule) {
      stopped = { step: index + 1, input: token, state, reason: 'transition_missing' };
      break;
    }
    const before = value;
    if (rule.operation !== undefined) {
      const computed = calculateSteps([{ operation: rule.operation, width: start.width,
        inputs: [before, rule.operand === 'input' ? String(byte) : rule.operand] }]).steps[0];
      if (computed.status !== 'computed') {
        stopped = { step: index + 1, input: token, state, rule_line: rule.line, reason: computed.reason };
        break;
      }
      value = computed.result;
    }
    const emitted = rule.emit ? value : null;
    if (emitted !== null) output.push(emitted);
    steps.push({ step: index + 1, input: token, state_before: state, state: rule.next, value_before: before, value,
      output: emitted, rule_line: rule.line, operation: rule.operation });
    state = rule.next;
  }
  const checks = {
    state: expectedState === undefined || stopped ? undefined : state === expectedState ? 'match' : 'mismatch',
    value: expected === undefined || stopped ? undefined : value === expected ? 'match' : 'mismatch',
  };
  const status = stopped ? 'incomplete' : Object.values(checks).includes('mismatch') ? 'mismatch' : 'ok';
  return { status, width: start.width, initial_state: start.state, initial_value: initial, initial_line: start.line,
    final_state: state, final_value: value, output, steps, stopped, checks, sources: [source] };
}
