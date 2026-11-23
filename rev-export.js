import { parseEvidenceJson } from './evidence.js';
import { hexAddress, MAX_REV_ADDRESS, revAddress, revText } from './rev-evidence.js';

const FORMATS = ['jsonl', 'listing'];
const QUERIES = ['function', 'address', 'string'];
const SYMBOL = /^\s*([0-9a-f]{1,16})\s+<([^\r\n]{1,256})>:\s*$/iu;
const INSTRUCTION = /^\s*([0-9a-f]{1,16}):\s*(.*)$/iu;
const DIRECT_CALL = /^(?:[0-9a-f]{2,8}[ \t]+)*(?:callq?|bl|jal)[ \t]+(?:0x)?([0-9a-f]{1,16})(?=[ \t<]|$)/iu;
const MAX_MATCHES = 10;
const MAX_EDGES = 8;

export const REV_EXPORT_PROPERTIES = {
  file_path: { type: 'string', description: '本地静态导出文本的相对路径。' },
  format: { type: 'string', enum: FORMATS, description: '结构化 JSONL 或已有 GNU 式带地址列表。' },
  query: {
    type: 'object', additionalProperties: false, required: ['kind', 'value'],
    properties: {
      kind: { type: 'string', enum: QUERIES },
      value: { type: 'string', maxLength: 256, description: '已知函数名、0x 地址或完整字符串。' },
    },
  },
};

function shortText(value, allowEmpty = false) {
  return typeof value === 'string' && value.length <= 256 && (allowEmpty || value.length > 0)
    && !/[\u0000-\u001f\u007f\p{Cs}]/u.test(value);
}

function structuredRow(content, source) {
  const row = parseEvidenceJson(content);
  const address = revAddress(row?.address);
  if (address === undefined) return undefined;
  if (row.kind === 'function' && shortText(row.name)) {
    const size = row.size === undefined ? 1 : row.size;
    if (!Number.isSafeInteger(size) || size < 1 || address + BigInt(size) - 1n > MAX_REV_ADDRESS) return undefined;
    return { kind: 'function', name: row.name, address: hexAddress(address), end: address + BigInt(size), source };
  }
  if (row.kind === 'string' && shortText(row.value, true)) {
    return { kind: 'string', value: row.value, address: hexAddress(address), source };
  }
  if (['call', 'ref'].includes(row.kind)) {
    const from = revAddress(row.from);
    const to = revAddress(row.to);
    if (from !== undefined && to !== undefined) {
      return { kind: row.kind, address: hexAddress(address), from: hexAddress(from), to: hexAddress(to), source };
    }
  }
}

function readListing(rows, root) {
  const records = [];
  let owner;
  for (const { content, location } of rows) {
    const source = { ...root, ...location };
    if (/^\s*Disassembly of section /u.test(content)) owner = undefined;
    const symbol = SYMBOL.exec(content);
    if (symbol) {
      owner = { kind: 'function', name: symbol[2], address: hexAddress(BigInt(`0x${symbol[1]}`)), source };
      records.push(owner);
      continue;
    }
    const instruction = INSTRUCTION.exec(content);
    if (!owner || !instruction) continue;
    const address = hexAddress(BigInt(`0x${instruction[1]}`));
    records.push({ kind: 'instruction', address, from: owner.address, source });
    const direct = DIRECT_CALL.exec(instruction[2]);
    if (direct) records.push({ kind: 'call', address, from: owner.address, to: hexAddress(BigInt(`0x${direct[1]}`)), source });
  }
  return records;
}

function relation(rows, definitions) {
  return rows.slice(0, MAX_EDGES).map(row => {
    const from = definitions.get(row.from) ?? [];
    const to = definitions.get(row.to) ?? [];
    return {
      ...row, from_names: from.map(item => item.name), to_names: to.map(item => item.name),
      from_definitions: from, to_definitions: to,
    };
  });
}

export function queryRevExport(bytes, file_path, format, query) {
  if (!FORMATS.includes(format) || !query || !QUERIES.includes(query.kind) || !shortText(query.value, query.kind === 'string')
    || Object.keys(query).some(key => key !== 'kind' && key !== 'value')) throw new Error('请指定导出格式和有效的已知查询值。');
  const address = query.kind === 'address' ? revAddress(query.value) : undefined;
  if (query.kind === 'address' && address === undefined) throw new Error('地址须为带 0x 的十六进制字符串。');
  const { source, rows } = revText(bytes, file_path);
  if (format === 'listing' && query.kind === 'string') return { status: 'unavailable', reason: '该查询需带字符串记录的 JSONL 导出。', sources: [source] };

  const records = format === 'listing' ? readListing(rows, source) : [];
  let malformed = 0;
  if (format === 'jsonl') {
    for (const { content, location } of rows) {
      const row = structuredRow(content, { ...source, ...location });
      if (row) records.push(row);
      else malformed++;
    }
  }
  const symbols = records.filter(row => ['function', 'string'].includes(row.kind));
  const definitions = new Map();
  for (const row of symbols) {
    if (row.kind !== 'function') continue;
    const aliases = definitions.get(row.address) ?? [];
    if (aliases.length < 2 && !aliases.some(item => item.name === row.name)) {
      const { line, byte_offset, byte_length } = row.source;
      aliases.push({ name: row.name, line, byte_offset, byte_length });
    }
    definitions.set(row.address, aliases);
  }
  const exact = address === undefined ? undefined : hexAddress(address);
  const exactInstructions = exact === undefined ? [] : records.filter(row => row.kind === 'instruction' && row.address === exact);
  const instructionOwners = new Set(exactInstructions.map(row => row.from));
  const matches = symbols.filter(row => {
    if (query.kind === 'function') return row.kind === 'function' && row.name === query.value;
    if (query.kind === 'string') return row.kind === 'string' && row.value === query.value;
    return row.address === exact || (row.kind === 'function' && (
      (row.end !== undefined && address >= BigInt(row.address) && address < row.end)
      || instructionOwners.has(row.address)
    ));
  });
  const edges = records.filter(row => row.kind === 'call' || row.kind === 'ref');
  const detail = matches.slice(0, MAX_MATCHES).map(({ end, ...row }) => {
    const incoming = edges.filter(edge => edge.to === row.address);
    const outgoing = edges.filter(edge => edge.from === row.address);
    return {
      ...row, exclusive_end: end !== undefined ? hexAddress(end) : undefined,
      incoming: matches.length === 1 ? relation(incoming, definitions) : [],
      outgoing: matches.length === 1 ? relation(outgoing, definitions) : [],
      incoming_count: incoming.length, outgoing_count: outgoing.length,
      instruction_positions: matches.length === 1 ? exactInstructions.filter(site => site.from === row.address).slice(0, 4).map(site => site.source) : [],
    };
  });
  const status = matches.length > 1 ? 'ambiguous' : malformed || !symbols.length ? 'incomplete' : matches.length === 1 ? 'matched' : 'not_found';
  return { status, format, query, match_count: matches.length, malformed_records: malformed, matches: detail,
    sources: [matches.length === 1 ? matches[0].source : source] };
}
