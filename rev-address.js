import { createHash } from 'node:crypto';
import { peSections, readPeHeader, wasmSections, wasmVersion } from './attachment.js';
import { elfLoadRanges } from './elf.js';
import { hexAddress, MAX_REV_ADDRESS, revAddress, REV_HEX_ADDRESS } from './rev-evidence.js';

const COORDINATES = ['file_offset', 'va', 'rva', 'runtime_va', 'section_offset'];
const MAX_QUERIES = 12;
const MAX_SPAN = 4096;

export const REV_ADDRESS_PROPERTIES = {
  file_path: { type: 'string', description: '本地 ELF、PE 或 WebAssembly 原件路径。' },
  image_base: { ...REV_HEX_ADDRESS, description: 'ELF 的链接基准地址，可用于 RVA 与运行时地址对照。PE 使用原件的 ImageBase。' },
  load_base: { ...REV_HEX_ADDRESS, description: '已有记录中的实际模块加载基址，runtime_va 使用。' },
  queries: {
    type: 'array', minItems: 1, maxItems: MAX_QUERIES,
    items: {
      type: 'object', additionalProperties: false, required: ['kind', 'value'],
      properties: {
        kind: { type: 'string', enum: COORDINATES },
        value: REV_HEX_ADDRESS,
        byte_length: { type: 'integer', minimum: 1, maximum: MAX_SPAN, default: 1 },
        section_index: { type: 'integer', minimum: 0, description: 'Wasm 节内容偏移使用的节序号，从 0 起算。' },
        expected_file_offset: { type: 'integer', minimum: 0, description: '可选的待核对原件字节偏移。' },
      },
    },
  },
};

function prepareQueries(args) {
  if (!Array.isArray(args.queries) || args.queries.length < 1 || args.queries.length > MAX_QUERIES) {
    throw new Error('请选择 1 至 12 处待核对地址。');
  }
  return args.queries.map(query => {
    const value = revAddress(query?.value);
    const span = query?.byte_length ?? 1;
    const index = query?.section_index;
    const expected = query?.expected_file_offset;
    if (value === undefined || !COORDINATES.includes(query?.kind) || !Number.isSafeInteger(span) || span < 1 || span > MAX_SPAN
      || (query.kind === 'section_offset' ? !Number.isSafeInteger(index) || index < 0 : index !== undefined)
      || (expected !== undefined && (!Number.isSafeInteger(expected) || expected < 0))
      || Object.keys(query).some(key => !['kind', 'value', 'byte_length', 'section_index', 'expected_file_offset'].includes(key))) {
      throw new Error('地址、偏移类型或字节范围无效。');
    }
    return { query, value, span: BigInt(span) };
  });
}

function optionalAddress(value) {
  if (value === undefined) return undefined;
  const result = revAddress(value);
  if (result === undefined) throw new Error('基址须为有效的 0x 十六进制地址。');
  return result;
}

function peRanges(bytes, header) {
  const ranges = [];
  if (header.headerSize !== 0 && header.headerSize <= bytes.length) {
    ranges.push({ name: 'PE headers', address: header.imageBase, fileOffset: 0n,
      fileSize: BigInt(header.headerSize), memorySize: BigInt(header.headerSize), headerOffset: header.optional });
  }
  for (const item of peSections(bytes, header)) {
    const memorySize = item.virtualSize || item.rawSize;
    ranges.push({ name: item.name, address: header.imageBase + BigInt(item.rva), fileOffset: BigInt(item.rawOffset),
      fileSize: BigInt(Math.min(item.rawSize, memorySize)), memorySize: BigInt(memorySize), headerOffset: item.start });
  }
  return ranges;
}

function mapped(source, offset, span, fields) {
  return {
    status: 'mapped', file_offset: Number(offset), ...fields,
    source: { ...source, byte_offset: Number(offset), byte_length: Number(span) },
  };
}

function nativeMapping({ query, value, span }, ranges, imageBase, loadBase, source) {
  const { kind } = query;
  if (kind === 'section_offset') return { status: 'unsupported_coordinate' };
  if (kind === 'runtime_va' && loadBase === undefined) return { status: 'needs_load_base' };
  if (['rva', 'runtime_va'].includes(kind) && imageBase === undefined) return { status: 'needs_image_base' };
  if (kind === 'runtime_va' && value < loadBase) return { status: 'unmapped' };
  const fromFile = kind === 'file_offset';
  const coordinate = kind === 'rva' ? imageBase + value : kind === 'runtime_va' ? imageBase + value - loadBase : value;
  if (coordinate + span - 1n > MAX_REV_ADDRESS) return { status: 'unmapped' };

  const hits = new Map();
  for (const range of ranges) {
    const delta = coordinate - (fromFile ? range.fileOffset : range.address);
    if (delta < 0n || delta >= (fromFile ? range.fileSize : range.memorySize)) continue;
    const va = range.address + delta;
    const file = range.fileOffset + delta;
    if (va + span - 1n > MAX_REV_ADDRESS) continue;
    const virtual = { va: hexAddress(va), region: range.name, header_file_offset: range.headerOffset };
    if (imageBase !== undefined && va >= imageBase) {
      const rva = va - imageBase;
      virtual.rva = hexAddress(rva);
      if (loadBase !== undefined && loadBase + rva <= MAX_REV_ADDRESS) virtual.runtime_va = hexAddress(loadBase + rva);
    }
    if (delta + span > range.fileSize) {
      const status = delta + span > range.memorySize || delta < range.fileSize ? 'partial_range' : 'memory_only';
      hits.set(`${status}:${va}`, { status, ...virtual, source: { ...source, byte_offset: range.headerOffset } });
    } else {
      hits.set(`${va}:${file}`, mapped(source, file, span, virtual));
    }
  }
  if (hits.size > 1) return { status: 'ambiguous', match_count: hits.size, candidates: [...hits.values()].slice(0, 6) };
  return hits.values().next().value ?? { status: 'unmapped' };
}

function wasmMapping({ query, value, span }, sections, size, source) {
  if (query.kind === 'section_offset') {
    const section = sections[query.section_index];
    if (!section || value + span > BigInt(section.size)) return { status: 'unmapped' };
    return mapped(source, value + BigInt(section.payload), span, {
      section_index: section.index, section: section.name, section_offset: hexAddress(value),
    });
  }
  if (query.kind !== 'file_offset') return { status: 'unsupported_coordinate' };
  if (value + span > BigInt(size)) return { status: 'unmapped' };
  const section = sections.find(item => value >= BigInt(item.start) && value < BigInt(item.payload + item.size));
  if (!section) return value + span <= 8n ? mapped(source, value, span, { region: 'module_header' }) : { status: 'partial_range' };
  if (value + span > BigInt(section.payload + section.size)) return { status: 'partial_range' };
  const delta = value - BigInt(section.payload);
  return mapped(source, value, span, {
    section_index: section.index, section: section.name,
    ...(delta < 0n ? { region: 'section_header' } : { section_offset: hexAddress(delta) }),
  });
}

export function mapRevAddress(bytes, file_path, args) {
  const queries = prepareQueries(args);
  let imageBase = optionalAddress(args.image_base);
  const loadBase = optionalAddress(args.load_base);
  const source = { file_path, sha256: createHash('sha256').update(bytes).digest('hex') };
  const signature = bytes.subarray(0, 4).toString('hex');
  let map;
  let format;
  if (signature === '7f454c46') {
    format = 'ELF';
    const ranges = elfLoadRanges(bytes);
    map = selection => nativeMapping(selection, ranges, imageBase, loadBase, source);
  } else if (signature.startsWith('4d5a')) {
    const header = readPeHeader(bytes);
    if (header.status !== 'ok') return { format: header.format, status: 'unsupported', sources: [source] };
    format = header.magic === 0x10b ? 'PE32' : 'PE32+';
    if (imageBase !== undefined && imageBase !== header.imageBase) throw new Error('给出的链接基址与 PE 原件的 ImageBase 不一致。');
    imageBase = header.imageBase;
    const ranges = peRanges(bytes, header);
    map = selection => nativeMapping(selection, ranges, imageBase, loadBase, source);
  } else if (signature === '0061736d' && wasmVersion(bytes) === 1) {
    format = 'WebAssembly';
    const sections = [...wasmSections(bytes)];
    map = selection => wasmMapping(selection, sections, bytes.length, source);
  } else {
    return { status: 'unsupported', reason: '支持 ELF、PE32/PE32+ 和版本 1 的 WebAssembly。', sources: [source] };
  }
  const mappings = queries.map(selection => {
    const result = map(selection);
    const expected = selection.query.expected_file_offset;
    const check = expected === undefined || result.status !== 'mapped' ? undefined : expected === result.file_offset ? 'match' : 'mismatch';
    return { query: selection.query, ...result, check };
  });
  const status = mappings.some(item => item.check === 'mismatch') ? 'mismatch'
    : mappings.every(item => item.status === 'mapped') ? 'ok' : 'incomplete';
  return { format, status, image_base: imageBase === undefined ? undefined : hexAddress(imageBase), mappings, sources: [source] };
}
