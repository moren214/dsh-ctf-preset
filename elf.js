import { createHash } from 'node:crypto';

const ELF_MAGIC = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);
const MAX_HEADERS = 8192;
const MAX_TABLE_ENTRIES = 65536;
const PT_LOAD = 1;
const PT_DYNAMIC = 2;
const PT_INTERP = 3;
const SHT_SYMTAB = 2;
const SHT_STRTAB = 3;
const SHT_RELA = 4;
const SHT_DYNSYM = 11;
const PF_X = 1;
const EM_X86_64 = 62;
const GLIBC_START = Buffer.from('31ed4989d15e4889e24883e4f050544531c031c9', 'hex');
const ENDBR64 = Buffer.from('f30f1efa', 'hex');
const LIBC_SYMBOL = Buffer.from('__libc_start_main\0');
const PT_GNU_STACK = 0x6474e551;
const PT_GNU_RELRO = 0x6474e552;
const SHT_DYNAMIC = 6;
const SHN_UNDEF = 0;
const DT_NULL = 0n;
const DT_NEEDED = 1n;
const DT_STRTAB = 5n;
const DT_SYMTAB = 6n;
const DT_STRSZ = 10n;
const DT_BIND_NOW = 24n;
const DT_FLAGS = 30n;
const DT_FLAGS_1 = 0x6ffffffbn;
const DF_BIND_NOW = 0x8;
const DF_1_NOW = 0x1;
const DF_1_PIE = 0x08000000;
const MAX_IMPORT_NAMES = 96;
const MAX_NOTABLE_IMPORTS = 16;
const MAX_NEEDED = 32;
const MAX_SYMBOL_NAME_BYTES = 256;
const MAX_GADGET_SCAN_BYTES = 8 * 1024 * 1024;
const NOTABLE_IMPORTS = new Set([
  'system', 'execve', 'popen', 'gets', 'strcpy', 'strcat', 'sprintf',
  'mprotect', 'read', 'write', 'open', 'openat', 'mmap',
]);
const R_X86_64_64 = 1n;
const R_X86_64_COPY = 5n;
const R_X86_64_GLOB_DAT = 6n;
const R_X86_64_JUMP_SLOT = 7n;
const MAX_PWN_RELOCATIONS = 24;
const MAX_PWN_PLT = 24;
const MAX_PWN_EXPORTS = 24;
const PWN_EXPORTS = new Set([
  'system', 'execve', 'read', 'write', 'open', 'openat', 'mprotect', 'dup2',
  'popen', 'printf', 'puts', 'exit', '__libc_start_main', 'environ', '__environ',
  'malloc', 'free', 'gets', 'strcpy', 'strcat', 'sprintf', 'setuid', 'setgid',
  'mmap', '__free_hook', '__malloc_hook',
]);
const BIN_SH = Buffer.from('/bin/sh\0', 'latin1');
const RELOCATION_NAMES = new Map([
  [R_X86_64_64, 'R_X86_64_64'],
  [R_X86_64_COPY, 'R_X86_64_COPY'],
  [R_X86_64_GLOB_DAT, 'R_X86_64_GLOB_DAT'],
  [R_X86_64_JUMP_SLOT, 'R_X86_64_JUMP_SLOT'],
]);
const GADGET_PATTERNS = [
  { name: 'pop rdi; ret', bytes: Buffer.from([0x5f, 0xc3]) },
  { name: 'pop rsi; ret', bytes: Buffer.from([0x5e, 0xc3]) },
  { name: 'pop rdx; ret', bytes: Buffer.from([0x5a, 0xc3]) },
  { name: 'pop rax; ret', bytes: Buffer.from([0x58, 0xc3]) },
  { name: 'pop rbp; ret', bytes: Buffer.from([0x5d, 0xc3]) },
  { name: 'leave; ret', bytes: Buffer.from([0xc9, 0xc3]) },
  { name: 'syscall; ret', bytes: Buffer.from([0x0f, 0x05, 0xc3]) },
  { name: 'syscall', bytes: Buffer.from([0x0f, 0x05]) },
  { name: 'int 0x80', bytes: Buffer.from([0xcd, 0x80]) },
];

function hex(value) {
  return `0x${value.toString(16)}`;
}

function invalid(message) {
  throw new Error(`ELF 结构不完整或无效：${message}`);
}

function fileRange(bytes, offset, length) {
  return offset >= 0n && length >= 0n && offset + length <= BigInt(bytes.length);
}

function tableOffsets(bytes, offset, count, stride, minimumStride, label) {
  if (count === 0n) return [];
  if (offset === 0n || count > MAX_HEADERS || stride < minimumStride
    || !fileRange(bytes, offset, count * BigInt(stride))) {
    invalid(label);
  }
  return Array.from({ length: Number(count) }, (_, index) => Number(offset) + index * stride);
}

function parseElf(bytes) {
  if (!bytes.subarray(0, 4).equals(ELF_MAGIC)) {
    throw new Error('此附件的文件头不是 ELF。请提供支持的 ELF 文件或其他格式的静态导出。');
  }
  const is64 = bytes[4] === 2;
  const littleEndian = bytes[5] === 1;
  if ((!is64 && bytes[4] !== 1) || (!littleEndian && bytes[5] !== 2)
    || bytes.length < (is64 ? 64 : 52) || bytes[6] !== 1) {
    invalid('文件头');
  }
  const u16 = offset => littleEndian ? bytes.readUInt16LE(offset) : bytes.readUInt16BE(offset);
  const u32 = offset => littleEndian ? bytes.readUInt32LE(offset) : bytes.readUInt32BE(offset);
  const u64 = offset => littleEndian ? bytes.readBigUInt64LE(offset) : bytes.readBigUInt64BE(offset);
  const word = is64 ? u64 : offset => BigInt(u32(offset));
  const headerSize = u16(is64 ? 52 : 40);
  if (u32(20) !== 1 || headerSize < (is64 ? 64 : 52) || headerSize > bytes.length) {
    invalid('文件头版本或长度');
  }

  const type = u16(16);
  const machine = u16(18);
  const entry = word(24);
  const programOffset = word(is64 ? 32 : 28);
  const sectionOffset = word(is64 ? 40 : 32);
  const programStride = u16(is64 ? 54 : 42);
  const sectionStride = u16(is64 ? 58 : 46);
  const minimumSectionStride = is64 ? 64 : 40;
  let programCount = BigInt(u16(is64 ? 56 : 44));
  let sectionCount = BigInt(u16(is64 ? 60 : 48));
  if (programCount === 0xffffn || (sectionCount === 0n && sectionOffset !== 0n)) {
    if (sectionOffset === 0n || sectionStride < minimumSectionStride
      || !fileRange(bytes, sectionOffset, BigInt(sectionStride))) {
      invalid('扩展编号所需的首个节头');
    }
    const first = Number(sectionOffset);
    if (sectionCount === 0n) sectionCount = word(first + (is64 ? 32 : 20));
    if (programCount === 0xffffn) programCount = BigInt(u32(first + (is64 ? 44 : 28)));
  }

  const programs = tableOffsets(bytes, programOffset, programCount, programStride, is64 ? 56 : 32, '程序头表')
    .map(offset => ({
      headerOffset: offset,
      type: u32(offset),
      flags: u32(offset + (is64 ? 4 : 24)),
      fileOffset: word(offset + (is64 ? 8 : 4)),
      address: word(offset + (is64 ? 16 : 8)),
      fileSize: word(offset + (is64 ? 32 : 16)),
      memorySize: word(offset + (is64 ? 40 : 20)),
    }));
  for (const segment of programs) {
    if (segment.type === PT_LOAD && (segment.fileSize > segment.memorySize
      || !fileRange(bytes, segment.fileOffset, segment.fileSize))) {
      invalid('PT_LOAD 文件范围');
    }
  }
  const sections = tableOffsets(bytes, sectionOffset, sectionCount, sectionStride, minimumSectionStride, '节头表')
    .map(offset => ({
      headerOffset: offset,
      nameOffset: u32(offset),
      type: u32(offset + 4),
      flags: word(offset + 8),
      address: word(offset + (is64 ? 16 : 12)),
      offset: word(offset + (is64 ? 24 : 16)),
      size: word(offset + (is64 ? 32 : 20)),
      link: u32(offset + (is64 ? 40 : 24)),
      stride: word(offset + (is64 ? 56 : 36)),
    }));
  const elf = { bytes, is64, littleEndian, type, machine, entry, programs, sections, u16, u32, word };
  let stringIndex = u16(is64 ? 62 : 50);
  if (stringIndex === 0xffff) stringIndex = sections[0]?.link ?? 0;
  const strings = sections[stringIndex];
  if (strings?.type === SHT_STRTAB) {
    for (const section of sections) {
      section.name = tableString(elf, strings, BigInt(section.nameOffset));
    }
  }
  return elf;
}

export function elfLoadRanges(bytes) {
  const elf = parseElf(bytes);
  return elf.programs.filter(item => item.type === PT_LOAD).map(item => ({
    address: item.address, fileOffset: item.fileOffset, fileSize: item.fileSize, memorySize: item.memorySize,
    headerOffset: item.headerOffset,
  }));
}

function mappedFileOffset(elf, address, size, executable = true) {
  const offsets = new Set();
  for (const segment of elf.programs) {
    if (segment.type !== PT_LOAD || (executable && (segment.flags & PF_X) === 0)) continue;
    const displacement = address - segment.address;
    if (displacement >= 0n && displacement + size <= segment.fileSize) {
      offsets.add(segment.fileOffset + displacement);
    }
  }
  return offsets.size === 1 ? offsets.values().next().value : undefined;
}

function sectionTable(elf, section, entrySize) {
  if (section?.stride !== BigInt(entrySize) || section.size % section.stride !== 0n
    || !fileRange(elf.bytes, section.offset, section.size)) return undefined;
  const count = section.size / section.stride;
  if (count > MAX_TABLE_ENTRIES) return undefined;
  return { offset: Number(section.offset), count: Number(count) };
}

function libcRelocation(elf, slot) {
  let inspected = 0;
  let matched = 0;
  for (const section of elf.sections) {
    const symbols = elf.sections[section.link];
    if (section.type !== SHT_RELA || symbols?.type !== SHT_DYNSYM) continue;
    const relocations = sectionTable(elf, section, 24);
    const dynamicSymbols = sectionTable(elf, symbols, 24);
    const strings = elf.sections[symbols.link];
    if (!relocations || !dynamicSymbols || strings?.type !== SHT_STRTAB
      || !fileRange(elf.bytes, strings.offset, strings.size)) return false;
    inspected += relocations.count;
    if (inspected > MAX_TABLE_ENTRIES) return false;
    for (let index = 0; index < relocations.count; index++) {
      const offset = relocations.offset + index * 24;
      if (elf.word(offset) !== slot) continue;
      const info = elf.word(offset + 8);
      const type = info & 0xffffffffn;
      const symbolIndex = Number(info >> 32n);
      if ((type !== 6n && type !== 7n) || symbolIndex >= dynamicSymbols.count) return false;
      const symbolOffset = dynamicSymbols.offset + symbolIndex * 24;
      const nameOffset = BigInt(elf.u32(symbolOffset));
      if (elf.u16(symbolOffset + 6) !== 0 || nameOffset + BigInt(LIBC_SYMBOL.length) > strings.size) return false;
      const name = Number(strings.offset + nameOffset);
      if (!elf.bytes.subarray(name, name + LIBC_SYMBOL.length).equals(LIBC_SYMBOL)) return false;
      matched++;
    }
  }
  return matched === 1;
}

function startupEvidence(elf) {
  if (!elf.is64 || !elf.littleEndian || elf.machine !== EM_X86_64 || (elf.type !== 2 && elf.type !== 3)) {
    return { status: 'unavailable', reason: '入口识别只覆盖 x86-64 glibc 的标准启动形式。' };
  }
  const initialOffset = mappedFileOffset(elf, elf.entry, BigInt(ENDBR64.length));
  if (initialOffset === undefined) {
    return { status: 'unavailable', reason: '入口没有唯一的可执行文件偏移。' };
  }
  const start = Number(initialOffset);
  const prefixSize = elf.bytes.subarray(start, start + ENDBR64.length).equals(ENDBR64) ? ENDBR64.length : 0;
  const leaOffset = prefixSize + GLIBC_START.length;
  const callOffset = leaOffset + 7;
  const stubSize = callOffset + 7;
  if (mappedFileOffset(elf, elf.entry, BigInt(stubSize)) === undefined
    || !elf.bytes.subarray(start + prefixSize, start + leaOffset).equals(GLIBC_START)
    || !elf.bytes.subarray(start + leaOffset, start + leaOffset + 3).equals(Buffer.from([0x48, 0x8d, 0x3d]))
    || !elf.bytes.subarray(start + callOffset, start + callOffset + 2).equals(Buffer.from([0xff, 0x15]))
    || elf.bytes[start + callOffset + 6] !== 0xf4) {
    return { status: 'unavailable', reason: '入口没有匹配受支持的启动指令序列。' };
  }
  const main = elf.entry + BigInt(callOffset) + BigInt(elf.bytes.readInt32LE(start + leaOffset + 3));
  const slot = elf.entry + BigInt(callOffset + 6) + BigInt(elf.bytes.readInt32LE(start + callOffset + 2));
  const mainOffset = mappedFileOffset(elf, main, 1n);
  if (mainOffset === undefined || mappedFileOffset(elf, slot, 8n, false) === undefined
    || !libcRelocation(elf, slot)) {
    return { status: 'unavailable', reason: '入口传参、文件映射和 __libc_start_main 重定位无法共同确认 main。' };
  }
  return {
    status: 'confirmed',
    main: hex(main),
    main_file_offset: hex(mainOffset),
    argument_instruction: hex(elf.entry + BigInt(leaOffset)),
    call_instruction: hex(elf.entry + BigInt(callOffset)),
    relocation_slot: hex(slot),
    imported_symbol: '__libc_start_main',
  };
}

function definedDynamicAddress(elf, address) {
  const entrySize = elf.is64 ? 24 : 16;
  let inspected = 0;
  let hasTable = false;
  for (const section of elf.sections) {
    if (section.type !== SHT_DYNSYM) continue;
    hasTable = true;
    const table = sectionTable(elf, section, entrySize);
    if (!table) return undefined;
    inspected += table.count;
    if (inspected > MAX_TABLE_ENTRIES) return undefined;
    for (let index = 0; index < table.count; index++) {
      const offset = table.offset + index * entrySize;
      if (elf.u16(offset + (elf.is64 ? 6 : 14)) !== 0
        && elf.word(offset + (elf.is64 ? 8 : 4)) === address) return true;
    }
  }
  return hasTable ? false : undefined;
}

function tableString(elf, strings, offset) {
  const start = Number(strings.offset) + Number(offset);
  const end = Number(strings.offset + strings.size);
  if (start >= end || start >= elf.bytes.length) return '';
  let stop = start;
  const limit = Math.min(end, start + MAX_SYMBOL_NAME_BYTES);
  while (stop < limit && elf.bytes[stop] !== 0) stop++;
  return elf.bytes.toString('utf8', start, stop);
}

function symbolFacts(elf) {
  const entrySize = elf.is64 ? 24 : 16;
  const names = new Set();
  let importTotal = 0;
  let canary = null;
  let fortify = null;
  let hasTable = false;
  for (const section of elf.sections) {
    if (section.type !== SHT_SYMTAB && section.type !== SHT_DYNSYM) continue;
    const table = sectionTable(elf, section, entrySize);
    const strings = elf.sections[section.link];
    if (!table || strings?.type !== SHT_STRTAB || !fileRange(elf.bytes, strings.offset, strings.size)) continue;
    hasTable = true;
    for (let index = 0; index < table.count; index++) {
      const offset = table.offset + index * entrySize;
      const nameOffset = BigInt(elf.u32(offset));
      if (nameOffset >= strings.size) continue;
      const name = tableString(elf, strings, nameOffset);
      if (name === '') continue;
      if (name === '__stack_chk_fail' || name === '__stack_chk_fail_local' || name === '__stack_chk_guard') canary = true;
      const undefinedDynamicSymbol = section.type === SHT_DYNSYM
        && elf.u16(offset + (elf.is64 ? 6 : 14)) === SHN_UNDEF;
      if (undefinedDynamicSymbol && /^__[A-Za-z0-9_]+_chk$/u.test(name)) fortify = true;
      if (undefinedDynamicSymbol) {
        importTotal++;
        names.add(name);
      }
    }
  }
  const unique = [...names];
  return {
    canary: canary ?? (hasTable ? false : null),
    fortify: fortify ?? (hasTable ? false : null),
    importTotal,
    imports: unique.slice(0, MAX_IMPORT_NAMES),
    notable: unique.filter(name => NOTABLE_IMPORTS.has(name)).slice(0, MAX_NOTABLE_IMPORTS),
  };
}

function dynamicFacts(elf) {
  const section = elf.sections.find(item => item.type === SHT_DYNAMIC);
  const entrySize = elf.is64 ? 16 : 8;
  let table;
  let stringFileOffset;
  let stringSize = 0n;
  if (section !== undefined) {
    table = sectionTable(elf, section, entrySize);
    if (!table) return undefined;
    const strings = elf.sections[section.link];
    if (strings?.type === SHT_STRTAB && fileRange(elf.bytes, strings.offset, strings.size)) {
      stringFileOffset = strings.offset;
      stringSize = strings.size;
    }
  } else {
    const segment = elf.programs.find(item => item.type === PT_DYNAMIC);
    if (segment === undefined || segment.fileSize % BigInt(entrySize) !== 0n
      || !fileRange(elf.bytes, segment.fileOffset, segment.fileSize)) return undefined;
    const count = segment.fileSize / BigInt(entrySize);
    if (count > MAX_TABLE_ENTRIES) return undefined;
    table = { offset: Number(segment.fileOffset), count: Number(count) };
  }
  let flags = 0;
  let flags1 = 0;
  let bindNow = false;
  const needed = [];
  let stringAddress;
  let dynamicStringSize;
  let hasDynamicSymbols = false;
  for (let index = 0; index < table.count; index++) {
    const offset = table.offset + index * entrySize;
    const tag = elf.word(offset);
    const value = elf.word(offset + (elf.is64 ? 8 : 4));
    if (tag === DT_NULL) break;
    if (tag === DT_NEEDED) {
      if (needed.length < MAX_NEEDED && value < stringSize && stringFileOffset !== undefined) {
        const name = tableString(elf, { offset: stringFileOffset, size: stringSize }, value);
        if (name !== '') needed.push(name);
      }
    } else if (tag === DT_FLAGS) {
      flags = Number(value);
    } else if (tag === DT_FLAGS_1) {
      flags1 = Number(value);
    } else if (tag === DT_BIND_NOW) {
      bindNow = true;
    } else if (tag === DT_STRTAB) {
      stringAddress = value;
    } else if (tag === DT_STRSZ) {
      dynamicStringSize = value;
    } else if (tag === DT_SYMTAB) {
      hasDynamicSymbols = true;
    }
  }
  if (stringFileOffset === undefined && stringAddress !== undefined && dynamicStringSize !== undefined) {
    const mapped = mappedFileOffset(elf, stringAddress, dynamicStringSize, false);
    if (mapped !== undefined && fileRange(elf.bytes, mapped, dynamicStringSize)) {
      stringFileOffset = mapped;
      stringSize = dynamicStringSize;
      // Re-read DT_NEEDED after locating the dynamic string table.
      for (let index = 0; index < table.count && needed.length < MAX_NEEDED; index++) {
        const offset = table.offset + index * entrySize;
        if (elf.word(offset) === DT_NULL) break;
        if (elf.word(offset) !== DT_NEEDED) continue;
        const value = elf.word(offset + (elf.is64 ? 8 : 4));
        if (value < stringSize) {
          const name = tableString(elf, { offset: stringFileOffset, size: stringSize }, value);
          if (name) needed.push(name);
        }
      }
    }
  }
  return { flags, flags1, bindNow, needed, hasDynamicSymbols };
}

function gadgetFacts(elf) {
  if (elf.machine !== EM_X86_64 || (elf.type !== 2 && elf.type !== 3)) {
    return { status: 'unavailable', reason: 'gadget 字节扫描只覆盖 x86-64 的可执行文件和共享库。', patterns: [] };
  }
  const patterns = GADGET_PATTERNS.map(item => ({ name: item.name, count: 0, first_address: null }));
  const segments = elf.programs.filter(item => item.type === PT_LOAD && (item.flags & PF_X) !== 0 && item.fileSize > 0n);
  let scanned = 0;
  let truncated = false;
  for (const segment of segments) {
    if (scanned >= MAX_GADGET_SCAN_BYTES) break;
    const start = Number(segment.fileOffset);
    const size = Number(segment.fileSize);
    const available = Math.min(size, MAX_GADGET_SCAN_BYTES - scanned);
    if (available < size) truncated = true;
    const window = elf.bytes.subarray(start, start + available);
    for (let index = 0; index < patterns.length; index++) {
      const pattern = GADGET_PATTERNS[index].bytes;
      let found = window.indexOf(pattern);
      while (found !== -1) {
        patterns[index].count++;
        if (patterns[index].first_address === null) {
          patterns[index].first_address = hex(segment.address + BigInt(found));
        }
        found = window.indexOf(pattern, found + 1);
      }
    }
    scanned += available;
  }
  return { status: 'scanned', bytes_scanned: scanned, truncated, patterns };
}

function securityFacts(elf, dynamic = dynamicFacts(elf)) {
  const stack = elf.programs.find(item => item.type === PT_GNU_STACK);
  const relroSegment = elf.programs.some(item => item.type === PT_GNU_RELRO);
  const interpreter = elf.programs.some(item => item.type === PT_INTERP);
  let pie = null;
  let pieEvidence = '没有可判定的装载类型。';
  if (elf.type === 2) {
    pie = false;
    pieEvidence = 'ET_EXEC，按固定地址装载。';
  } else if (elf.type === 3) {
    if (interpreter) {
      pie = true;
      pieEvidence = 'ET_DYN 且带 PT_INTERP，按 PIE 处理。';
    } else if (dynamic !== undefined && (dynamic.flags1 & DF_1_PIE) !== 0) {
      pie = true;
      pieEvidence = 'ET_DYN 且 DT_FLAGS_1 带 DF_1_PIE。';
    } else {
      pieEvidence = 'ET_DYN 但无解释器和 DF_1_PIE，可能是共享库或静态 PIE。';
    }
  }
  let relro = 'none';
  let relroEvidence = '没有 PT_GNU_RELRO。';
  if (relroSegment) {
    relro = 'partial';
    relroEvidence = '有 PT_GNU_RELRO，未在动态段确认立即绑定。';
    if (dynamic !== undefined && (((dynamic.flags & DF_BIND_NOW) !== 0)
      || ((dynamic.flags1 & DF_1_NOW) !== 0) || dynamic.bindNow)) {
      relro = 'full';
      relroEvidence = 'PT_GNU_RELRO 且动态段带 DT_BIND_NOW/DF_1_NOW。';
    }
  }
  const symbols = symbolFacts(elf);
  return {
    nx: {
      enabled: stack === undefined ? null : (stack.flags & PF_X) === 0,
      evidence: stack === undefined ? '缺少 PT_GNU_STACK，无法确认栈权限。'
        : (stack.flags & PF_X) === 0 ? 'PT_GNU_STACK 未设置 PF_X，栈不可执行。'
          : 'PT_GNU_STACK 设置 PF_X，栈可执行。',
    },
    pie: { enabled: pie, evidence: pieEvidence },
    relro: { status: relro, evidence: relroEvidence },
    canary: symbols.canary,
    fortify: symbols.fortify,
    imports: {
      total: symbols.importTotal,
      names: symbols.imports,
      truncated: symbols.importTotal > symbols.imports.length,
      notable: symbols.notable,
    },
    needed: dynamic?.needed ?? [],
    gadgets: gadgetFacts(elf),
  };
}

function signedHex(value) {
  return value < 0n ? `-${hex(-value)}` : hex(value);
}

function readDynamicSymbols(elf, section) {
  if (section?.type !== SHT_DYNSYM || !elf.is64) return undefined;
  const table = sectionTable(elf, section, 24);
  const strings = elf.sections[section.link];
  if (!table || strings?.type !== SHT_STRTAB || !fileRange(elf.bytes, strings.offset, strings.size)) {
    return undefined;
  }
  const entries = [];
  for (let index = 0; index < table.count; index++) {
    const offset = table.offset + index * 24;
    const nameOffset = BigInt(elf.u32(offset));
    const info = elf.bytes[offset + 4];
    entries.push({
      index,
      name: nameOffset < strings.size ? tableString(elf, strings, nameOffset) : '',
      info,
      type: info & 0xf,
      bind: info >> 4,
      shndx: elf.u16(offset + 6),
      value: elf.word(offset + 8),
      size: elf.word(offset + 16),
    });
  }
  return { entries, strings };
}

function pwnFacts(elf) {
  if (!elf.is64 || !elf.littleEndian || elf.machine !== EM_X86_64
    || (elf.type !== 2 && elf.type !== 3)) {
    return {
      status: 'unavailable',
      reason: 'PLT/GOT 与 libc 偏移解析只覆盖小端 x86-64 的可执行文件和共享库。',
    };
  }
  if (elf.sections.length === 0) {
    return { status: 'unavailable', reason: '缺少节头，无法解析 PLT/GOT、导出符号与 /bin/sh。' };
  }
  const relocations = [];
  const jumpSlots = new Map();
  let relocationTotal = 0;
  for (const section of elf.sections) {
    if (section.type !== SHT_RELA) continue;
    const symbols = readDynamicSymbols(elf, elf.sections[section.link]);
    const table = sectionTable(elf, section, 24);
    if (!symbols || !table) continue;
    for (let index = 0; index < table.count; index++) {
      const offset = table.offset + index * 24;
      const info = elf.word(offset + 8);
      const type = info & 0xffffffffn;
      const symbolIndex = Number(info >> 32n);
      if (type !== R_X86_64_64 && type !== R_X86_64_COPY
        && type !== R_X86_64_GLOB_DAT && type !== R_X86_64_JUMP_SLOT) continue;
      const symbol = symbols.entries[symbolIndex];
      if (!symbol || symbol.name === '') continue;
      const slot = elf.word(offset);
      relocationTotal++;
      if (type === R_X86_64_JUMP_SLOT) jumpSlots.set(slot, symbol.name);
      if (relocations.length < MAX_PWN_RELOCATIONS) {
        relocations.push({
          type: RELOCATION_NAMES.get(type),
          symbol: symbol.name,
          slot: hex(slot),
          addend: signedHex(BigInt.asIntN(64, elf.word(offset + 16))),
        });
      }
    }
  }

  const pltByGot = new Map();
  let pltTotal = 0;
  let sawPlt = false;
  for (const section of elf.sections) {
    if (typeof section.name !== 'string' || !section.name.startsWith('.plt')) continue;
    if ((section.flags & 4n) === 0n || section.size < 6n
      || !fileRange(elf.bytes, section.offset, section.size)) continue;
    sawPlt = true;
    const start = Number(section.offset);
    const end = start + Number(section.size);
    for (let index = start; index + 6 <= end; index++) {
      if (elf.bytes[index] !== 0xff || elf.bytes[index + 1] !== 0x25) continue;
      const jump = section.address + BigInt(index - start);
      const target = jump + 6n + BigInt(elf.bytes.readInt32LE(index + 2));
      const symbol = jumpSlots.get(target);
      if (symbol === undefined) continue;
      pltTotal++;
      let instruction = index;
      if (index > start && elf.bytes[index - 1] === 0xf2) instruction = index - 1;
      let stubIndex = instruction;
      if (instruction - start >= 4 && elf.bytes.subarray(instruction - 4, instruction).equals(ENDBR64)) {
        stubIndex = instruction - 4;
      }
      const stub = section.address + BigInt(stubIndex - start);
      const fileOffset = mappedFileOffset(elf, stub, 1n);
      const candidate = {
        symbol,
        got: hex(target),
        stub: hex(stub),
        file_offset: fileOffset === undefined ? null : hex(fileOffset),
        endbr: stubIndex !== instruction,
        _got: target,
        _stub: stub,
      };
      const previous = pltByGot.get(target);
      if (previous === undefined || (candidate.endbr && !previous.endbr)) {
        pltByGot.set(target, candidate);
      }
    }
  }
  const plt = [...pltByGot.values()]
    .sort((left, right) => left._stub < right._stub ? -1 : left._stub > right._stub ? 1 : 0)
    .slice(0, MAX_PWN_PLT)
    .map(({ _got, _stub, endbr, ...entry }) => entry);
  const pltTruncated = pltByGot.size > plt.length;

  let exportTotal = 0;
  const notable = [];
  const seen = new Set();
  for (const section of elf.sections) {
    if (section.type !== SHT_DYNSYM) continue;
    const symbols = readDynamicSymbols(elf, section);
    if (!symbols) continue;
    for (const symbol of symbols.entries) {
      if (symbol.name === '' || symbol.shndx === 0) continue;
      if (symbol.type !== 1 && symbol.type !== 2) continue;
      exportTotal++;
      if (!PWN_EXPORTS.has(symbol.name) || seen.has(symbol.name)) continue;
      seen.add(symbol.name);
      notable.push({
        name: symbol.name,
        address: hex(symbol.value),
        size: Number(symbol.size),
      });
    }
  }
  notable.sort((left, right) => left.name.localeCompare(right.name));
  const exportTruncated = notable.length > MAX_PWN_EXPORTS;

  let binSh = null;
  for (const section of elf.sections) {
    if ((section.flags & 4n) !== 0n || section.type === 8
      || section.size < BigInt(BIN_SH.length) || !fileRange(elf.bytes, section.offset, section.size)) continue;
    const start = Number(section.offset);
    const found = elf.bytes.subarray(start, start + Number(section.size)).indexOf(BIN_SH);
    if (found === -1) continue;
    binSh = {
      address: hex(section.address + BigInt(found)),
      file_offset: hex(section.offset + BigInt(found)),
      section: section.name ?? '',
    };
    break;
  }

  return {
    status: 'ok',
    relocations: {
      total: relocationTotal,
      truncated: relocationTotal > relocations.length,
      entries: relocations,
    },
    plt: {
      status: sawPlt && pltTotal > 0 ? 'ok' : 'unavailable',
      ...(sawPlt && pltTotal > 0 ? {} : { reason: sawPlt ? '没有匹配到可解析的 PLT 跳转。' : '没有找到 .plt 节。' }),
      total: pltTotal,
      truncated: pltTruncated,
      entries: plt,
    },
    exports: {
      total: exportTotal,
      truncated: exportTruncated,
      notable: notable.slice(0, MAX_PWN_EXPORTS),
    },
    strings: { bin_sh: binSh },
  };
}


function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function inspectElf(bytes, paging) {
  const elf = parseElf(bytes);
  const dynamic = dynamicFacts(elf);
  const entryOffset = mappedFileOffset(elf, elf.entry, 1n);
  const hasInterpreter = elf.programs.some(segment => segment.type === PT_INTERP);
  const facts = {
    format: elf.is64 ? 'ELF64' : 'ELF32',
    byte_order: elf.littleEndian ? 'little-endian' : 'big-endian',
    machine: ({ 3: 'x86', 40: 'ARM', 62: 'x86-64', 183: 'AArch64', 243: 'RISC-V' })[elf.machine] ?? `EM_${elf.machine}`,
    type: ({ 1: 'ET_REL', 2: 'ET_EXEC', 3: 'ET_DYN', 4: 'ET_CORE' })[elf.type] ?? `ET_${elf.type}`,
    size: bytes.length,
    sha256: digest(bytes),
    entry: hex(elf.entry),
    entry_file_offset: entryOffset === undefined ? null : hex(entryOffset),
    program_headers: elf.programs.length,
    section_headers: elf.sections.length,
    has_interpreter: hasInterpreter,
    has_static_symbols: elf.sections.some(section => section.type === SHT_SYMTAB),
    has_dynamic_symbols: elf.sections.some(section => section.type === SHT_DYNSYM) || dynamic?.hasDynamicSymbols === true,
    security: securityFacts(elf, dynamic),
    pwn: pwnFacts(elf),
    startup: startupEvidence(elf),
  };
  if (paging !== undefined) {
    const { offset, limit } = paging;
    const total = elf.programs.length;
    facts.layout = {
      table: 'program_headers',
      total,
      offset,
      rows: elf.programs.slice(offset, offset + limit).map(segment => ({
        type_id: segment.type,
        executable: (segment.flags & PF_X) !== 0,
        address: hex(segment.address),
        file_offset: hex(segment.fileOffset),
        file_size: hex(segment.fileSize),
        memory_size: hex(segment.memorySize),
      })),
      next_offset: offset + limit < total ? offset + limit : null,
    };
  }
  return facts;
}

function compare(expected, actual) {
  return { expected, actual: actual ?? null, status: actual === undefined ? 'unavailable' : expected === actual ? 'match' : 'different' };
}

export function verifyElf(bytes, claims) {
  const elf = parseElf(bytes);
  const checks = {};
  const sha256 = digest(bytes);
  if (claims.entry !== undefined) checks.entry = compare(hex(claims.entry), hex(elf.entry));
  if (claims.main !== undefined) {
    const startup = startupEvidence(elf);
    checks.main = { ...compare(hex(claims.main), startup.main), evidence: startup };
  }
  if (claims.sha256 !== undefined) checks.sha256 = compare(claims.sha256, sha256);
  if (claims.symbol_label !== undefined) {
    const { base, displacement, address } = claims.symbol_label;
    const computed = base + displacement;
    const basePresent = definedDynamicAddress(elf, base);
    checks.symbol_label = {
      actual_address: computed < 0n ? `-${hex(-computed)}` : hex(computed),
      expected_address: hex(address),
      arithmetic_matches: computed === address,
      base_in_dynamic_symbols: basePresent ?? null,
      status: computed !== address || basePresent === false ? 'different' : basePresent === undefined ? 'unavailable' : 'match',
      note: '符号基址和偏移吻合只说明标注可解释，不能证明目标地址有同名符号。',
    };
  }
  return { sha256, checks };
}
