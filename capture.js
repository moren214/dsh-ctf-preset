import { checkRange, inPage, page } from './attachment-layout.js';
import { createPcapngStatistics } from './pcapng-statistics.js';

const PCAP_MAGICS = new Map([
  [0xa1b2c3d4, { littleEndian: false, timestampUnit: 'microseconds' }],
  [0xd4c3b2a1, { littleEndian: true, timestampUnit: 'microseconds' }],
  [0xa1b23c4d, { littleEndian: false, timestampUnit: 'nanoseconds' }],
  [0x4d3cb2a1, { littleEndian: true, timestampUnit: 'nanoseconds' }],
]);
const SECTION_HEADER = 0x0a0d0d0a;
const INTERFACE_DESCRIPTION = 1;
const PACKET_BLOCK = 2;
const SIMPLE_PACKET = 3;
const ENHANCED_PACKET = 6;
const BLOCK_NAMES = {
  [SECTION_HEADER]: 'section_header',
  [INTERFACE_DESCRIPTION]: 'interface_description',
  [PACKET_BLOCK]: 'packet',
  [SIMPLE_PACKET]: 'simple_packet',
  [ENHANCED_PACKET]: 'enhanced_packet',
};

function reader(bytes, littleEndian) {
  return {
    byteOrder: littleEndian ? 'little' : 'big',
    u16: (littleEndian ? bytes.readUInt16LE : bytes.readUInt16BE).bind(bytes),
    u32: (littleEndian ? bytes.readUInt32LE : bytes.readUInt32BE).bind(bytes),
    i64: (littleEndian ? bytes.readBigInt64LE : bytes.readBigInt64BE).bind(bytes),
  };
}

function inspectPcap(bytes, paging, { littleEndian, timestampUnit }) {
  const format = 'PCAP';
  checkRange(bytes.length, 0, 24, 'PCAP 文件头');
  const { byteOrder, u16, u32 } = reader(bytes, littleEndian);
  const major = u16(4);
  const minor = u16(6);
  const version = major + '.' + minor;
  if (major !== 2 || minor !== 4) {
    return { format, status: 'unsupported', version, reason: '当前检查覆盖 PCAP 2.4。' };
  }

  const snaplen = u32(16);
  if (snaplen === 0) throw new Error('附件结构无效：PCAP 快照长度为 0。');
  const rows = [];
  const issues = [];
  let cursor = 24;
  let total = 0;
  let packets = 0;
  let malformedPackets = 0;
  let complete = true;
  while (cursor < bytes.length) {
    if (bytes.length - cursor < 16) {
      issues.push({ code: 'truncated_record', offset: cursor, detail: 'PCAP 包记录头不完整。' });
      complete = false;
      break;
    }
    const captured = u32(cursor + 8);
    total++;
    if (captured > bytes.length - cursor - 16) {
      issues.push({ code: 'truncated_record', offset: cursor, detail: 'PCAP 包记录数据不完整。' });
      complete = false;
      break;
    }
    const original = u32(cursor + 12);
    const invalid = captured > snaplen || captured > original;
    if (invalid) {
      malformedPackets++;
      issues.push({ code: 'invalid_packet', offset: cursor,
        detail: captured > snaplen ? 'PCAP 记录中的捕获长度超过快照长度。' : 'PCAP 记录的原始长度小于捕获长度。' });
    } else {
      packets++;
    }
    if (inPage(total, paging)) {
      rows.push({
        record_offset: cursor,
        timestamp_seconds: u32(cursor),
        timestamp_fraction: u32(cursor + 4),
        captured_size: captured,
        original_size: original,
      });
    }
    cursor += 16 + captured;
  }
  return {
    format,
    status: issues.length ? 'partial' : 'ok',
    complete,
    packet_count: packets,
    packet_records: total,
    malformed_packets: malformedPackets,
    issues,
    version,
    byte_order: byteOrder,
    timestamp_unit: timestampUnit,
    link_type: u32(20) & 0xffff,
    snapshot_length: snaplen,
    file_packet_count: total,
    layout: page('packets', total, rows, paging.offset),
  };
}

function sectionReader(bytes, cursor) {
  checkRange(bytes.length, cursor, 28, 'PCAPNG 节头');
  const magic = bytes.readUInt32BE(cursor + 8);
  if (magic !== 0x1a2b3c4d && magic !== 0x4d3c2b1a) {
    throw new Error('附件结构无效：PCAPNG 节头的字节序标记不匹配。');
  }
  return reader(bytes, magic === 0x4d3c2b1a);
}

function nextSectionEnd(bytes, size, following) {
  if (size === -1n) return null;
  if (size < 0n || size % 4n !== 0n || size > BigInt(bytes.length - following)) {
    throw new Error('附件结构无效：PCAPNG 声明的节长度无效。');
  }
  return following + Number(size);
}

export function pcapngPacketBlock(type, cursor, size, read, interfaces) {
  if (type !== ENHANCED_PACKET && type !== PACKET_BLOCK && type !== SIMPLE_PACKET) return undefined;
  const simple = type === SIMPLE_PACKET;
  const overhead = simple ? 16 : 32;
  checkRange(cursor + size, cursor, overhead, 'PCAPNG 包记录块');
  const interfaceId = simple ? 0 : type === PACKET_BLOCK ? read.u16(cursor + 8) : read.u32(cursor + 8);
  const info = interfaces[interfaceId];
  if (info === undefined) throw new Error('附件结构无效：PCAPNG 包记录引用了当前节中不存在的接口。');
  const snaplen = info.snapshot_length;
  const original = read.u32(cursor + (simple ? 8 : 24));
  const captured = simple ? Math.min(original, snaplen || original) : read.u32(cursor + 20);
  const padded = Math.ceil(captured / 4) * 4;
  const available = size - overhead;
  if (captured > original || (snaplen !== 0 && captured > snaplen) || padded > available || (simple && padded !== available)) {
    throw new Error('附件结构无效：PCAPNG 包记录中的捕获长度无效。');
  }
  return {
    interfaceId, info, original, captured, simple,
    dataOffset: cursor + (simple ? 12 : 28), name: BLOCK_NAMES[type],
  };
}

function inspectPcapng(bytes, paging, query) {
  const format = 'PCAPNG';
  const rows = [];
  const issues = [];
  const statistics = query === undefined ? undefined : createPcapngStatistics(bytes, paging, query);
  let cursor = 0;
  let total = 0;
  let sections = 0;
  let interfaceCount = 0;
  let packets = 0;
  let sectionEnd = null;
  let interfaces = [];
  let read;
  let malformedPackets = 0;
  while (cursor < bytes.length) {
    checkRange(bytes.length, cursor, 12, 'PCAPNG 块头和尾');
    const startsSection = bytes.readUInt32BE(cursor) === SECTION_HEADER;
    if (startsSection) {
      if (sectionEnd !== null && cursor !== sectionEnd) {
        throw new Error('附件结构无效：PCAPNG 节头出现在声明的节边界以外。');
      }
      read = sectionReader(bytes, cursor);
    }
    const { byteOrder, u16, u32, i64 } = read;
    const type = u32(cursor);
    const size = u32(cursor + 4);
    if (size < 12 || size % 4 !== 0) throw new Error('附件结构无效：PCAPNG 块长度或对齐不正确。');
    checkRange(startsSection ? bytes.length : sectionEnd ?? bytes.length, cursor, size, 'PCAPNG 块');
    const next = cursor + size;
    if (u32(next - 4) !== size) throw new Error('附件结构无效：PCAPNG 块头与块尾长度不一致。');
    const row = statistics === undefined && inPage(total, paging) ? {
      type: BLOCK_NAMES[type] ?? 'unknown', type_id: type, file_offset: cursor, block_size: size,
    } : null;

    if (startsSection) {
      checkRange(next, cursor, 28, 'PCAPNG 节头');
      const major = u16(cursor + 12);
      const minor = u16(cursor + 14);
      const version = major + '.' + minor;
      if (major !== 1 || (minor !== 0 && minor !== 2)) {
        return { format, status: 'unsupported', version, reason: '当前检查覆盖 PCAPNG 1.0 及兼容的 1.2 节头。' };
      }
      sectionEnd = nextSectionEnd(bytes, i64(cursor + 16), next);
      interfaces = [];
      sections++;
      statistics?.startSection();
      if (row) Object.assign(row, { version, byte_order: byteOrder });
    } else if (type === INTERFACE_DESCRIPTION) {
      checkRange(next, cursor, 20, 'PCAPNG 接口描述块');
      const snaplen = u32(cursor + 12);
      const info = { interface_id: interfaces.length, link_type: u16(cursor + 8), snapshot_length: snaplen };
      if (row) Object.assign(row, info);
      statistics?.addInterface({ ...info, section_index: sections - 1, file_offset: cursor });
      interfaces.push({ ...info, file_offset: cursor });
      interfaceCount++;
    } else if (type === ENHANCED_PACKET || type === PACKET_BLOCK || type === SIMPLE_PACKET) {
      try {
        const { simple, interfaceId, info, original, captured } = pcapngPacketBlock(type, cursor, size, read, interfaces);
        if (row) Object.assign(row, { interface_id: interfaceId, captured_size: captured, original_size: original });
        statistics?.addPacket({
          section_index: sections - 1, interface_id: interfaceId, file_offset: cursor,
          type: type === PACKET_BLOCK ? 'legacy_packet' : BLOCK_NAMES[type], type_id: type,
          captured_size: captured, original_size: original,
        }, info.file_offset, read, simple);
        packets++;
      } catch (error) {
        malformedPackets++;
        issues.push({ code: 'invalid_packet', offset: cursor, detail: error.message });
      }
    }
    if (row) {
      row.section_index = sections - 1;
      rows.push(row);
    }
    cursor = next;
    total++;
  }
  const filtered = statistics?.report();
  return {
    format,
    status: issues.length ? 'partial' : 'ok',
    complete: true,
    packet_count: packets,
    packet_records: packets + malformedPackets,
    malformed_packets: malformedPackets,
    issues,
    section_count: sections,
    interface_count: interfaceCount,
    packet_count: filtered?.statistics.packet_count ?? packets,
    ...(filtered ? { file_packet_count: packets, ...filtered } : { layout: page('blocks', total, rows, paging.offset) }),
  };
}

export function inspectCapture(bytes, paging, pcapngQuery) {
  const magic = bytes.length >= 4 ? bytes.readUInt32BE(0) : undefined;
  if (magic === SECTION_HEADER) return inspectPcapng(bytes, paging, pcapngQuery);
  if (pcapngQuery !== undefined) throw new Error('pcapng 查询须用于 PCAPNG 原件。');
  const pcap = PCAP_MAGICS.get(magic);
  if (pcap) return inspectPcap(bytes, paging, pcap);
  return undefined;
}
