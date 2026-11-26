import { checkRange, inPage, page } from './attachment-layout.js';
import { ToolError } from './tool-errors.js';

const IF_TSRESOL = 9;
const IF_TSOFFSET = 14;
const UTC_TIMESTAMP = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,127}))?Z$/u;

export const PCAPNG_QUERY_SCHEMA = {
  type: 'object',
  description: 'PCAPNG 统计/筛选查询。',
  additionalProperties: false,
  properties: {
    view: { type: 'string', enum: ['interfaces', 'packets'] },
    section_index: { type: 'integer', minimum: 0 },
    interface_id: { type: 'integer', minimum: 0 },
    start_utc: { type: 'string' },
    end_utc: { type: 'string' },
    end_inclusive: { type: 'boolean' },
  },
};

function parseBoundary(value, field) {
  if (value === undefined) return undefined;
  const match = typeof value === 'string' && UTC_TIMESTAMP.exec(value);
  const error = () => new ToolError('unsupported', `${field} 须是有效的 UTC 时间，例如 2026-11-21T00:00:00.25Z。`);
  if (!match) throw error();
  const [, whole, fraction = ''] = match;
  const date = new Date(whole + 'Z');
  if (Number.isNaN(date.valueOf()) || date.toISOString().slice(0, 19) !== whole) throw error();
  const scale = 10n ** BigInt(fraction.length);
  return { text: value, scale, value: BigInt(date.valueOf() / 1000) * scale + BigInt(fraction || '0') };
}

export function parsePcapngQuery(query) {
  if (query === undefined) return undefined;
  if (query === null || typeof query !== 'object' || Array.isArray(query)
    || Object.keys(query).some(key => !Object.hasOwn(PCAPNG_QUERY_SCHEMA.properties, key))) {
    throw new ToolError('unsupported', 'pcapng 须为有效的接口或时间窗口查询。');
  }
  const { view = 'interfaces', section_index: section, interface_id: id } = query;
  if (view !== 'interfaces' && view !== 'packets') throw new ToolError('unsupported', 'pcapng.view 须为 interfaces 或 packets。');
  if ([section, id].some(value => value !== undefined && (!Number.isSafeInteger(value) || value < 0))) {
    throw new ToolError('unsupported', 'section_index 和 interface_id 须为非负整数。');
  }
  const start = parseBoundary(query.start_utc, 'start_utc');
  const end = parseBoundary(query.end_utc, 'end_utc');
  const endInclusive = query.end_inclusive ?? false;
  if (typeof endInclusive !== 'boolean' || (endInclusive && !end)) throw new ToolError('unsupported', 'end_inclusive 须是布尔值，开启时需要 end_utc。');
  if (start && end) {
    const difference = start.value * end.scale - end.value * start.scale;
    if (difference > 0n || (difference === 0n && !endInclusive)) throw new ToolError('unsupported', 'PCAPNG 时间窗口的起点、终点顺序不正确。');
  }
  return { view, section, id, start, end, endInclusive };
}

function boundaryTicks(boundary, ticksPerSecond, offsetSeconds, inclusiveEnd = false) {
  if (boundary === undefined) return undefined;
  // Both comparisons use the ceiling: ticks >= start and ticks < end.
  const local = (boundary.value - offsetSeconds * boundary.scale) * ticksPerSecond;
  const quotient = local / boundary.scale;
  const remainder = local % boundary.scale;
  if (inclusiveEnd) return remainder < 0n ? quotient : quotient + 1n;
  return remainder > 0n ? quotient + 1n : quotient;
}

export function interfaceClock(bytes, { u16, u32, i64 }, offset, query = {}) {
  const end = offset + u32(offset + 4) - 4;
  let resolution;
  let offsetSeconds;
  for (let cursor = offset + 16; cursor < end;) {
    const optionLabel = `PCAPNG 接口选项（文件偏移 ${cursor}）`;
    checkRange(end, cursor, 4, optionLabel);
    const code = u16(cursor);
    const length = u16(cursor + 2);
    const start = cursor + 4;
    const padded = Math.ceil(length / 4) * 4;
    checkRange(end, start, padded, optionLabel);
    if (code === 0) {
      if (length !== 0) throw new ToolError('unsupported', `${optionLabel}的结束标记长度无效。`);
      break;
    }
    if (code === IF_TSRESOL) {
      if (length !== 1 || resolution !== undefined) throw new ToolError('unsupported', `${optionLabel}的 if_tsresol 长度无效或重复。`);
      resolution = bytes[start];
    } else if (code === IF_TSOFFSET) {
      if (length !== 8 || offsetSeconds !== undefined) throw new ToolError('unsupported', `${optionLabel}的 if_tsoffset 长度无效或重复。`);
      offsetSeconds = i64(start);
    }
    cursor = start + padded;
  }
  resolution ??= 6;
  offsetSeconds ??= 0n;
  const exponent = resolution & 0x7f;
  const binary = (resolution & 0x80) !== 0;
  const ticksPerSecond = (binary ? 2n : 10n) ** BigInt(exponent);
  return {
    offsetSeconds, exponent, ticksPerSecond, decimalMultiplier: binary ? 5n ** BigInt(exponent) : 1n,
    start: boundaryTicks(query.start, ticksPerSecond, offsetSeconds),
    end: boundaryTicks(query.end, ticksPerSecond, offsetSeconds, query.endInclusive),
  };
}

export function formatTimestamp(ticks, clock) {
  if (ticks === undefined) return { timestamp_utc: null };
  const { ticksPerSecond, offsetSeconds, exponent, decimalMultiplier } = clock;
  const decimals = remainder => remainder === 0n ? ''
    : '.' + (remainder * decimalMultiplier).toString().padStart(exponent, '0').replace(/0+$/u, '');
  const seconds = offsetSeconds + ticks / ticksPerSecond;
  const date = new Date(Number(seconds) * 1000);
  if (!Number.isNaN(date.valueOf())) {
    return { timestamp_utc: date.toISOString().replace(/\.000Z$/u, decimals(ticks % ticksPerSecond) + 'Z') };
  }
  const epochTicks = offsetSeconds * ticksPerSecond + ticks;
  const magnitude = epochTicks < 0n ? -epochTicks : epochTicks;
  const sign = epochTicks < 0n ? '-' : '';
  return { timestamp_utc: null, unix_time_seconds: sign + magnitude / ticksPerSecond + decimals(magnitude % ticksPerSecond) };
}

export function pcapngPacketTicks(read, offset) {
  return (BigInt(read.u32(offset + 12)) << 32n) | BigInt(read.u32(offset + 16));
}

export function createPcapngStatistics(bytes, paging, query) {
  const byOffset = new Map();
  const clocks = new Map();
  const packetRows = [];
  const limitingTime = query.start !== undefined || query.end !== undefined;
  let defaultClock;
  let selectedInterfaces = 0;
  let packetCount = 0;
  let capturedBytes = 0;
  let untimed = 0;

  function selected({ section_index, interface_id }) {
    return (query.section === undefined || query.section === section_index)
      && (query.id === undefined || query.id === interface_id);
  }

  function getClock(read, offset) {
    if (read.u32(offset + 4) === 20) {
      defaultClock ??= interfaceClock(bytes, read, offset, query);
      return defaultClock;
    }
    const cached = clocks.get(offset);
    if (cached !== undefined) return cached;
    const clock = interfaceClock(bytes, read, offset, query);
    clocks.set(offset, clock);
    return clock;
  }

  function addInterface(info) {
    if (!selected(info)) return;
    if (query.view === 'interfaces' && inPage(selectedInterfaces, paging)) {
      byOffset.set(info.file_offset, { row: { ...info, packet_count: 0, captured_bytes: 0, packets_without_timestamp: 0 } });
    }
    selectedInterfaces++;
  }

  function addPacket(info, interfaceOffset, read, simple) {
    if (!selected(info)) return;
    const group = byOffset.get(interfaceOffset);
    let ticks;
    let clock;
    if (simple) {
      untimed++;
      if (group) group.row.packets_without_timestamp++;
      if (limitingTime) return;
    } else {
      clock = getClock(read, interfaceOffset);
      ticks = pcapngPacketTicks(read, info.file_offset);
      if ((clock.start !== undefined && ticks < clock.start) || (clock.end !== undefined && ticks >= clock.end)) return;
    }

    if (group) {
      group.row.packet_count++;
      group.row.captured_bytes += info.captured_size;
      if (ticks !== undefined) {
        group.clock = clock;
        if (!group.earliest || ticks < group.earliest.ticks) group.earliest = { ticks, file_offset: info.file_offset };
        if (!group.latest || ticks > group.latest.ticks) group.latest = { ticks, file_offset: info.file_offset };
      }
    }
    if (query.view === 'packets' && inPage(packetCount, paging)) {
      packetRows.push({ ...info, ...formatTimestamp(ticks, clock) });
    }
    packetCount++;
    capturedBytes += info.captured_size;
  }

  function report() {
    const interfaces = [...byOffset.values()].map(({ row, clock, earliest, latest }) => ({
      ...row,
      excluded_untimed_packets: limitingTime ? row.packets_without_timestamp : 0,
      earliest_packet: earliest ? { file_offset: earliest.file_offset, ...formatTimestamp(earliest.ticks, clock) } : null,
      latest_packet: latest ? { file_offset: latest.file_offset, ...formatTimestamp(latest.ticks, clock) } : null,
    }));
    const interfaceView = query.view === 'interfaces';
    return {
      statistics: {
        count_scope: limitingTime || query.section !== undefined || query.id !== undefined ? 'filtered_records' : 'all_records',
        time_window: { start_utc: query.start?.text ?? null, end_utc: query.end?.text ?? null, end_inclusive: query.endInclusive },
        interface_count: selectedInterfaces, packet_count: packetCount,
        captured_bytes: capturedBytes, packets_without_timestamp: untimed,
        excluded_untimed_packets: limitingTime ? untimed : 0,
      },
      layout: page(query.view, interfaceView ? selectedInterfaces : packetCount, interfaceView ? interfaces : packetRows, paging.offset),
    };
  }

  return { startSection: () => clocks.clear(), addInterface, addPacket, report };
}
