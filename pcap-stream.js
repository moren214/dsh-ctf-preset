import { createHash } from 'node:crypto';
import { open, readFile, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { inspectCapture as inspectCaptureLayout, pcapngPacketBlock } from './capture.js';
import { interfaceClock, formatTimestamp, pcapngPacketTicks } from './pcapng-statistics.js';
import { ipv4Fragments } from './pcap-fragments.js';
import { dnsDetails } from './pcap-dns.js';
import { ToolError } from './tool-errors.js';

const MAX_FILE_SIZE = 64 * 1024 * 1024;
const MAX_STREAMED_FILE_SIZE = 1024 * 1024 * 1024;
const STREAM_BUFFER_SIZE = 1024 * 1024;
const MAX_PACKET_CAPTURE = 16 * 1024 * 1024;
const MAX_PCAPNG_BLOCK = MAX_PACKET_CAPTURE + 1024 * 1024;
const DEFAULT_MAX_FLOWS = 8;
const MAX_FLOWS_LIMIT = 16;
const DEFAULT_MAX_BYTES_PER_FLOW = 65536;
const MIN_BYTES_PER_FLOW = 1024;
const MAX_BYTES_PER_FLOW_LIMIT = 1024 * 1024;
const MAX_PENDING_SEGMENTS = 64;
const MAX_PENDING_BYTES = 16 * 1024 * 1024;
const MAX_PAYLOAD_TEXT = 4096;
const MAX_HEADERS = 32;
const MAX_HEADER_NAME = 128;
const MAX_HEADER_VALUE = 2048;
const MAX_BODY_PREVIEW = 1024;
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_PATH_LENGTH = 1024;
const MAX_START_LINE = 1024;
const MAX_TARGET = 2048;
const MAX_REASON = 512;
const MAX_DNS_SAMPLES = 24;
const TCP_SYN = 0x02;
const SECTION_HEADER = 0x0a0d0d0a;
const INTERFACE_DESCRIPTION = 1;
const LINK_NULL = 0;
const LINK_ETHERNET = 1;
const LINK_RAW_IP = 101;
const LINK_LINUX_SLL = 113;
const LINK_LINUX_SLL2 = 276;
const SUPPORTED_LINK_TYPES = new Set([LINK_NULL, LINK_ETHERNET, LINK_RAW_IP, LINK_LINUX_SLL, LINK_LINUX_SLL2]);
const PCAP_MAGICS = new Map([
  [0xa1b2c3d4, { littleEndian: false, timestampUnit: 'microseconds' }],
  [0xd4c3b2a1, { littleEndian: true, timestampUnit: 'microseconds' }],
  [0xa1b23c4d, { littleEndian: false, timestampUnit: 'nanoseconds' }],
  [0x4d3cb2a1, { littleEndian: true, timestampUnit: 'nanoseconds' }],
]);
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9a-z-]+$/u;
const REQUEST_LINE = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT) ([^ \r\n]+) (HTTP\/1\.[0-9])$/u;
const RESPONSE_LINE = /^(HTTP\/1\.[0-9]) ([0-9]{3})(?: ([^\r\n]*))?$/u;
const PRINTABLE = new Uint8Array(256);
for (const byte of [0x09, 0x0a, 0x0d]) PRINTABLE[byte] = 1;
for (let byte = 0x20; byte <= 0x7e; byte += 1) PRINTABLE[byte] = 1;

export const PCAP_STREAM_PROPERTIES = {
  file_path: { type: 'string', description: '相对工作区 PCAP/PCAPNG 路径。' },
  max_flows: { type: 'integer', minimum: 1, maximum: MAX_FLOWS_LIMIT },
  max_bytes_per_flow: { type: 'integer', minimum: MIN_BYTES_PER_FLOW, maximum: MAX_BYTES_PER_FLOW_LIMIT },
  include_hex: { type: 'boolean' },
  filter: {
    type: 'object', additionalProperties: false,
    description: '按协议、IP/端口与 UTC 时间筛选。',
    properties: {
      protocol: { type: 'string', enum: ['tcp', 'udp', 'dns'] },
      src_ip: { type: 'string', maxLength: 15 }, dst_ip: { type: 'string', maxLength: 15 },
      src_port: { type: 'integer', minimum: 1, maximum: 65535 }, dst_port: { type: 'integer', minimum: 1, maximum: 65535 },
      start_utc: { type: 'string', maxLength: 40 },
      end_utc: { type: 'string', maxLength: 40 },
    },
  },
};

function makeAbortError() {
  const error = new ToolError('abort', '操作已取消。');
  error.name = 'AbortError';
  return error;
}

function throwIfAborted(signal) {
  if (signal !== undefined && signal.aborted) throw makeAbortError();
}

function parseOptions(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new ToolError('unsupported', 'options 必须是对象。');
  }
  for (const key of Object.keys(options)) {
    if (key !== 'signal' && key !== 'cwd') throw new ToolError('unsupported', `options 不支持 ${key}。`);
  }
  const { signal } = options;
  if (signal !== undefined && (signal === null || typeof signal !== 'object'
    || typeof signal.aborted !== 'boolean')) {
    throw new ToolError('unsupported', 'options.signal 必须是 AbortSignal。');
  }
  const cwd = options.cwd === undefined ? process.cwd() : options.cwd;
  if (typeof cwd !== 'string' || cwd.trim() === '') throw new ToolError('unsupported', 'options.cwd 必须是非空路径字符串。');
  return { signal, cwd: path.resolve(cwd) };
}

function parseArguments(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new ToolError('unsupported', 'pcap_stream 参数必须是 JSON 对象。');
  }
  for (const key of Object.keys(input)) {
    if (!Object.hasOwn(PCAP_STREAM_PROPERTIES, key)) throw new ToolError('unsupported', `pcap_stream 不支持参数 ${key}。`);
  }
  const maxFlows = input.max_flows === undefined ? DEFAULT_MAX_FLOWS : input.max_flows;
  if (!Number.isInteger(maxFlows) || maxFlows < 1 || maxFlows > MAX_FLOWS_LIMIT) {
    throw new ToolError('unsupported', `max_flows 必须是 1 至 ${MAX_FLOWS_LIMIT} 的整数。`);
  }
  const maxBytes = input.max_bytes_per_flow === undefined
    ? DEFAULT_MAX_BYTES_PER_FLOW
    : input.max_bytes_per_flow;
  if (!Number.isInteger(maxBytes) || maxBytes < MIN_BYTES_PER_FLOW || maxBytes > MAX_BYTES_PER_FLOW_LIMIT) {
    throw new ToolError('unsupported', `max_bytes_per_flow 必须是 ${MIN_BYTES_PER_FLOW} 至 ${MAX_BYTES_PER_FLOW_LIMIT} 的整数。`);
  }
  const includeHex = input.include_hex === undefined ? false : input.include_hex;
  if (typeof includeHex !== 'boolean') throw new ToolError('unsupported', 'include_hex 必须是布尔值。');
  const filter = input.filter;
  if (filter !== undefined && (filter === null || typeof filter !== 'object' || Array.isArray(filter)
    || Object.keys(filter).some(key => !['protocol', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'start_utc', 'end_utc'].includes(key)))) {
    throw new ToolError('unsupported', 'filter 必须是包含已声明字段的对象。');
  }
  const normalizeIp = (value, field) => {
    if (value === undefined) return undefined;
    const pieces = typeof value === 'string' ? value.split('.') : [];
    if (pieces.length !== 4 || pieces.some(piece => !/^\d{1,3}$/u.test(piece) || Number(piece) > 255)) {
      throw new ToolError('unsupported', `filter.${field} 必须是 IPv4 地址。`);
    }
    return pieces.map(Number).join('.');
  };
  const parseTime = (value, field) => {
    if (value === undefined) return undefined;
    if (typeof value !== 'string' || value.length > 40
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value)) {
      throw new ToolError('unsupported', `filter.${field} 须为 UTC ISO 8601 时间并以 Z 结尾。`);
    }
    const time = Date.parse(value);
    const whole = value.slice(0, 19);
    if (!Number.isFinite(time) || new Date(value).toISOString().slice(0, 19) !== whole) throw new ToolError('unsupported', `filter.${field} 时间无效。`);
    return time;
  };
  let normalizedFilter;
  if (filter !== undefined) {
    if (filter.protocol !== undefined && !['tcp', 'udp', 'dns'].includes(filter.protocol)) throw new ToolError('unsupported', 'filter.protocol 须为 tcp、udp 或 dns。');
    for (const field of ['src_port', 'dst_port']) {
      if (filter[field] !== undefined && (!Number.isInteger(filter[field]) || filter[field] < 1 || filter[field] > 65535)) {
        throw new ToolError('unsupported', `filter.${field} 须在 1 至 65535 之间。`);
      }
    }
    const startTime = parseTime(filter.start_utc, 'start_utc');
    const endTime = parseTime(filter.end_utc, 'end_utc');
    if (startTime !== undefined && endTime !== undefined && startTime > endTime) throw new ToolError('unsupported', 'filter.start_utc 不能晚于 end_utc。');
    normalizedFilter = {
      ...(filter.protocol === undefined ? {} : { protocol: filter.protocol }),
      ...(normalizeIp(filter.src_ip, 'src_ip') === undefined ? {} : { src_ip: normalizeIp(filter.src_ip, 'src_ip') }),
      ...(normalizeIp(filter.dst_ip, 'dst_ip') === undefined ? {} : { dst_ip: normalizeIp(filter.dst_ip, 'dst_ip') }),
      ...(filter.src_port === undefined ? {} : { src_port: filter.src_port }),
      ...(filter.dst_port === undefined ? {} : { dst_port: filter.dst_port }),
      ...(startTime === undefined ? {} : { start_utc: new Date(startTime).toISOString() }),
      ...(endTime === undefined ? {} : { end_utc: new Date(endTime).toISOString() }),
    };
  }
  return { filePath: input.file_path, maxFlows, maxBytes, includeHex, filter: normalizedFilter };
}

function normalizeFilePath(value) {
  if (value === undefined) throw new ToolError('unsupported', '缺少必填参数 file_path。');
  if (typeof value !== 'string' || value.trim() === '') throw new ToolError('unsupported', 'file_path 必须是非空字符串。');
  if (value.length > MAX_PATH_LENGTH) throw new ToolError('path', `file_path 不能超过 ${MAX_PATH_LENGTH} 个字符。`);
  if (/[\u0000-\u001f\u007f]/u.test(value)) throw new ToolError('path', 'file_path 不能包含控制字符。');
  const raw = value.replaceAll('\\', '/');
  if (raw.startsWith('/') || /^[A-Za-z]:/u.test(raw)) {
    throw new ToolError('path', 'file_path 必须是相对会话工作目录的路径，不能是绝对路径或盘符。');
  }
  if (raw.includes(':')) throw new ToolError('path', 'file_path 不能包含盘符或冒号。');
  const pieces = raw.split('/');
  if (pieces.some(piece => piece === '..')) {
    throw new ToolError('path', 'file_path 不能包含 ".." 路径段。');
  }
  const parts = pieces.filter(piece => piece !== '' && piece !== '.');
  if (parts.length === 0) throw new ToolError('path', 'file_path 不能为空。');
  return { display: parts.join('/'), parts };
}

function stripLongPathPrefix(value) {
  return value.startsWith('\\\\?\\') ? value.slice(4) : value;
}

function insideDirectory(directory, candidate) {
  const base = stripLongPathPrefix(path.resolve(directory));
  const target = stripLongPathPrefix(path.resolve(candidate));
  if (process.platform === 'win32') {
    const lowerBase = base.toLowerCase();
    const lowerTarget = target.toLowerCase();
    const prefix = lowerBase.endsWith(path.sep) ? lowerBase : lowerBase + path.sep;
    return lowerTarget === lowerBase || lowerTarget.startsWith(prefix);
  }
  const prefix = base.endsWith(path.sep) ? base : base + path.sep;
  return target === base || target.startsWith(prefix);
}

function createReader(bytes, littleEndian) {
  return {
    u16: (littleEndian ? bytes.readUInt16LE : bytes.readUInt16BE).bind(bytes),
    u32: (littleEndian ? bytes.readUInt32LE : bytes.readUInt32BE).bind(bytes),
    i64: (littleEndian ? bytes.readBigInt64LE : bytes.readBigInt64BE).bind(bytes),
  };
}

function packetLocation({ index, offset, ticks, clock }) {
  return { packet_index: index, file_offset: offset, ...formatTimestamp(ticks, clock) };
}

class InvalidPacket extends Error {}

function malformed(packetIndex, detail) {
  return new InvalidPacket('包 ' + packetIndex + '：' + detail);
}

function ipv4Text(frame, offset) {
  return `${frame[offset]}.${frame[offset + 1]}.${frame[offset + 2]}.${frame[offset + 3]}`;
}

function readableBytes(buffer) {
  let text = '';
  for (const byte of buffer) text += PRINTABLE[byte] ? String.fromCharCode(byte) : '.';
  return text;
}

function parseFrame(frame, linkType, packetIndex) {
  let ipOffset = 0;
  let etherType = 0x0800;
  let interfaceIndex;
  if (linkType === LINK_ETHERNET) {
    if (frame.length < 14) throw malformed(packetIndex, 'Ethernet 头被截断');
    etherType = frame.readUInt16BE(12);
    ipOffset = 14;
    while (etherType === 0x8100 || etherType === 0x88a8) {
      if (frame.length < ipOffset + 4) throw malformed(packetIndex, 'VLAN 头被截断');
      etherType = frame.readUInt16BE(ipOffset + 2);
      ipOffset += 4;
    }
  } else if (linkType === LINK_NULL) {
    ipOffset = 4;
    if (frame.length < ipOffset) throw malformed(packetIndex, 'BSD 回环头被截断');
    if (frame.readUInt32LE(0) !== 2 && frame.readUInt32BE(0) !== 2) return { skip: 'non_ipv4' };
  } else if (linkType === LINK_LINUX_SLL) {
    ipOffset = 16;
    if (frame.length < ipOffset) throw malformed(packetIndex, 'Linux cooked v1 头被截断');
    etherType = frame.readUInt16BE(14);
  } else if (linkType === LINK_LINUX_SLL2) {
    ipOffset = 20;
    if (frame.length < ipOffset) throw malformed(packetIndex, 'Linux cooked v2 头被截断');
    etherType = frame.readUInt16BE(0);
    interfaceIndex = frame.readUInt32BE(4);
  } else if (linkType !== LINK_RAW_IP) {
    return { skip: 'unsupported_link' };
  }
  if (etherType !== 0x0800 || (frame.length > ipOffset && (frame[ipOffset] >>> 4) !== 4)) return { skip: 'non_ipv4' };
  if (frame.length < ipOffset + 20) throw malformed(packetIndex, 'IPv4 头被截断');
  const headerLength = (frame[ipOffset] & 0x0f) * 4;
  if (headerLength < 20 || ipOffset + headerLength > frame.length) throw malformed(packetIndex, 'IPv4 头长度无效');
  const totalLength = frame.readUInt16BE(ipOffset + 2);
  if (totalLength < headerLength || ipOffset + totalLength > frame.length) throw malformed(packetIndex, 'IPv4 总长度无效。');
  const field = frame.readUInt16BE(ipOffset + 6);
  return {
    src: ipv4Text(frame, ipOffset + 12), dst: ipv4Text(frame, ipOffset + 16),
    protocol: frame[ipOffset + 9], identifier: frame.readUInt16BE(ipOffset + 4), interfaceIndex,
    offset: (field & 0x1fff) * 8, more: (field & 0x2000) !== 0,
    bytes: frame.subarray(ipOffset + headerLength, ipOffset + totalLength),
  };
}

function parseTransport(info, bytes, packetIndex) {
  if (info.protocol === 17) return parseUdp(bytes);
  if (info.protocol !== 6) return { skip: 'non_tcp' };
  if (bytes.length < 20) throw malformed(packetIndex, 'TCP 头被截断');
  const length = (bytes[12] >>> 4) * 4;
  if (length < 20 || length > bytes.length) throw malformed(packetIndex, 'TCP 头长度无效');
  return { tcp: true, src: info.src, dst: info.dst, srcPort: bytes.readUInt16BE(0), dstPort: bytes.readUInt16BE(2),
    seq: bytes.readUInt32BE(4), flags: bytes[13], payload: bytes.subarray(length) };
}

function parseUdp(bytes) {
  if (bytes.length < 8) return { skip: 'invalid_udp' };
  const length = bytes.readUInt16BE(4);
  if (length < 8 || length > bytes.length) return { skip: 'invalid_udp' };
  const srcPort = bytes.readUInt16BE(0);
  const dstPort = bytes.readUInt16BE(2);
  const port53 = srcPort === 53 || dstPort === 53;
  if (!port53) return { udp: true, srcPort, dstPort, port53: false };
  if (length < 20) return { udp: true, srcPort, dstPort, port53: true, shortDnsHeader: true };
  const flags = bytes.readUInt16BE(10);
  return { udp: true, srcPort, dstPort, port53: true, dns: { response: (flags & 0x8000) !== 0, truncated: (flags & 0x0200) !== 0, rcode: flags & 15,
    message: bytes.subarray(8, length) } };
}

function createCollector(maxFlows, maxBytes, includeHex, filter) {
  const skipped = { non_ipv4: 0, non_tcp: 0, fragmented: 0, truncated_capture: 0, invalid_udp: 0,
    invalid_packet: 0, unsupported_link: 0 };
  const fragments = ipv4Fragments();
  const connectionStates = new Map();
  let nextConnection = 0;
  const dns = { port53_datagrams: 0, short_header: 0, queries: 0, responses: 0, truncated: 0, response_codes: {},
    samples: [], unsampled_datagrams: 0 };
  const directions = new Map();
  const dropped = new Set();
  let truncatedFlows = 0;
  let tcpPackets = 0;
  let udpPackets = 0;
  let filteredPackets = 0;
  let pendingBytes = 0;

  const startMs = filter?.start_utc !== undefined ? Date.parse(filter.start_utc) : undefined;
  const endMs = filter?.end_utc !== undefined ? Date.parse(filter.end_utc) : undefined;
  function timeMatches(packet) {
    if (startMs === undefined && endMs === undefined) return true;
    const utc = packet.timestamp_utc ?? formatTimestamp(packet.ticks, packet.clock)?.timestamp_utc;
    const timestamp = Date.parse(utc ?? '');
    if (!Number.isFinite(timestamp)) return false;
    return (startMs === undefined || timestamp >= startMs)
      && (endMs === undefined || timestamp <= endMs);
  }

  function addressMatches(ip, packet) {
    if (!timeMatches(packet) || (filter?.src_ip !== undefined && ip.src !== filter.src_ip)
      || (filter?.dst_ip !== undefined && ip.dst !== filter.dst_ip)) return false;
    if (filter?.protocol === 'tcp' && ip.protocol !== 6) return false;
    if ((filter?.protocol === 'udp' || filter?.protocol === 'dns') && ip.protocol !== 17) return false;
    return true;
  }

  function portsMatch(parsed) {
    return (filter?.src_port === undefined || parsed.srcPort === filter.src_port)
      && (filter?.dst_port === undefined || parsed.dstPort === filter.dst_port)
      && (filter?.protocol !== 'dns' || (parsed.udp && parsed.port53));
  }

  function peekFlowKey(info) {
    return `${info.src}:${info.srcPort}->${info.dst}:${info.dstPort}`;
  }

  function clearPending(direction) {
    pendingBytes -= direction.pendingBytes;
    direction.pendingBytes = 0;
    direction.pending.length = 0;
  }

  function addPending(direction, seq, bytes) {
    if (direction.truncated || bytes.length === 0) return;
    if (direction.pending.length >= MAX_PENDING_SEGMENTS || bytes.length > MAX_PENDING_BYTES - pendingBytes) {
      direction.pendingDropped = true;
      return;
    }
    const copy = Buffer.from(bytes);
    direction.pending.push({ seq, bytes: copy });
    direction.pendingBytes += copy.length;
    pendingBytes += copy.length;
  }

  function appendPayload(direction, bytes) {
    if (bytes.length === 0 || direction.truncated) return;
    const remaining = maxBytes - direction.payloadBytes;
    if (remaining <= 0) {
      direction.truncated = true;
      clearPending(direction);
      return;
    }
    const take = Math.min(remaining, bytes.length);
    direction.chunks.push(Buffer.from(bytes.subarray(0, take)));
    direction.payloadBytes += take;
    if (take < bytes.length) {
      direction.truncated = true;
      clearPending(direction);
    }
  }

  function prependPayload(direction, seq, bytes) {
    if (bytes.length === 0 || direction.truncated) return;
    if (direction.payloadBytes + bytes.length > maxBytes) {
      direction.truncated = true;
      clearPending(direction);
      return;
    }
    direction.chunks.unshift(Buffer.from(bytes));
    direction.payloadBytes += bytes.length;
    direction.startSeq = seq;
  }

  function flushPending(direction) {
    let progressed = true;
    while (progressed && direction.pending.length > 0 && !direction.truncated) {
      progressed = false;
      for (let index = 0; index < direction.pending.length; index += 1) {
        const segment = direction.pending[index];
        if (!mergeSegment(direction, segment.seq, segment.bytes)) continue;
        const removed = direction.pending.splice(index, 1)[0];
        if (removed) {
          direction.pendingBytes -= removed.bytes.length;
          pendingBytes -= removed.bytes.length;
        }
        progressed = true;
        break;
      }
    }
    if (direction.truncated) clearPending(direction);
  }

  function mergeSegment(direction, payloadSeq, payload) {
    const offset = (payloadSeq - direction.startSeq) >>> 0;
    const covered = direction.payloadBytes;
    if (offset < 0x80000000) {
      if (offset > covered) return false;
      appendPayload(direction, payload.subarray(covered - offset));
    } else {
      const behind = (0 - offset) >>> 0;
      if (behind > payload.length) return false;
      prependPayload(direction, payloadSeq, payload.subarray(0, behind));
      appendPayload(direction, payload.subarray(behind + covered));
    }
    return true;
  }

  function addSegment(direction, seq, payload, syn) {
    if (payload.length === 0 || direction.truncated) return;
    const payloadSeq = (seq + (syn ? 1 : 0)) >>> 0;
    if (direction.startSeq === undefined) {
      direction.startSeq = payloadSeq;
      appendPayload(direction, payload);
    } else if (!mergeSegment(direction, payloadSeq, payload)) {
      addPending(direction, payloadSeq, payload);
    }
    flushPending(direction);
  }

  function skip(reason) {
    skipped[reason] += 1;
  }

  function consume(frame, linkType, packet, captureTruncated) {
    if (captureTruncated) {
      skip('truncated_capture');
      return;
    }
    try {
      const { index: packetIndex, iface: interfaceKey = '0' } = packet;
      let iface = interfaceKey;
      const ip = parseFrame(frame, linkType, packetIndex);
      if (ip.skip !== undefined) { skip(ip.skip); return; }
      if (!addressMatches(ip, packet)) { filteredPackets += 1; return; }
      if (ip.interfaceIndex !== undefined) iface += '/' + ip.interfaceIndex;
      const key = JSON.stringify([iface, ip.src, ip.dst, ip.protocol, ip.identifier]);
      const bytes = ip.offset > 0 || ip.more ? fragments.add(key, ip, packetIndex) : ip.bytes;
      if (bytes === null) return;
      const parsed = parseTransport(ip, bytes, packetIndex);
      if (parsed.skip !== undefined) { skip(parsed.skip); return; }
      if (!portsMatch(parsed)) { filteredPackets += 1; return; }
      if (parsed.tcp) { addTcp(parsed, iface, packet); return; }
      addUdp(parsed, packet, ip);
    } catch (error) {
      if (!(error instanceof InvalidPacket)) throw error;
      skip('invalid_packet');
    }
  }

  function addUdp(parsed, packet, ip) {
    udpPackets++;
    if (parsed.shortDnsHeader) {
      dns.port53_datagrams++;
      dns.short_header++;
    } else if (parsed.dns) {
      dns.port53_datagrams++;
      if (parsed.dns.truncated) dns.truncated++;
      if (parsed.dns.response) {
        dns.responses++;
        const { rcode } = parsed.dns;
        dns.response_codes[rcode] = (dns.response_codes[rcode] ?? 0) + 1;
      } else {
        dns.queries++;
      }
      if (dns.samples.length < MAX_DNS_SAMPLES) {
        const { message, response, rcode, truncated } = parsed.dns;
        dns.samples.push({ ...packetLocation(packet), src: ip.src, dst: ip.dst, response, rcode, truncated,
          ...dnsDetails(message) });
      } else {
        dns.unsampled_datagrams++;
      }
    }
  }

  function addTcp(info, iface, packet) {
    tcpPackets += 1;
    const key = peekFlowKey(info);
    const endpoints = [info.src + ':' + info.srcPort, info.dst + ':' + info.dstPort].sort();
    const pair = JSON.stringify([iface, ...endpoints]);
    const initiating = (info.flags & (TCP_SYN | 0x10)) === TCP_SYN;
    let connection = connectionStates.get(pair);
    if (!connection || (initiating && (connection.closed || connection.initiator !== key || connection.initialSeq !== info.seq))) {
      connection = { id: ++nextConnection, initiator: initiating ? key : undefined,
        initialSeq: initiating ? info.seq : undefined, fins: new Set(), closed: false };
    }
    connectionStates.delete(pair);
    connectionStates.set(pair, connection);
    if (connectionStates.size > 8192) connectionStates.delete(connectionStates.keys().next().value);
    if ((info.flags & 1) !== 0) connection.fins.add(key);
    if ((info.flags & 4) !== 0 || connection.fins.size === 2) connection.closed = true;
    const streamKey = connection.id + '/' + key;
    let direction = directions.get(streamKey);
    if (direction === undefined) {
      if (directions.size >= maxFlows) {
        if (!dropped.has(streamKey) && dropped.size < 65536) {
          dropped.add(streamKey);
          truncatedFlows += 1;
        }
        return;
      }
      direction = {
        key, connection: connection.id, interface: iface,
        src: info.src,
        dst: info.dst,
        srcPort: info.srcPort,
        dstPort: info.dstPort,
        packets: 0,
        bytes: 0,
        payloadBytes: 0,
        truncated: false,
        chunks: [],
        startSeq: undefined,
        pending: [],
        pendingBytes: 0,
        pendingDropped: false,
        firstPacket: packet,
      };
      directions.set(streamKey, direction);
    }
    direction.packets += 1;
    direction.bytes += info.payload.length;
    direction.lastPacket = packet;
    addSegment(direction, info.seq, info.payload, (info.flags & TCP_SYN) !== 0);
  }

  function finalize() {
    const flows = [];
    for (const direction of directions.values()) {
      const payload = Buffer.concat(direction.chunks, direction.payloadBytes);
      const textLength = Math.min(MAX_PAYLOAD_TEXT, payload.length);
      const gap = direction.pending.length > 0;
      const incomplete = direction.truncated || gap || direction.pendingDropped;
      const flow = {
        key: direction.key, connection_id: direction.connection, interface_key: direction.interface,
        src: direction.src,
        dst: direction.dst,
        src_port: direction.srcPort,
        dst_port: direction.dstPort,
        packets: direction.packets,
        first_packet: packetLocation(direction.firstPacket),
        last_packet: packetLocation(direction.lastPacket),
        bytes: direction.bytes,
        payload_bytes: payload.length,
        payload_truncated: direction.truncated,
        reassembly_incomplete: incomplete,
        sequence_gap: gap,
        pending_segments_dropped: direction.pendingDropped,
        payload_text: readableBytes(payload.subarray(0, textLength)),
      };
      if (includeHex) flow.payload_hex = payload.toString('hex');
      const messages = parseHttpMessages(payload);
      if (messages !== undefined) flow.http_messages = messages.map(message => ({
        ...message, reassembly_incomplete: incomplete,
      }));
      flows.push(flow);
    }
    const ipFragments = fragments.stats();
    skipped.fragmented = ipFragments.unresolved;
    return { flows, skipped, tcpPackets, udpPackets, dns, truncatedFlows, filteredPackets, ipFragments };
  }

  return { addTcp, skip, consume, finalize };
}

function parseHttpMessages(payload) {
  if (payload.length === 0) return undefined;
  const newline = payload.indexOf(0x0a);
  if (newline < 0 || newline > 8192) return undefined;
  const lineEnd = newline > 0 && payload[newline - 1] === 0x0d ? newline - 1 : newline;
  const startLine = payload.subarray(0, lineEnd).toString('latin1').slice(0, MAX_START_LINE);

  const request = REQUEST_LINE.exec(startLine);
  const response = request === null ? RESPONSE_LINE.exec(startLine) : null;
  if (request === null && response === null) return undefined;

  let separator = payload.indexOf('\r\n\r\n', Math.max(0, newline - 1));
  let separatorLength = 4;
  if (separator < 0) {
    separator = payload.indexOf('\n\n', newline);
    separatorLength = 2;
  }
  const headerEnd = separator < 0 ? payload.length : separator;
  const headers = {};
  if (separator >= 0) {
    const headerText = payload.subarray(newline + 1, headerEnd).toString('latin1');
    let count = 0;
    for (const rawLine of headerText.split(/\r?\n/u)) {
      if (count >= MAX_HEADERS) break;
      const colon = rawLine.indexOf(':');
      if (colon <= 0) continue;
      const name = rawLine.slice(0, colon).trim().toLowerCase();
      if (name.length === 0 || name.length > MAX_HEADER_NAME || !HEADER_NAME.test(name)) continue;
      let value = rawLine.slice(colon + 1).trim();
      if (value.length > MAX_HEADER_VALUE) value = value.slice(0, MAX_HEADER_VALUE);
      if (Object.hasOwn(headers, name)) {
        headers[name] = `${headers[name]}, ${value}`.slice(0, MAX_HEADER_VALUE);
      } else {
        Object.defineProperty(headers, name, {
          value, enumerable: true, configurable: true, writable: true,
        });
      }
      count += 1;
    }
  }
  const bodyStart = separator < 0 ? payload.length : separator + separatorLength;
  const bodyPreview = readableBytes(payload.subarray(bodyStart, bodyStart + MAX_BODY_PREVIEW));

  if (request !== null) {
    return [{
      kind: 'request',
      start_line: startLine,
      method: request[1],
      target: request[2].slice(0, MAX_TARGET),
      version: request[3],
      headers,
      headers_complete: separator >= 0,
      body_preview: bodyPreview,
      offset: 0,
    }];
  }
  return [{
    kind: 'response',
    start_line: startLine,
    version: response[1],
    status: Number(response[2]),
    reason: (response[3] ?? '').slice(0, MAX_REASON),
    headers,
    headers_complete: separator >= 0,
    body_preview: bodyPreview,
    offset: 0,
  }];
}

function parseClassicPcap(bytes, collector) {
  if (bytes.length < 24) throw new ToolError('unsupported', 'PCAP 文件头被截断。');
  const magic = bytes.readUInt32BE(0);
  const info = PCAP_MAGICS.get(magic);
  if (info === undefined) throw new ToolError('unsupported', '不支持的抓包格式：只支持经典 PCAP 和 PCAPNG。');
  const read = createReader(bytes, info.littleEndian);
  const major = read.u16(4);
  if (major !== 2) throw new ToolError('unsupported', `不支持的 PCAP 版本 ${major}.${read.u16(6)}。`);
  const linkType = read.u32(20) & 0xffff;
  if (!SUPPORTED_LINK_TYPES.has(linkType)) {
    throw new ToolError('unsupported', '不支持的链路类型（unsupported）：' + linkType + '。支持 BSD 回环、Ethernet、裸 IP、Linux SLL 和 SLL2。');
  }

  let cursor = 24;
  let packets = 0;
  const snapshot = read.u32(16);
  const exponent = info.timestampUnit === 'nanoseconds' ? 9 : 6;
  const units = 10 ** exponent;
  const clock = { exponent, ticksPerSecond: BigInt(units), offsetSeconds: 0n, decimalMultiplier: 1n };
  while (cursor < bytes.length) {
    if (bytes.length - cursor < 16) break;
    const captured = read.u32(cursor + 8);
    if (captured > MAX_PACKET_CAPTURE) {
      throw new ToolError('size', `PCAP 包数据长度 ${captured} 超过 16 MiB 上限。`);
    }
    packets += 1;
    if (captured > bytes.length - cursor - 16) break;
    const original = read.u32(cursor + 12);
    if ((snapshot !== 0 && captured > snapshot) || captured > original) {
      collector.skip('invalid_packet');
    } else {
      const fraction = read.u32(cursor + 4);
      const ticks = fraction < units ? BigInt(read.u32(cursor)) * clock.ticksPerSecond + BigInt(fraction) : undefined;
      collector.consume(bytes.subarray(cursor + 16, cursor + 16 + captured), linkType,
        { index: packets, offset: cursor, ticks, clock }, captured < original);
    }
    cursor += 16 + captured;
  }
  return { format: 'PCAP', linkType, packets, linkTypes: [linkType] };
}

function parsePcapng(bytes, collector) {
  let cursor = 0;
  let read;
  let packets = 0;
  let interfaces = [];
  let firstLinkType;
  let sectionNumber = 0;
  let invalidClocks = 0;
  const linkTypes = [];
  const packetBlockCounts = { enhanced_packet: 0, packet: 0, simple_packet: 0 };

  while (cursor < bytes.length) {
    if (bytes.length - cursor < 12) {
      throw new ToolError('unsupported', `PCAPNG 块头在偏移 ${cursor} 处被截断。`);
    }
    const rawType = bytes.readUInt32BE(cursor);
    let size;
    if (rawType === SECTION_HEADER) {
      if (bytes.length - cursor < 28) {
        throw new ToolError('unsupported', `PCAPNG 节头块在偏移 ${cursor} 处被截断。`);
      }
      const byteOrderMagic = bytes.readUInt32BE(cursor + 8);
      if (byteOrderMagic === 0x1a2b3c4d) read = createReader(bytes, false);
      else if (byteOrderMagic === 0x4d3c2b1a) read = createReader(bytes, true);
      else throw new ToolError('unsupported', `PCAPNG 节头块在偏移 ${cursor} 处的字节序标记无效。`);
      size = read.u32(cursor + 4);
    } else {
      if (read === undefined) throw new ToolError('unsupported', 'PCAPNG 文件必须以节头块开始。');
      size = read.u32(cursor + 4);
    }
    if (size < 12 || size % 4 !== 0) {
      throw new ToolError('unsupported', `PCAPNG 块在偏移 ${cursor} 处的长度无效。`);
    }
    if (size > bytes.length - cursor) {
      throw new ToolError('unsupported', `PCAPNG 块在偏移 ${cursor} 处被截断。`);
    }
    if (read.u32(cursor + size - 4) !== size) {
      throw new ToolError('unsupported', `PCAPNG 块在偏移 ${cursor} 处的块头与块尾长度不一致。`);
    }

    if (rawType === SECTION_HEADER) {
      if (size < 28) throw new ToolError('unsupported', `PCAPNG 节头块在偏移 ${cursor} 处的长度无效。`);
      read = createReader(bytes, bytes.readUInt32BE(cursor + 8) === 0x4d3c2b1a);
      interfaces = [];
      sectionNumber++;
    } else {
      const type = read.u32(cursor);
      if (type === INTERFACE_DESCRIPTION) {
        if (size < 20) throw new ToolError('unsupported', `PCAPNG 接口描述块在偏移 ${cursor} 处的长度无效。`);
        const linkType = read.u16(cursor + 8);
        let clock;
        try {
          clock = interfaceClock(bytes, read, cursor);
        } catch {
          invalidClocks++;
        }
        interfaces.push({ link_type: linkType, snapshot_length: read.u32(cursor + 12), clock });
        linkTypes.push(linkType);
        firstLinkType ??= linkType;
      } else {
        let packet;
        try {
          packet = pcapngPacketBlock(type, cursor, size, read, interfaces);
        } catch {
          // The section and enclosing block are intact, so the next record is still locatable.
          packets++;
          collector.skip('invalid_packet');
        }
        if (packet !== undefined) {
          const { captured, dataOffset, info, name, original, interfaceId, simple } = packet;
          if (captured > MAX_PACKET_CAPTURE) {
            throw new ToolError('size', `PCAPNG 包数据长度 ${captured} 超过 16 MiB 上限。`);
          }
          packetBlockCounts[name]++;
          packets += 1;
          const ticks = simple || !info.clock ? undefined : pcapngPacketTicks(read, cursor);
          collector.consume(
            bytes.subarray(dataOffset, dataOffset + captured), info.link_type,
            { index: packets, offset: cursor, iface: sectionNumber + '/' + interfaceId, ticks, clock: info.clock },
            captured < original,
          );
        }
      }
    }
    cursor += size;
  }
  if (read === undefined) throw new ToolError('unsupported', 'PCAPNG 文件缺少节头块。');
  return { format: 'PCAPNG', linkType: firstLinkType ?? 0, packets, linkTypes, packetBlockCounts, invalidClocks };
}

async function streamLargeCapture(filePath, size, collector, signal) {
  const handle = await open(filePath, 'r');
  const hash = createHash('sha256');
  let readPosition = 0;
  let consumed = 0;
  let pending = Buffer.alloc(0);
  let reachedEof = false;
  let partial = false;
  let issue;
  async function exact(length) {
    while (pending.length < length && readPosition < size) {
      throwIfAborted(signal);
      const amount = Math.min(STREAM_BUFFER_SIZE, size - readPosition);
      const chunk = Buffer.allocUnsafe(amount);
      const { bytesRead } = await handle.read(chunk, 0, amount, readPosition);
      if (bytesRead === 0) { reachedEof = true; break; }
      const useful = chunk.subarray(0, bytesRead);
      hash.update(useful);
      pending = pending.length ? Buffer.concat([pending, useful], pending.length + useful.length) : useful;
      readPosition += bytesRead;
    }
    const count = Math.min(length, pending.length);
    const result = pending.subarray(0, count);
    pending = pending.subarray(count);
    consumed += count;
    return result;
  }
  async function drain() {
    while (readPosition < size && !reachedEof) await exact(Math.min(STREAM_BUFFER_SIZE, size - consumed));
    if (pending.length) await exact(pending.length);
  }
  try {
    if (size < 4) throw new ToolError('unsupported', '不支持的抓包格式：只支持经典 PCAP 和 PCAPNG。');
    const prefix = await exact(4);
    if (prefix.length !== 4) throw new ToolError('unsupported', '抓包文件头被截断。');
    const firstMagic = prefix.readUInt32BE(0);
    let parseInfo;
    if (firstMagic !== SECTION_HEADER) {
      const rest = await exact(20);
      if (rest.length !== 20) throw new ToolError('unsupported', 'PCAP 文件头被截断。');
      const header = Buffer.concat([prefix, rest], 24);
      const info = PCAP_MAGICS.get(header.readUInt32BE(0));
      if (info === undefined) throw new ToolError('unsupported', '不支持的抓包格式：只支持经典 PCAP 和 PCAPNG。');
      const read = createReader(header, info.littleEndian);
      const major = read.u16(4);
      if (major !== 2) throw new ToolError('unsupported', `不支持的 PCAP 版本 ${major}.${read.u16(6)}。`);
      const linkType = read.u32(20) & 0xffff;
      if (!SUPPORTED_LINK_TYPES.has(linkType)) throw new ToolError('unsupported', '不支持的链路类型：' + linkType + '。');
      const snapshot = read.u32(16);
      const exponent = info.timestampUnit === 'nanoseconds' ? 9 : 6;
      const units = 10 ** exponent;
      const clock = { exponent, ticksPerSecond: BigInt(units), offsetSeconds: 0n, decimalMultiplier: 1n };
      let packets = 0;
      while (consumed < size) {
        const recordOffset = consumed;
        const record = await exact(16);
        if (record.length === 0) break;
        if (record.length < 16) { partial = true; issue = 'truncated_record_header'; break; }
        const recordRead = createReader(record, info.littleEndian);
        const captured = recordRead.u32(8);
        if (captured > MAX_PACKET_CAPTURE) throw new ToolError('size', `PCAP 包数据长度 ${captured} 超过 16 MiB 上限。`);
        const packetBytes = await exact(captured);
        packets += 1;
        if (packetBytes.length < captured) {
          collector.consume(packetBytes, linkType, { index: packets, offset: recordOffset }, true);
          partial = true; issue = 'truncated_packet'; break;
        }
        const original = recordRead.u32(12);
        if ((snapshot !== 0 && captured > snapshot) || captured > original) collector.skip('invalid_packet');
        else {
          const fraction = recordRead.u32(4);
          const seconds = recordRead.u32(0);
          const ticks = fraction < units ? BigInt(seconds) * clock.ticksPerSecond + BigInt(fraction) : undefined;
          collector.consume(packetBytes, linkType, { index: packets, offset: recordOffset, ticks, clock }, captured < original);
        }
      }
      parseInfo = { format: 'PCAP', linkType, packets, linkTypes: [linkType] };
    } else {
      let sectionReady = false;
      let littleEndian;
      let interfaces = [];
      let sectionNumber = 0;
      let firstLinkType;
      let packets = 0;
      let invalidClocks = 0;
      const linkTypes = [];
      const packetBlockCounts = { enhanced_packet: 0, packet: 0, simple_packet: 0 };
      let blockPrefix = prefix;
      while (consumed < size) {
        throwIfAborted(signal);
        const recordOffset = blockPrefix.length === 4 ? 0 : consumed;
        const first = blockPrefix.length === 4 ? Buffer.concat([blockPrefix, await exact(4)], 8) : await exact(8);
        if (first.length === 0) break;
        if (first.length < 8) { partial = true; issue = 'truncated_block_header'; break; }
        const rawType = first.readUInt32BE(0);
        let leading = first;
        let blockSize;
        if (rawType === SECTION_HEADER) {
          const bom = await exact(4);
          if (bom.length < 4) { partial = true; issue = 'truncated_section_header'; break; }
          const byteOrder = bom.readUInt32BE(0);
          if (byteOrder === 0x1a2b3c4d) littleEndian = false;
          else if (byteOrder === 0x4d3c2b1a) littleEndian = true;
          else throw new ToolError('unsupported', `PCAPNG 节头块在偏移 ${recordOffset} 处的字节序标记无效。`);
          const firstRead = createReader(first, littleEndian);
          blockSize = firstRead.u32(4);
          leading = Buffer.concat([first, bom], 12);
        } else {
          if (!sectionReady || littleEndian === undefined) throw new ToolError('unsupported', 'PCAPNG 文件必须以节头块开始。');
          blockSize = createReader(first, littleEndian).u32(4);
        }
      if (blockSize < (rawType === SECTION_HEADER ? 28 : 12) || blockSize % 4 !== 0 || blockSize > MAX_PCAPNG_BLOCK) {
          const label = rawType === SECTION_HEADER ? 'Section Header Block' : '块';
          throw new ToolError('size', `PCAPNG ${label} 在偏移 ${recordOffset} 处的长度无效或超过解析上限。`);
        }
        if (blockSize > size - recordOffset) { partial = true; issue = 'truncated_block'; break; }
        const tail = await exact(blockSize - leading.length);
        if (tail.length < blockSize - leading.length) { partial = true; issue = 'truncated_block'; break; }
        const block = Buffer.concat([leading, tail], blockSize);
        const read = createReader(block, littleEndian);
        if (read.u32(blockSize - 4) !== blockSize) throw new ToolError('unsupported', `PCAPNG 块在偏移 ${recordOffset} 处的块头与块尾长度不一致。`);
        if (rawType === SECTION_HEADER) {
          if (read.u16(12) !== 1) throw new ToolError('unsupported', '不支持的 PCAPNG 主版本。');
          sectionReady = true;
          interfaces = [];
          sectionNumber++;
        } else {
          const type = read.u32(0);
          if (type === INTERFACE_DESCRIPTION) {
            if (blockSize < 20) throw new ToolError('unsupported', `PCAPNG 接口描述块在偏移 ${recordOffset} 处的长度无效。`);
            const linkType = read.u16(8);
            let clock;
            try { clock = interfaceClock(block, read, 0); } catch { invalidClocks++; }
            interfaces.push({ link_type: linkType, snapshot_length: read.u32(12), clock });
            linkTypes.push(linkType);
            firstLinkType ??= linkType;
          } else {
            let packet;
            try { packet = pcapngPacketBlock(type, 0, blockSize, read, interfaces); }
            catch {
              packets++;
              collector.skip('invalid_packet');
            }
            if (packet !== undefined) {
              const { captured, dataOffset, info, name, original, interfaceId, simple } = packet;
              if (captured > MAX_PACKET_CAPTURE) throw new ToolError('size', `PCAPNG 包数据长度 ${captured} 超过 16 MiB 上限。`);
              packetBlockCounts[name]++;
              packets++;
              const ticks = simple || !info.clock ? undefined : pcapngPacketTicks(read, 0);
              collector.consume(block.subarray(dataOffset, dataOffset + captured), info.link_type,
                { index: packets, offset: recordOffset, iface: sectionNumber + '/' + interfaceId, ticks, clock: info.clock }, captured < original);
            }
          }
        }
        blockPrefix = Buffer.alloc(0);
      }
      if (!sectionReady) throw new ToolError('unsupported', 'PCAPNG 文件缺少完整节头块。');
      parseInfo = { format: 'PCAPNG', linkType: firstLinkType ?? 0, packets, linkTypes, packetBlockCounts, invalidClocks };
    }
    await drain();
    return { parseInfo, sha256: hash.digest('hex'), partial, issue };
  } finally {
    await handle.close();
  }
}

function enforceOutputLimit(report) {
  if (Buffer.byteLength(JSON.stringify(report)) <= MAX_OUTPUT_BYTES) return report;
  report.output_truncated = true;
  report.notes.push('输出超过 4 MiB，已截断部分载荷或 HTTP 字段。');
  const fits = () => Buffer.byteLength(JSON.stringify(report)) <= MAX_OUTPUT_BYTES;

  const trimField = (field, limit) => {
    let changed = false;
    for (const flow of report.flows) {
      if (typeof flow[field] === 'string' && flow[field].length > limit) {
        flow[field] = flow[field].slice(0, limit);
        changed = true;
      }
    }
    return changed;
  };
  const trimHeaders = (limit) => {
    let changed = false;
    for (const flow of report.flows) {
      for (const message of flow.http_messages ?? []) {
        const names = Object.keys(message.headers ?? {});
        if (names.length <= limit) continue;
        const kept = {};
        for (const name of names.slice(0, limit)) kept[name] = message.headers[name];
        message.headers = kept;
        changed = true;
      }
    }
    return changed;
  };
  const trimPreview = limit => {
    let changed = false;
    for (const flow of report.flows) {
      for (const message of flow.http_messages ?? []) {
        if (message.body_preview.length > limit) {
          message.body_preview = message.body_preview.slice(0, limit);
          changed = true;
        }
      }
    }
    return changed;
  };
  const dropMessages = () => {
    let changed = false;
    for (const flow of report.flows) {
      if (flow.http_messages !== undefined) {
        flow.http_messages = [];
        changed = true;
      }
    }
    return changed;
  };
  const trimFlows = limit => {
    if (report.flows.length <= limit) return false;
    report.flows = report.flows.slice(0, limit);
    report.flow_count = report.flows.length;
    return true;
  };

  const steps = [
    () => trimField('payload_hex', 8192),
    () => trimPreview(256),
    () => trimHeaders(8),
    () => trimField('payload_text', 1024),
    () => trimField('payload_hex', 2048),
    () => trimField('payload_text', 256),
    () => trimField('payload_hex', 512),
    () => dropMessages(),
    () => trimField('payload_text', 64),
    () => trimFlows(8),
    () => trimFlowPayloads(report, 64),
    () => trimFlows(1),
  ];
  for (const step of steps) {
    if (fits()) break;
    step();
  }
  if (!fits()) {
    report.flows = [];
    report.flow_count = 0;
  }
  return report;
}

function trimFlowPayloads(report, limit) {
  let changed = false;
  for (const flow of report.flows) {
    if (typeof flow.payload_hex === 'string' && flow.payload_hex.length > 0) {
      flow.payload_hex = '';
      changed = true;
    }
    if (flow.payload_text.length > limit) {
      flow.payload_text = flow.payload_text.slice(0, limit);
      changed = true;
    }
  }
  return changed;
}

/**
 * 解析 PCAP/PCAPNG，按方向重组 IPv4/TCP 载荷并识别 HTTP 起始行与头。
 *
 * @param {object} input
 * @param {{ cwd?: string, signal?: AbortSignal }} [options]
 * @returns {Promise<object>} 可直接并入工具报告的对象
 */
export async function pcapStream(input, options = {}) {
  const { filePath, maxFlows, maxBytes, includeHex, filter } = parseArguments(input);
  const { signal, cwd } = parseOptions(options);
  throwIfAborted(signal);
  const { display, parts } = normalizeFilePath(filePath);
  const absolute = path.resolve(cwd, ...parts);
  if (!insideDirectory(cwd, absolute)) throw new ToolError('path', 'file_path 不能越出会话工作目录。');

  let info;
  try {
    info = await stat(absolute);
  } catch {
    throw new ToolError('missing', `无法读取文件 ${display}。`);
  }
  if (!info.isFile()) throw new ToolError('missing', `${display} 不是普通文件。`);
  if (info.size > MAX_STREAMED_FILE_SIZE) {
    throw new ToolError('size', `${display} 超过 1 GiB，PCAP 流式分析上限为 1 GiB。`);
  }
  throwIfAborted(signal);
  let realCwd;
  let realFile;
  try {
    realCwd = stripLongPathPrefix(await realpath(cwd));
    realFile = stripLongPathPrefix(await realpath(absolute));
  } catch (error) {
    if (error?.name === 'AbortError') throw error;
    throw new ToolError('missing', `无法读取文件 ${display}。`);
  }
  if (!insideDirectory(realCwd, realFile)) throw new ToolError('path', 'file_path 解析后越出会话工作目录。');

  const collector = createCollector(maxFlows, maxBytes, includeHex, filter);
  let parseInfo;
  let captureLayout;
  let sha256;
  if (info.size > MAX_FILE_SIZE) {
    const streamed = await streamLargeCapture(absolute, info.size, collector, signal);
    parseInfo = streamed.parseInfo;
    sha256 = streamed.sha256;
    captureLayout = { status: streamed.partial ? 'partial' : 'ok', complete: !streamed.partial,
      packet_count: parseInfo.packets, packet_records: parseInfo.packets, malformed_packets: 0,
      issues: streamed.issue === undefined ? [] : [{ code: streamed.issue }] };
    const after = await stat(absolute);
    if (after.size !== info.size || after.mtimeMs !== info.mtimeMs) throw new ToolError('conflict', '抓包文件在流式读取期间发生变化，请重新运行分析。');
  } else {
    let bytes;
    try {
      bytes = await readFile(absolute, { signal });
    } catch (error) {
      if (error?.name === 'AbortError') throw error;
      throw new ToolError('missing', `无法读取文件 ${display}。`);
    }
    if (bytes.length > MAX_FILE_SIZE) throw new ToolError('size', `${display} 在读取期间增大并超过 64 MiB 内存读取上限。`);
    throwIfAborted(signal);
    if (bytes.length < 4) throw new ToolError('unsupported', '不支持的抓包格式：只支持经典 PCAP 和 PCAPNG。');
    captureLayout = inspectCaptureLayout(bytes, { offset: 0, limit: 0 });
    const magic = bytes.readUInt32BE(0);
    if (magic === SECTION_HEADER) parseInfo = parsePcapng(bytes, collector);
    else parseInfo = parseClassicPcap(bytes, collector);
    sha256 = createHash('sha256').update(bytes).digest('hex');
  }
  throwIfAborted(signal);

  const { flows, skipped, tcpPackets, udpPackets, dns, truncatedFlows, filteredPackets, ipFragments } = collector.finalize();
  const notes = [
    '重组 IPv4/TCP 载荷，并统计 IPv4/UDP 和端口 53 的 DNS 报文。DNS 样本包含查询名、应答 TXT 和可用的捕获时间。',
    `方向流按四元组首次出现顺序保留前 ${maxFlows} 条，单方向最多重组 ${maxBytes} 字节载荷。`,
  ];
  if (filter !== undefined) notes.push('已在 TCP 重组之前按指定 IPv4、协议、端口和 UTC 时间筛选可解析包。');
  if (truncatedFlows > 0) notes.push(`另有 ${truncatedFlows} 条方向流因 max_flows 上限未保留。`);
  if (flows.some(flow => flow.payload_truncated)) {
    notes.push('部分方向流载荷超过 max_bytes_per_flow，已标记 payload_truncated。');
  }
  if (flows.some(flow => flow.sequence_gap || flow.pending_segments_dropped)) {
    notes.push('部分方向流有序列缺口或等待队列溢出。HTTP 字段仅依据已连续重组的片段。');
  }
  if (Object.values(skipped).some(count => count > 0)) {
    notes.push(`跳过非 IPv4 ${skipped.non_ipv4} 个、其他 IPv4 协议 ${skipped.non_tcp} 个、IP 分片 ${skipped.fragmented} 个、截断捕获 ${skipped.truncated_capture} 个、无效 UDP ${skipped.invalid_udp} 个、无效包 ${skipped.invalid_packet} 个、不支持的链路 ${skipped.unsupported_link} 个。`);
  }
  if (captureLayout?.issues?.length) {
    notes.push(`捕获文件有 ${captureLayout.issues.length} 条结构告警：${captureLayout.issues.map(issue => issue.code).join('、')}。`);
  }
  if (parseInfo.format === 'PCAPNG') {
    if (parseInfo.linkTypes.length > 1) {
      notes.push('PCAPNG 含多个接口，link_type 取第一个接口的链路类型。');
    }
    if (parseInfo.invalidClocks > 0) {
      notes.push(`有 ${parseInfo.invalidClocks} 个接口的时钟选项无效，对应包不提供时间戳。`);
    }
  }
  if (tcpPackets === 0) notes.push('未发现可重组的 IPv4 TCP 包。');
  const warnings = notes.slice(2 + (filter === undefined ? 0 : 1));

  const report = {
    file: display,
    size: info.size,
    sha256,
    format: parseInfo.format,
    capture_scope: { kind: 'whole_file', packet_records: parseInfo.packets, filtered: filter !== undefined,
      filtered_ipv4_packets: filteredPackets, ...(filter === undefined ? {} : { filter }) },
    status: captureLayout?.status ?? 'ok',
    complete: captureLayout?.complete ?? true,
    packet_count: captureLayout?.packet_count ?? parseInfo.packets,
    packet_records: captureLayout?.packet_records ?? parseInfo.packets,
    malformed_packets: captureLayout?.malformed_packets ?? skipped.invalid_packet,
    issues: captureLayout?.issues ?? [],
    analysis_status: warnings.length ? 'partial' : 'complete',
    warnings,
    link_type: parseInfo.linkType,
    packets: parseInfo.packets,
    ...(parseInfo.packetBlockCounts === undefined ? {} : { packet_blocks: parseInfo.packetBlockCounts }),
    tcp_packets: tcpPackets,
    udp_packets: udpPackets,
    dns_udp: dns,
    ip_fragments: ipFragments,
    skipped,
    flow_count: flows.length,
    truncated_flows: truncatedFlows,
    flows,
    notes,
  };
  return enforceOutputLimit(report);
}
