import { execFile } from 'node:child_process';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectAudioMetadata } from './audio-metadata.js';
import { WorkbenchDependencyError } from './workbench-config.js';
import { ToolError } from './tool-errors.js';

const SCRIPT_PATH = fileURLToPath(new URL('./core/workers/media-reader-worker.py', import.meta.url));
const MAX_PIXELS_PER_PAGE = 128;
const MAX_PIXELS_PER_LSB_PAGE = 8192;
const MAX_BITSTREAM_BITS_PER_PAGE = 32768;
const CHANNELS = ['L', 'P', 'R', 'G', 'B', 'A'];
const BIT_ORDERS = ['msb_first', 'lsb_first'];
const MEDIA_KINDS = ['pdf', 'qr', 'audio', 'image', 'sqlite', 'office', 'model'];
const REGION_KEYS = ['x', 'y', 'width', 'height'];
const MAX_DIMENSION = 16384;
const FRAME_INDEX = { type: 'integer', minimum: 0, maximum: 255, description: '帧/页序号（从 0 起）。' };

export const PNG_PIXEL_PROPERTIES = {
  operation: { type: 'string', enum: ['pixels', 'lsb', 'bitstream'], description: 'pixels 读像素；lsb 单页位平面；bitstream 连续位流分页。' },
  frame_index: FRAME_INDEX,
  region: {
    type: 'object', additionalProperties: false, required: REGION_KEYS,
    description: '选区（x/y/width/height），省略为全图。',
    properties: {
      x: { type: 'integer', minimum: 0, maximum: MAX_DIMENSION - 1 },
      y: { type: 'integer', minimum: 0, maximum: MAX_DIMENSION - 1 },
      width: { type: 'integer', minimum: 1, maximum: MAX_DIMENSION },
      height: { type: 'integer', minimum: 1, maximum: MAX_DIMENSION },
    },
  },
  pixel_offset: { type: 'integer', minimum: 0 },
  pixel_count: { type: 'integer', minimum: 1, maximum: MAX_PIXELS_PER_LSB_PAGE },
  channels: { type: 'array', minItems: 1, maxItems: 4, uniqueItems: true, items: { type: 'string', enum: CHANNELS } },
  bit_index: { type: 'integer', minimum: 0, maximum: 15 },
  bit_order: { type: 'string', enum: BIT_ORDERS },
  bit_offset: { type: 'integer', minimum: 0 },
  bit_count: { type: 'integer', minimum: 8, maximum: MAX_BITSTREAM_BITS_PER_PAGE },
};

export const MEDIA_PROPERTIES = {
  kind: { type: 'string', enum: MEDIA_KINDS, description: 'pdf/qr/audio/image/sqlite/office/model（AI 模型/Pickle 静态安全体检）。' },
  frame_index: FRAME_INDEX,
  page_offset: { type: 'integer', minimum: 0 },
  page_limit: { type: 'integer', minimum: 1, maximum: 4 },
  include_text: { type: 'boolean' },
  pdf_action: { type: 'string', enum: ['inspect', 'render_page', 'list_attachments', 'read_attachment'] },
  render_dpi: { type: 'integer', minimum: 36, maximum: 240 },
  attachment_index: { type: 'integer', minimum: 0, maximum: 63 },
  sqlite_table: { type: 'string', maxLength: 256 },
  sqlite_query: { type: 'string', maxLength: 4096, description: '只读 SELECT 查询。' },
  row_offset: { type: 'integer', minimum: 0, maximum: 1000000 },
  row_limit: { type: 'integer', minimum: 1, maximum: 100 },
  office_part: { type: 'string', maxLength: 256 },
};

function integer(value, fallback, minimum, maximum, name) {
  if (value === undefined) value = fallback;
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new ToolError('unsupported', name + ' 须是 ' + minimum + ' 至 ' + maximum + ' 之间的整数。');
  }
  return value;
}

export function parsePngRequest(args) {
  const { operation = 'pixels', region, channels, bit_order: bitOrder = 'msb_first' } = args;
  if (!['pixels', 'lsb', 'bitstream'].includes(operation)) throw new ToolError('unsupported', 'operation 须为 pixels、lsb 或 bitstream。');
  const lsb = operation !== 'pixels';
  if (!lsb && (args.bit_index !== undefined || args.bit_order !== undefined || args.bit_offset !== undefined || args.bit_count !== undefined)) {
    throw new ToolError('unsupported', '只有 lsb 可指定 bit_index 或 bit_order。');
  }
  if (operation !== 'bitstream' && (args.bit_offset !== undefined || args.bit_count !== undefined)) {
    throw new ToolError('unsupported', 'bit_offset 和 bit_count 只适用于 bitstream。');
  }
  if (operation === 'bitstream' && (args.pixel_offset !== undefined || args.pixel_count !== undefined)) {
    throw new ToolError('unsupported', 'bitstream 使用 bit_offset 和 bit_count 分页。');
  }
  if (!BIT_ORDERS.includes(bitOrder)) throw new ToolError('unsupported', 'bit_order 须为 msb_first 或 lsb_first。');
  if (channels !== undefined && (!Array.isArray(channels) || channels.length < 1 || channels.length > 4
    || new Set(channels).size !== channels.length || ![...channels].every(channel => CHANNELS.includes(channel)))) {
    throw new ToolError('unsupported', 'channels 须为 1 至 4 个不重复的通道名。');
  }
  let bounds;
  if (region !== undefined) {
    if (region === null || typeof region !== 'object' || Array.isArray(region)
      || Object.keys(region).length !== REGION_KEYS.length || !REGION_KEYS.every(name => Object.hasOwn(region, name))) {
      throw new ToolError('unsupported', 'region 须包含 x、y、width、height。');
    }
    bounds = {
      x: integer(region.x, undefined, 0, MAX_DIMENSION - 1, 'region.x'),
      y: integer(region.y, undefined, 0, MAX_DIMENSION - 1, 'region.y'),
      width: integer(region.width, undefined, 1, MAX_DIMENSION, 'region.width'),
      height: integer(region.height, undefined, 1, MAX_DIMENSION, 'region.height'),
    };
  }
  const bitOffset = operation === 'bitstream' ? integer(args.bit_offset, 0, 0, Number.MAX_SAFE_INTEGER, 'bit_offset') : undefined;
  const bitCount = operation === 'bitstream'
    ? integer(args.bit_count, MAX_BITSTREAM_BITS_PER_PAGE, 8, MAX_BITSTREAM_BITS_PER_PAGE, 'bit_count') : undefined;
  if (operation === 'bitstream' && (bitOffset % 8 !== 0 || bitCount % 8 !== 0)) {
    throw new ToolError('unsupported', 'bitstream 的 bit_offset 和 bit_count 必须按整字节对齐。');
  }
  return {
    kind: 'png', operation, region: bounds, channels,
    frame_index: integer(args.frame_index, 0, 0, 255, 'frame_index'),
    ...(operation === 'bitstream' ? {
      bit_offset: bitOffset,
      bit_count: bitCount,
    } : {
      pixel_offset: integer(args.pixel_offset, 0, 0, Number.MAX_SAFE_INTEGER, 'pixel_offset'),
      pixel_count: integer(args.pixel_count, lsb ? 256 : 16, 1, lsb ? MAX_PIXELS_PER_LSB_PAGE : MAX_PIXELS_PER_PAGE, 'pixel_count'),
    }),
    ...(lsb ? { bit_index: integer(args.bit_index, 0, 0, 15, 'bit_index'), bit_order: bitOrder } : {}),
  };
}

export function parseMediaRequest(args) {
  const { kind, page_offset: offset, page_limit: limit, include_text: includeText = false } = args;
  if (!MEDIA_KINDS.includes(kind)) throw new ToolError('unsupported', 'kind 须为 pdf、qr、audio、image、sqlite、office 或 model。');
  if (kind !== 'image' && args.frame_index !== undefined) throw new ToolError('unsupported', 'frame_index 只适用于 image。');
  if (kind === 'pdf') {
    if (args.sqlite_table !== undefined || args.sqlite_query !== undefined || args.row_offset !== undefined
      || args.row_limit !== undefined || args.office_part !== undefined) throw new ToolError('unsupported', 'PDF 不能使用 SQLite 或 Office 参数。');
    if (typeof includeText !== 'boolean') throw new ToolError('unsupported', 'include_text 须为布尔值。');
    const action = args.pdf_action ?? 'inspect';
    if (!['inspect', 'render_page', 'list_attachments', 'read_attachment'].includes(action)) throw new ToolError('unsupported', 'pdf_action 不受支持。');
    if (action === 'read_attachment' && args.attachment_index === undefined) throw new ToolError('unsupported', 'read_attachment 必须提供 attachment_index。');
    if (action !== 'read_attachment' && args.attachment_index !== undefined) throw new ToolError('unsupported', 'attachment_index 只适用于 read_attachment。');
    return { kind, pdf_action: action, include_text: includeText,
      page_offset: integer(offset, 0, 0, Number.MAX_SAFE_INTEGER, 'page_offset'),
      page_limit: integer(limit, 1, 1, 4, 'page_limit'),
      render_dpi: integer(args.render_dpi, 144, 36, 240, 'render_dpi'),
      ...(args.attachment_index === undefined ? {} : { attachment_index: integer(args.attachment_index, undefined, 0, 63, 'attachment_index') }),
    };
  }
  if (kind === 'sqlite') {
    if (offset !== undefined || limit !== undefined || args.include_text !== undefined || args.pdf_action !== undefined
      || args.attachment_index !== undefined || args.render_dpi !== undefined || args.office_part !== undefined) {
      throw new ToolError('unsupported', 'SQLite 不能使用 PDF 或 Office 参数。');
    }
    if (args.sqlite_table !== undefined && (typeof args.sqlite_table !== 'string' || args.sqlite_table.length > 256)) throw new ToolError('unsupported', 'sqlite_table 须是不超过 256 字符的字符串。');
    if (args.sqlite_query !== undefined && (typeof args.sqlite_query !== 'string' || args.sqlite_query.trim().length === 0 || args.sqlite_query.length > 4096)) throw new ToolError('unsupported', 'sqlite_query 须为 1 至 4096 字符。');
    return { kind, ...(args.sqlite_table === undefined ? {} : { table: args.sqlite_table }),
      ...(args.sqlite_query === undefined ? {} : { query: args.sqlite_query }),
      row_offset: integer(args.row_offset, 0, 0, 1000000, 'row_offset'),
      row_limit: integer(args.row_limit, 25, 1, 100, 'row_limit') };
  }
  if (kind === 'office') {
    if (offset !== undefined || limit !== undefined || args.include_text !== undefined || args.pdf_action !== undefined
      || args.attachment_index !== undefined || args.render_dpi !== undefined || args.sqlite_table !== undefined
      || args.sqlite_query !== undefined || args.row_offset !== undefined || args.row_limit !== undefined) {
      throw new ToolError('unsupported', 'Office 参数只支持 office_part。');
    }
    if (args.office_part !== undefined && (typeof args.office_part !== 'string' || args.office_part.length === 0 || args.office_part.length > 256)) {
      throw new ToolError('unsupported', 'office_part 须为 1 至 256 字符的部件路径。');
    }
    return { kind, ...(args.office_part === undefined ? {} : { part: args.office_part }) };
  }
  const allowed = kind === 'image' ? ['frame_index'] : [];
  if (Object.keys(args).some(key => !['kind', 'file_path', 'source_result_id', 'source_result_ids', 'expected_sha256'].includes(key)
    && !allowed.includes(key))) throw new ToolError('unsupported', `${kind} 不支持传入的专用参数。`);
  return kind === 'image' ? { kind, frame_index: integer(args.frame_index, 0, 0, 255, 'frame_index') } : { kind };
}

export async function inspectMedia(bytes, request, signal, workbench) {
  signal?.throwIfAborted();
  if (request.kind === 'audio') return inspectAudioMetadata(bytes);
  let python;
  try {
    python = await workbench.resolvePython(signal);
  } catch (error) {
    if (!(error instanceof WorkbenchDependencyError)) throw error;
    return { status: 'dependency_missing', dependency: 'Python', reason: error.message };
  }
  signal?.throwIfAborted();
  return new Promise((resolve, reject) => {
    const child = execFile(python, ['-E', '-P', '-B', '-X', 'utf8', SCRIPT_PATH, JSON.stringify(request)], {
      cwd: dirname(python), maxBuffer: 20 * 1024 * 1024, timeout: 30000, encoding: 'utf8', windowsHide: true, signal,
    }, (error, stdout) => {
      if (signal?.aborted) return reject(signal.reason);
      if (error) {
        return reject(new ToolError('timeout', error.killed ? '媒体检查超时。' : '本机媒体读取器未返回有效结果。'));
      }
      try {
        const report = JSON.parse(stdout);
        if (typeof report?.status !== 'string') throw new ToolError('unsupported', '工具执行失败。');
        if (typeof report.artifact_base64 === 'string') {
          const artifact = Buffer.from(report.artifact_base64, 'base64');
          delete report.artifact_base64;
          report.__artifact_bytes = artifact;
        }
        resolve(report);
      } catch {
        reject(new ToolError('unsupported', '本机媒体读取器未返回有效结果。'));
      }
    });
    child.stdin.on('error', () => {
      // The process callback reports early exits, including a closed input pipe.
    });
    child.stdin.end(bytes);
  });
}
