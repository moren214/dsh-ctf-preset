import { execFile } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { inspectAudioMetadata } from './audio-metadata.js';
import { WorkbenchDependencyError } from './workbench-config.js';

const SCRIPT = readFileSync(new URL('./media-reader-worker.py', import.meta.url), 'utf8');
const MAX_PIXELS_PER_PAGE = 128;
const MAX_PIXELS_PER_LSB_PAGE = 8192;
const CHANNELS = ['L', 'P', 'R', 'G', 'B', 'A'];
const BIT_ORDERS = ['msb_first', 'lsb_first'];
const MEDIA_KINDS = ['pdf', 'qr', 'audio', 'image'];
const REGION_KEYS = ['x', 'y', 'width', 'height'];
const MAX_DIMENSION = 16384;
const FRAME_INDEX = { type: 'integer', minimum: 0, maximum: 255, description: '图像帧或 TIFF 页，从零起算，默认 0。' };

export const PNG_PIXEL_PROPERTIES = {
  operation: { type: 'string', enum: ['pixels', 'lsb'], description: '读取原始样本或提取单个位平面。默认 pixels。' },
  frame_index: FRAME_INDEX,
  region: {
    type: 'object', additionalProperties: false, required: REGION_KEYS,
    description: '从零起算的坐标。省略时选取整张图片。区域按先行后列读取。',
    properties: {
      x: { type: 'integer', minimum: 0, maximum: MAX_DIMENSION - 1 },
      y: { type: 'integer', minimum: 0, maximum: MAX_DIMENSION - 1 },
      width: { type: 'integer', minimum: 1, maximum: MAX_DIMENSION },
      height: { type: 'integer', minimum: 1, maximum: MAX_DIMENSION },
    },
  },
  pixel_offset: { type: 'integer', minimum: 0, description: '所选区域内从零起算的像素序号。续读用 next_pixel_offset。' },
  pixel_count: {
    type: 'integer', minimum: 1, maximum: MAX_PIXELS_PER_LSB_PAGE,
    description: '每页像素数。pixels 默认 16、最多 128。lsb 默认 256、最多 8192。',
  },
  channels: {
    type: 'array', minItems: 1, maxItems: 4, uniqueItems: true,
    items: { type: 'string', enum: CHANNELS },
    description: '按给定顺序读通道。省略时用图像的原始通道顺序，索引色用 P。',
  },
  bit_index: { type: 'integer', minimum: 0, maximum: 15, description: '从最低位 0 起算，只用于 lsb。' },
  bit_order: { type: 'string', enum: BIT_ORDERS, description: '提取位在输出字节内的排列。默认 msb_first。' },
};

export const MEDIA_PROPERTIES = {
  kind: { type: 'string', enum: MEDIA_KINDS, description: '读取 PDF、图像元数据、二维码或音频元数据。' },
  frame_index: FRAME_INDEX,
  page_offset: { type: 'integer', minimum: 0, description: 'PDF 的首个页序号，从零起算。默认 0。' },
  page_limit: { type: 'integer', minimum: 1, maximum: 4, description: '每次检查的 PDF 页数。默认 1。' },
  include_text: { type: 'boolean', description: '是否返回所选 PDF 页面内嵌的文本预览。默认 false。' },
};

function integer(value, fallback, minimum, maximum, name) {
  if (value === undefined) value = fallback;
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(name + ' 须是 ' + minimum + ' 至 ' + maximum + ' 之间的整数。');
  }
  return value;
}

export function parsePngRequest(args) {
  const { operation = 'pixels', region, channels, bit_order: bitOrder = 'msb_first' } = args;
  if (operation !== 'pixels' && operation !== 'lsb') throw new Error('operation 须为 pixels 或 lsb。');
  const lsb = operation === 'lsb';
  if (!lsb && (args.bit_index !== undefined || args.bit_order !== undefined)) {
    throw new Error('只有 lsb 可指定 bit_index 或 bit_order。');
  }
  if (!BIT_ORDERS.includes(bitOrder)) throw new Error('bit_order 须为 msb_first 或 lsb_first。');
  if (channels !== undefined && (!Array.isArray(channels) || channels.length < 1 || channels.length > 4
    || new Set(channels).size !== channels.length || ![...channels].every(channel => CHANNELS.includes(channel)))) {
    throw new Error('channels 须为 1 至 4 个不重复的通道名。');
  }
  let bounds;
  if (region !== undefined) {
    if (region === null || typeof region !== 'object' || Array.isArray(region)
      || Object.keys(region).length !== REGION_KEYS.length || !REGION_KEYS.every(name => Object.hasOwn(region, name))) {
      throw new Error('region 须包含 x、y、width、height。');
    }
    bounds = {
      x: integer(region.x, undefined, 0, MAX_DIMENSION - 1, 'region.x'),
      y: integer(region.y, undefined, 0, MAX_DIMENSION - 1, 'region.y'),
      width: integer(region.width, undefined, 1, MAX_DIMENSION, 'region.width'),
      height: integer(region.height, undefined, 1, MAX_DIMENSION, 'region.height'),
    };
  }
  return {
    kind: 'png', operation, region: bounds, channels,
    frame_index: integer(args.frame_index, 0, 0, 255, 'frame_index'),
    pixel_offset: integer(args.pixel_offset, 0, 0, Number.MAX_SAFE_INTEGER, 'pixel_offset'),
    pixel_count: integer(args.pixel_count, lsb ? 256 : 16, 1, lsb ? MAX_PIXELS_PER_LSB_PAGE : MAX_PIXELS_PER_PAGE, 'pixel_count'),
    ...(lsb ? { bit_index: integer(args.bit_index, 0, 0, 15, 'bit_index'), bit_order: bitOrder } : {}),
  };
}

export function parseMediaRequest(args) {
  const { kind, page_offset: offset, page_limit: limit, include_text: includeText = false } = args;
  if (!MEDIA_KINDS.includes(kind)) throw new Error('kind 须为 pdf、qr、audio 或 image。');
  if (kind !== 'image' && args.frame_index !== undefined) throw new Error('frame_index 只适用于 image。');
  if (kind !== 'pdf') {
    if (offset !== undefined || limit !== undefined || args.include_text !== undefined) {
      throw new Error('page_offset、page_limit 和 include_text 只适用于 PDF。');
    }
    return kind === 'image' ? { kind, frame_index: integer(args.frame_index, 0, 0, 255, 'frame_index') } : { kind };
  }
  if (typeof includeText !== 'boolean') throw new Error('include_text 须为布尔值。');
  return {
    kind, include_text: includeText,
    page_offset: integer(offset, 0, 0, Number.MAX_SAFE_INTEGER, 'page_offset'),
    page_limit: integer(limit, 1, 1, 4, 'page_limit'),
  };
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
    const child = execFile(python, ['-I', '-B', '-X', 'utf8', '-c', SCRIPT, JSON.stringify(request)], {
      cwd: dirname(python), maxBuffer: 256 * 1024, timeout: 15000, encoding: 'utf8', windowsHide: true, signal,
    }, (error, stdout) => {
      if (signal?.aborted) return reject(signal.reason);
      if (error) {
        return reject(new Error(error.killed ? '媒体检查超时。' : '本机媒体读取器未返回有效结果。'));
      }
      try {
        const report = JSON.parse(stdout);
        if (typeof report?.status !== 'string') throw new Error();
        resolve(report);
      } catch {
        reject(new Error('本机媒体读取器未返回有效结果。'));
      }
    });
    child.stdin.on('error', () => {
      // The process callback reports early exits, including a closed input pipe.
    });
    child.stdin.end(bytes);
  });
}
