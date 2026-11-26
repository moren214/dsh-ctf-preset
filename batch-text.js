import { createHash } from 'node:crypto';
import { decodeEvidenceText, lineBounds } from './evidence.js';
import { ToolError } from './tool-errors.js';

export const MAX_BATCH_FILE_BYTES = 8 * 1024 * 1024;
const MAX_RANGES = 10;
const MAX_LINES = 160;
const MAX_RANGE_BYTES = 4096;
const TOTAL_TEXT_BYTES = 8192;

export const BATCH_TEXT_PROPERTIES = {
  files: {
    type: 'array', minItems: 1, maxItems: MAX_RANGES,
    description: '题面给定的文本文件和需要的行段，支持在同一批中读取不同子目录。',
    items: {
      type: 'object', additionalProperties: false, required: ['file_path'],
      properties: {
        file_path: { type: 'string', description: '相对于当前题目目录的路径。' },
        start_line: { type: 'integer', minimum: 1, default: 1 },
        line_count: { type: 'integer', minimum: 1, maximum: MAX_LINES, default: 64 },
      },
    },
  },
};

function requestRanges(files, normalizePath) {
  if (!Array.isArray(files) || files.length < 1 || files.length > MAX_RANGES) throw new ToolError('unsupported', '请选择 1 至 10 段本地文本。');
  return files.map(range => {
    if (!range || typeof range !== 'object' || Array.isArray(range)
      || Object.keys(range).some(key => !['file_path', 'start_line', 'line_count'].includes(key))) {
      throw new ToolError('unsupported', '文本范围须包含原件路径，可附行号及行数。');
    }
    const { start_line = 1, line_count = 64 } = range;
    if (!Number.isSafeInteger(start_line) || start_line < 1 || !Number.isSafeInteger(line_count) || line_count < 1 || line_count > MAX_LINES) {
      throw new ToolError('unsupported', '起始行从 1 开始，每段最多读 160 行。');
    }
    return { file_path: normalizePath(range.file_path), start_line, line_count };
  });
}

function window(text, start, count, allowance) {
  const first = lineBounds(text, start);
  if (first === null) return { status: 'out_of_range' };
  const after = lineBounds(text, start + count);
  const wanted = text.slice(first.start, after?.start ?? text.length);
  const byte_offset = Buffer.byteLength(text.slice(0, first.start), 'utf8');
  let length = 0;
  let used = 0;
  let lines = 0;
  for (const [row] of wanted.matchAll(/[^\r\n]+(?:\r\n|\r|\n)?|\r\n|\r|\n/gu)) {
    const bytes = Buffer.byteLength(row, 'utf8');
    if (used + bytes > allowance) break;
    used += bytes;
    length += row.length;
    lines++;
  }
  const partial = length < wanted.length;
  if (partial && lines === 0) return { status: 'line_too_large', byte_offset, next_line: start };
  return {
    status: partial ? 'partial' : 'read', start_line: start, end_line: start + Math.max(1, lines) - 1,
    byte_offset, byte_length: used, text: wanted.slice(0, length),
    next_line: partial || (after && after.start < text.length) ? start + lines : undefined,
  };
}

export async function readCtfFiles(args, files) {
  const requests = requestRanges(args.files, files.normalizePath);
  const opened = new Map();
  const sources = [];
  const items = [];
  let used = 0;
  for (const [index, { file_path, start_line, line_count }] of requests.entries()) {
    if (!opened.has(file_path)) {
      const snapshot = await files.read(file_path);
      if (snapshot) {
        const sha256 = createHash('sha256').update(snapshot.bytes).digest('hex');
        const source = { file_path, sha256 };
        opened.set(file_path, { source, text: decodeEvidenceText(snapshot.bytes) });
        sources.push(source);
      } else {
        opened.set(file_path, null);
      }
    }
    const file = opened.get(file_path);
    if (file === null || file.text === null) {
      items.push({ file_path, status: file === null ? 'unavailable' : 'unsupported_text', source: file?.source });
      continue;
    }
    const allowance = Math.min(MAX_RANGE_BYTES, Math.floor((TOTAL_TEXT_BYTES - used) / (requests.length - index)));
    const content = window(file.text, start_line, line_count, allowance);
    used += content.byte_length ?? 0;
    const source = content.status === 'out_of_range' ? file.source : { ...file.source, line: start_line };
    items.push({ ...content, source });
  }
  return { status: items.every(item => item.status === 'read') ? 'ok' : 'partial', items, sources };
}
