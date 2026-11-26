import { createHash } from 'node:crypto';
import { ToolError } from './tool-errors.js';

const HASH_CHUNK_BYTES = 4 * 1024 * 1024;
const CACHED_FILES = 8;
const UTF8_LOOKAROUND = 3;
export const MAX_LOG_WINDOW_BYTES = 4096;

export class WorkspaceFileError extends Error {
  constructor(message, kind = 'path') {
    super(message);
    this.kind = kind;
  }
}

export async function requireCurrentFile(fs, file, signal) {
  const after = await fs.stat(file.target, signal);
  if (after?.type !== 'file' || after.size !== file.size || after.version !== file.version) {
    throw new WorkspaceFileError('附件在读取期间发生变化，请确认文件保存完毕再核验。', 'conflict');
  }
  signal?.throwIfAborted();
}

export function checkAttachmentHash(expected, actual) {
  if (expected !== undefined && expected !== actual) {
    throw new ToolError('conflict', '原件 SHA-256 与待核对的值不同，请重新读取第一页或第一段。');
  }
}

async function hashRanges(size, read, visit) {
  const hash = createHash('sha256');
  for (let offset = 0; offset < size; offset += HASH_CHUNK_BYTES) {
    const bytes = await read(offset, Math.min(HASH_CHUNK_BYTES, size - offset));
    hash.update(bytes);
    visit?.(bytes, offset);
  }
  return hash.digest('hex');
}

export async function inspectEvidenceLines({ size, read }, references) {
  const requested = new Set(references.filter(reference => reference.line !== undefined).map(reference => reference.line));
  const lastLine = Math.max(...requested);
  const lines = new Map();
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  let number = 1;
  let start = 0;
  let afterCR = false;
  let valid = true;

  function finishLine(end) {
    if (requested.has(number)) lines.set(number, { start, end });
  }

  function visit(bytes, offset) {
    if (!valid) return;
    try {
      decoder.decode(bytes, { stream: true });
      if (bytes.includes(0)) valid = false;
    } catch {
      valid = false;
    }
    if (!valid) return;
    for (let index = 0; index < bytes.length && number <= lastLine; index++) {
      const byte = bytes[index];
      if (afterCR) {
        afterCR = false;
        if (byte === 0x0a) {
          start = offset + index + 1;
          continue;
        }
      }
      if (byte === 0x0a || byte === 0x0d) {
        finishLine(offset + index);
        start = offset + index + 1;
        number++;
        afterCR = byte === 0x0d;
      }
    }
  }

  const sha256 = await hashRanges(size, read, visit);
  try {
    decoder.decode();
  } catch {
    valid = false;
  }
  if (valid) finishLine(size);
  return { report: { sha256, line_bounds: valid ? lines : new Map() } };
}

export function createRangeInspector(fs) {
  const cache = new Map();
  return async (file, signal, expectedHash, inspect, { hashFile = true } = {}) => {
    const { size, target, version } = file;
    if (!Number.isSafeInteger(size) || size < 0 || typeof version !== 'string' || version === '') {
      throw new WorkspaceFileError('无法核对原件的大小和版本。');
    }

    const previous = cache.get(target.targetKey);
    const cached = previous?.version === version && previous.size === size ? previous : undefined;
    let bytesRead = 0;
    async function read(offset, length) {
      if (length === 0) return Buffer.alloc(0);
      signal?.throwIfAborted();
      const bytes = await fs.readByteRange(target, { offset, length }, signal);
      if (bytes.byteLength !== length) {
        throw new WorkspaceFileError('附件读取长度与原件记录不符，请确认文件保存完毕再核验。');
      }
      bytesRead += bytes.byteLength;
      return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    }

    const inspection = await inspect({ size, read }, cached?.zipIndex);
    if (inspection === undefined) return undefined;
    if (!hashFile) {
      await requireCurrentFile(fs, file, signal);
      return { ...inspection.report, size, bytes_read: bytesRead };
    }

    const sha256 = cached?.sha256 ?? await hashRanges(size, read);
    await requireCurrentFile(fs, file, signal);
    cache.delete(target.targetKey);
    cache.set(target.targetKey, { size, version, sha256, zipIndex: inspection.zipIndex ?? cached?.zipIndex });
    if (cache.size > CACHED_FILES) cache.delete(cache.keys().next().value);
    checkAttachmentHash(expectedHash, sha256);
    return { ...inspection.report, size, sha256, hash_reused: cached !== undefined, bytes_read: bytesRead };
  };
}

export async function inspectLogWindow({ size, read }, offset, length) {
  if (offset > size) throw new ToolError('size', 'byte_offset 超出了原件大小。');
  if (offset === size) return { report: { byte_offset: offset, byte_length: 0, next_byte_offset: null, text: '' } };

  const first = Math.max(0, offset - UTF8_LOOKAROUND);
  const last = offset + Math.min(size - offset, length + UTF8_LOOKAROUND);
  const bytes = await read(first, last - first);
  let start = offset - first;
  let end = start + Math.min(size - offset, length);
  while (start > 0 && (bytes[start] & 0xc0) === 0x80) start--;
  while (end < bytes.length && (bytes[end] & 0xc0) === 0x80) end++;

  let text;
  try {
    const snippet = bytes.subarray(start, end);
    if (snippet.includes(0)) throw new ToolError('encoding', '包含 NUL 字节');
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(snippet);
  } catch {
    throw new ToolError('encoding', '所选范围须是有效的 UTF-8 文本。');
  }
  return { report: {
    byte_offset: first + start,
    byte_length: end - start,
    next_byte_offset: first + end < size ? first + end : null,
    text,
  } };
}
