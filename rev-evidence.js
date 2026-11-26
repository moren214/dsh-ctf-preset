import { createHash } from 'node:crypto';
import { decodeEvidenceText, locatedTextRows } from './evidence.js';
import { ToolError } from './tool-errors.js';

export const MAX_REV_TEXT_BYTES = 8 * 1024 * 1024;
export const MAX_REV_ADDRESS = (1n << 64n) - 1n;
export const REV_HEX_ADDRESS = { type: 'string', pattern: '^0x[0-9a-fA-F]{1,16}$' };

export function revAddress(value) {
  return typeof value === 'string' && /^0x[\da-f]{1,16}$/iu.test(value) ? BigInt(value) : undefined;
}

export function hexAddress(value) {
  return `0x${value.toString(16)}`;
}

export function revText(bytes, file_path, limit = 50000) {
  const text = decodeEvidenceText(bytes);
  if (text === null) throw new ToolError('encoding', `Rev 证据须为 UTF-8 文本。${file_path}`);
  const source = { file_path, sha256: createHash('sha256').update(bytes).digest('hex') };
  return { source, rows: locatedTextRows(text, limit, '每份 Rev 原件') };
}
