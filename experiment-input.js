import { createHash } from 'node:crypto';
import { ATTACHMENT_OPERATIONS } from './offline-calculation.js';

export const EXPERIMENT_TOOLS = ['scan_binary', 'inspect_attachment', 'read_binary_range', 'read_archive_member', 'calculate_offline'];

function canonical(value, depth = 0) {
  if (depth > 12) throw new Error('input nesting');
  if (Array.isArray(value)) return value.map(item => canonical(item, depth + 1));
  if (value === null || typeof value !== 'object') return value;
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key], depth + 1)]));
}

export function experimentRequestHash(tool, args) {
  if (!EXPERIMENT_TOOLS.includes(tool) || args === null || typeof args !== 'object' || Array.isArray(args)
    || (tool === 'read_archive_member' && args.password !== undefined)) return undefined;
  if (tool === 'calculate_offline' && (!Array.isArray(args.steps)
    || args.steps.some(step => !ATTACHMENT_OPERATIONS.includes(step?.operation)))) return undefined;
  try {
    const input = { ...args };
    if (tool === 'calculate_offline') {
      delete input.resume_id;
      delete input.checkpoint_scope;
    }
    const json = JSON.stringify(input);
    if (Buffer.byteLength(json) > 8192) return undefined;
    return createHash('sha256').update(tool).update('\0').update(JSON.stringify(canonical(input))).digest('hex');
  } catch {
    return undefined;
  }
}
