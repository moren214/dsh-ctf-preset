import { createHash } from 'node:crypto';
import { CALCULATION_RESUME_ID } from './offline-calculation.js';
import { ToolError } from './tool-errors.js';

export const CHECKPOINT_INDEX_BYTES = 2 * 1024 * 1024;
const MAX_CHECKPOINT_BYTES = 192 * 1024;
const MAX_WORKSPACE_CHECKPOINTS = 8;
const checkpointId = payload => createHash('sha256').update(payload).digest('hex').slice(0, 32);

export function encodeCheckpoint(digest, steps, completed) {
  const records = completed.map((record, index) => Object.fromEntries(
    Object.entries(record).filter(([key]) => key !== 'step' && !Object.hasOwn(steps[index], key)),
  ));
  const payload = JSON.stringify({ version: 1, digest, records });
  if (Buffer.byteLength(payload) > MAX_CHECKPOINT_BYTES) {
    throw new ToolError('size', '完整中间结果超过工作区检查点的 192 KiB 上限。');
  }
  return { id: checkpointId(payload), payload };
}

export function restoreCheckpoint(payload, id, digest, steps) {
  const conflict = () => new ToolError('conflict', '工作区检查点已失效或原计算参数已变化。请核对目录、步骤和编号。');
  if (typeof payload !== 'string' || Buffer.byteLength(payload) > MAX_CHECKPOINT_BYTES || checkpointId(payload) !== id) {
    throw conflict();
  }
  let checkpoint;
  try { checkpoint = JSON.parse(payload); } catch { throw conflict(); }
  const records = checkpoint?.records;
  if (checkpoint?.version !== 1 || checkpoint.digest !== digest || !Array.isArray(records)
    || records.length < 1 || records.length >= steps.length || !records.every((record, index) =>
      record !== null && typeof record === 'object' && !Array.isArray(record)
      && Object.keys(record).every(key => key !== 'step' && !Object.hasOwn(steps[index], key))
      && (record.status === 'computed' ? typeof record.result === 'string'
        : ['error', 'blocked'].includes(record.status) && record.result === undefined))) {
    throw conflict();
  }
  return records.map((record, index) => ({ step: index + 1, ...steps[index], ...record }));
}

function checkpointEntries(text) {
  if (!text) return [];
  const invalid = () => new ToolError('conflict', '工作区计算检查点索引损坏或超过大小上限。');
  if (Buffer.byteLength(text) > CHECKPOINT_INDEX_BYTES) throw invalid();
  let index;
  try { index = JSON.parse(text); } catch { throw invalid(); }
  if (index?.version !== 1 || !Array.isArray(index.entries) || index.entries.length > MAX_WORKSPACE_CHECKPOINTS
    || !index.entries.every(entry => typeof entry?.id === 'string' && CALCULATION_RESUME_ID.test(entry.id)
      && typeof entry.payload === 'string' && Buffer.byteLength(entry.payload) <= MAX_CHECKPOINT_BYTES)) throw invalid();
  return index.entries;
}

export function findWorkspaceCheckpoint(text, id) {
  return checkpointEntries(text).find(entry => entry.id === id)?.payload;
}

export function appendWorkspaceCheckpoint(text, checkpoint) {
  const entries = checkpointEntries(text);
  if (entries.some(entry => entry.id === checkpoint.id && entry.payload === checkpoint.payload)) return text;
  const next = [...entries.filter(entry => entry.id !== checkpoint.id), checkpoint].slice(-MAX_WORKSPACE_CHECKPOINTS);
  const serialize = () => JSON.stringify({ version: 1, entries: next }) + '\n';
  let updated = serialize();
  while (Buffer.byteLength(updated) > CHECKPOINT_INDEX_BYTES && next.length > 1) {
    next.shift();
    updated = serialize();
  }
  return updated;
}
