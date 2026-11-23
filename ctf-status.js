import { randomUUID } from 'node:crypto';
import { ToolError } from './tool-errors.js';

export const STATUS_FILE = '.ctf-status.json';
const STATUS_BACKUP = '.ctf/status.saved.json';
const MAX_ENTRIES = 60;
const ATTEMPTS = 3;

function entriesIn(document, normalizeEntry) {
  if (document.version === undefined) return [];
  try {
    if (document.invalidText) throw new Error('Invalid text');
    const { entries } = JSON.parse(document.text);
    if (Array.isArray(entries) && entries.length <= MAX_ENTRIES
      && entries.every(entry => entry && typeof entry === 'object' && Number.isFinite(Date.parse(entry.at)))) {
      return entries.map(normalizeEntry);
    }
  } catch {
    // Let the caller try the last committed copy.
  }
  return undefined;
}

async function readStatus(files) {
  const document = await files.read(STATUS_FILE);
  const entries = entriesIn(document, files.normalizeEntry);
  if (entries !== undefined && document.version !== undefined) return { document, entries, recovered: false };
  const backup = await files.read(STATUS_BACKUP);
  if (backup.version !== undefined) {
    const saved = entriesIn(backup, files.normalizeEntry);
    if (saved !== undefined) return { document, entries: saved, recovered: true };
  }
  if (entries !== undefined) return { document, entries, recovered: false };
  throw new ToolError('encoding', '状态文件和恢复副本均不可读。');
}

async function preserveLatest(files, body) {
  for (let attempt = 0; attempt < ATTEMPTS; attempt++) {
    const backup = await files.read(STATUS_BACKUP);
    if (backup.text === body || (await files.read(STATUS_FILE)).text !== body) return;
    try {
      await files.write(backup, body);
      return;
    } catch (error) {
      if (attempt + 1 === ATTEMPTS || (await files.read(STATUS_BACKUP)).version === backup.version) throw error;
    }
  }
}

export async function readStatusHistory(files) {
  const { entries, recovered } = await readStatus(files);
  return { entries, recovered };
}

export async function appendStatus(files, summary) {
  const entry = { at: new Date().toISOString(), record_id: randomUUID(), ...summary };
  for (let attempt = 0; attempt < ATTEMPTS; attempt++) {
    const { document, entries, recovered } = await readStatus(files);
    const next = [...entries, entry].slice(-MAX_ENTRIES);
    const body = JSON.stringify({ entries: next }, null, 2) + '\n';
    try {
      await files.write(document, body);
    } catch (error) {
      const current = await files.read(STATUS_FILE);
      if (entriesIn(current, files.normalizeEntry)?.some(item => item.record_id === entry.record_id)) {
        return { entries: entriesIn(current, files.normalizeEntry), recovered, entry };
      }
      if (current.version === document.version) throw error;
      if (attempt + 1 === ATTEMPTS) throw new ToolError('conflict', '状态记录正被其他会话更新，重试次数已用完。');
      continue;
    }
    let warning;
    try { await preserveLatest(files, body); }
    catch { warning = '状态已提交，恢复副本尚未刷新。'; }
    return { entries: next, recovered, entry, warning };
  }
}

function minutesSince(entry) {
  return Math.max(0, Math.floor((Date.now() - Date.parse(entry.at)) / 60000));
}

export function summarizeStatus(entries) {
  const warnings = [];
  const last = entries.at(-1);
  if (last) {
    const elapsed = minutesSince(last);
    const thresholds = [
      [60, 'timebox_escalate', 'escalate', '整理卡点并求助，带上候选路径与排除证据。'],
      [30, 'timebox_review', 'warning', '列出三条候选路径及各自的验证代价。'],
      [15, 'timebox_switch', 'info', '检查有无新假设，并排除一条已经尝试的路径。'],
    ];
    const threshold = thresholds.find(([minutes]) => elapsed >= minutes);
    if (threshold) {
      const [minutes, code, severity, message] = threshold;
      warnings.push({ code, severity, elapsed_minutes: elapsed, threshold_minutes: minutes, message });
    }
    if (!last.next_step && last.phase !== 'scoreboard') warnings.push({
      code: 'next_step_missing', severity: 'info', message: '补一条具体可执行的下一步。',
    });
  }
  if (entries.length < 2) warnings.push({
    code: 'too_few_records', severity: 'info', message: '本题状态记录不足 2 条。',
  });
  return { records: entries.length, elapsed_minutes: entries.length ? minutesSince(entries[0]) : 0, last, warnings };
}
