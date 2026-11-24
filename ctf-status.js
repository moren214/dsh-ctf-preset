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
  return Math.max(0, Math.round((Date.now() - Date.parse(entry.at)) / 60000));
}

export function summarizeStatus(entries) {
  const warnings = [];
  const add = (code, severity, message, action, thresholdMinutes) =>
    warnings.push({ code, severity, message, action, ...(thresholdMinutes === undefined ? {} : { threshold_minutes: thresholdMinutes }) });
  const last = entries.at(-1);
  if (last) {
    const minutes = minutesSince(last);
    if (minutes >= 60) add('timebox_60', 'urgent', '距上一条状态已 ' + minutes + ' 分钟：整理卡点并升级求助，给出三条候选路径和排除证据。', '升级求助并比较三条路径。', 60);
    else if (minutes >= 30) add('timebox_30', 'warning', '距上一条状态已 ' + minutes + ' 分钟：列出三条候选路径，写清各自的验证代价。', '列出三条候选路径并选择验证成本最低的一条。', 30);
    else if (minutes >= 15) add('timebox_15', 'info', '距上一条状态已 ' + minutes + ' 分钟：没有新假设就换方向，先排除一条已走路径。', '核对新假设或排除一条已走路径。', 15);
    if (!last.next_step && last.phase !== 'scoreboard') {
      add('next_step_missing', 'warning', '本条状态没有写 next_step：补一条具体可执行的下一步。', '保存一个可执行的下一步。');
    }
  }
  if (entries.length < 2) {
    add('status_records_low', 'info', '本题状态记录不足 2 条，收尾前至少再记录一次。', '收尾前补一条状态记录。');
  }
  return { records: entries.length, elapsed_minutes: entries.length ? minutesSince(entries[0]) : 0, last, warnings };
}
