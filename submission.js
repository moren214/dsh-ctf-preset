import { createHash, randomUUID } from 'node:crypto';
import { Worker } from 'node:worker_threads';

const patternWorker = new URL('./flag-pattern-worker.js', import.meta.url);
const patternWorkers = new Set();
const PATTERN_TIMEOUT_MS = 500;
const MAX_PATTERN_WORKERS = 4;

export function classifyVerdict(response) {
  if (response?.truncated || response?.body_error) return 'unknown';
  const status = Number(response?.status ?? 0);
  // Authentication, throttling, and server failures say nothing about whether
  // the flag was right. Preserve the pending receipt as unknown in those cases.
  if (status === 401 || status === 403 || status === 408 || status === 425 || status === 429 || status >= 500) return 'unknown';
  let body = response?.body;
  if (typeof body !== 'string' || body.trim() === '') return 'unknown';
  try {
    body = JSON.parse(body);
  } catch {
    body = body.trim();
  }
  const notes = [body, body?.data];
  const labels = notes.flatMap(value => typeof value === 'string' ? [value] : [value?.verdict, value?.status, value?.result]);
  const named = new Set(labels.filter(value => typeof value === 'string').map(value => value.toLowerCase()));
  const has = names => names.some(name => named.has(name));
  const rejected = notes.some(value => value?.correct === false || value?.accepted === false || value?.success === false)
    || has(['incorrect', 'wrong', 'invalid', 'rejected']);
  const duplicate = notes.some(value => value?.duplicate === true) || has(['duplicate', 'already_solved', 'already_submitted']);
  const accepted = notes.some(value => value?.correct === true || value?.accepted === true)
    || has(['correct', 'accepted', 'solved']);
  if (rejected) return accepted || duplicate ? 'unknown' : 'rejected';
  if (duplicate) return !accepted && (status === 409 || (status >= 200 && status < 300)) ? 'duplicate' : 'unknown';
  if (accepted && status >= 200 && status < 300) return 'accepted';
  return 'unknown';
}

function scopePart(value) {
  return typeof value === 'string' && value.trim() !== '' ? value.trim().slice(0, 200) : undefined;
}

function matchesScope(receipt, scope) {
  return ['platform', 'challenge', 'instance'].every(key =>
    receipt[key] === undefined || scope[key] === undefined || receipt[key] === scope[key]);
}

function isSubmission(receipt) {
  return receipt.kind === 'submit' || (receipt.kind === undefined && receipt.verdict !== 'checked'
    && (receipt.platform_status != null || ['accepted', 'duplicate', 'unknown', 'pending'].includes(receipt.verdict)));
}

async function checkFormat(pattern, flag, signal) {
  if (pattern === undefined) {
    return { ok: /^[A-Za-z0-9_]{1,16}\{[^{}\r\n]{4,256}\}$/u.test(flag), detail: '默认要求 prefix{...} 形式。' };
  }
  if (typeof pattern !== 'string' || pattern.length === 0 || pattern.length > 200 || flag.length > 512) {
    return { ok: false, detail: 'pattern 或待校验文本超出允许范围。' };
  }
  signal?.throwIfAborted();
  if (patternWorkers.size >= MAX_PATTERN_WORKERS) return { ok: false, detail: '格式校验繁忙，请稍后重试。' };
  const worker = new Worker(patternWorker, { workerData: { pattern, flag }, execArgv: [],
    resourceLimits: { maxOldGenerationSizeMb: 24, maxYoungGenerationSizeMb: 4 } });
  patternWorkers.add(worker);
  try {
    return await new Promise((resolve, reject) => {
      const finish = (report, error) => {
        clearTimeout(timer);
        signal?.removeEventListener('abort', abort);
        if (error === undefined) resolve(report);
        else reject(error);
      };
      const abort = () => finish(undefined, signal.reason ?? new Error('格式校验已取消。'));
      const timer = setTimeout(() => finish({ ok: false, detail: '格式校验超时，请简化 pattern。' }), PATTERN_TIMEOUT_MS);
      worker.once('message', result => finish(result.invalid
        ? { ok: false, detail: 'pattern 不是有效正则。' }
        : { ok: result.matches === true, detail: '按题目配置的格式校验。' }));
      worker.on('error', () => finish({ ok: false, detail: '格式校验进程未完成。' }));
      worker.once('exit', () => finish({ ok: false, detail: '格式校验进程已结束。' }));
      signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) abort();
    });
  } finally {
    try { await worker.terminate(); }
    finally { patternWorkers.delete(worker); }
  }
}

function checksFor(args, flag, sha256, receipts, scope, format) {
  const retryUnknown = args.retry_unknown === true;
  const duplicate = receipts.filter(receipt => receipt.flag_sha256 === sha256 && isSubmission(receipt)
    && receipt.verdict !== 'rejected'
    && (!retryUnknown || (receipt.verdict !== 'unknown' && receipt.verdict !== 'pending'))
    && matchesScope(receipt, scope)).length;
  const checks = [
    { name: 'single_token', ok: flag.length > 0 && !/\s/u.test(flag), detail: 'flag 不能包含空白或换行。' },
    { name: 'length', ok: flag.length >= 6 && flag.length <= 512, detail: 'flag 长度应在 6 到 512 字符之间。' },
    { name: 'format', ...format },
    { name: 'source', ok: typeof args.source === 'string' && args.source.trim().length > 0, detail: '提交前记录结果来源。' },
    { name: 'not_duplicate', ok: duplicate === 0, detail: duplicate === 0 ? '无已完成或待确认的同项提交。'
      : '已有同项正式提交或待确认记录。若上次因 429/网络异常为 unknown，核对平台后可传 retry_unknown: true 重提。' },
  ];
  if (args.dynamic === true) {
    const age = Date.now() - Date.parse(args.refreshed_at ?? '');
    checks.push({ name: 'instance', ok: scope.instance !== undefined, detail: '动态 flag 要填写所属实例。' });
    checks.push({ name: 'freshness', ok: Number.isFinite(age) && age >= -5 * 60000 && age <= 30 * 60000,
      detail: '动态 flag 要填写 30 分钟内的实例刷新时间。' });
  }
  return { duplicate, checks, ready: checks.every(item => item.ok) };
}

export async function handleSubmission(args, files, submit, platform, signal) {
  const flag = typeof args.flag === 'string' ? args.flag.trim() : '';
  const sha256 = createHash('sha256').update(flag).digest('hex');
  const scope = { platform, challenge: scopePart(args.challenge), instance: scopePart(args.instance) };
  const base = { flag_sha256: sha256, ...scope };
  const format = await checkFormat(args.pattern, flag, signal);
  const preflight = receipts => checksFor(args, flag, sha256, receipts, scope, format);
  if (submit === undefined) {
    const { receipts, document, corruptedLines } = await files.read();
    const check = preflight(receipts);
    if (args.record === true) {
      await files.write(document, [...receipts, { ...base, at: new Date().toISOString(), kind: 'check', verdict: 'checked', ready: check.ready }]);
    }
    return { status: 'checked', ...check, receipts: receipts.length, flag_sha256: sha256, corrupted_receipts: corruptedLines };
  }

  const { receipts, document, corruptedLines } = await files.read();
  const check = preflight(receipts);
  if (!check.ready) return { status: 'rejected', verdict: 'rejected_local', ...check, receipts: receipts.length, flag_sha256: sha256, corrupted_receipts: corruptedLines };
  if (platform === undefined) throw new Error('未配置竞赛平台地址。');

  const id = randomUUID();
  const pending = { ...base, id, at: new Date().toISOString(), kind: 'submit', verdict: 'pending' };
  // Claim the attempt before calling the platform. A conflicting writer never sends a request.
  await files.write(document, [...receipts, pending]);
  let response;
  try {
    response = await submit({ ...(scope.challenge === undefined ? {} : { challenge: scope.challenge }), flag });
  } catch {
    // An interrupted request may already have reached the platform.
  }
  const verdict = classifyVerdict(response);
  const outcome = { ...pending, verdict, platform_status: response?.status ?? null };
  let recorded = false;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const current = await files.read();
      const index = current.receipts.findIndex(item => item.id === id);
      if (index < 0) break;
      const updated = current.receipts.with(index, outcome);
      await files.write(current.document, updated);
      recorded = true;
      break;
    } catch {
      // Preserve the pending receipt if an update cannot be committed.
    }
  }
  return { status: verdict === 'unknown' ? 'unconfirmed' : 'submitted', verdict, ready: verdict === 'accepted',
    platform_status: outcome.platform_status, checks: check.checks, receipts: receipts.length + 1,
    flag_sha256: sha256, receipt_id: id, receipt_recorded: recorded, corrupted_receipts: corruptedLines };
}
