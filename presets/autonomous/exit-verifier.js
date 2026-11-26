import { createHash } from 'node:crypto';
import { ToolError } from '../../core/contracts/errors.js';

const DEFAULT_FLAG_RE = /^[A-Za-z0-9_]{1,24}\{[^{}\r\n]{4,256}\}$/u;

/**
 * Deterministic, machine-verifiable exit gate for autonomous runs and headless competition runners.
 */
export async function verifyExitCondition({
  flag,
  pattern,
  source,
  evidenceIds = [],
  localVerifyFn,
  submitResult,
  requireSubmission = false,
} = {}) {
  const trimmed = typeof flag === 'string' ? flag.trim() : '';
  const sha256 = trimmed ? createHash('sha256').update(trimmed, 'utf8').digest('hex') : null;
  const checks = [];

  const nonEmpty = trimmed.length >= 6 && trimmed.length <= 512 && !/\s/u.test(trimmed);
  checks.push({ name: 'non_empty_token', ok: nonEmpty, detail: nonEmpty ? 'ok' : 'flag 为空、含空白或长度异常。' });

  let formatOk = false;
  let formatDetail = '未匹配格式规则。';
  if (nonEmpty) {
    if (pattern) {
      try {
        formatOk = new RegExp(pattern, 'u').test(trimmed);
        formatDetail = formatOk ? 'matched_pattern' : `不匹配自定义格式 ${pattern}`;
      } catch {
        throw new ToolError('unsupported', 'verifyExitCondition 的 pattern 不是合法正则表达式。');
      }
    } else {
      formatOk = DEFAULT_FLAG_RE.test(trimmed);
      formatDetail = formatOk ? 'matched_default_flag_pattern' : '不符合 prefix{...} 形式。';
    }
  }
  checks.push({ name: 'flag_format', ok: formatOk, detail: formatDetail });

  const hasSource = (typeof source === 'string' && source.trim().length > 0)
    || (Array.isArray(evidenceIds) && evidenceIds.length > 0);
  checks.push({
    name: 'provenance',
    ok: hasSource,
    detail: hasSource ? 'ok' : '缺少 source 或 evidenceIds，拒绝无来源幻觉退出。',
  });

  if (typeof localVerifyFn === 'function') {
    let localOk = false;
    let localDetail = '';
    try {
      const res = await localVerifyFn(trimmed);
      localOk = res === true || res?.ok === true || res?.exit_code === 0;
      localDetail = res?.detail ?? (localOk ? 'local_verifier_passed' : 'local_verifier_failed');
    } catch (err) {
      localOk = false;
      localDetail = err?.message ?? 'local_verifier_threw';
    }
    checks.push({ name: 'local_verifier', ok: localOk, detail: localDetail });
  }

  if (requireSubmission || submitResult !== undefined) {
    const subOk = submitResult?.verdict === 'accepted' || submitResult?.verdict === 'duplicate' || submitResult?.ready === true;
    checks.push({
      name: 'platform_verdict',
      ok: subOk,
      detail: subOk ? `verdict=${submitResult.verdict}` : `未拿到平台 accepted/duplicate 回执（actual=${submitResult?.verdict ?? 'none'}）。`,
    });
  }

  const done = checks.every(c => c.ok);
  return {
    status: done ? 'verified' : 'incomplete',
    done,
    exit_code: done ? 0 : 2,
    ...(done ? { verified_flag: trimmed, verified_flag_sha256: sha256 } : { verified_flag_sha256: sha256 }),
    checks,
    reason: done ? 'All machine exit conditions verified.' : checks.filter(c => !c.ok).map(c => `${c.name}: ${c.detail}`).join('; '),
  };
}
