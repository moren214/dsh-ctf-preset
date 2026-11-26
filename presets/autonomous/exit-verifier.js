import { createHash } from 'node:crypto';
import { ToolError } from '../../core/contracts/errors.js';

const DEFAULT_FLAG_RE = /^[A-Za-z0-9_]{1,24}\{[^{}\r\n]{4,256}\}$/u;
const RESULT_ID_RE = /^[a-f0-9]{64}$/u;
const SUBMISSION_TOOLS = new Set(['submit_flag', 'ctf_arena']);
const ACCEPTED_VERDICTS = new Set(['accepted', 'duplicate', 'already_solved', 'already_submitted']);

function containsFlag(value, flag, seen = new Set()) {
  if (typeof value === 'string') return value.includes(flag);
  if (value === null || typeof value !== 'object' || seen.has(value)) return false;
  seen.add(value);
  if (value instanceof Map) {
    for (const item of value.values()) if (containsFlag(item, flag, seen)) return true;
    return false;
  }
  if (Array.isArray(value)) return value.some(item => containsFlag(item, flag, seen));
  return Object.values(value).some(item => containsFlag(item, flag, seen));
}

function collectReceiptFields(record) {
  const fields = [];
  const visit = (value, seen = new Set()) => {
    if (value === null || typeof value !== 'object' || seen.has(value)) return;
    seen.add(value);
    if (value instanceof Map) {
      for (const item of value.values()) visit(item, seen);
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) visit(item, seen);
      return;
    }
    fields.push(value);
    for (const item of Object.values(value)) visit(item, seen);
  };
  visit(record?.report ?? record);
  return fields;
}

/** Only accept receipts produced by the registered platform submission tools. */
export function isAcceptedSubmissionEvidence(record, flag) {
  if (!SUBMISSION_TOOLS.has(record?.tool)) return false;
  if (record.tool === 'ctf_arena' && record.report?.action !== 'submit') return false;
  const flagHash = createHash('sha256').update(flag, 'utf8').digest('hex');
  return collectReceiptFields(record).some(field => {
    const verdict = String(field.verdict ?? field.status ?? field.result ?? '').toLowerCase();
    const accepted = ACCEPTED_VERDICTS.has(verdict)
      || field.accepted === true
      || field.correct === true;
    const matchesFlag = field.flag === flag
      || field.flag_sha256 === flagHash
      || field.verified_flag_sha256 === flagHash;
    return accepted && matchesFlag;
  });
}

/**
 * A source path or an arbitrary result id is provenance text, not verification.
 * Completion requires a trusted local verifier or a matching platform receipt
 * resolved by the runtime from an actual result record.
 */
export async function verifyExitCondition({
  flag,
  pattern,
  source,
  evidenceIds = [],
  resolveEvidence,
  localVerifyFn,
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

  const records = [];
  if (typeof resolveEvidence === 'function' && Array.isArray(evidenceIds)) {
    for (const id of evidenceIds.slice(0, 32)) {
      if (typeof id !== 'string' || !RESULT_ID_RE.test(id)) continue;
      try {
        const record = await resolveEvidence(id);
        if (record && typeof record === 'object') records.push({ id, record });
      } catch {
        // A stale or inaccessible evidence id is not verification evidence.
      }
    }
  }
  const evidenceObserved = nonEmpty && records.some(({ record }) => containsFlag(record.report ?? record, trimmed));

  let localOk = false;
  let localDetail = '未配置可信本地验证器。';
  if (typeof localVerifyFn === 'function' && nonEmpty) {
    try {
      const res = await localVerifyFn(trimmed);
      localOk = res === true || res?.ok === true || res?.exit_code === 0;
      localDetail = res?.detail ?? (localOk ? 'local_verifier_passed' : 'local_verifier_failed');
    } catch (err) {
      localDetail = err?.message ?? 'local_verifier_threw';
    }
  }

  const submissionReceipt = nonEmpty
    ? records.find(({ record }) => isAcceptedSubmissionEvidence(record, trimmed))
    : undefined;
  const platformOk = submissionReceipt !== undefined;
  const submissionAttemptObserved = records.some(({ record }) => (
    record?.tool === 'submit_flag' || (record?.tool === 'ctf_arena' && record.report?.action === 'submit')
  ));
  if (requireSubmission || submissionAttemptObserved) {
    checks.push({
      name: 'platform_verdict',
      ok: platformOk,
      detail: platformOk ? `accepted receipt result_id=${submissionReceipt.id}` : '缺少与该 flag 匹配的平台 accepted/duplicate 回执。',
    });
  }

  const provenanceOk = localOk || platformOk;
  checks.push({
    name: 'provenance',
    ok: provenanceOk,
    detail: localOk
      ? localDetail
      : platformOk
        ? `accepted receipt result_id=${submissionReceipt.id}`
        : `source 文本（${typeof source === 'string' ? source : '未提供'}）不是验证证据；缺少可信本地验证器或匹配的平台回执。`,
  });

  const done = checks.every(check => check.ok) && (!requireSubmission || platformOk);
  return {
    status: done ? 'verified' : 'incomplete',
    done,
    exit_code: done ? 0 : 2,
    ...(done ? { verified_flag: trimmed, verified_flag_sha256: sha256 } : { verified_flag_sha256: sha256 }),
    evidence_observed: evidenceObserved,
    checks,
    reason: done ? '可信本地验证器或匹配的平台回执已通过。' : checks.filter(c => !c.ok).map(c => `${c.name}: ${c.detail}`).join('; '),
  };
}
