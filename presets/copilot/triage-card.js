import { createHash } from 'node:crypto';
import { classifyChallengeDomain } from '../../core/routing/ctf-router.js';
import { ToolError } from '../../core/contracts/errors.js';
import { inspectElf } from '../../elf.js';

function detectMagic(bytes, fileName = '') {
  if (!bytes || bytes.length === 0) return 'empty';
  const hex4 = bytes.subarray(0, 4).toString('hex');
  if (hex4 === '7f454c46') return 'elf';
  if (hex4 === '504b0304' || hex4 === '504b0506') return /\.apk$/iu.test(fileName) ? 'apk_zip' : 'zip';
  if (hex4 === '89504e47') return 'png';
  if (bytes.subarray(0, 4).toString('latin1') === '%PDF') return 'pdf';
  if (bytes.subarray(0, 4).toString('latin1') === 'GGUF') return 'gguf';
  if (hex4 === 'd4c3b2a1' || hex4 === 'a1b2c3d4' || hex4 === '0a0d0d0a') return 'pcap';
  if (bytes.subarray(0, 4).toString('ascii') === 'dex\n') return 'dex';
  if (bytes.subarray(0, 2).toString('ascii') === 'MZ') return 'pe';
  return 'generic';
}

function buildSuggestions(domains, magic, filePath) {
  const target = filePath || '<file>';
  const suggestions = [];
  if (magic === 'elf') {
    suggestions.push(`inspect_elf({ file_path: "${target}" }) 确认 PIE/NX/Canary 与导入符号`);
    suggestions.push(`ctf_sandbox({ action: "decompile", file_path: "${target}" }) 提取反编译伪 C`);
  } else if (magic === 'apk_zip' || domains.includes('mobile')) {
    suggestions.push(`mobile_apk({ action: "info", file_path: "${target}" }) 检查 manifest/dex/ABI`);
    suggestions.push(`mobile_apk({ action: "decompile", file_path: "${target}" }) 反编译 Java 源码`);
  } else if (magic === 'gguf' || domains.includes('ai')) {
    suggestions.push(`inspect_media({ kind: "model", file_path: "${target}" }) 执行静态安全体检`);
  } else if (magic === 'pcap') {
    suggestions.push(`pcap_stream({ action: "summary", file_path: "${target}" }) 重组流与 DNS 查询`);
  } else if (domains.includes('web')) {
    suggestions.push('先用 ctf_domain({ action: "enable", domain: "web" }) 热加载 http_request / browser_session');
    suggestions.push('http_request 检查响应头、cookie 与关键路由');
  } else if (domains.includes('crypto')) {
    suggestions.push('crypto_solver({ action: "solve" | "check" }) 或 calculate_offline 复算模数/密文');
  } else {
    suggestions.push(`inspect_attachment({ file_path: "${target}" }) 核验文件结构与哈希`);
  }
  suggestions.push(`ctf_domain({ action: "enable", domain: "${domains[0] ?? 'triage'}" }) 按需激活专项工具与 Skill`);
  return suggestions.slice(0, 3);
}

/**
 * Build a concise, readable Human-AI Copilot first-turn triage card from a file and challenge prompt.
 */
export async function buildTriageCard({
  filePath,
  title = '',
  description = '',
  url = '',
  connectionInfo = '',
  files = [],
  readFileBytes,
} = {}) {
  const targetFiles = [...new Set([...(filePath ? [filePath] : []), ...files].filter(Boolean))];
  let sha256;
  let sizeBytes;
  let magic = 'none';
  let elfSummary;
  const fileHeaders = [];

  if (filePath) {
    if (typeof readFileBytes !== 'function') {
      throw new ToolError('unsupported', 'buildTriageCard 需要 readFileBytes 回调。');
    }
    const bytes = await readFileBytes(filePath);
    sizeBytes = bytes.length;
    sha256 = createHash('sha256').update(bytes).digest('hex');
    magic = detectMagic(bytes, filePath);
    fileHeaders.push({ name: filePath, header_hex: bytes.subarray(0, 16).toString('hex') });
    if (magic === 'elf') {
      try {
        const elf = inspectElf(bytes);
        elfSummary = {
          arch: elf.arch ?? elf.machine,
          bits: elf.bits,
          endian: elf.endian,
          checksec: elf.checksec,
        };
      } catch {
        // Ignore truncated ELF header in triage summary.
      }
    }
  }

  const classification = classifyChallengeDomain({
    title,
    description,
    url: url || undefined,
    connection_info: connectionInfo || undefined,
    files: targetFiles,
    file_headers: fileHeaders,
  });

  const nextSteps = buildSuggestions(classification.domains, magic, filePath);
  const lines = [
    `### 题目首轮情报卡（${classification.primary.toUpperCase()} · 置信度 ${classification.confidence}）`,
    filePath ? `- **附件**: \`${filePath}\` (${sizeBytes} B, magic=\`${magic}\`, sha256=\`${sha256.slice(0, 16)}…\`)` : '- **附件**: 未指定',
    elfSummary ? `- **ELF**: ${elfSummary.arch ?? 'unknown'} ${elfSummary.bits ?? '?'}bit ${elfSummary.endian ?? ''} | checksec=${JSON.stringify(elfSummary.checksec)}` : null,
    `- **候选域**: ${classification.domains.join(', ')} | 建议工具: ${classification.recommended_tools.slice(0, 6).join(', ')}`,
    `- **建议下一步**:`,
    ...nextSteps.map((s, idx) => `  ${idx + 1}. ${s}`),
  ].filter(Boolean);

  return {
    status: 'ok',
    primary_domain: classification.primary,
    domains: classification.domains,
    confidence: classification.confidence,
    reasons: classification.reasons,
    recommended_tools: classification.recommended_tools,
    ...(filePath ? { file: filePath, size_bytes: sizeBytes, sha256, magic } : {}),
    ...(elfSummary ? { elf: elfSummary } : {}),
    next_steps: nextSteps,
    markdown: lines.join('\n'),
  };
}
