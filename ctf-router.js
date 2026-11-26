import { ToolError } from './tool-errors.js';

export const ROUTER_DOMAINS = Object.freeze([
  'all', 'triage', 'web', 'pwn', 'rev', 'crypto', 'misc', 'mobile', 'ai',
]);

const SHARED_WORKFLOW_TOOLS = Object.freeze([
  'ctf_sandbox',
  'ctf_graph',
  'ctf_arena',
  'fetch_attachment',
  'check_flag',
  'submit_flag',
]);

const SHARED_TRIAGE_TOOLS = Object.freeze([
  'inspect_attachment',
  ...SHARED_WORKFLOW_TOOLS,
]);

export const DOMAIN_TOOL_PROFILES = Object.freeze({
  triage: Object.freeze([
    ...SHARED_TRIAGE_TOOLS,
    'scan_binary',
    'ctf_doctor',
  ]),
  web: Object.freeze([
    ...SHARED_TRIAGE_TOOLS,
    'http_request',
    'browser_session',
    'net_session',
    'ctf_instance',
  ]),
  pwn: Object.freeze([
    ...SHARED_TRIAGE_TOOLS,
    'inspect_elf',
    'pwn_cyclic',
    'pwn_payload',
    'gdb_driver',
    'net_session',
    'rev_query',
    'ctf_instance',
  ]),
  rev: Object.freeze([
    ...SHARED_TRIAGE_TOOLS,
    'rev_query',
    'inspect_elf',
    'gdb_driver',
    'read_binary_range',
    'scan_binary',
  ]),
  crypto: Object.freeze([
    ...SHARED_TRIAGE_TOOLS,
    'crypto_solver',
    'calculate_offline',
    'read_binary_range',
  ]),
  misc: Object.freeze([
    ...SHARED_TRIAGE_TOOLS,
    'inspect_media',
    'read_png_pixels',
    'read_archive_member',
    'archive_crack',
    'stego_audio',
    'pcap_stream',
    'scan_binary',
    'read_binary_range',
  ]),
  mobile: Object.freeze([
    ...SHARED_TRIAGE_TOOLS,
    'mobile_apk',
    'inspect_media',
    'read_archive_member',
    'rev_query',
  ]),
  ai: Object.freeze([
    ...SHARED_TRIAGE_TOOLS,
    'inspect_media',
    'read_archive_member',
  ]),
});

const DOMAIN_ALIASES = Object.freeze({
  all: 'all',
  full: 'all',
  default: 'all',
  triage: 'triage',
  recon: 'triage',
  commander: 'triage',
  web: 'web',
  http: 'web',
  pwn: 'pwn',
  binary: 'pwn',
  exploit: 'pwn',
  exploitation: 'pwn',
  rev: 'rev',
  reverse: 'rev',
  reversing: 'rev',
  re: 'rev',
  crypto: 'crypto',
  cryptography: 'crypto',
  math: 'crypto',
  misc: 'misc',
  forensics: 'misc',
  forensic: 'misc',
  stego: 'misc',
  steganography: 'misc',
  pcap: 'misc',
  network: 'misc',
  mobile: 'mobile',
  android: 'mobile',
  apk: 'mobile',
  ai: 'ai',
  'ai-sec': 'ai',
  aisec: 'ai',
  ml: 'ai',
  llm: 'ai',
});

export function normalizeDomainName(raw) {
  if (typeof raw !== 'string') return undefined;
  const key = raw.trim().toLowerCase();
  if (!key) return undefined;
  return DOMAIN_ALIASES[key];
}

export function resolveToolDomainSelection(config = {}) {
  const raw = config?.toolDomain;
  if (raw === undefined || raw === null || (typeof raw === 'string' && raw.trim() === '')) {
    return { active: false, domains: ['all'], label: 'all', allowedTools: null };
  }
  const tokens = Array.isArray(raw)
    ? raw.flatMap(item => String(item ?? '').split(','))
    : String(raw).split(',');
  const normalized = [];
  for (const token of tokens) {
    const trimmed = token.trim();
    if (!trimmed) continue;
    const mapped = normalizeDomainName(trimmed);
    if (!mapped) {
      throw new ToolError('unsupported', `不支持的 toolDomain：${trimmed}。可选值：${ROUTER_DOMAINS.join(', ')}。`);
    }
    if (!normalized.includes(mapped)) normalized.push(mapped);
  }
  if (normalized.length === 0 || normalized.includes('all')) {
    return { active: false, domains: ['all'], label: 'all', allowedTools: null };
  }
  const allowedTools = new Set();
  for (const domain of normalized) {
    for (const toolName of DOMAIN_TOOL_PROFILES[domain] ?? []) {
      allowedTools.add(toolName);
    }
  }
  return {
    active: true,
    domains: normalized,
    label: normalized.join('+'),
    allowedTools,
  };
}

export function shouldRegisterTool(toolName, selection) {
  if (!selection?.active || !selection.allowedTools) return true;
  return selection.allowedTools.has(toolName);
}

const FILE_EXT_RULES = [
  { re: /\.(?:apk|dex|aab|ipa)$/iu, domain: 'mobile', weight: 5, reason: 'mobile_ext' },
  { re: /\.(?:pkl|pickle|pt|pth|ckpt|safetensors|gguf|onnx|h5)$/iu, domain: 'ai', weight: 5, reason: 'ai_model_ext' },
  { re: /\.(?:pcap|pcapng|cap|png|jpg|jpeg|bmp|gif|wav|flac|mp3|pdf|sqlite|db|docx|xlsx|pptx|zip|7z|rar|tar|gz|xz)$/iu, domain: 'misc', weight: 4, reason: 'misc_media_ext' },
  { re: /\.(?:exe|dll|so|elf|bin|out|wasm|pyc|class|jar)$/iu, domain: 'rev', weight: 3, reason: 'binary_ext' },
  { re: /\.(?:php|js|ts|html|htm|jsp|asp|aspx|vue|jsx|tsx)$/iu, domain: 'web', weight: 3, reason: 'web_source_ext' },
  { re: /\.(?:sage|pem|pub|key|enc|cipher)$/iu, domain: 'crypto', weight: 4, reason: 'crypto_ext' },
];

const TEXT_RULES = [
  { re: /\b(?:xss|csrf|ssrf|sqli|ssti|rce|jwt|cookie|graphql|flask|django|express|nginx|apache|php|web|http:\/\/|https:\/\/)\b/iu, domain: 'web', weight: 2, reason: 'web_keyword' },
  { re: /\b(?:pwn|rop|ret2libc|canary|got|plt|heap|tcache|fastbin|libc|seccomp|shellcode|bof|overflow|uaf|fmtstr|nc\s+[a-z0-9.-]+\s+\d+)\b/iu, domain: 'pwn', weight: 3, reason: 'pwn_keyword' },
  { re: /\b(?:reverse|reversing|ghidra|ida|radare2|angr|decompile|obfuscate|upx|vm|crackme|keygen|disasm)\b/iu, domain: 'rev', weight: 3, reason: 'rev_keyword' },
  { re: /\b(?:rsa|aes|ecc|ecdsa|lcg|mt19937|coppersmith|lattice|lll|bkz|sage|padding oracle|diffie|dh|elliptic|modulus|ciphertext|decrypt)\b/iu, domain: 'crypto', weight: 3, reason: 'crypto_keyword' },
  { re: /\b(?:pcap|pcapng|wireshark|stego|lsb|exif|png|wav|spectrogram|zip|bkcrack|forensics|volatility|memory dump|qr)\b/iu, domain: 'misc', weight: 3, reason: 'misc_keyword' },
  { re: /\b(?:android|apk|jadx|apktool|smali|frida|dex|jni|dalvik)\b/iu, domain: 'mobile', weight: 4, reason: 'mobile_keyword' },
  { re: /\b(?:pickle|pytorch|safetensors|gguf|onnx|llm|prompt injection|model weights|chat_template|torch\.load)\b/iu, domain: 'ai', weight: 4, reason: 'ai_keyword' },
];

export function classifyChallengeDomain(input = {}) {
  const scores = { web: 0, pwn: 0, rev: 0, crypto: 0, misc: 0, mobile: 0, ai: 0 };
  const reasons = [];

  const cat = normalizeDomainName(input.category);
  if (cat && cat !== 'all' && cat !== 'triage') {
    scores[cat] += 6;
    reasons.push(`category:${cat}`);
  }

  const files = Array.isArray(input.files) ? input.files : [];
  for (const file of files) {
    const name = typeof file === 'string' ? file : String(file?.name ?? file?.file_path ?? '');
    if (!name) continue;
    for (const rule of FILE_EXT_RULES) {
      if (rule.re.test(name)) {
        scores[rule.domain] += rule.weight;
        if (!reasons.includes(rule.reason)) reasons.push(rule.reason);
      }
    }
    if (/libc(?:\.so|-2\.\d)/iu.test(name) || /ld-linux/iu.test(name)) {
      scores.pwn += 5;
      if (!reasons.includes('pwn_libc_file')) reasons.push('pwn_libc_file');
    }
  }

  const text = [input.title, input.challenge, input.description, input.connection_info]
    .filter(part => typeof part === 'string' && part.trim() !== '')
    .join('\n');
  if (text) {
    for (const rule of TEXT_RULES) {
      if (rule.re.test(text)) {
        scores[rule.domain] += rule.weight;
        if (!reasons.includes(rule.reason)) reasons.push(rule.reason);
      }
    }
    if (/(?:^|[\s(])https?:\/\/[^\s)]+/iu.test(input.connection_info ?? '')) {
      scores.web += 3;
      if (!reasons.includes('web_connection_url')) reasons.push('web_connection_url');
    }
    if (/\bnc\s+[^\s]+\s+\d{2,5}\b/iu.test(input.connection_info ?? '')) {
      scores.pwn += 2;
      if (!reasons.includes('tcp_connection_nc')) reasons.push('tcp_connection_nc');
    }
  }

  const ranked = Object.entries(scores)
    .filter(([, score]) => score > 0)
    .sort((a, b) => b[1] - a[1]);

  if (ranked.length === 0) {
    return {
      primary: 'triage',
      domains: ['triage'],
      confidence: 'low',
      reasons: ['no_domain_signal'],
      recommended_tools: [...DOMAIN_TOOL_PROFILES.triage],
    };
  }

  const [topDomain, topScore] = ranked[0];
  const domains = [topDomain];
  if (ranked.length > 1 && ranked[1][1] >= Math.max(3, Math.ceil(topScore * 0.6))) {
    domains.push(ranked[1][0]);
  }
  const recommendedTools = [...new Set(domains.flatMap(d => DOMAIN_TOOL_PROFILES[d] ?? []))];
  const confidence = topScore >= 6 ? 'high' : topScore >= 3 ? 'medium' : 'low';
  return {
    primary: topDomain,
    domains,
    confidence,
    reasons: reasons.slice(0, 8),
    recommended_tools: recommendedTools,
  };
}
