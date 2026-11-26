import { ToolError } from '../contracts/errors.js';

export const ROUTER_DOMAINS = Object.freeze([
  'all', 'triage', 'web', 'pwn', 'rev', 'crypto', 'misc', 'mobile', 'ai',
]);

const SHARED_WORKFLOW_TOOLS = Object.freeze([
  'ctf_sandbox',
  'ctf_graph',
  'ctf_arena',
  'ctf_domain',
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

export const DOMAIN_ALIASES = Object.freeze({
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
    ? raw
    : String(raw).split(/[,+\s]+/u).filter(Boolean);
  if (tokens.length === 0) {
    return { active: false, domains: ['all'], label: 'all', allowedTools: null };
  }
  const normalized = [];
  for (const token of tokens) {
    const domain = normalizeDomainName(token);
    if (!domain) {
      throw new ToolError('unsupported', `toolDomain 不支持 "${token}"；可选值：${ROUTER_DOMAINS.join('、')}。`);
    }
    if (domain === 'all') {
      return { active: false, domains: ['all'], label: 'all', allowedTools: null };
    }
    if (!normalized.includes(domain)) normalized.push(domain);
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

export const FILE_EXT_RULES = [
  { re: /\.(?:apk|dex|aab|ipa)$/iu, domain: 'mobile', weight: 5, reason: 'mobile_ext' },
  { re: /\.(?:pkl|pickle|pt|pth|ckpt|safetensors|gguf|onnx|h5)$/iu, domain: 'ai', weight: 5, reason: 'ai_model_ext' },
  { re: /\.(?:pcap|pcapng|cap|png|jpg|jpeg|bmp|gif|wav|flac|mp3|pdf|sqlite|db|docx|xlsx|pptx)$/iu, domain: 'misc', weight: 4, reason: 'misc_media_ext' },
  // Archive containers often wrap pwn/rev/crypto tasks; down-weight so they don't shadow real signals.
  { re: /\.(?:zip|7z|rar|tar|gz|xz)$/iu, domain: 'misc', weight: 1, reason: 'archive_wrapper_ext' },
  { re: /\.(?:exe|dll|so|elf|bin|out|wasm|pyc|class|jar)$/iu, domain: 'rev', weight: 3, reason: 'binary_ext' },
  { re: /\.(?:php|js|ts|html|htm|jsp|asp|aspx|vue|jsx|tsx)$/iu, domain: 'web', weight: 3, reason: 'web_source_ext' },
  { re: /\.(?:sage|pem|pub|key|enc|cipher)$/iu, domain: 'crypto', weight: 4, reason: 'crypto_ext' },
];

export const TEXT_RULES = [
  {
    re: /(?:\b(?:xss|csrf|ssrf|sqli|ssti|rce|jwt|cookie|graphql|flask|django|express|nginx|apache|php|web|http:\/\/|https:\/\/)\b|代码审计|反序列化|文件上传|任意文件读取|原型链污染|跨站|SQL注入|命令执行)/iu,
    domain: 'web',
    weight: 2,
    reason: 'web_keyword',
  },
  {
    re: /(?:\b(?:pwn|rop|ret2libc|canary|got|plt|heap|tcache|fastbin|libc|seccomp|shellcode|bof|overflow|uaf|fmtstr|nc\s+[a-z0-9.-]+\s+\d+)\b|栈溢出|堆溢出|堆利用|格式化字符串|二进制利用|沙箱逃逸|虚表|ret2text|ret2syscall)/iu,
    domain: 'pwn',
    weight: 3,
    reason: 'pwn_keyword',
  },
  {
    re: /(?:\b(?:reverse|reversing|ghidra|ida|radare2|angr|decompile|obfuscate|upx|crackme|keygen|disasm)\b|(?:custom|bytecode|opcode|crackme|virtual\s+machine)\s+\bvm\b|\bvm\b\s+(?:bytecode|opcode|protection|protect|obfuscat|crackme)|逆向|反编译|脱壳|加壳|花指令|控制流平坦化|动态调试|自定义虚拟机|虚拟机保护|字节码)/iu,
    domain: 'rev',
    weight: 3,
    reason: 'rev_keyword',
  },
  {
    re: /(?:\b(?:rsa|aes|ecc|ecdsa|lcg|mt19937|coppersmith|lattice|lll|bkz|sage|padding oracle|diffie|elliptic|modulus|ciphertext|decrypt|prng)\b|密码学|古典密码|非对称加密|对称加密|格密码|椭圆曲线|同余|中国剩余|流密码|分组密码|公钥|私钥|密文|明文|签名伪造|随机数预测)/iu,
    domain: 'crypto',
    weight: 3,
    reason: 'crypto_keyword',
  },
  {
    re: /(?:\b(?:pcap|pcapng|wireshark|stego|lsb|exif|png|wav|spectrogram|bkcrack|forensics|volatility|memory dump|qr)\b|杂项|隐写|电子取证|内存取证|磁盘取证|流量分析|频谱|二维码|伪加密|压缩包密码)/iu,
    domain: 'misc',
    weight: 3,
    reason: 'misc_keyword',
  },
  {
    re: /(?:\b(?:android|apk|jadx|apktool|smali|frida|dex|jni|dalvik)\b|安卓|移动安全|小程序|签名校验|原生层)/iu,
    domain: 'mobile',
    weight: 4,
    reason: 'mobile_keyword',
  },
  {
    re: /(?:\b(?:pickle|pytorch|safetensors|gguf|onnx|llm|chatbot|prompt injection|prompt leak|jailbreak|system prompt|model weights|chat_template|torch\.load|rag|mcp|backdoor|poisoning|agent hijacking)\b|大模型|提示词注入|提示注入|越狱|模型权重|模型投毒|模型窃取|智能体|聊天机器人|知识库|安全护栏)/iu,
    domain: 'ai',
    weight: 4,
    reason: 'ai_keyword',
  },
];

const NEGATION_PATTERNS = [
  /\b(?:not(?:\s+a)?|never|no|without|rather\s+than)\s+(?:web|pwn|rev|reverse|crypto|misc|mobile|android|ai|llm)\b/giu,
  /(?:不是|并非|非|无关|不需要|排除)\s*(?:web|pwn|rev|逆向|密码学?|杂项|安卓|ai|大模型)/giu,
];

function stripNegatedPhrases(text) {
  let cleaned = text;
  for (const pattern of NEGATION_PATTERNS) {
    cleaned = cleaned.replace(pattern, ' ');
  }
  return cleaned;
}

function applyFileHeaderHints(fileHeaders, scores, reasons) {
  if (!fileHeaders) return;
  const entries = Array.isArray(fileHeaders)
    ? fileHeaders
    : Object.entries(fileHeaders).map(([name, magic]) => ({ name, magic }));
  for (const entry of entries) {
    const raw = typeof entry === 'string'
      ? entry
      : String(entry?.header_hex ?? entry?.magic ?? '').trim();
    const norm = raw.replace(/\s+/gu, '').toLowerCase();
    if (!norm) continue;
    if (norm.startsWith('7f454c46') || /^elf\b/iu.test(raw)) {
      scores.rev += 3;
      scores.pwn += 2;
      if (!reasons.includes('header_elf')) reasons.push('header_elf');
    } else if (norm.startsWith('4d5a') || /^pe32/iu.test(raw)) {
      scores.rev += 3;
      if (!reasons.includes('header_pe')) reasons.push('header_pe');
    } else if (norm.startsWith('6465780a') || /^dex/iu.test(raw)) {
      scores.mobile += 5;
      if (!reasons.includes('header_dex')) reasons.push('header_dex');
    } else if (norm.startsWith('47475546') || /gguf|safetensors|onnx|pytorch|pickle/iu.test(raw)) {
      scores.ai += 5;
      if (!reasons.includes('header_ai_model')) reasons.push('header_ai_model');
    } else if (norm.startsWith('d4c3b2a1') || norm.startsWith('a1b2c3d4') || norm.startsWith('0a0d0d0a')
      || norm.startsWith('89504e47') || norm.startsWith('52494646') || /pcap|png|wav|riff/iu.test(raw)) {
      scores.misc += 4;
      if (!reasons.includes('header_misc_media')) reasons.push('header_misc_media');
    }
  }
}

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

  applyFileHeaderHints(input.file_headers, scores, reasons);

  const rawText = [input.title, input.challenge, input.description, input.connection_info, input.url]
    .filter(part => typeof part === 'string' && part.trim() !== '')
    .join('\n');
  if (rawText) {
    const filteredText = stripNegatedPhrases(rawText);
    for (const rule of TEXT_RULES) {
      if (rule.re.test(filteredText)) {
        scores[rule.domain] += rule.weight;
        if (!reasons.includes(rule.reason)) reasons.push(rule.reason);
      }
    }
    const conn = [input.connection_info, input.url].filter(v => typeof v === 'string' && v.trim() !== '').join('\n');
    const hasHttpConn = /(?:^|[\s(])https?:\/\/[^\s)]+/iu.test(conn);
    if (hasHttpConn) {
      scores.web += 3;
      if (!reasons.includes('web_connection_url')) reasons.push('web_connection_url');
    }
    if (/\bnc\s+[^\s]+\s+\d{2,5}\b/iu.test(conn)) {
      scores.pwn += 2;
      if (!reasons.includes('tcp_connection_nc')) reasons.push('tcp_connection_nc');
    } else if (!hasHttpConn && /(?:^|\s)[a-z0-9.-]+:\d{2,5}(?:\s|$)/iu.test(conn)) {
      scores.pwn += 2;
      if (!reasons.includes('tcp_connection_host_port')) reasons.push('tcp_connection_host_port');
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

/**
 * Stateful runtime domain router enabling cold-start triage plus dynamic hot-expansion.
 */
export function createDomainRouter({ initialDomain = 'all', coreOnly = false } = {}) {
  let selection = resolveToolDomainSelection({ toolDomain: initialDomain });
  const domainSet = new Set(selection.active ? selection.domains : []);

  function rebuildSelection() {
    if (domainSet.size === 0) {
      selection = { active: false, domains: ['all'], label: 'all', allowedTools: null };
      return;
    }
    selection = resolveToolDomainSelection({ toolDomain: [...domainSet] });
  }

  return {
    coreOnly,
    status() {
      return {
        active: selection.active,
        domains: [...selection.domains],
        label: selection.label,
        allowed_tool_count: selection.allowedTools ? selection.allowedTools.size : null,
      };
    },
    activeDomains() {
      return [...selection.domains];
    },
    isToolAllowed(toolName) {
      return shouldRegisterTool(toolName, selection);
    },
    enableDomain(domainInput) {
      const incoming = resolveToolDomainSelection({ toolDomain: domainInput });
      if (!incoming.active) {
        domainSet.clear();
        rebuildSelection();
        return { domains: ['all'], added_domains: [], added_tools: [] };
      }
      const prevTools = selection.allowedTools ? new Set(selection.allowedTools) : null;
      if (!selection.active) {
        return { domains: ['all'], added_domains: [], added_tools: [] };
      }
      const addedDomains = [];
      for (const d of incoming.domains) {
        if (!domainSet.has(d)) {
          domainSet.add(d);
          addedDomains.push(d);
        }
      }
      rebuildSelection();
      const addedTools = [];
      if (prevTools && selection.allowedTools) {
        for (const t of selection.allowedTools) {
          if (!prevTools.has(t)) addedTools.push(t);
        }
      }
      return {
        domains: [...selection.domains],
        added_domains: addedDomains,
        added_tools: addedTools,
      };
    },
    classify(input) {
      return classifyChallengeDomain(input);
    },
  };
}
