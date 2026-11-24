import { createHmac, timingSafeEqual } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import { ToolError } from './tool-errors.js';

export const CRYPTO_SOLVE_OPERATIONS = [
  'jwt_inspect',
  'jwt_crack',
  'flask_session',
  'lcg_recover',
  'mt19937_recover',
];

const DEFAULT_TIMEOUT_MS = 15000;
const MAX_TIMEOUT_MS = 120000;

const COMMON_SECRETS = [
  '', 'secret', 'secret123', 'secret_key', 'secretkey', 'jwt_secret', 'jwtsecret',
  'supersecret', 'super_secret', 'mysecret', 'my_secret', 'your-256-bit-secret',
  'your-secret-key', 'changeme', 'change_me', 'default', 'key', 'mykey', 'test',
  'dev', 'development', 'prod', 'production', 'debug', 'flask', 'flask_secret',
  'app', 'app_secret', 'session', 'cookie', 'admin', 'root', 'password', 'pass',
  '1234', '12345', '123456', '12345678', '123456789', 'qwerty', 'abc123',
  'flag', 'ctf', 'ctf_secret', 'hackme', 'letmein', 'welcome', 'monkey',
  'dragon', 'master', 'shadow', '000000', '111111', '654321', 'password1',
  'admin123', 'root123', 'P@ssw0rd', 'Passw0rd', 'hard to guess string',
  'super secret key', 'topsecret', 'top_secret', 'verysecret', 'qwertyuiop',
];

const JWT_ALG_TO_HASH = {
  HS256: 'sha256',
  HS384: 'sha384',
  HS512: 'sha512',
};

function decodeBase64Url(segment, label) {
  if (typeof segment !== 'string' || !/^[A-Za-z0-9_-]*$/u.test(segment)) {
    throw new ToolError('unsupported', `${label} 不是合法的 Base64URL 编码。`);
  }
  const padded = segment + '='.repeat((4 - (segment.length % 4)) % 4);
  return Buffer.from(padded.replaceAll('-', '+').replaceAll('_', '/'), 'base64');
}

function parseJsonObject(buffer, label) {
  try {
    const parsed = JSON.parse(buffer.toString('utf8'));
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('not object');
    }
    return parsed;
  } catch {
    throw new ToolError('unsupported', `${label} 不是合法的 UTF-8 JSON 对象。`);
  }
}

function parseJwtParts(token) {
  if (typeof token !== 'string' || token.trim().length === 0 || token.length > 16384) {
    throw new ToolError('unsupported', 'token 须为非空 JWT 字符串（不超过 16384 字符）。');
  }
  const parts = token.trim().split('.');
  if (parts.length !== 3) {
    throw new ToolError('unsupported', 'JWT 须由三段以 "." 分隔的 Base64URL 组成。');
  }
  const header = parseJsonObject(decodeBase64Url(parts[0], 'JWT header'), 'JWT header');
  const payload = parseJsonObject(decodeBase64Url(parts[1], 'JWT payload'), 'JWT payload');
  const signature = decodeBase64Url(parts[2], 'JWT signature');
  return {
    signingInput: `${parts[0]}.${parts[1]}`,
    header,
    payload,
    signature,
    signatureRaw: parts[2],
  };
}

function* secretCandidates(args, wordlistText) {
  const seen = new Set();
  const push = value => {
    if (typeof value !== 'string' || value.length > 256) return false;
    if (seen.size < 50000) {
      if (seen.has(value)) return false;
      seen.add(value);
    }
    return true;
  };
  if (Array.isArray(args.passwords)) {
    for (const password of args.passwords) {
      if (push(password)) yield password;
    }
  }
  if (typeof wordlistText === 'string') {
    for (const line of wordlistText.split(/\r?\n/u)) {
      if (line.length > 0 && push(line)) yield line;
    }
  }
  for (const secret of COMMON_SECRETS) {
    if (push(secret)) yield secret;
  }
}

function inspectJwt(args) {
  const { header, payload, signature, signatureRaw } = parseJwtParts(args.token);
  const findings = [];
  const alg = typeof header.alg === 'string' ? header.alg : '';
  if (!alg || alg.toLowerCase() === 'none') {
    findings.push({ code: 'alg_none', severity: 'high', message: 'JWT 声明了 alg=none 或缺少算法字段，存在无签名绕过风险。' });
  } else if (Object.hasOwn(JWT_ALG_TO_HASH, alg)) {
    findings.push({ code: 'hmac_alg', severity: 'info', message: `使用对称 HMAC 算法 ${alg}，可用 jwt_crack 验证弱密钥。` });
  } else if (/^(?:RS|PS|ES)/u.test(alg)) {
    findings.push({ code: 'asymmetric_alg', severity: 'info', message: `使用非对称算法 ${alg}（如存在公钥泄漏，可留意算法混淆检查）。` });
  }
  if (header.kid !== undefined) {
    findings.push({ code: 'kid_present', severity: 'medium', message: `Header 包含 kid=${JSON.stringify(header.kid)}，可检查密钥定位路径或查询逻辑。` });
  }
  for (const key of ['jku', 'x5u', 'jwk']) {
    if (header[key] !== undefined) {
      findings.push({ code: `${key}_present`, severity: 'medium', message: `Header 包含 ${key} 字段，可检查服务端密钥源校验逻辑。` });
    }
  }
  const nowSec = Math.floor(Date.now() / 1000);
  const timing = {};
  if (typeof payload.iat === 'number' && Number.isFinite(payload.iat)) {
    timing.iat_iso = new Date(payload.iat * 1000).toISOString();
  }
  if (typeof payload.nbf === 'number' && Number.isFinite(payload.nbf)) {
    timing.nbf_iso = new Date(payload.nbf * 1000).toISOString();
  }
  if (typeof payload.exp === 'number' && Number.isFinite(payload.exp)) {
    timing.exp_iso = new Date(payload.exp * 1000).toISOString();
    timing.expired = nowSec > payload.exp;
  }
  return {
    operation: 'jwt_inspect',
    status: 'ok',
    alg: alg || null,
    header,
    payload,
    signature_present: signatureRaw.length > 0,
    signature_bytes: signature.length,
    ...(Object.keys(timing).length > 0 ? { timing } : {}),
    findings,
  };
}

async function crackJwt(args, wordlistText, signal) {
  const { signingInput, header, payload, signature } = parseJwtParts(args.token);
  const alg = typeof header.alg === 'string' ? header.alg : '';
  const hashName = JWT_ALG_TO_HASH[alg];
  if (!hashName) {
    throw new ToolError('unsupported', `jwt_crack 仅支持 HS256/HS384/HS512，当前 alg 为 ${alg || '(缺失)'}。`);
  }
  if (signature.length === 0) {
    throw new ToolError('unsupported', 'JWT 签名段为空，无法校验 HMAC 密钥。');
  }
  const timeoutMs = Math.min(Math.max(args.timeout_ms ?? DEFAULT_TIMEOUT_MS, 1000), MAX_TIMEOUT_MS);
  const deadline = Date.now() + timeoutMs;
  let tried = 0;
  for (const secret of secretCandidates(args, wordlistText)) {
    if ((tried & 0xff) === 0) {
      signal?.throwIfAborted();
      if (Date.now() > deadline) {
        return { operation: 'jwt_crack', status: 'not_found', alg, timed_out: true, tried, header, payload };
      }
      if (tried > 0) await new Promise(resolve => setImmediate(resolve));
    }
    tried += 1;
    const digest = createHmac(hashName, secret).update(signingInput).digest();
    if (digest.length === signature.length && timingSafeEqual(digest, signature)) {
      return { operation: 'jwt_crack', status: 'found', alg, secret, tried, timed_out: false, header, payload };
    }
  }
  signal?.throwIfAborted();
  return { operation: 'jwt_crack', status: 'not_found', alg, timed_out: false, tried, header, payload };
}

function parseUnsignedBigEndian(buf) {
  let value = 0n;
  for (const byte of buf) value = (value << 8n) | BigInt(byte);
  return value;
}

async function inspectAndCrackFlaskSession(args, wordlistText, signal) {
  if (typeof args.token !== 'string' || args.token.trim().length === 0 || args.token.length > 32768) {
    throw new ToolError('unsupported', 'token 须为非空 Flask Session Cookie 字符串。');
  }
  const cookie = args.token.trim();
  const lastDot = cookie.lastIndexOf('.');
  if (lastDot <= 0 || lastDot === cookie.length - 1) {
    throw new ToolError('unsupported', '不是合法的 Flask itsdangerous Session Cookie（缺少签名分隔符）。');
  }
  const signedValue = cookie.slice(0, lastDot);
  const signature = decodeBase64Url(cookie.slice(lastDot + 1), 'Flask session signature');
  const tsDot = signedValue.lastIndexOf('.');
  if (tsDot <= 0 || tsDot === signedValue.length - 1) {
    throw new ToolError('unsupported', '不是合法的 Flask itsdangerous Session Cookie（缺少时间戳段）。');
  }
  const payloadPart = signedValue.slice(0, tsDot);
  const tsPart = signedValue.slice(tsDot + 1);
  const compressed = payloadPart.startsWith('.');
  const rawPayloadBytes = decodeBase64Url(compressed ? payloadPart.slice(1) : payloadPart, 'Flask session payload');
  let payloadBytes = rawPayloadBytes;
  if (compressed) {
    try {
      payloadBytes = inflateSync(rawPayloadBytes, { maxOutputLength: 256 * 1024 });
    } catch {
      throw new ToolError('unsupported', 'Flask Session 压缩载荷 zlib 解压失败。');
    }
  }
  const payloadText = payloadBytes.toString('utf8');
  let payload;
  try {
    payload = JSON.parse(payloadText);
  } catch {
    payload = payloadText;
  }

  const tsRaw = parseUnsignedBigEndian(decodeBase64Url(tsPart, 'Flask session timestamp'));
  const ITSDANGEROUS_V1_EPOCH = 1293840000n;
  const unixSec = tsRaw < 1000000000n ? tsRaw + ITSDANGEROUS_V1_EPOCH : tsRaw;
  const issuedAt = unixSec <= 4102444800n ? new Date(Number(unixSec) * 1000).toISOString() : undefined;

  const salt = typeof args.salt === 'string' && args.salt.length > 0 ? args.salt : 'cookie-session';
  const hashName = signature.length === 20 ? 'sha1'
    : signature.length === 32 ? 'sha256'
      : signature.length === 64 ? 'sha512' : null;

  const base = {
    operation: 'flask_session',
    status: 'ok',
    compressed,
    payload,
    timestamp_raw: tsRaw.toString(),
    ...(issuedAt ? { issued_at: issuedAt } : {}),
    signature_bytes: signature.length,
    digest: hashName ?? 'unknown',
    salt,
  };

  if (args.crack === false || !hashName) {
    return base;
  }

  const timeoutMs = Math.min(Math.max(args.timeout_ms ?? DEFAULT_TIMEOUT_MS, 1000), MAX_TIMEOUT_MS);
  const deadline = Date.now() + timeoutMs;
  let tried = 0;
  for (const secret of secretCandidates(args, wordlistText)) {
    if ((tried & 0xff) === 0) {
      signal?.throwIfAborted();
      if (Date.now() > deadline) {
        return { ...base, secret_status: 'not_found', timed_out: true, tried };
      }
      if (tried > 0) await new Promise(resolve => setImmediate(resolve));
    }
    tried += 1;
    const derivedKey = createHmac(hashName, secret).update(salt).digest();
    const expected = createHmac(hashName, derivedKey).update(signedValue).digest();
    if (expected.length === signature.length && timingSafeEqual(expected, signature)) {
      return { ...base, status: 'found', secret_status: 'found', secret, tried, timed_out: false };
    }
  }
  signal?.throwIfAborted();
  return { ...base, secret_status: 'not_found', timed_out: false, tried };
}

// ── LCG 参数反推（纯 BigInt）─────────────────────────────────────────────────

function parseBigIntValue(value, label) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new ToolError('unsupported', `${label} 须为精确整数或十进制/十六进制字符串。`);
    return BigInt(value);
  }
  if (typeof value === 'string') {
    const text = value.trim();
    if (/^-?(?:0[xX][0-9a-fA-F]+|[0-9]+)$/u.test(text)) {
      return BigInt(text);
    }
  }
  throw new ToolError('unsupported', `${label} 须为整数或十进制/0x 十六进制字符串。`);
}

function absBigInt(x) {
  return x < 0n ? -x : x;
}

function modBigInt(x, m) {
  const r = x % m;
  return r < 0n ? r + m : r;
}

function gcdBigInt(a, b) {
  let x = absBigInt(a);
  let y = absBigInt(b);
  while (y !== 0n) {
    const t = x % y;
    x = y;
    y = t;
  }
  return x;
}

function extendedGcd(a, b) {
  let oldR = a;
  let r = b;
  let oldS = 1n;
  let s = 0n;
  let oldT = 0n;
  let t = 1n;
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
    [oldT, t] = [t, oldT - q * t];
  }
  return { g: oldR, x: oldS, y: oldT };
}

function modInverseBigInt(a, m) {
  const { g, x } = extendedGcd(modBigInt(a, m), m);
  if (g !== 1n) return null;
  return modBigInt(x, m);
}

function solveMultiplierAndIncrement(states, m) {
  if (m <= 1n) return null;
  for (const s of states) {
    if (s < 0n || s >= m) return null;
  }
  const verify = (a, c) => {
    for (let i = 0; i < states.length - 1; i += 1) {
      if (modBigInt(a * states[i] + c, m) !== states[i + 1]) return false;
    }
    return true;
  };
  const diffs = [];
  for (let i = 0; i < states.length - 1; i += 1) {
    diffs.push(modBigInt(states[i + 1] - states[i], m));
  }
  let multiplierResidue = 0n;
  let multiplierModulus = 1n;
  for (let i = 0; i < diffs.length - 1; i += 1) {
    const t0 = diffs[i];
    const t1 = diffs[i + 1];
    if (t0 === 0n) {
      if (t1 !== 0n) return null;
      continue;
    }
    const d = gcdBigInt(t0, m);
    if (t1 % d !== 0n) continue;
    const mReduced = m / d;
    let residue = 0n;
    if (mReduced > 1n) {
      const inv = modInverseBigInt(t0 / d, mReduced);
      if (inv === null) return null;
      residue = modBigInt((t1 / d) * inv, mReduced);
    }
    const common = gcdBigInt(multiplierModulus, mReduced);
    const difference = residue - multiplierResidue;
    if (difference % common !== 0n) return null;
    const rightModulus = mReduced / common;
    const factor = rightModulus === 1n ? 0n
      : modBigInt((difference / common) * (modInverseBigInt(multiplierModulus / common, rightModulus) ?? 0n), rightModulus);
    if (rightModulus > 1n && modInverseBigInt(multiplierModulus / common, rightModulus) === null) return null;
    multiplierResidue = modBigInt(multiplierResidue + multiplierModulus * factor, multiplierModulus * rightModulus);
    multiplierModulus *= rightModulus;
  }
  const a = multiplierResidue;
  const c = modBigInt(states[1] - a * states[0], m);
  return verify(a, c) ? { a, c, candidateCount: m / multiplierModulus } : null;
}

function recoverLcg(args) {
  if (!Array.isArray(args.outputs) || args.outputs.length < 3 || args.outputs.length > 32) {
    throw new ToolError('unsupported', 'lcg_recover 需要 3 至 32 个连续输出（未知模数时至少需要 4 个）。');
  }
  const states = args.outputs.map((item, idx) => parseBigIntValue(item, `outputs[${idx}]`));
  const predictCount = args.predict_count ?? 5;
  if (!Number.isSafeInteger(predictCount) || predictCount < 1 || predictCount > 32) {
    throw new ToolError('unsupported', 'predict_count 须为 1 至 32 的整数。');
  }

  let m;
  let modulusRecovered = false;
  if (args.modulus !== undefined) {
    m = parseBigIntValue(args.modulus, 'modulus');
    if (m <= 1n) throw new ToolError('unsupported', 'modulus 须大于 1。');
  } else {
    if (states.length < 4) {
      throw new ToolError('unsupported', '未提供 modulus 时，lcg_recover 至少需要 4 个连续输出（建议 6 个以上以唯一确定模数）。');
    }
    const diffs = [];
    for (let i = 0; i < states.length - 1; i += 1) {
      diffs.push(states[i + 1] - states[i]);
    }
    let g = 0n;
    for (let i = 0; i < diffs.length - 2; i += 1) {
      const det = diffs[i + 2] * diffs[i] - diffs[i + 1] * diffs[i + 1];
      g = gcdBigInt(g, det);
    }
    if (g <= 1n) {
      throw new ToolError('unsupported', '无法从给定输出推导出非平凡模数（行列式 GCD ≤ 1）。');
    }
    m = g;
    modulusRecovered = true;
  }

  let solved = solveMultiplierAndIncrement(states, m);
  if (!solved && modulusRecovered) {
    const maxState = states.reduce((acc, cur) => (cur > acc ? cur : acc), 0n);
    const smallPrimes = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n];
    const visited = new Set([m]);
    const queue = [m];
    while (queue.length > 0 && !solved && visited.size <= 256) {
      const current = queue.shift();
      for (const p of smallPrimes) {
        if (current % p !== 0n) continue;
        const nextM = current / p;
        if (nextM <= maxState || visited.has(nextM)) continue;
        visited.add(nextM);
        const attempt = solveMultiplierAndIncrement(states, nextM);
        if (attempt) {
          m = nextM;
          solved = attempt;
          break;
        }
        queue.push(nextM);
      }
    }
  }

  if (!solved) {
    throw new ToolError('unsupported', '未能找到满足全部输入序列的 LCG 参数 (m, a, c)；请提供更多连续输出或确认模数。');
  }

  const predictions = [];
  let cur = states[states.length - 1];
  for (let i = 0; i < predictCount; i += 1) {
    cur = modBigInt(solved.a * cur + solved.c, m);
    predictions.push(cur.toString());
  }

  return {
    operation: 'lcg_recover',
    status: 'ok',
    modulus_recovered: modulusRecovered,
    modulus: m.toString(),
    multiplier: solved.a.toString(),
    increment: solved.c.toString(),
    parameter_candidates: solved.candidateCount.toString(),
    parameters_unique: solved.candidateCount === 1n,
    verified_inputs: states.length,
    predictions,
  };
}

// ── MT19937 状态恢复与预测 ────────────────────────────────────────────────────

const MT_N = 624;
const MT_M = 397;
const MT_MATRIX_A = 0x9908b0df;
const MT_UPPER_MASK = 0x80000000;
const MT_LOWER_MASK = 0x7fffffff;

function undoRightShiftXor(value, shift) {
  let x = value >>> 0;
  for (let bits = shift; bits < 32; bits <<= 1) {
    x = (x ^ (x >>> bits)) >>> 0;
  }
  return x >>> 0;
}

function undoLeftShiftXorMask(value, shift, mask) {
  const y = value >>> 0;
  let x = y;
  const steps = Math.ceil(32 / shift);
  for (let i = 0; i < steps; i += 1) {
    x = (y ^ (((x << shift) >>> 0) & (mask >>> 0))) >>> 0;
  }
  return x >>> 0;
}

export function untemperMt19937(y) {
  let x = y >>> 0;
  x = undoRightShiftXor(x, 18);
  x = undoLeftShiftXorMask(x, 15, 0xefc60000);
  x = undoLeftShiftXorMask(x, 7, 0x9d2c5680);
  x = undoRightShiftXor(x, 11);
  return x >>> 0;
}

export function temperMt19937(x) {
  let y = x >>> 0;
  y = (y ^ (y >>> 11)) >>> 0;
  y = (y ^ (((y << 7) >>> 0) & 0x9d2c5680)) >>> 0;
  y = (y ^ (((y << 15) >>> 0) & 0xefc60000)) >>> 0;
  y = (y ^ (y >>> 18)) >>> 0;
  return y >>> 0;
}

function twistMt19937(mt) {
  for (let i = 0; i < MT_N; i += 1) {
    const x = ((mt[i] & MT_UPPER_MASK) | (mt[(i + 1) % MT_N] & MT_LOWER_MASK)) >>> 0;
    let xA = x >>> 1;
    if ((x & 1) !== 0) xA = (xA ^ MT_MATRIX_A) >>> 0;
    mt[i] = (mt[(i + MT_M) % MT_N] ^ xA) >>> 0;
  }
}

function recoverMt19937(args) {
  if (!Array.isArray(args.outputs) || args.outputs.length !== MT_N) {
    throw new ToolError('unsupported', `mt19937_recover 需要恰好 ${MT_N} 个连续的 32 位无符号整数输出。`);
  }
  const predictCount = args.predict_count ?? 10;
  if (!Number.isSafeInteger(predictCount) || predictCount < 1 || predictCount > 64) {
    throw new ToolError('unsupported', 'predict_count 须为 1 至 64 的整数。');
  }
  const mt = new Uint32Array(MT_N);
  for (let i = 0; i < MT_N; i += 1) {
    const raw = args.outputs[i];
    let num;
    if (typeof raw === 'number') num = raw;
    else if (typeof raw === 'string' && /^(?:0[xX][0-9a-fA-F]+|[0-9]+)$/u.test(raw.trim())) num = Number(raw.trim());
    else throw new ToolError('unsupported', `outputs[${i}] 须为 0 至 4294967295 的整数。`);
    if (!Number.isSafeInteger(num) || num < 0 || num > 0xffffffff) {
      throw new ToolError('unsupported', `outputs[${i}] 超出 32 位无符号整数范围。`);
    }
    mt[i] = untemperMt19937(num);
  }
  twistMt19937(mt);
  const predictions = [];
  const predictionsHex = [];
  for (let i = 0; i < predictCount; i += 1) {
    const val = temperMt19937(mt[i]);
    predictions.push(val);
    predictionsHex.push('0x' + val.toString(16).padStart(8, '0'));
  }
  return {
    operation: 'mt19937_recover',
    status: 'ok',
    state_size: MT_N,
    predictions,
    predictions_hex: predictionsHex,
  };
}

export async function runCryptoSolve(args, { readWordlist, signal } = {}) {
  const op = args.operation;
  if (!CRYPTO_SOLVE_OPERATIONS.includes(op)) {
    throw new ToolError('unsupported', `operation 须为 ${CRYPTO_SOLVE_OPERATIONS.join('、')} 之一。`);
  }
  if (op === 'jwt_inspect') return inspectJwt(args);
  if (op === 'jwt_crack') {
    const wordlistText = typeof args.wordlist === 'string' && readWordlist ? await readWordlist(args.wordlist) : undefined;
    return crackJwt(args, wordlistText, signal);
  }
  if (op === 'flask_session') {
    const wordlistText = typeof args.wordlist === 'string' && readWordlist ? await readWordlist(args.wordlist) : undefined;
    return inspectAndCrackFlaskSession(args, wordlistText, signal);
  }
  if (op === 'lcg_recover') return recoverLcg(args);
  return recoverMt19937(args);
}
