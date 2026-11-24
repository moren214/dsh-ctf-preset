import { createHash, randomBytes } from 'node:crypto';
import { pinnedLookup } from './network-boundary.js';
import http from 'node:http';
import https from 'node:https';
import { Readable, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import zlib from 'node:zlib';

const METHODS = Object.freeze(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const BODY_ENCODINGS = Object.freeze(['utf8', 'hex', 'base64']);
const DEFAULT_METHOD = 'GET';
const DEFAULT_BODY_ENCODING = 'utf8';
const DEFAULT_TIMEOUT_MS = 10000;
const MIN_TIMEOUT_MS = 1000;
const MAX_TIMEOUT_MS = 30000;
const DEFAULT_MAX_BYTES = 262144;
const MIN_MAX_BYTES = 1024;
const MAX_MAX_BYTES = 1048576;
const MAX_HEADERS = 32;
const MAX_HEADER_VALUE_CHARS = 4096;
const MAX_HEADER_TOTAL_CHARS = 16384;
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_URL_LENGTH = 8192;
const MAX_REDIRECTS = 5;
const DEFAULT_ACCEPT_ENCODING = 'gzip, deflate, br';
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const HEADER_VALUE = /^[\t\x20-\x7e\x80-\xff]*$/u;
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u;
const TEXT_APPLICATION_TYPES = new Set([
  'application/json',
  'application/xml',
  'application/x-www-form-urlencoded',
  'application/javascript',
  'application/ecmascript',
]);
const SUPPORTED_CONTENT_ENCODINGS = new Set(['gzip', 'x-gzip', 'deflate', 'br']);
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const EMPTY_SHA256 = createHash('sha256').update(Buffer.alloc(0)).digest('hex');

export const HTTP_REQUEST_PROPERTIES = {
  url: { type: 'string', minLength: 1, maxLength: MAX_URL_LENGTH, description: '目标 http(s) URL。' },
  method: { type: 'string', enum: METHODS, default: DEFAULT_METHOD },
  headers: {
    type: 'object', maxProperties: MAX_HEADERS,
    additionalProperties: { type: 'string', maxLength: MAX_HEADER_VALUE_CHARS },
    description: '自定义请求头（支持 Host/Cookie/Authorization）。',
  },
  body: { type: 'string', maxLength: MAX_BODY_BYTES * 2, description: '请求体（与 multipart 互斥，限 1 MiB）。' },
  body_encoding: { type: 'string', enum: BODY_ENCODINGS, default: DEFAULT_BODY_ENCODING },
  multipart: {
    type: 'array', minItems: 1, maxItems: 16,
    description: 'multipart/form-data 表单/文件上传项（与 body 互斥）。',
    items: {
      type: 'object', additionalProperties: false, required: ['name'],
      properties: {
        name: { type: 'string', minLength: 1, maxLength: 256 },
        value: { type: 'string', maxLength: MAX_BODY_BYTES * 2 },
        value_encoding: { type: 'string', enum: BODY_ENCODINGS, default: DEFAULT_BODY_ENCODING },
        file_path: { type: 'string', maxLength: 1024 },
        filename: { type: 'string', maxLength: 256 },
        content_type: { type: 'string', maxLength: 256 },
      },
    },
  },
  cookie_jar: { type: 'string', minLength: 1, maxLength: 64, description: '会话 Cookie 容器名。' },
  timeout_ms: { type: 'integer', minimum: MIN_TIMEOUT_MS, maximum: MAX_TIMEOUT_MS, default: DEFAULT_TIMEOUT_MS },
  max_bytes: { type: 'integer', minimum: MIN_MAX_BYTES, maximum: MAX_MAX_BYTES, default: DEFAULT_MAX_BYTES },
  follow_redirects: { type: 'boolean', default: true },
  allow_insecure: { type: 'boolean', default: false },
};

function namedError(message, name) {
  const error = new Error(message);
  if (name !== undefined) error.name = name;
  return error;
}

function errorLocation(url) {
  return url.origin + url.pathname;
}

function timeoutError(timeoutMs, url) {
  return namedError(`HTTP 请求超时：超过 ${timeoutMs} ms 未完成（${errorLocation(url)}）。`, 'TimeoutError');
}

function abortError(url) {
  return namedError(`HTTP 请求已取消（${errorLocation(url)}）。`, 'AbortError');
}

function networkError(error, url) {
  const code = typeof error?.code === 'string' ? error.code : '';
  let reason;
  if (code === 'ENOTFOUND') reason = `无法解析主机名 ${url.hostname}`;
  else if (code === 'EAI_AGAIN') reason = `DNS 解析暂时失败（${url.hostname}）`;
  else if (code === 'ECONNREFUSED') reason = `连接被拒绝（${url.hostname}）`;
  else if (code === 'ECONNRESET') reason = '连接被对端重置';
  else if (code === 'ETIMEDOUT') reason = '连接超时';
  else if (code === 'EHOSTUNREACH') reason = '目标主机不可达';
  else if (code === 'ENETUNREACH') reason = '目标网络不可达';
  else if (code === 'EPIPE') reason = '连接已断开';
  else if (code.startsWith('CERT_') || code.startsWith('ERR_TLS') || code.startsWith('ERR_SSL')
    || code === 'EPROTO' || code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'
    || code === 'SELF_SIGNED_CERT_IN_CHAIN' || code === 'DEPTH_ZERO_SELF_SIGNED_CERT') {
    reason = 'TLS 握手或证书校验失败，若目标使用自签名证书可设置 allow_insecure=true';
  } else reason = '网络请求失败';
  const suffix = code === '' ? '' : `（${code}）`;
  return namedError(`HTTP 请求失败：${reason}${suffix}（${errorLocation(url)}）。`);
}

function bodyError(error, url) {
  if (error?.name === 'TimeoutError') return { code: 'timeout', message: error.message };
  if (error?.name === 'AbortError') return { code: 'aborted', message: abortError(url).message };
  const code = typeof error?.code === 'string' ? error.code : '';
  if (code.startsWith('Z_') || code.startsWith('ERR_ZLIB') || code.startsWith('ERR_BROTLI')) {
    return { code: 'decoding_failed', message: '响应体未能完整解压。' };
  }
  return { code: 'response_incomplete', message: '响应体在读取完毕前中断。' };
}

function parseUrl(value) {
  if (value === undefined) throw new Error('缺少必填参数 url。');
  if (typeof value !== 'string' || value.length === 0) throw new Error('url 必须是非空字符串。');
  if (value.length > MAX_URL_LENGTH) throw new Error(`url 不能超过 ${MAX_URL_LENGTH} 字符。`);
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('url 不是合法的绝对 URL，请包含 http:// 或 https://。');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('url 只支持 http 或 https 协议。');
  }
  if (url.hostname === '') throw new Error('url 缺少主机名。');
  if (url.username || url.password) throw new Error('URL 不能包含用户名或密码。');
  url.hash = '';
  return url;
}

function parseMethod(value) {
  if (value === undefined) return DEFAULT_METHOD;
  if (typeof value !== 'string' || !METHODS.includes(value)) {
    throw new Error(`method 必须是 ${METHODS.join('、')} 之一。`);
  }
  return value;
}

function parseHeaders(value) {
  if (value === undefined) return {};
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('headers 必须是字符串键值对象。');
  }
  const entries = Object.entries(value);
  if (entries.length > MAX_HEADERS) throw new Error(`headers 最多 ${MAX_HEADERS} 个。`);
  const headers = {};
  const seen = new Set();
  let total = 0;
  for (const [name, headerValue] of entries) {
    if (typeof name !== 'string' || !TOKEN.test(name)) {
      throw new Error(`header 名不合法：${JSON.stringify(name)}；只允许 RFC token 字符。`);
    }
    if (typeof headerValue !== 'string') throw new Error(`header ${name} 的值必须是字符串。`);
    if (!HEADER_VALUE.test(headerValue)) {
      throw new Error(`header ${name} 的值不能包含控制字符或 CR/LF，只允许制表符和可打印字符。`);
    }
    if (headerValue.length > MAX_HEADER_VALUE_CHARS) {
      throw new Error(`header ${name} 的值不能超过 ${MAX_HEADER_VALUE_CHARS} 字符。`);
    }
    const lower = name.toLowerCase();
    if (seen.has(lower)) throw new Error(`header 名重复（忽略大小写）：${name}。`);
    seen.add(lower);
    total += name.length + headerValue.length;
    if (total > MAX_HEADER_TOTAL_CHARS) {
      throw new Error(`header 名称与值合计不能超过 ${MAX_HEADER_TOTAL_CHARS} 字符。`);
    }
    headers[name] = headerValue;
  }
  return headers;
}

function decodeBody(text, encoding) {
  if (encoding === 'utf8') return Buffer.from(text, 'utf8');
  if (encoding === 'hex') {
    if (text.length % 2 !== 0 || !/^[0-9a-fA-F]*$/u.test(text)) {
      throw new Error('hex 编码的 body 必须是偶数个十六进制字符。');
    }
    return Buffer.from(text, 'hex');
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/u.test(text) || text.length % 4 === 1) {
    throw new Error('base64 编码的 body 格式无效。');
  }
  return Buffer.from(text, 'base64');
}

function parseBody(input) {
  const text = input.body === undefined ? '' : input.body;
  if (typeof text !== 'string') throw new Error('body 必须是字符串。');
  if (text.length > MAX_BODY_BYTES * 2) throw new Error(`body 文本不能超过 ${MAX_BODY_BYTES * 2} 字符。`);
  const encoding = input.body_encoding === undefined ? DEFAULT_BODY_ENCODING : input.body_encoding;
  if (typeof encoding !== 'string' || !BODY_ENCODINGS.includes(encoding)) {
    throw new Error(`body_encoding 必须是 ${BODY_ENCODINGS.join('、')} 之一。`);
  }
  const bytes = decodeBody(text, encoding);
  if (bytes.length > MAX_BODY_BYTES) {
    throw new Error(`body 编码后不能超过 ${MAX_BODY_BYTES} 字节（1 MiB）。`);
  }
  return bytes;
}

function parseInteger(value, fallback, minimum, maximum, name) {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} 必须是 ${minimum} 至 ${maximum} 的整数。`);
  }
  return value;
}

function parseBoolean(value, fallback, name) {
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') throw new Error(`${name} 必须是布尔值。`);
  return value;
}

function parseOptions(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new Error('options 必须是对象。');
  }
  for (const key of Object.keys(options)) {
    if (!['signal', 'authorize', 'cookieJar', 'readFile'].includes(key)) throw new Error(`options 不支持 ${key}。`);
  }
  const { signal, authorize, cookieJar, readFile } = options;
  if (authorize !== undefined && typeof authorize !== 'function') throw new Error('options.authorize 须为函数。');
  if (readFile !== undefined && typeof readFile !== 'function') throw new Error('options.readFile 须为函数。');
  if (cookieJar !== undefined && (cookieJar === null || typeof cookieJar !== 'object'
    || typeof cookieJar.headerFor !== 'function' || typeof cookieJar.store !== 'function')) {
    throw new Error('options.cookieJar 无效。');
  }
  if (signal !== undefined) {
    if (signal === null || typeof signal !== 'object' || typeof signal.addEventListener !== 'function'
      || typeof signal.removeEventListener !== 'function' || typeof signal.aborted !== 'boolean') {
      throw new Error('options.signal 必须是 AbortSignal。');
    }
  }
  return signal;
}

function defaultCookiePath(pathname) {
  if (!pathname || !pathname.startsWith('/')) return '/';
  const slash = pathname.lastIndexOf('/');
  return slash <= 0 ? '/' : pathname.slice(0, slash);
}

function cookiePathMatches(requestPath, cookiePath) {
  if (requestPath === cookiePath) return true;
  if (!requestPath.startsWith(cookiePath)) return false;
  return cookiePath.endsWith('/') || requestPath[cookiePath.length] === '/';
}

function cookieDomainMatches(hostname, cookie) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/gu, '');
  if (cookie.hostOnly) return host === cookie.domain;
  return host === cookie.domain || host.endsWith('.' + cookie.domain);
}

function parseSetCookie(header, url) {
  if (typeof header !== 'string' || header.length === 0 || header.length > 8192) return undefined;
  const segments = header.split(';');
  const pair = segments[0];
  const eq = pair.indexOf('=');
  if (eq <= 0) return undefined;
  const name = pair.slice(0, eq).trim();
  const value = pair.slice(eq + 1).trim();
  if (!name || /[\x00-\x1f\x7f;=]/u.test(name)) return undefined;
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/gu, '');
  const cookie = {
    name, value, domain: host, hostOnly: true, path: defaultCookiePath(url.pathname),
    secure: false, httpOnly: false, expiresAt: undefined,
  };
  for (let index = 1; index < segments.length; index += 1) {
    const raw = segments[index].trim();
    if (!raw) continue;
    const sep = raw.indexOf('=');
    const attr = (sep === -1 ? raw : raw.slice(0, sep)).trim().toLowerCase();
    const attrVal = sep === -1 ? '' : raw.slice(sep + 1).trim();
    if (attr === 'secure') cookie.secure = true;
    else if (attr === 'httponly') cookie.httpOnly = true;
    else if (attr === 'path' && attrVal.startsWith('/')) cookie.path = attrVal;
    else if (attr === 'domain' && attrVal) {
      const cleaned = attrVal.replace(/^\.+/u, '').toLowerCase();
      if (cleaned && (host === cleaned || host.endsWith('.' + cleaned))) {
        cookie.domain = cleaned;
        cookie.hostOnly = false;
      } else {
        return undefined;
      }
    } else if (attr === 'max-age' && /^-?\d+$/u.test(attrVal)) {
      const seconds = Number(attrVal);
      cookie.expiresAt = seconds <= 0 ? 0 : Date.now() + seconds * 1000;
    } else if (attr === 'expires' && cookie.expiresAt === undefined) {
      const parsed = Date.parse(attrVal);
      if (Number.isFinite(parsed)) cookie.expiresAt = parsed;
    }
  }
  return cookie;
}

export function createCookieJarStore({ maxJars = 16, maxCookiesPerJar = 64 } = {}) {
  const jars = new Map();
  function getJar(name) {
    let jar = jars.get(name);
    if (jar === undefined) {
      if (jars.size >= maxJars) jars.delete(jars.keys().next().value);
      jar = new Map();
      jars.set(name, jar);
    }
    return jar;
  }
  return {
    forJar(name) {
      return {
        headerFor(url) {
          const jar = jars.get(name);
          if (!jar || jar.size === 0) return '';
          const now = Date.now();
          const matched = [];
          for (const [key, cookie] of jar) {
            if (cookie.expiresAt !== undefined && cookie.expiresAt <= now) {
              jar.delete(key);
              continue;
            }
            if (cookie.secure && url.protocol !== 'https:') continue;
            if (!cookieDomainMatches(url.hostname, cookie)) continue;
            if (!cookiePathMatches(url.pathname || '/', cookie.path)) continue;
            matched.push(cookie);
          }
          matched.sort((a, b) => b.path.length - a.path.length);
          return matched.map(cookie => `${cookie.name}=${cookie.value}`).join('; ');
        },
        store(url, setCookies) {
          if (!Array.isArray(setCookies) || setCookies.length === 0) return [];
          const jar = getJar(name);
          const now = Date.now();
          const updated = [];
          for (const raw of setCookies) {
            const cookie = parseSetCookie(raw, url);
            if (!cookie) continue;
            const key = `${cookie.domain}|${cookie.path}|${cookie.name}`;
            if (cookie.expiresAt !== undefined && cookie.expiresAt <= now) {
              jar.delete(key);
              updated.push({ name: cookie.name, domain: cookie.domain, path: cookie.path, action: 'deleted' });
            } else {
              if (!jar.has(key) && jar.size >= maxCookiesPerJar) jar.delete(jar.keys().next().value);
              jar.set(key, cookie);
              updated.push({ name: cookie.name, domain: cookie.domain, path: cookie.path, action: 'set' });
            }
          }
          return updated;
        },
      };
    },
  };
}

function escapeMultipartParam(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256 || /[\r\n\0]/u.test(value)) {
    throw new Error(`multipart.${label} 须为 1 至 256 字符的单行文本。`);
  }
  return value.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
}

async function buildMultipartBody(parts, readFile) {
  if (!Array.isArray(parts) || parts.length < 1 || parts.length > 16) {
    throw new Error('multipart 须包含 1 至 16 个字段。');
  }
  const boundary = '----dshCtfBoundary' + randomBytes(12).toString('hex');
  const chunks = [];
  let total = 0;
  for (const part of parts) {
    if (!part || typeof part !== 'object' || Array.isArray(part)) throw new Error('multipart 每项须是对象。');
    for (const key of Object.keys(part)) {
      if (!['name', 'value', 'value_encoding', 'file_path', 'filename', 'content_type'].includes(key)) {
        throw new Error(`multipart 不支持字段 ${key}。`);
      }
    }
    const fieldName = escapeMultipartParam(part.name, 'name');
    const hasValue = part.value !== undefined;
    const hasFile = part.file_path !== undefined;
    if (hasValue === hasFile) throw new Error(`multipart 字段 ${part.name} 须在 value 和 file_path 中二选一。`);
    let payload;
    let filename = part.filename;
    if (hasFile) {
      if (typeof part.file_path !== 'string' || part.file_path.length === 0 || part.file_path.length > 1024) {
        throw new Error('multipart.file_path 无效。');
      }
      if (typeof readFile !== 'function') throw new Error('当前环境不支持 multipart.file_path 文件上传。');
      payload = await readFile(part.file_path, MAX_BODY_BYTES);
      filename ??= part.file_path.split(/[\\/]/u).pop() || 'upload.bin';
    } else {
      if (typeof part.value !== 'string') throw new Error('multipart.value 必须是字符串。');
      const encoding = part.value_encoding ?? DEFAULT_BODY_ENCODING;
      if (!BODY_ENCODINGS.includes(encoding)) throw new Error(`value_encoding 必须是 ${BODY_ENCODINGS.join('、')} 之一。`);
      payload = decodeBody(part.value, encoding);
    }
    let disposition = `Content-Disposition: form-data; name="${fieldName}"`;
    if (filename !== undefined) disposition += `; filename="${escapeMultipartParam(filename, 'filename')}"`;
    const partLines = [`--${boundary}`, disposition];
    if (part.content_type !== undefined) {
      if (typeof part.content_type !== 'string' || !HEADER_VALUE.test(part.content_type) || part.content_type.length > 256) {
        throw new Error('multipart.content_type 格式无效。');
      }
      partLines.push(`Content-Type: ${part.content_type}`);
    } else if (hasFile) {
      partLines.push('Content-Type: application/octet-stream');
    }
    const headerBuf = Buffer.from(partLines.join('\r\n') + '\r\n\r\n', 'utf8');
    const trailerBuf = Buffer.from('\r\n', 'utf8');
    total += headerBuf.length + payload.length + trailerBuf.length;
    if (total > MAX_BODY_BYTES) throw new Error(`multipart 请求体超过 ${MAX_BODY_BYTES} 字节（1 MiB）。`);
    chunks.push(headerBuf, payload, trailerBuf);
  }
  const closing = Buffer.from(`--${boundary}--\r\n`, 'utf8');
  if (total + closing.length > MAX_BODY_BYTES) throw new Error(`multipart 请求体超过 ${MAX_BODY_BYTES} 字节（1 MiB）。`);
  chunks.push(closing);
  return { body: Buffer.concat(chunks), contentType: `multipart/form-data; boundary=${boundary}` };
}

function mergeCookieHeader(headers, jarHeader) {
  if (!jarHeader) return headers;
  const existingKey = Object.keys(headers).find(key => key.toLowerCase() === 'cookie');
  if (!existingKey) return { ...headers, Cookie: jarHeader };
  const merged = new Map();
  for (const part of [jarHeader, headers[existingKey]]) {
    for (const item of String(part).split(';')) {
      const trimmed = item.trim();
      const eq = trimmed.indexOf('=');
      if (eq > 0) merged.set(trimmed.slice(0, eq).trim(), trimmed);
    }
  }
  return { ...headers, [existingKey]: [...merged.values()].join('; ') };
}

function parseInput(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('请求参数必须是对象。');
  }
  for (const key of Object.keys(input)) {
    if (!Object.prototype.hasOwnProperty.call(HTTP_REQUEST_PROPERTIES, key)) {
      throw new Error(`不支持的参数：${key}。`);
    }
  }
  if (input.body !== undefined && input.multipart !== undefined) {
    throw new Error('body 和 multipart 不能同时提供。');
  }
  if (input.cookie_jar !== undefined && (typeof input.cookie_jar !== 'string'
    || input.cookie_jar.length < 1 || input.cookie_jar.length > 64 || /[\r\n\0]/u.test(input.cookie_jar))) {
    throw new Error('cookie_jar 须为 1 至 64 字符的单行标识。');
  }
  return {
    url: parseUrl(input.url),
    method: parseMethod(input.method),
    headers: parseHeaders(input.headers),
    body: input.multipart === undefined ? parseBody(input) : null,
    multipart: input.multipart,
    cookieJarName: input.cookie_jar,
    timeoutMs: parseInteger(input.timeout_ms, DEFAULT_TIMEOUT_MS, MIN_TIMEOUT_MS, MAX_TIMEOUT_MS, 'timeout_ms'),
    maxBytes: parseInteger(input.max_bytes, DEFAULT_MAX_BYTES, MIN_MAX_BYTES, MAX_MAX_BYTES, 'max_bytes'),
    followRedirects: parseBoolean(input.follow_redirects, true, 'follow_redirects'),
    allowInsecure: parseBoolean(input.allow_insecure, false, 'allow_insecure'),
  };
}

function buildHeaders(given, body) {
  const headers = { ...given };
  const names = new Set(Object.keys(headers).map(name => name.toLowerCase()));
  if (!names.has('accept-encoding')) headers['Accept-Encoding'] = DEFAULT_ACCEPT_ENCODING;
  if (body !== null && body.length > 0 && !names.has('content-length') && !names.has('transfer-encoding')) {
    headers['Content-Length'] = String(body.length);
  }
  return headers;
}

function collectHeaders(rawHeaders) {
  const headers = {};
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = String(rawHeaders[index]).toLowerCase();
    const value = String(rawHeaders[index + 1]);
    if (name === 'set-cookie') {
      if (headers[name] === undefined) headers[name] = [value];
      else headers[name].push(value);
    } else if (headers[name] === undefined) {
      headers[name] = value;
    } else {
      headers[name] += `, ${value}`;
    }
  }
  return headers;
}

function mediaType(value) {
  if (typeof value !== 'string') return '';
  return value.split(';', 1)[0].trim().toLowerCase();
}

function allowsText(type) {
  if (type === '') return true;
  if (type.startsWith('text/')) return true;
  if (TEXT_APPLICATION_TYPES.has(type)) return true;
  return type.endsWith('+json') || type.endsWith('+xml');
}

function decodeUtf8(bytes) {
  try {
    const text = UTF8.decode(bytes);
    return CONTROL.test(text) ? undefined : text;
  } catch {
    return undefined;
  }
}

function parseContentEncodings(value) {
  if (value === undefined) return { encodings: [], supported: true };
  const encodings = value.split(',')
    .map(part => part.trim().toLowerCase())
    .filter(part => part.length > 0 && part !== 'identity');
  if (encodings.length === 0) return { encodings: [], supported: true };
  if (encodings.some(encoding => !SUPPORTED_CONTENT_ENCODINGS.has(encoding))) {
    return { encodings: [], supported: false };
  }
  return { encodings, supported: true };
}

function createDecoder(encoding) {
  if (encoding === 'gzip' || encoding === 'x-gzip') return zlib.createGunzip();
  if (encoding === 'deflate') return zlib.createUnzip();
  return zlib.createBrotliDecompress();
}

// 只保留前 limit 字节；一旦超限就标记 truncated 并停止读取，避免把超大响应读进内存。
async function readCapped(stream, limit, decoders, retainPartial) {
  const chunks = [];
  let total = 0;
  const limitReached = new Error('Response preview limit reached');
  const output = new Writable({
    write(chunk, _encoding, callback) {
      const keep = Math.min(chunk.length, limit - total);
      if (keep > 0) {
        chunks.push(chunk.subarray(0, keep));
        total += keep;
      }
      callback(keep < chunk.length ? limitReached : undefined);
    },
  });
  try {
    await pipeline(stream, ...decoders, output);
  } catch (error) {
    const buffer = Buffer.concat(chunks, total);
    if (error === limitReached) return { buffer, truncated: true };
    if (retainPartial) return { buffer, truncated: false, readError: error };
    throw error;
  }
  return { buffer: Buffer.concat(chunks, total), truncated: false };
}

function sha256Hex(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

export async function readResponseBody(source, { method, status, contentEncoding, limit, retainPartial = false }) {
  const empty = { buffer: Buffer.alloc(0), truncated: false };
  if (method === 'HEAD' || status === 204 || status === 304) {
    source.on('error', () => {});
    source.resume();
    return empty;
  }
  const { encodings } = parseContentEncodings(contentEncoding);
  if (encodings.length === 0) return readCapped(source, limit, [], retainPartial);
  const iterator = source[Symbol.asyncIterator]();
  try {
    const first = await iterator.next();
    if (first.done) return { ...empty, empty_encoded_body: true };
    async function* input() {
      yield first.value;
      yield* iterator;
    }
    return await readCapped(Readable.from(input(), { objectMode: false }), limit, encodings.reverse().map(createDecoder), retainPartial);
  } catch (error) {
    if (retainPartial) return { ...empty, readError: error };
    throw error;
  } finally {
    await iterator.return().catch(() => {});
  }
}

export function redirectBlockReason(current, target, method, bodyLength) {
  const upgrade = current.protocol === 'http:' && target.protocol === 'https:' && current.hostname === target.hostname;
  if ((target.origin !== current.origin && !upgrade) || target.username || target.password) return 'cross_origin_or_credentials';
  if ((method !== 'GET' && method !== 'HEAD') || bodyLength > 0) return 'request_replay';
  return undefined;
}

function redirectTarget(location, current) {
  try {
    const url = new URL(location, current);
    if (!['http:', 'https:'].includes(url.protocol) || url.href.length > MAX_URL_LENGTH) return undefined;
    url.hash = '';
    return url;
  } catch {
    return undefined;
  }
}

function safeLocation(location, target) {
  if (target === undefined) return '[无效 Location]';
  return target.username || target.password ? errorLocation(target) : location;
}

function requestOnce(hop) {
  const { url, method, headers, body, timeoutMs, maxBytes, allowInsecure, signal, address } = hop;
  return new Promise((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : http;
    const controller = new AbortController();
    let request;
    let response;
    let timer;
    let done = false;
    let interrupted;

    const cleanup = () => {
      if (timer !== undefined) {
        clearTimeout(timer);
        timer = undefined;
      }
      if (signal !== undefined) signal.removeEventListener('abort', onExternalAbort);
      if (request !== undefined) {
        try {
          request.setTimeout(0);
        } catch {
          // 请求可能已经销毁，忽略。
        }
      }
    };

    const fail = error => {
      if (done) return;
      done = true;
      cleanup();
      if (request !== undefined) request.destroy();
      if (response !== undefined) response.destroy();
      reject(error);
    };

    const finish = value => {
      if (done) return;
      done = true;
      cleanup();
      resolve(value);
    };

    const interrupt = error => {
      if (done) return;
      interrupted ??= error;
      if (response === undefined) fail(interrupted);
      else response.destroy(interrupted);
      controller.abort();
    };

    const onTimeout = () => interrupt(timeoutError(timeoutMs, url));

    function onExternalAbort() {
      interrupt(abortError(url));
    }

    if (signal !== undefined) {
      if (signal.aborted) {
        fail(abortError(url));
        return;
      }
      signal.addEventListener('abort', onExternalAbort, { once: true });
    }

    const requestOptions = {
      method,
      headers,
      agent: false,
      signal: controller.signal,
      ...(address === undefined ? {} : { lookup: pinnedLookup(address) }),
    };
    if (url.protocol === 'https:') requestOptions.rejectUnauthorized = !allowInsecure;

    try {
      request = transport.request(url, requestOptions, onResponse);
    } catch (error) {
      fail(networkError(error, url));
      return;
    }

    request.on('error', error => {
      if (done) return;
      if (response !== undefined) response.destroy(interrupted ?? error);
      else fail(interrupted ?? networkError(error, url));
    });

    request.setTimeout(timeoutMs, onTimeout);
    timer = setTimeout(onTimeout, timeoutMs);

    try {
      if (body !== null && body.length > 0) request.end(body);
      else request.end();
    } catch {
      fail(namedError(`发送请求失败（${errorLocation(url)}）。`));
      return;
    }

    function onResponse(res) {
      if (done) {
        res.resume();
        return;
      }
      response = res;
      const status = res.statusCode ?? 0;
      const statusText = res.statusMessage ?? '';
      const responseHeaders = collectHeaders(res.rawHeaders);
      const remoteAddress = res.socket?.remoteAddress ?? '';
      const contentEncoding = responseHeaders['content-encoding'];

      const finishHop = body => {
        const { readError, ...preview } = body;
        const failure = interrupted ?? readError;
        if (preview.truncated || failure) res.destroy();
        finish({
          url: url.href,
          status,
          statusText,
          headers: responseHeaders,
          remoteAddress,
          ...preview,
          ...(failure ? { body_error: bodyError(failure, url) } : {}),
          contentEncoding,
        });
      };

      readResponseBody(res, { method, status, contentEncoding, limit: maxBytes, retainPartial: true })
        .then(finishHop, error => finishHop({ buffer: Buffer.alloc(0), truncated: false, readError: error }));
    }
  });
}

/**
 * 发出一次 HTTP 请求并返回结构化结果。4xx/5xx 正常返回，不抛错。
 * 网络错误、DNS 失败、超时与取消都会抛出中文 Error。
 */
export async function httpRequest(input, options = {}) {
  const config = parseInput(input);
  const signal = parseOptions(options);
  if (signal !== undefined && signal.aborted) throw abortError(config.url);

  const startedAt = Date.now();
  const redirects = [];
  const notes = [];
  const cookiesStored = [];
  const visited = new Set([config.url.href]);
  let currentUrl = config.url;
  const { method } = config;
  const givenHeaders = { ...config.headers };
  let body = config.body;
  if (config.multipart !== undefined) {
    const built = await buildMultipartBody(config.multipart, options.readFile);
    body = built.body;
    if (!Object.keys(givenHeaders).some(name => name.toLowerCase() === 'content-type')) {
      givenHeaders['Content-Type'] = built.contentType;
    }
  }
  let baseHeaders = buildHeaders(givenHeaders, body);
  let address = await options.authorize?.(currentUrl, signal);

  if (body.length > 0 && (method === 'GET' || method === 'HEAD')) {
    notes.push(`${method} 请求携带了 body，部分服务器会忽略它。`);
  }
  if (config.allowInsecure) {
    notes.push('allow_insecure=true：已跳过 HTTPS 证书校验。');
  }

  for (;;) {
    if (signal !== undefined && signal.aborted) throw abortError(currentUrl);
    const headers = options.cookieJar
      ? mergeCookieHeader(baseHeaders, options.cookieJar.headerFor(currentUrl))
      : baseHeaders;

    const hop = await requestOnce({
      url: currentUrl,
      address,
      method,
      headers,
      body,
      timeoutMs: config.timeoutMs,
      maxBytes: config.maxBytes,
      allowInsecure: config.allowInsecure,
      signal,
    });
    if (options.cookieJar && Array.isArray(hop.headers['set-cookie'])) {
      cookiesStored.push(...options.cookieJar.store(currentUrl, hop.headers['set-cookie']));
    }

    const location = hop.headers.location;
    const isRedirect = REDIRECT_STATUSES.has(hop.status)
      && typeof location === 'string' && location.length > 0;

    let redirectBlocked;
    const target = typeof location === 'string' ? redirectTarget(location, currentUrl) : undefined;
    if (typeof location === 'string') hop.headers.location = safeLocation(location, target);
    if (config.followRedirects && isRedirect && !hop.body_error) {
      if (target === undefined) redirectBlocked = 'invalid_location';
      else if (redirects.length >= MAX_REDIRECTS) redirectBlocked = 'redirect_limit';
      else if (visited.has(target.href)) redirectBlocked = 'redirect_loop';
      else redirectBlocked = redirectBlockReason(currentUrl, target, method, body.length);
      if (redirectBlocked === undefined) {
        try {
          address = await options.authorize?.(target, signal);
        } catch {
          redirectBlocked = 'target_not_authorized';
        }
      }
      if (redirectBlocked === undefined) {
        if (currentUrl.origin !== target.origin) {
          baseHeaders = buildHeaders({}, body);
          notes.push('同主机升级为 HTTPS，已清除原请求自定义头。');
        }
        visited.add(target.href);
        redirects.push({ status: hop.status, location: hop.headers.location, url: target.href });
        currentUrl = target;
        continue;
      }
      notes.push(redirectBlocked === 'request_replay' ? '重定向需要重发原请求，已保留首个响应。'
        : '重定向未通过规则或授权检查，已保留当前响应。');
    }

    if (config.followRedirects && REDIRECT_STATUSES.has(hop.status) && !isRedirect) {
      notes.push(`${hop.status} 响应缺少可用的 Location，未跟随重定向。`);
    }
    if (!config.followRedirects && isRedirect) {
      notes.push(`follow_redirects=false：未跟随 ${hop.status} 重定向。`);
    }

    const contentType = mediaType(hop.headers['content-type']);
    const text = decodeUtf8(hop.buffer);
    const textual = allowsText(contentType) && text !== undefined;
    const result = {
      url: config.url.href,
      final_url: hop.url,
      method,
      status: hop.status,
      status_text: hop.statusText,
      headers: hop.headers,
      redirects,
      elapsed_ms: Math.max(0, Date.now() - startedAt),
      body_bytes: hop.buffer.length,
      truncated: hop.truncated,
      body_complete: !hop.truncated && !hop.body_error,
      ...(hop.body_error ? { body_error: hop.body_error } : {}),
      sha256: hop.buffer.length === 0 ? EMPTY_SHA256 : sha256Hex(hop.buffer),
      ...(redirectBlocked === undefined ? {} : { redirect_blocked: redirectBlocked }),
      ...(config.cookieJarName === undefined ? {} : { cookie_jar: config.cookieJarName, cookies_stored: cookiesStored }),
      remote_address: hop.remoteAddress,
    };
    if (hop.contentEncoding !== undefined) result.content_encoding = hop.contentEncoding;
    if (textual) {
      result.body = text;
      result.body_encoding_used = 'utf8';
    } else {
      result.body_hex = hop.buffer.toString('hex');
      result.body_encoding_used = 'hex';
    }
    if (method === 'HEAD') notes.push('HEAD 请求不读取响应体。');
    if (hop.empty_encoded_body) notes.push('响应声明了压缩编码，实际正文为零字节。');
    if (hop.body_error) notes.push('响应体未读取完整。sha256 只覆盖已返回的字节。');
    if (hop.truncated) {
      notes.push(`响应体超过 max_bytes（${config.maxBytes} 字节），仅返回前 ${hop.buffer.length} 字节；sha256 只覆盖返回的字节。`);
    }
    if (hop.contentEncoding !== undefined && !parseContentEncodings(hop.contentEncoding).supported) {
      notes.push(`响应 Content-Encoding 为 ${hop.contentEncoding}，不支持自动解压，按原始字节返回。`);
    }
    if (!textual && hop.buffer.length > 0) {
      notes.push('响应体不是合法 UTF-8 文本或含控制字符，按十六进制返回。');
    }
    result.notes = notes;
    return result;
  }
}
