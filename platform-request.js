import { httpRequest } from './http-client.js';
import { pinAddress, webUrl } from './network-boundary.js';
import { ToolError } from './tool-errors.js';

const PRIVATE_HEADERS = new Set(['set-cookie', 'cookie', 'authorization', 'proxy-authorization', 'www-authenticate']);
const HEADER_TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;

export function platformBase(config) {
  return typeof config?.platformUrl === 'string' ? config.platformUrl.trim() : '';
}

export function platformCredential(config) {
  const tokenEnv = config?.platformTokenEnv ?? 'CTF_PLATFORM_TOKEN';
  const token = process.env[tokenEnv] ?? '';
  return { tokenEnv, token };
}

export function platformAuthHeaders(config) {
  const { token } = platformCredential(config);
  if (!token) return {};
  const header = typeof config?.platformAuthHeader === 'string' && config.platformAuthHeader.trim() !== ''
    ? config.platformAuthHeader.trim() : 'Authorization';
  if (!HEADER_TOKEN.test(header)) throw new ToolError('unsupported', 'platformAuthHeader 不是合法的 HTTP 头名称。');
  const scheme = config?.platformAuthScheme === undefined ? 'Bearer' : String(config.platformAuthScheme).trim();
  if (/[\r\n\0]/u.test(scheme)) throw new ToolError('unsupported', 'platformAuthScheme 不能包含换行或控制字符。');
  return { [header]: scheme ? `${scheme} ${token}` : token };
}

export function redactPlatformToken(response, token = '') {
  if (!token) return response;
  const hide = value => typeof value === 'string' ? value.replaceAll(token, '[已脱敏]') : value;
  const { body_hex, ...values } = response;
  const hiddenHex = typeof body_hex === 'string' && body_hex.includes(Buffer.from(token).toString('hex'));
  return {
    ...values,
    ...(body_hex !== undefined && !hiddenHex ? { body_hex } : {}),
    ...(hiddenHex ? { body_redacted: true } : {}),
    ...Object.fromEntries(['body', 'status_text'].filter(key => response[key] !== undefined)
      .map(key => [key, hide(response[key])])),
    headers: Object.fromEntries(Object.entries(response.headers ?? {}).map(([name, value]) => [
      name, Array.isArray(value) ? value.map(hide) : hide(value),
    ])),
  };
}

export function cleanHttpResponse(response, token = '') {
  const hide = value => token && typeof value === 'string' ? value.replaceAll(token, '[已脱敏]') : value;
  const { body_hex, ...values } = response;
  const hiddenHex = token && body_hex?.includes(Buffer.from(token).toString('hex'));
  return {
    ...values,
    ...(body_hex !== undefined && !hiddenHex ? { body_hex } : {}),
    ...(hiddenHex ? { body_redacted: true } : {}),
    ...Object.fromEntries(['body', 'status_text'].filter(key => response[key] !== undefined)
      .map(key => [key, hide(response[key])])),
    headers: Object.fromEntries(Object.entries(response.headers ?? {}).map(([name, value]) => [
      name, PRIVATE_HEADERS.has(name.toLowerCase()) ? '[已脱敏]' : Array.isArray(value) ? value.map(hide) : hide(value),
    ])),
  };
}

export async function platformRequest(config, signal, method, route, body, request = httpRequest) {
  const base = platformBase(config);
  if (!base) throw new ToolError('dependency', '未配置比赛平台。请设置 platformUrl。');
  const origin = webUrl(base);
  if (origin.search || origin.hash) throw new ToolError('unsupported', 'platformUrl 须是平台 API 根路径。');
  const { token } = platformCredential(config);
  if (token && origin.protocol !== 'https:' && config?.allowInsecurePlatformHttp !== true) {
    throw new ToolError('permission', '平台令牌只通过 HTTPS 发送；内网 HTTP 平台请在配置中显式设置 allowInsecurePlatformHttp: true。');
  }
  const url = base.replace(/[\\/]+$/u, '') + (route.startsWith('/') ? route : '/' + route);
  const response = await request({
    url, method,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...platformAuthHeaders(config) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    timeout_ms: 30000,
    follow_redirects: false,
  }, {
    signal,
    authorize(target, requestSignal) {
      if (target.origin !== origin.origin) throw new ToolError('permission', '平台请求超出配置来源。');
      return pinAddress(target.hostname, { signal: requestSignal });
    },
  });
  return cleanHttpResponse(response, token);
}
