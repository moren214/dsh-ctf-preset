import { lookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';

const nonglobal = new BlockList();
for (const [prefix, length] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
  ['168.63.129.16', 32],
]) nonglobal.addSubnet(prefix, length, 'ipv4');
for (const [prefix, length] of [['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20]]) {
  nonglobal.addSubnet(prefix, length, 'ipv6');
}
const globalIPv6 = new BlockList();
globalIPv6.addSubnet('2000::', 3, 'ipv6');

const infrastructure = new BlockList();
for (const [prefix, length] of [['0.0.0.0', 8], ['169.254.0.0', 16], ['224.0.0.0', 4],
  ['240.0.0.0', 4], ['168.63.129.16', 32]]) infrastructure.addSubnet(prefix, length, 'ipv4');
for (const [prefix, length] of [['::', 128], ['64:ff9b::', 96], ['64:ff9b:1::', 48],
  ['fe80::', 10], ['ff00::', 8], ['fd00:ec2::254', 128]]) infrastructure.addSubnet(prefix, length, 'ipv6');
const mapped = new BlockList();
mapped.addSubnet('::ffff:0:0', 96, 'ipv6');

export function webUrl(value) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.href.length > 8192) {
    throw new Error('网络目标必须是不含登录信息的 HTTP(S) 地址。');
  }
  return url;
}

function hostName(host) {
  return host.replace(/^\[|\]$/gu, '').toLowerCase().replace(/\.$/u, '');
}

function familyName(family) {
  return family === 4 ? 'ipv4' : 'ipv6';
}

export function publicAddress(address) {
  const family = isIP(address);
  return family !== 0 && (family === 4 || globalIPv6.check(address, 'ipv6'))
    && !nonglobal.check(address, familyName(family));
}

function abortable(promise, signal) {
  if (signal === undefined) return promise;
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
  });
}

export async function pinAddress(host, { publicOnly = false, signal, resolve = lookup } = {}) {
  signal?.throwIfAborted();
  const hostname = hostName(host);
  const family = isIP(hostname);
  if (!hostname || hostname.includes('%')) throw new Error('网络目标主机无效。');
  const addresses = family ? [{ address: hostname, family }]
    : await abortable(resolve(hostname, { all: true, verbatim: true }), signal);
  if (addresses.length === 0 || addresses.some(({ address, family }) => isIP(address) !== family
    || infrastructure.check(address, familyName(family)) || (family === 6 && mapped.check(address, 'ipv6'))
    || (publicOnly && !publicAddress(address)))) {
    throw new Error('网络目标的解析结果超出授权地址范围。');
  }
  signal?.throwIfAborted();
  return addresses[0];
}

export function pinnedLookup(entry) {
  return (_hostname, options, callback) => {
    if (options?.all) callback(null, [entry]);
    else callback(null, entry.address, entry.family);
  };
}

function parsePortMatcher(text, defaultPort) {
  if (text === undefined || text === '') return port => port === defaultPort;
  if (text === '*') return () => true;
  const range = /^(\d{1,5})-(\d{1,5})$/u.exec(text);
  if (range) {
    const min = Number(range[1]);
    const max = Number(range[2]);
    if (min < 1 || max > 65535 || min > max) return undefined;
    return port => port >= min && port <= max;
  }
  if (/^\d{1,5}$/u.test(text)) {
    const exact = Number(text);
    if (exact < 1 || exact > 65535) return undefined;
    return port => port === exact;
  }
  return undefined;
}

function parseHostMatcher(rawHost) {
  if (typeof rawHost !== 'string' || rawHost.length === 0 || rawHost.length > 255) return undefined;
  if (rawHost.includes('/')) {
    const slash = rawHost.indexOf('/');
    const ipPart = hostName(rawHost.slice(0, slash));
    const prefixText = rawHost.slice(slash + 1);
    const family = isIP(ipPart);
    if (family === 0 || !/^\d{1,3}$/u.test(prefixText)) return undefined;
    const prefix = Number(prefixText);
    const maxBits = family === 4 ? 32 : 128;
    if (prefix < 1 || prefix > maxBits) return undefined;
    const subnet = new BlockList();
    subnet.addSubnet(ipPart, prefix, familyName(family));
    return target => {
      const targetFamily = isIP(target);
      return targetFamily === family && subnet.check(target, familyName(family));
    };
  }
  const normalized = hostName(rawHost);
  if (!normalized || normalized === '*' || normalized.includes('%')) return undefined;
  if (normalized.startsWith('*.')) {
    const suffix = normalized.slice(1);
    if (suffix.length < 2 || suffix.includes('*') || !suffix.slice(1).includes('.')) return undefined;
    return target => target.length > suffix.length && target.endsWith(suffix);
  }
  if (normalized.includes('*')) return undefined;
  return target => target === normalized;
}

function parseHttpRule(value) {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  const match = /^(https?):\/\/(\[[^\]]+\](?:\/\d{1,3})?|[^/:?#\s]+(?:\/\d{1,3})?)(?::(\*|\d{1,5}(?:-\d{1,5})?))?\/?$/iu.exec(trimmed);
  if (!match) {
    try {
      const url = webUrl(trimmed);
      const exactOrigin = url.origin;
      return urlTarget => urlTarget.origin === exactOrigin;
    } catch {
      return undefined;
    }
  }
  const protocol = match[1].toLowerCase() + ':';
  const defaultPort = protocol === 'https:' ? 443 : 80;
  const matchHost = parseHostMatcher(match[2]);
  const matchPort = parsePortMatcher(match[3], defaultPort);
  if (!matchHost || !matchPort) return undefined;
  return urlTarget => {
    if (urlTarget.protocol !== protocol) return false;
    const targetPort = urlTarget.port ? Number(urlTarget.port) : (urlTarget.protocol === 'https:' ? 443 : 80);
    return matchPort(targetPort) && matchHost(hostName(urlTarget.hostname));
  };
}

function parseTcpRule(value) {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  const match = /^(\[[^\]]+\](?:\/\d{1,3})?|[^/:?#\s]+(?:\/\d{1,3})?):(\*|\d{1,5}(?:-\d{1,5})?)$/u.exec(trimmed);
  if (!match) return undefined;
  const matchHost = parseHostMatcher(match[1]);
  const matchPort = parsePortMatcher(match[2], undefined);
  if (!matchHost || !matchPort) return undefined;
  return (targetHost, targetPort) => matchPort(targetPort) && matchHost(hostName(targetHost));
}

const MAX_DYNAMIC_GRANTS = 64;

export function createNetworkBoundary(configSource = {}) {
  const getConfig = typeof configSource === 'function' ? configSource : () => configSource ?? {};
  const dynamicOrigins = new Set();
  const dynamicTcp = new Set();
  const list = value => Array.isArray(value) ? value.filter(item => typeof item === 'string') : [];
  let cachedOriginsKey = '';
  let cachedHttpRules = [];
  let cachedTcpKey = '';
  let cachedTcpRules = [];

  function httpRules() {
    const items = list(getConfig()?.networkOrigins);
    const key = JSON.stringify(items);
    if (key !== cachedOriginsKey) {
      cachedOriginsKey = key;
      cachedHttpRules = items.map(parseHttpRule).filter(Boolean);
    }
    return cachedHttpRules;
  }

  function tcpRules() {
    const items = list(getConfig()?.tcpTargets);
    const key = JSON.stringify(items);
    if (key !== cachedTcpKey) {
      cachedTcpKey = key;
      cachedTcpRules = items.map(parseTcpRule).filter(Boolean);
    }
    return cachedTcpRules;
  }

  function isHttpAuthorized(value) {
    let url;
    try { url = value instanceof URL ? value : webUrl(value); }
    catch { return false; }
    return dynamicOrigins.has(url.origin) || httpRules().some(rule => rule(url));
  }

  function isTcpAuthorized(host, port) {
    const key = hostName(host) + '/' + port;
    return dynamicTcp.has(key) || tcpRules().some(rule => rule(host, port));
  }

  function grantHttp(value) {
    let url;
    try { url = webUrl(value); }
    catch { return undefined; }
    const hostname = hostName(url.hostname);
    const family = isIP(hostname);
    if (family && (infrastructure.check(hostname, familyName(family)) || (family === 6 && mapped.check(hostname, 'ipv6')))) {
      return undefined;
    }
    if (!dynamicOrigins.has(url.origin) && dynamicOrigins.size >= MAX_DYNAMIC_GRANTS) {
      dynamicOrigins.delete(dynamicOrigins.values().next().value);
    }
    dynamicOrigins.add(url.origin);
    return url.origin;
  }

  function grantTcp(host, port) {
    const numericPort = Number(port);
    const normalized = hostName(String(host ?? ''));
    if (!normalized || normalized.includes('%') || /[\s/\\:?#]/u.test(normalized)
      || !Number.isInteger(numericPort) || numericPort < 1 || numericPort > 65535) return undefined;
    const family = isIP(normalized);
    if (family && (infrastructure.check(normalized, familyName(family)) || (family === 6 && mapped.check(normalized, 'ipv6')))) {
      return undefined;
    }
    const key = normalized + '/' + numericPort;
    if (!dynamicTcp.has(key) && dynamicTcp.size >= MAX_DYNAMIC_GRANTS) {
      dynamicTcp.delete(dynamicTcp.values().next().value);
    }
    dynamicTcp.add(key);
    return normalized + ':' + numericPort;
  }

  return {
    isHttpAuthorized,
    isTcpAuthorized,
    grantHttp,
    grantTcp,
    async http(value, signal) {
      const url = value instanceof URL ? webUrl(value.href) : webUrl(value);
      if (!isHttpAuthorized(url)) throw new Error('此 HTTP(S) 来源尚未在 networkOrigins 中授权。');
      return pinAddress(url.hostname, { signal });
    },
    async tcp(host, port, signal) {
      if (!isTcpAuthorized(host, port)) throw new Error('此 TCP 目标尚未在 tcpTargets 中授权。');
      return pinAddress(host, { signal });
    },
  };
}
