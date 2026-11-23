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

export function createNetworkBoundary(config = {}) {
  const list = value => Array.isArray(value) ? value.filter(item => typeof item === 'string') : [];
  const origins = new Set();
  for (const value of list(config.networkOrigins)) {
    try { origins.add(webUrl(value).origin); } catch { /* Invalid entries authorize nothing. */ }
  }
  const tcp = new Set();
  for (const value of list(config.tcpTargets)) {
    try {
      const authority = new URL('tcp://' + value);
      if (authority.hostname && authority.port && !authority.pathname && !authority.username && !authority.password
        && !authority.search && !authority.hash) tcp.add(hostName(authority.hostname) + '/' + Number(authority.port));
    } catch { /* Invalid entries authorize nothing. */ }
  }
  return {
    async http(value, signal) {
      const url = webUrl(value);
      if (!origins.has(url.origin)) throw new Error('此 HTTP(S) 来源尚未在 networkOrigins 中授权。');
      return pinAddress(url.hostname, { signal });
    },
    async tcp(host, port, signal) {
      if (!tcp.has(hostName(host) + '/' + port)) throw new Error('此 TCP 目标尚未在 tcpTargets 中授权。');
      return pinAddress(host, { signal });
    },
  };
}
