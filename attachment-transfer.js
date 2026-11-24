import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { pinAddress, pinnedLookup, webUrl } from './network-boundary.js';

export const MAX_TRANSFER_BYTES = 256 * 1024 * 1024;
const REDIRECTS = new Set([301, 302, 303, 307, 308]);

export function provenanceUrl(url) {
  return url.origin + url.pathname;
}

export async function stageAttachment(source, destination, { signal, limit = MAX_TRANSFER_BYTES } = {}) {
  const hash = createHash('sha256');
  const head = Buffer.alloc(512);
  let size = 0;
  const meter = new Transform({
    transform(bytes, _encoding, done) {
      if (size + bytes.length > limit) return done(new Error('附件超过大小上限，已终止传输。'));
      if (size < head.length) bytes.copy(head, size, 0, Math.min(head.length - size, bytes.length));
      size += bytes.length;
      hash.update(bytes);
      done(null, bytes);
    },
  });
  await pipeline(source, meter, createWriteStream(destination, { flags: 'wx', mode: 0o600 }), { signal });
  return { size, sha256: hash.digest('hex'), head: head.subarray(0, Math.min(size, head.length)) };
}

function requestAttachment(url, address, signal, extraHeaders = {}) {
  const transport = url.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const request = transport.get(url, {
      agent: false, signal, lookup: pinnedLookup(address),
      headers: { 'User-Agent': 'dsh-ctf-preset', Accept: '*/*', 'Accept-Encoding': 'identity', ...extraHeaders },
    }, resolve);
    request.once('error', reject);
  });
}

export async function downloadAttachment(target, destination, {
  signal, resolveAddress, authorizeHop, headersFor, request = requestAttachment, limit = MAX_TRANSFER_BYTES,
} = {}) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_TRANSFER_BYTES) throw new Error('附件下载上限无效。');
  const timeout = AbortSignal.timeout(60000);
  const deadline = signal ? AbortSignal.any([signal, timeout]) : timeout;
  let url = webUrl(target);
  const seen = new Set();
  for (let hops = 0; hops <= 5; hops++) {
    deadline.throwIfAborted();
    if (seen.has(url.href)) throw new Error('下载重定向循环。');
    seen.add(url.href);
    const address = authorizeHop
      ? await authorizeHop(url, deadline)
      : await pinAddress(url.hostname, { publicOnly: true, signal: deadline, resolve: resolveAddress });
    const extraHeaders = headersFor ? (headersFor(url) ?? {}) : {};
    const response = await request(url, address, deadline, extraHeaders);
    const status = response.statusCode ?? 0;
    if (REDIRECTS.has(status)) {
      response.destroy();
      if (hops === 5 || typeof response.headers.location !== 'string') throw new Error('下载跳转超限或缺少目标。');
      const next = webUrl(new URL(response.headers.location, url));
      if (url.protocol === 'https:' && next.protocol === 'http:') throw new Error('拒绝附件下载从 HTTPS 降级。');
      url = next;
      continue;
    }
    if (status < 200 || status >= 300 || status === 206 || Number(response.headers['content-length']) > limit) {
      response.destroy();
      throw new Error('附件响应不可用或超过大小上限（HTTP ' + status + '）。');
    }
    const contentType = String(response.headers['content-type'] ?? '').slice(0, 200);
    const attachment = await stageAttachment(response, destination, { signal: deadline, limit });
    return { ...attachment, status, contentType, finalUrl: provenanceUrl(url) };
  }
  throw new Error('下载重定向次数超出上限。');
}
