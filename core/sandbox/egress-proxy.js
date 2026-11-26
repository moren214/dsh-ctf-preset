import { randomBytes } from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import { ToolError } from '../contracts/errors.js';
import { pinAddress, webUrl } from '../../network-boundary.js';

function parseBasicAuth(header) {
  if (typeof header !== 'string' || !header.startsWith('Basic ')) return undefined;
  try {
    return Buffer.from(header.slice(6).trim(), 'base64').toString('utf8');
  } catch {
    return undefined;
  }
}

/**
 * Host-side authenticated HTTP/CONNECT egress proxy for Docker sandbox containers.
 * Every outbound connection is checked against `networkBoundary` (static rules +
 * workspace SQLite dynamic grants) and pinned against DNS rebinding / metadata IPs.
 */
export async function createSandboxEgressProxy({ networkBoundary, scope, listenHost = '127.0.0.1', pin = pinAddress } = {}) {
  if (!networkBoundary) throw new ToolError('dependency', '创建沙箱出网代理需要 networkBoundary。');
  const username = 'dsh';
  const password = randomBytes(18).toString('hex');
  const expectedAuth = `${username}:${password}`;

  const server = http.createServer(async (req, res) => {
    const auth = parseBasicAuth(req.headers['proxy-authorization']);
    if (auth !== expectedAuth) {
      res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="dsh-sandbox"' });
      res.end('Proxy Authentication Required');
      return;
    }
    let targetUrl;
    try {
      targetUrl = webUrl(req.url);
    } catch {
      res.writeHead(400);
      res.end('Invalid proxy target URL');
      return;
    }
    if (!networkBoundary.isHttpAuthorized(targetUrl, scope)) {
      res.writeHead(403);
      res.end(`Forbidden by CTF egress policy: ${targetUrl.origin}`);
      return;
    }
    let pinned;
    try {
      pinned = await pin(targetUrl.hostname);
    } catch (error) {
      res.writeHead(403);
      res.end(`Address blocked: ${error.message}`);
      return;
    }
    const headers = { ...req.headers };
    delete headers['proxy-authorization'];
    delete headers['proxy-connection'];
    const port = targetUrl.port ? Number(targetUrl.port) : (targetUrl.protocol === 'https:' ? 443 : 80);
    const upstream = http.request({
      host: pinned.address,
      port,
      method: req.method,
      path: `${targetUrl.pathname}${targetUrl.search}`,
      headers: { ...headers, host: targetUrl.host },
    }, upRes => {
      res.writeHead(upRes.statusCode ?? 502, upRes.headers);
      upRes.pipe(res);
    });
    upstream.on('error', err => {
      if (!res.headersSent) res.writeHead(502);
      res.end(`Upstream error: ${err.message}`);
    });
    req.pipe(upstream);
  });

  server.on('connect', async (req, clientSocket, head) => {
    const auth = parseBasicAuth(req.headers['proxy-authorization']);
    if (auth !== expectedAuth) {
      clientSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="dsh-sandbox"\r\n\r\n');
      clientSocket.destroy();
      return;
    }
    const rawTarget = String(req.url ?? '');
    const lastColon = rawTarget.lastIndexOf(':');
    const host = lastColon > 0 ? rawTarget.slice(0, lastColon).replace(/^\[|\]$/gu, '') : '';
    const port = lastColon > 0 ? Number(rawTarget.slice(lastColon + 1)) : NaN;
    if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
      clientSocket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
      clientSocket.destroy();
      return;
    }
    const httpEquivalent = `https://${host.includes(':') ? `[${host}]` : host}:${port}`;
    const httpPlain = `http://${host.includes(':') ? `[${host}]` : host}:${port}`;
    const allowed = networkBoundary.isTcpAuthorized(host, port, scope)
      || networkBoundary.isHttpAuthorized(httpEquivalent, scope)
      || networkBoundary.isHttpAuthorized(httpPlain, scope);
    if (!allowed) {
      clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      clientSocket.destroy();
      return;
    }
    let pinned;
    try {
      pinned = await pin(host);
    } catch {
      clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      clientSocket.destroy();
      return;
    }
    const upstream = net.connect(port, pinned.address, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length > 0) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    upstream.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => upstream.destroy());
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, listenHost, () => {
      server.removeListener('error', reject);
      resolve();
    });
  });

  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  const proxyUrlForContainer = (containerHost = 'host.docker.internal') =>
    `http://${username}:${password}@${containerHost}:${port}`;

  return {
    port,
    username,
    password,
    proxyUrlForContainer,
    localProxyUrl: `http://${username}:${password}@127.0.0.1:${port}`,
    close() {
      return new Promise(resolve => server.close(() => resolve()));
    },
  };
}
