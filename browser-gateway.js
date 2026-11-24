import http from 'node:http';
import net from 'node:net';
import { pinnedLookup, webUrl } from './network-boundary.js';

const SKIP_HEADERS = new Set(['connection', 'proxy-connection', 'proxy-authorization', 'keep-alive', 'upgrade',
  'transfer-encoding', 'te', 'trailer']);

function forwardHeaders(headers) {
  const connection = new Set(String(headers.connection ?? '').toLowerCase().split(',').map(value => value.trim()));
  return Object.fromEntries(Object.entries(headers).filter(([key]) => !SKIP_HEADERS.has(key) && !connection.has(key)));
}

export async function browserGateway(authorize, { timeoutMs = 30000 } = {}) {
  const sockets = new Set();
  const lifecycle = new AbortController();
  const track = socket => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket));
    return socket;
  };
  const server = http.createServer(async (input, output) => {
    try {
      const url = webUrl(input.url);
      if (url.protocol !== 'http:') throw new Error('需要通过 HTTPS 隧道。');
      const signal = AbortSignal.any([lifecycle.signal, AbortSignal.timeout(timeoutMs)]);
      const address = await authorize(url, signal);
      if (lifecycle.signal.aborted) throw new Error('网关已关闭。');
      const upstream = http.request(url, {
        method: input.method, lookup: pinnedLookup(address), agent: false,
        headers: { ...forwardHeaders(input.headers), host: url.host },
      }, response => {
        upstream.setTimeout(0);
        output.writeHead(response.statusCode ?? 502, forwardHeaders(response.headers));
        response.once('error', error => output.destroy(error));
        response.pipe(output);
      });
      upstream.setTimeout(timeoutMs, () => upstream.destroy(new Error('上游响应空闲超时。')));
      upstream.once('error', () => {
        if (!output.headersSent) output.writeHead(502);
        output.end();
      });
      output.once('close', () => upstream.destroy());
      input.pipe(upstream);
    } catch {
      output.writeHead(403);
      output.end();
    }
  });
  server.on('connection', track);
  server.on('connect', async (message, client, head) => {
    try {
      const url = webUrl('https://' + message.url);
      if (url.pathname !== '/' || url.search || url.hash) throw new Error('隧道目标无效。');
      const signal = AbortSignal.any([lifecycle.signal, AbortSignal.timeout(timeoutMs)]);
      const address = await authorize(url, signal);
      if (client.destroyed) return;
      const upstream = track(net.createConnection({ host: address.address, port: Number(url.port || 443) }));
      const connectTimer = setTimeout(() => upstream.destroy(new Error('上游连接超时。')), timeoutMs);
      upstream.once('connect', () => {
        clearTimeout(connectTimer);
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head.length > 0) upstream.write(head);
        client.pipe(upstream).pipe(client);
      });
      upstream.once('close', () => clearTimeout(connectTimer));
      client.once('close', () => upstream.destroy());
      upstream.once('close', () => client.destroy());
    } catch {
      client.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
    }
  });
  server.on('upgrade', (_request, socket) => socket.destroy());
  server.maxConnections = 32;
  server.requestTimeout = 30000;
  server.headersTimeout = 10000;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return {
    address: 'http://127.0.0.1:' + server.address().port,
    dispose() {
      lifecycle.abort();
      for (const socket of sockets) socket.destroy();
      server.close();
    },
  };
}
