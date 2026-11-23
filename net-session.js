import net from 'node:net';

const DEFAULT_MAX_SESSIONS = 8;
const DEFAULT_IDLE_MS = 10 * 60 * 1000;
const DEFAULT_CONNECT_TIMEOUT_MS = 5000;
const DEFAULT_RECV_TIMEOUT_MS = 2000;
const MAX_TIMEOUT_MS = 30000;
const DEFAULT_MAX_BYTES = 4096;
const MAX_RECV_BYTES = 65536;
const MAX_SEND_BYTES = 1024 * 1024;
const MAX_READ_UNTIL_BYTES = 64 * 1024;
const MAX_DELIMITER_BYTES = 4096;
const MAX_BUFFERED_BYTES = 1024 * 1024;
const MAX_HOST_LENGTH = 255;
const MAX_SESSION_ID_LENGTH = 64;
const MAX_DATA_CHARS = MAX_SEND_BYTES * 2;
const MAX_DELIMITER_CHARS = MAX_DELIMITER_BYTES * 2;
const DATA_ENCODINGS = ['utf8', 'hex', 'base64'];
const DELIMITER_ENCODINGS = ['utf8', 'hex'];
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const CONTROL = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/u;

export const NET_SESSION_OPERATIONS = Object.freeze(['connect', 'send', 'recv', 'read_until', 'close', 'list']);

const OPERATION_KEYS = {
  connect: ['host', 'port', 'timeout_ms'],
  send: ['session_id', 'data', 'data_encoding'],
  recv: ['session_id', 'timeout_ms', 'max_bytes'],
  read_until: ['session_id', 'delimiter', 'delimiter_encoding', 'timeout_ms'],
  close: ['session_id'],
  list: [],
};

export const NET_SESSION_PROPERTIES = {
  operation: {
    type: 'string',
    enum: NET_SESSION_OPERATIONS,
    description: '操作类型。connect 建立 TCP 会话，send 发送数据，recv 读取数据，read_until 读到分隔符，close 关闭会话，list 列出当前会话。',
  },
  session_id: {
    type: 'string',
    minLength: 1,
    maxLength: MAX_SESSION_ID_LENGTH,
    description: 'connect 返回的会话标识，如 net-1。',
  },
  host: {
    type: 'string',
    minLength: 1,
    maxLength: MAX_HOST_LENGTH,
    description: '目标主机名或 IP 地址，不能含空白字符。',
  },
  port: {
    type: 'integer',
    minimum: 1,
    maximum: 65535,
    description: '目标 TCP 端口，1 至 65535。',
  },
  data: {
    type: 'string',
    minLength: 1,
    maxLength: MAX_DATA_CHARS,
    description: '要发送的数据，按 data_encoding 解码；解码后最多 1 MiB。',
  },
  data_encoding: {
    type: 'string',
    enum: DATA_ENCODINGS,
    description: 'data 的编码，默认 utf8。',
  },
  timeout_ms: {
    type: 'integer',
    minimum: 1,
    maximum: MAX_TIMEOUT_MS,
    description: '超时毫秒数。connect 默认 5000，recv 与 read_until 默认 2000；上限 30000。',
  },
  max_bytes: {
    type: 'integer',
    minimum: 1,
    maximum: MAX_RECV_BYTES,
    description: 'recv 单次最多返回的字节数，默认 4096，上限 65536。',
  },
  delimiter: {
    type: 'string',
    minLength: 1,
    maxLength: MAX_DELIMITER_CHARS,
    description: 'read_until 的目标分隔符，按 delimiter_encoding 解码，最多 4096 字节。',
  },
  delimiter_encoding: {
    type: 'string',
    enum: DELIMITER_ENCODINGS,
    description: 'delimiter 的编码，默认 utf8。',
  },
};

function parseOptions(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new Error('options 必须是对象。');
  }
  for (const key of Object.keys(options)) {
    if (key !== 'maxSessions' && key !== 'idleMs') throw new Error(`options 不支持 ${key}。`);
  }
  const maxSessions = options.maxSessions === undefined ? DEFAULT_MAX_SESSIONS : options.maxSessions;
  if (!Number.isSafeInteger(maxSessions) || maxSessions < 1) throw new Error('maxSessions 必须是正整数。');
  const idleMs = options.idleMs === undefined ? DEFAULT_IDLE_MS : options.idleMs;
  if (!Number.isSafeInteger(idleMs) || idleMs < 1) throw new Error('idleMs 必须是正整数。');
  return { maxSessions, idleMs };
}

function parseHost(value) {
  if (value === undefined) throw new Error('缺少必填参数 host。');
  if (typeof value !== 'string' || value.length < 1 || value.length > MAX_HOST_LENGTH
    || /[\s\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error('host 必须是不含空白字符的主机名或 IP 地址。');
  }
  return value;
}

function parsePort(value) {
  if (value === undefined) throw new Error('缺少必填参数 port。');
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error('port 必须是 1 至 65535 的整数。');
  }
  return value;
}

function parseTimeout(value, fallback) {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value < 1 || value > MAX_TIMEOUT_MS) {
    throw new Error(`timeout_ms 必须是 1 至 ${MAX_TIMEOUT_MS} 的整数。`);
  }
  return value;
}

function parseMaxBytes(value) {
  if (value === undefined) return DEFAULT_MAX_BYTES;
  if (!Number.isInteger(value) || value < 1 || value > MAX_RECV_BYTES) {
    throw new Error(`max_bytes 必须是 1 至 ${MAX_RECV_BYTES} 的整数。`);
  }
  return value;
}

function parseSessionId(input) {
  const value = input.session_id;
  if (value === undefined) throw new Error('缺少必填参数 session_id。');
  if (typeof value !== 'string' || value.length < 1 || value.length > MAX_SESSION_ID_LENGTH) {
    throw new Error('session_id 必须是字符串。');
  }
  return value;
}

function parseData(input) {
  const value = input.data;
  if (value === undefined) throw new Error('缺少必填参数 data。');
  if (typeof value !== 'string' || value.length < 1) throw new Error('data 必须是非空字符串。');
  if (value.length > MAX_DATA_CHARS) throw new Error('data 超过允许的最大长度。');
  return value;
}

function parseEncoding(value, allowed, fallback, label) {
  if (value === undefined) return fallback;
  if (!allowed.includes(value)) throw new Error(`${label} 必须是 ${allowed.join('、')} 之一。`);
  return value;
}

function decodeData(data, encoding) {
  if (encoding === 'utf8') return Buffer.from(data, 'utf8');
  if (encoding === 'hex') {
    if (data.length % 2 !== 0 || !/^[0-9a-fA-F]+$/u.test(data)) {
      throw new Error('hex 编码的 data 必须是偶数个十六进制字符。');
    }
    return Buffer.from(data, 'hex');
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/u.test(data) || data.length % 4 === 1) {
    throw new Error('base64 编码的 data 格式无效。');
  }
  return Buffer.from(data, 'base64');
}

function parseDelimiter(input) {
  const value = input.delimiter;
  if (value === undefined) throw new Error('缺少必填参数 delimiter。');
  if (typeof value !== 'string' || value.length < 1 || value.length > MAX_DELIMITER_CHARS) {
    throw new Error('delimiter 必须是非空字符串。');
  }
  const encoding = parseEncoding(input.delimiter_encoding, DELIMITER_ENCODINGS, 'utf8', 'delimiter_encoding');
  let bytes;
  if (encoding === 'utf8') {
    bytes = Buffer.from(value, 'utf8');
  } else {
    if (value.length % 2 !== 0 || !/^[0-9a-fA-F]+$/u.test(value)) {
      throw new Error('hex 编码的 delimiter 必须是偶数个十六进制字符。');
    }
    bytes = Buffer.from(value, 'hex');
  }
  if (bytes.length === 0) throw new Error('delimiter 不能为空。');
  if (bytes.length > MAX_DELIMITER_BYTES) throw new Error(`delimiter 不能超过 ${MAX_DELIMITER_BYTES} 字节。`);
  return bytes;
}

function safeText(bytes) {
  try {
    const text = UTF8.decode(bytes);
    return CONTROL.test(text) ? undefined : text;
  } catch {
    return undefined;
  }
}

function hexdump(bytes, offset) {
  const addressWidth = Math.max(8, (offset + bytes.length).toString(16).length);
  const rows = [];
  for (let index = 0; index < bytes.length; index += 16) {
    const row = bytes.subarray(index, index + 16);
    const address = (offset + index).toString(16).padStart(addressWidth, '0');
    const hex = [...row].map(byte => byte.toString(16).padStart(2, '0')).join(' ');
    const ascii = row.toString('latin1').replace(/[^\x20-\x7e]/gu, '.');
    rows.push(`${address}  ${hex.padEnd(47)}  |${ascii}|`);
  }
  return rows.join('\n');
}

function describeBytes(sessionId, bytes, extra) {
  const text = safeText(bytes);
  const report = {
    session_id: sessionId,
    data: text === undefined ? bytes.toString('hex') : text,
    data_encoding: text === undefined ? 'hex' : 'utf8',
    byte_length: bytes.length,
  };
  if (text === undefined) report.hexdump = hexdump(bytes, 0);
  return { ...report, ...extra };
}

function makeAbortError() {
  const error = new Error('操作已取消');
  error.name = 'AbortError';
  return error;
}

function isAbortError(error) {
  return error instanceof Error && error.name === 'AbortError';
}

function throwIfAborted(signal) {
  if (signal !== undefined && signal.aborted) throw makeAbortError();
}

function parseContext(context) {
  if (context === null || typeof context !== 'object' || Array.isArray(context)) {
    throw new Error('context 必须是对象。');
  }
  for (const key of Object.keys(context)) {
    if (key !== 'signal') throw new Error(`context 不支持 ${key}。`);
  }
  const { signal } = context;
  if (signal !== undefined && (typeof signal !== 'object' || signal === null
    || typeof signal.addEventListener !== 'function' || typeof signal.aborted !== 'boolean')) {
    throw new Error('context.signal 必须是 AbortSignal。');
  }
  return signal;
}

function releaseWaiter(waiter) {
  clearTimeout(waiter.timer);
  if (waiter.signal !== undefined) waiter.signal.removeEventListener('abort', waiter.onAbort);
}

function notify(session) {
  const waiter = session.waiter;
  if (waiter === undefined) return;
  session.waiter = undefined;
  releaseWaiter(waiter);
  waiter.resolve('ready');
}

function abortWaiter(session, error) {
  const waiter = session.waiter;
  if (waiter === undefined) return;
  session.waiter = undefined;
  releaseWaiter(waiter);
  waiter.reject(error);
}

function waitForProgress(session, timeoutMs, signal) {
  if (session.waiter !== undefined) throw new Error('会话已有等待中的读取操作，请勿并发读取。');
  return new Promise((resolve, reject) => {
    const waiter = {
      reject,
      resolve: undefined,
      timer: undefined,
      signal,
      onAbort: undefined,
    };
    function onAbort() {
      if (session.waiter !== waiter) return;
      session.waiter = undefined;
      releaseWaiter(waiter);
      reject(makeAbortError());
    }
    waiter.onAbort = onAbort;
    waiter.resolve = value => resolve(value);
    waiter.timer = setTimeout(() => {
      if (session.waiter !== waiter) return;
      session.waiter = undefined;
      releaseWaiter(waiter);
      resolve('timeout');
    }, timeoutMs);
    session.waiter = waiter;
    if (signal !== undefined) {
      signal.addEventListener('abort', onAbort, { once: true });
      if (signal.aborted) onAbort();
    }
  });
}

function resumeAfterDrain(session) {
  if (session.paused && session.buffer.length < MAX_BUFFERED_BYTES / 2) {
    session.paused = false;
    session.socket.resume();
  }
}

function connectionLost(session) {
  const code = session.error?.code;
  if (code === 'ECONNRESET') return new Error('连接被对端重置。');
  return new Error(code ? `连接已断开（${code}）。` : '连接已断开。');
}

function attachSession(session) {
  const { socket } = session;
  socket.setNoDelay(true);
  socket.on('data', chunk => {
    session.buffer = session.buffer.length === 0 ? chunk : Buffer.concat([session.buffer, chunk]);
    session.lastActivity = Date.now();
    if (session.buffer.length >= MAX_BUFFERED_BYTES && !session.paused) {
      session.paused = true;
      socket.pause();
    }
    notify(session);
  });
  socket.on('end', () => {
    session.ended = true;
    notify(session);
  });
  socket.on('error', error => {
    session.error = error;
    notify(session);
  });
  socket.on('close', () => {
    session.closed = true;
    session.ended = true;
    notify(session);
  });
}

function openSocket(session, timeoutMs, signal) {
  const { socket, host, port } = session;
  return new Promise((resolve, reject) => {
    let settled = false;
    function finish(callback, value) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.off('connect', onConnect);
      socket.off('error', onError);
      if (signal !== undefined) signal.removeEventListener('abort', onAbort);
      callback(value);
    }
    function onConnect() {
      session.localAddress = socket.localAddress;
      session.localPort = socket.localPort;
      attachSession(session);
      finish(resolve);
    }
    function onError(error) {
      finish(reject, new Error(`连接 ${host}:${port} 失败：${error.message}`));
    }
    function onAbort() {
      finish(reject, makeAbortError());
      socket.destroy();
    }
    const timer = setTimeout(() => {
      finish(reject, new Error('连接超时'));
      socket.destroy();
    }, timeoutMs);
    socket.once('connect', onConnect);
    socket.once('error', onError);
    if (signal !== undefined) {
      signal.addEventListener('abort', onAbort, { once: true });
      if (signal.aborted) onAbort();
    }
  });
}

export function createNetSessionManager(options = {}) {
  const { authorize, ...limits } = options;
  const { maxSessions, idleMs } = parseOptions(limits);
  const sessions = new Map();
  let nextId = 0;
  let pending = 0;
  let disposed = false;

  function requireSession(input) {
    const id = parseSessionId(input);
    const session = sessions.get(id);
    if (session === undefined) throw new Error('会话不存在或已关闭');
    return session;
  }

  function pruneSessions(operation, targetId) {
    const now = Date.now();
    for (const [id, session] of sessions) {
      const idle = now - session.lastActivity >= idleMs;
      const drainedEnd = (session.closed || session.ended) && session.buffer.length === 0;
      if (!idle && !drainedEnd) continue;
      if (!idle && id === targetId
        && (operation === 'send' || operation === 'recv' || operation === 'read_until' || operation === 'close')) {
        continue;
      }
      sessions.delete(id);
      abortWaiter(session, new Error(idle ? '会话因空闲已关闭。' : '会话不存在或已关闭'));
      session.closed = true;
      session.ended = true;
      session.socket.destroy();
    }
  }

  function removeSession(session) {
    if (sessions.get(session.id) === session) sessions.delete(session.id);
    abortWaiter(session, new Error('会话不存在或已关闭'));
    session.closed = true;
    session.ended = true;
    session.socket.destroy();
  }

  function cleanupAborted(session, error) {
    if (isAbortError(error)) removeSession(session);
  }

  async function connectSession(input, signal) {
    throwIfAborted(signal);
    const host = parseHost(input.host);
    const port = parsePort(input.port);
    const timeoutMs = parseTimeout(input.timeout_ms, DEFAULT_CONNECT_TIMEOUT_MS);
    if (sessions.size + pending >= maxSessions) {
      throw new Error(`会话数量已达上限 ${maxSessions}，请先关闭不用的会话。`);
    }
    pending += 1;
    const id = `net-${++nextId}`;
    let socket;
    try {
      const deadline = AbortSignal.timeout(timeoutMs);
      const authorizationSignal = signal ? AbortSignal.any([signal, deadline]) : deadline;
      const address = await authorize?.(host, port, authorizationSignal);
      throwIfAborted(signal);
      if (disposed) throw new Error('会话管理器已释放。');
      socket = net.createConnection({ host: address?.address ?? host, port });
    } catch (error) {
      pending -= 1;
      throw error;
    }
    const session = {
      id,
      socket,
      host,
      port,
      localAddress: undefined,
      localPort: undefined,
      connectedAt: undefined,
      lastActivity: Date.now(),
      buffer: Buffer.alloc(0),
      ended: false,
      closed: false,
      error: undefined,
      paused: false,
      waiter: undefined,
    };
    try {
      await openSocket(session, timeoutMs, signal);
    } catch (error) {
      socket.destroy();
      throw error;
    } finally {
      pending -= 1;
    }
    if (signal !== undefined && signal.aborted) {
      socket.destroy();
      throw makeAbortError();
    }
    if (disposed) {
      socket.destroy();
      throw new Error('会话管理器已释放。');
    }
    session.connectedAt = new Date();
    session.lastActivity = Date.now();
    sessions.set(id, session);
    return {
      session_id: id,
      host,
      port,
      local_address: session.localAddress,
      local_port: session.localPort,
      connected_at: session.connectedAt.toISOString(),
    };
  }

  async function sendData(input, signal) {
    const session = requireSession(input);
    try {
      throwIfAborted(signal);
      const encoding = parseEncoding(input.data_encoding, DATA_ENCODINGS, 'utf8', 'data_encoding');
      const bytes = decodeData(parseData(input), encoding);
      if (bytes.length > MAX_SEND_BYTES) throw new Error('发送数据超过 1 MiB。');
      if (session.closed || session.socket.destroyed) throw new Error('会话不存在或已关闭');
      if (session.ended) throw new Error('连接已被对端关闭，无法发送。');
      await new Promise((resolve, reject) => {
        let settled = false;
        function onAbort() {
          if (settled) return;
          settled = true;
          contract();
          reject(makeAbortError());
        }
        function contract() {
          if (signal !== undefined) signal.removeEventListener('abort', onAbort);
        }
        if (signal !== undefined) {
          signal.addEventListener('abort', onAbort, { once: true });
          if (signal.aborted) {
            onAbort();
            return;
          }
        }
        session.socket.write(bytes, error => {
          if (settled) return;
          settled = true;
          contract();
          if (error) reject(new Error(`发送数据失败：${error.message}`));
          else resolve();
        });
      });
      session.lastActivity = Date.now();
      return { session_id: session.id, bytes_sent: bytes.length };
    } catch (error) {
      cleanupAborted(session, error);
      throw error;
    }
  }

  async function receiveData(input, signal) {
    const session = requireSession(input);
    try {
      throwIfAborted(signal);
      const timeoutMs = parseTimeout(input.timeout_ms, DEFAULT_RECV_TIMEOUT_MS);
      const maxBytes = parseMaxBytes(input.max_bytes);
      const deadline = Date.now() + timeoutMs;
      while (true) {
        if (session.buffer.length > 0) break;
        if (session.error) throw connectionLost(session);
        if (session.closed || session.ended) {
          return describeBytes(session.id, Buffer.alloc(0), { truncated: false, eof: true });
        }
        const remaining = deadline - Date.now();
        if (remaining <= 0) {
          return describeBytes(session.id, Buffer.alloc(0), { truncated: false, eof: false });
        }
        await waitForProgress(session, remaining, signal);
        throwIfAborted(signal);
      }
      const length = Math.min(maxBytes, session.buffer.length);
      const data = Buffer.from(session.buffer.subarray(0, length));
      session.buffer = session.buffer.subarray(length);
      resumeAfterDrain(session);
      session.lastActivity = Date.now();
      return describeBytes(session.id, data, {
        truncated: session.buffer.length > 0,
        eof: session.ended && session.buffer.length === 0,
      });
    } catch (error) {
      cleanupAborted(session, error);
      throw error;
    }
  }

  function finishBuffered(session) {
    const data = Buffer.from(session.buffer);
    session.buffer = Buffer.alloc(0);
    session.lastActivity = Date.now();
    return describeBytes(session.id, data, { matched: false, truncated: false });
  }

  async function readUntil(input, signal) {
    const session = requireSession(input);
    try {
      throwIfAborted(signal);
      const delimiter = parseDelimiter(input);
      const timeoutMs = parseTimeout(input.timeout_ms, DEFAULT_RECV_TIMEOUT_MS);
      const deadline = Date.now() + timeoutMs;
      while (true) {
        const index = session.buffer.indexOf(delimiter);
        if (index !== -1 && index + delimiter.length <= MAX_READ_UNTIL_BYTES) {
          const end = index + delimiter.length;
          const data = Buffer.from(session.buffer.subarray(0, end));
          session.buffer = session.buffer.subarray(end);
          resumeAfterDrain(session);
          session.lastActivity = Date.now();
          return describeBytes(session.id, data, { matched: true, truncated: false });
        }
        if (session.buffer.length >= MAX_READ_UNTIL_BYTES) {
          const data = Buffer.from(session.buffer.subarray(0, MAX_READ_UNTIL_BYTES));
          session.buffer = session.buffer.subarray(MAX_READ_UNTIL_BYTES);
          resumeAfterDrain(session);
          session.lastActivity = Date.now();
          return describeBytes(session.id, data, { matched: false, truncated: true });
        }
        if (session.error) {
          if (session.buffer.length > 0) return finishBuffered(session);
          throw connectionLost(session);
        }
        if (session.closed || session.ended) return finishBuffered(session);
        const remaining = deadline - Date.now();
        if (remaining <= 0) return finishBuffered(session);
        await waitForProgress(session, remaining, signal);
        throwIfAborted(signal);
      }
    } catch (error) {
      cleanupAborted(session, error);
      throw error;
    }
  }

  function closeSession(input) {
    const session = requireSession(input);
    sessions.delete(session.id);
    abortWaiter(session, new Error('会话已关闭。'));
    session.closed = true;
    session.ended = true;
    session.socket.destroy();
    return { session_id: session.id, closed: true };
  }

  function listSessions() {
    const now = Date.now();
    return [...sessions.values()].map(session => ({
      session_id: session.id,
      host: session.host,
      port: session.port,
      idle_ms: now - session.lastActivity,
    }));
  }

  async function execute(input, context = {}) {
    if (disposed) throw new Error('会话管理器已释放。');
    if (input === null || typeof input !== 'object' || Array.isArray(input)) {
      throw new Error('参数必须是对象。');
    }
    const signal = parseContext(context);
    throwIfAborted(signal);
    const operation = input.operation;
    if (!NET_SESSION_OPERATIONS.includes(operation)) {
      throw new Error(`operation 必须是 ${NET_SESSION_OPERATIONS.join('、')} 之一。`);
    }
    for (const key of Object.keys(input)) {
      if (!Object.hasOwn(NET_SESSION_PROPERTIES, key)) throw new Error(`提供了不支持的参数：${key}。`);
      if (key !== 'operation' && !OPERATION_KEYS[operation].includes(key)) {
        throw new Error(`${operation} 操作不接受参数 ${key}。`);
      }
    }
    pruneSessions(operation, input.session_id);
    try {
      switch (operation) {
        case 'connect': return await connectSession(input, signal);
        case 'send': return await sendData(input, signal);
        case 'recv': return await receiveData(input, signal);
        case 'read_until': return await readUntil(input, signal);
        case 'close': return closeSession(input);
        default: return listSessions();
      }
    } finally {
      pruneSessions(undefined, undefined);
    }
  }

  function dispose() {
    disposed = true;
    for (const session of sessions.values()) {
      abortWaiter(session, new Error('会话管理器已释放。'));
      session.closed = true;
      session.ended = true;
      session.socket.destroy();
    }
    sessions.clear();
  }

  return { execute, dispose, size: () => sessions.size, idle: () => sessions.size === 0 && pending === 0 };
}
