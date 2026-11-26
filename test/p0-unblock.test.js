import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import http from 'node:http';
import { lstat as fsLstat, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { apply, extractInstanceTargets } from '../ctf-tools.js';
import { createNetworkBoundary } from '../network-boundary.js';
import { platformAuthHeaders, platformRequest, redactPlatformToken } from '../platform-request.js';
import { createWorkbenchEnvironment } from '../workbench-config.js';

function startServer(handler) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        port,
        origin: `http://127.0.0.1:${port}`,
        close: () => new Promise(done => server.close(() => done())),
      });
    });
  });
}

function liveContext(cwd, files, config = {}) {
  const entries = new Map(Object.entries(files).map(([name, bytes]) => [name, {
    bytes: Buffer.from(bytes), version: 'v1',
  }]));
  const tools = new Map();
  const base = cwd.replaceAll('\\', '/').replace(/\/$/u, '');
  const resolveTarget = (name, options = {}) => {
    const root = (options.cwd ?? cwd).replaceAll('\\', '/').replace(/\/$/u, '');
    const key = options.cwd ? `${root}/${name}` : name.replaceAll('\\', '/');
    return { targetKey: key, displayPath: key };
  };
  const ctx = {
    tools: { register(tool) { tools.set(tool.name, tool); } },
    effect() {},
    emit() {},
    workingDirectory: { async ensure() { return cwd; } },
    sandboxPolicy: { resolve() { return { mode: 'workspace-write' }; } },
    fs: {
      async resolve(name, options) { return resolveTarget(name, options); },
      contains(parent, child) {
        const prefix = parent.targetKey.replace(/\/$/u, '');
        return child.targetKey === prefix || child.targetKey.startsWith(prefix + '/');
      },
      async lstat(name, options) {
        const key = resolveTarget(name, options).targetKey;
        const rel = key.startsWith(base + '/') ? key.slice(base.length + 1) : name;
        if (entries.has(rel)) return { type: 'file' };
        if ([...entries.keys()].some(file => file.startsWith(rel.replace(/\/$/u, '') + '/'))) return { type: 'directory' };
        try {
          const info = await fsLstat(join(cwd, rel));
          return { type: info.isDirectory() ? 'directory' : info.isFile() ? 'file' : 'other' };
        } catch {
          return undefined;
        }
      },
      async stat(target) {
        const rel = target.targetKey.slice(base.length + 1);
        const entry = entries.get(rel);
        return entry ? { type: 'file', size: entry.bytes.length, version: entry.version } : null;
      },
      async readBytes(target) {
        const rel = target.targetKey.slice(base.length + 1);
        return entries.get(rel)?.bytes;
      },
      async writeText(target, text, intent) {
        const rel = target.targetKey.slice(base.length + 1);
        const prev = entries.get(rel);
        const nextVersion = 'v' + (Number(prev?.version.slice(1) ?? 0) + 1);
        if (intent.kind === 'replaceIfVersion') assert.equal(intent.version, prev?.version);
        entries.set(rel, { bytes: Buffer.from(text), version: nextVersion });
        return { version: nextVersion };
      },
    },
  };
  apply(ctx, config);
  const execution = {
    signal: new AbortController().signal,
    agent: { session: { header: { cwd }, id: 'p0-unblock-fixture' } },
  };
  return { tools, execution, entries };
}

test('network-boundary 支持通配端口、端口范围、子域通配、CIDR 及动态授权，仍拦截云元数据', async () => {
  const boundary = createNetworkBoundary({
    networkOrigins: [
      'http://10.0.0.0/8:*',
      'http://127.0.0.1:10000-65535',
      'https://*.ctf.example:*',
      'http://*:*', // 过宽规则必须被忽略
    ],
    tcpTargets: [
      '10.0.0.0/8:*',
      '127.0.0.1:20000-30000',
      '*.pwn.example:*',
      '*:*', // 过宽规则必须被忽略
    ],
  });
  assert.equal(boundary.isHttpAuthorized('http://10.20.30.40:31337/login'), true);
  assert.equal(boundary.isHttpAuthorized('http://127.0.0.1:18080/'), true);
  assert.equal(boundary.isHttpAuthorized('http://127.0.0.1:80/'), false);
  assert.equal(boundary.isHttpAuthorized('https://web1.ctf.example:8443/'), true);
  assert.equal(boundary.isHttpAuthorized('https://ctf.example/'), false);
  assert.equal(boundary.isHttpAuthorized('https://evilctf.example/'), false);
  assert.equal(boundary.isHttpAuthorized('http://evil.example:8080/'), false);

  assert.equal(boundary.isTcpAuthorized('10.1.2.3', 4444), true);
  assert.equal(boundary.isTcpAuthorized('127.0.0.1', 25000), true);
  assert.equal(boundary.isTcpAuthorized('127.0.0.1', 9999), false);
  assert.equal(boundary.isTcpAuthorized('chall.pwn.example', 1337), true);
  assert.equal(boundary.isTcpAuthorized('evil.example', 1337), false);

  // 动态授权仍拒绝云元数据保留地址
  assert.equal(boundary.grantHttp('http://169.254.169.254/latest/meta-data/'), undefined);
  assert.equal(boundary.grantTcp('169.254.169.254', 80), undefined);
  const scopeA = { session: {}, workspaceKey: 'challenge-a' };
  const scopeB = { session: {}, workspaceKey: 'challenge-a' };
  assert.equal(boundary.grantHttp('http://127.0.0.1:9999/api'), undefined);
  assert.equal(boundary.grantHttp('http://127.0.0.1:9999/api', scopeA), 'http://127.0.0.1:9999');
  assert.equal(boundary.isHttpAuthorized('http://127.0.0.1:9999/flag', scopeA), true);
  assert.equal(boundary.isHttpAuthorized('http://127.0.0.1:9999/flag', scopeB), false);
  assert.equal(boundary.revoke(scopeA), 1);
  assert.equal(boundary.isHttpAuthorized('http://127.0.0.1:9999/flag', scopeA), false);

  const ipv6Scope = { session: {}, workspaceKey: 'ipv6-challenge' };
  assert.equal(boundary.grantTcp('[2001:4860:4860::8888]', 443, ipv6Scope), '[2001:4860:4860::8888]:443');
  assert.equal(boundary.isTcpAuthorized('2001:4860:4860::8888', 443, ipv6Scope), true);

  const cappedScope = { session: {}, workspaceKey: 'many-targets' };
  for (let index = 1; index <= 64; index += 1) {
    assert.ok(boundary.grantHttp(`http://10.10.0.${index}:8080`, cappedScope));
  }
  assert.equal(boundary.grantHttp('http://10.20.0.1:8080', cappedScope), undefined);
  assert.equal(boundary.isHttpAuthorized('http://10.10.0.1:8080/', cappedScope), true,
    'a full grant table must not silently evict an unexpired endpoint');
});

test('workbench-config 支持配置文件热重载，动态修改白名单立即生效', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ctf-hot-reload-'));
  const file = join(dir, 'ctf-workbench.json');
  try {
    await writeFile(file, JSON.stringify({ networkOrigins: ['http://10.0.0.1:8000'] }));
    const env = createWorkbenchEnvironment({}, file);
    const boundary = createNetworkBoundary(() => env.presetConfig());
    assert.equal(boundary.isHttpAuthorized('http://10.0.0.2:9000/'), false);

    // 模拟赛中编辑 ctf-workbench.json 增加新网段
    await new Promise(resolve => setTimeout(resolve, 20));
    await writeFile(file, JSON.stringify({ networkOrigins: ['http://10.0.0.0/8:*'], allowInsecurePlatformHttp: true }));
    assert.equal(boundary.isHttpAuthorized('http://10.0.0.2:9000/'), true);
    assert.equal(env.presetConfig().allowInsecurePlatformHttp, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('workbench-config 热重载 pythonPath 后重新探测真实 Python 可执行文件', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'ctf-python-hot-reload-'));
  const file = join(dir, 'ctf-workbench.json');
  const venv = join(dir, 'venv');
  try {
    const python = execFileSync(process.platform === 'win32' ? 'py' : 'python3',
      process.platform === 'win32'
        ? ['-3', '-I', '-c', 'import sys; print(sys.executable)']
        : ['-I', '-c', 'import sys; print(sys.executable)'], { encoding: 'utf8' }).trim();
    try {
      execFileSync(python, ['-I', '-m', 'venv', venv], { stdio: 'pipe' });
    } catch (error) {
      // Debian/Ubuntu 上 python3 默认不带 venv 模块（要装 python3-venv）；这是环境缺陷，
      // 不是被测行为，直接跳过并说明如何补齐。
      t.skip(`当前 Python 无法创建 venv（${error.message.split('\n')[0]}），请安装 python3-venv 后重跑。`);
      return;
    }
    const venvPython = join(venv, process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
    await writeFile(file, JSON.stringify({ pythonPath: python }));
    const env = createWorkbenchEnvironment({}, file);
    assert.equal(await env.resolvePython(), python);

    await new Promise(resolve => setTimeout(resolve, 25));
    await writeFile(file, JSON.stringify({ pythonPath: venvPython }));
    assert.equal(await env.resolvePython(), venvPython,
      'resolvePython must observe a changed configuration before returning its cached interpreter');
  } finally {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 80 });
  }
});

test('workbench-config 在 Windows 接受大小写不同但等价的 Base100 文件名', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ctf-base100-case-'));
  try {
    const sourceName = process.platform === 'win32' ? 'CTF_EXTRA_OPS.PY' : 'ctf_extra_ops.py';
    const source = join(dir, sourceName);
    const bytes = Buffer.from('# trusted fixture\n', 'utf8');
    await writeFile(source, bytes);
    const env = createWorkbenchEnvironment({
      base100Source: source,
      base100Sha256: createHash('sha256').update(bytes).digest('hex'),
    });
    assert.equal(env.base100().source, source);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('http_request 保留赛题 Set-Cookie/WWW-Authenticate、支持自定义 Host、多 cookie_jar 与 multipart 上传，并仅脱敏平台令牌', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ctf-http-p0-'));
  const tokenEnv = 'CTF_TEST_P0_PLATFORM_TOKEN';
  const prevToken = process.env[tokenEnv];
  process.env[tokenEnv] = 'super-secret-platform-tok';
  const server = await startServer((req, res) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      if (req.url === '/vhost') {
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Set-Cookie': ['session=eyJyb2xlIjoiZ3Vlc3QifQ==; Path=/; HttpOnly', 'hint=flag_in_cookie; Path=/'],
          'WWW-Authenticate': 'Basic realm="ctf-admin"',
        });
        res.end(JSON.stringify({ host: req.headers.host, leak: 'super-secret-platform-tok' }));
        return;
      }
      if (req.url === '/login-redirect') {
        res.writeHead(302, {
          Location: '/me',
          'Set-Cookie': 'auth=logged_in_user; Path=/',
        });
        res.end();
        return;
      }
      if (req.url === '/me') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ cookie: req.headers.cookie ?? '' }));
        return;
      }
      if (req.url === '/upload') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          content_type: req.headers['content-type'],
          body_text: body.toString('utf8'),
        }));
        return;
      }
      res.writeHead(404);
      res.end('not found');
    });
  });

  try {
    const { tools, execution } = liveContext(dir, { 'avatar.txt': Buffer.from('PNG_PAYLOAD_123') }, {
      networkOrigins: ['http://127.0.0.1:*'],
      platformTokenEnv: tokenEnv,
    });
    const call = async args => JSON.parse(await tools.get('http_request').execute(args, execution));

    // 1. 自定义 Host + 保留 Set-Cookie / WWW-Authenticate + 仅脱敏平台 token
    const vhost = await call({
      url: `${server.origin}/vhost`,
      headers: { Host: 'admin.internal.ctf' },
      cookie_jar: 'user1',
    });
    assert.equal(vhost.status, 200, JSON.stringify(vhost));
    assert.equal(vhost.headers['www-authenticate'], 'Basic realm="ctf-admin"');
    assert.ok(Array.isArray(vhost.headers['set-cookie']));
    assert.ok(vhost.headers['set-cookie'].some(v => v.includes('session=eyJyb2xlIjoiZ3Vlc3QifQ==')));
    const vhostBody = JSON.parse(vhost.body);
    assert.equal(vhostBody.host, 'admin.internal.ctf');
    assert.equal(vhostBody.leak, '[已脱敏]');
    assert.equal(vhost.cookies_stored.length, 2);

    // 2. cookie_jar 跨请求自动携带 + 不同 jar 隔离
    const meUser1 = await call({ url: `${server.origin}/me`, cookie_jar: 'user1' });
    assert.match(JSON.parse(meUser1.body).cookie, /session=eyJyb2xlIjoiZ3Vlc3QifQ==/u);
    const meOther = await call({ url: `${server.origin}/me`, cookie_jar: 'other' });
    assert.equal(JSON.parse(meOther.body).cookie, '');

    // 3. 302 重定向过程自动落盘 Set-Cookie 并在下一跳携带
    const redir = await call({ url: `${server.origin}/login-redirect`, cookie_jar: 'redir' });
    assert.equal(redir.status, 200);
    assert.match(JSON.parse(redir.body).cookie, /auth=logged_in_user/u);

    // 4. multipart 文本字段 + 工作区文件上传
    const uploaded = await call({
      url: `${server.origin}/upload`,
      method: 'POST',
      multipart: [
        { name: 'note', value: 'hello-ctf' },
        { name: 'file', file_path: 'avatar.txt', filename: 'shell.png', content_type: 'image/png' },
      ],
    });
    assert.equal(uploaded.status, 200, JSON.stringify(uploaded));
    const uploadEcho = JSON.parse(uploaded.body);
    assert.match(uploadEcho.content_type, /^multipart\/form-data; boundary=----dshCtfBoundary/u);
    assert.ok(uploadEcho.body_text.includes('name="note"\r\n\r\nhello-ctf'));
    assert.ok(uploadEcho.body_text.includes('name="file"; filename="shell.png"\r\nContent-Type: image/png\r\n\r\nPNG_PAYLOAD_123'));
  } finally {
    await server.close();
    if (prevToken === undefined) delete process.env[tokenEnv];
    else process.env[tokenEnv] = prevToken;
    await rm(dir, { recursive: true, force: true });
  }
});

test('ctf_instance 自动授权返回的动态靶机端口，内网 HTTP 平台与附件下载带认证正常工作', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ctf-lan-platform-'));
  const tokenEnv = 'CTF_TEST_LAN_TOKEN';
  const prevToken = process.env[tokenEnv];
  process.env[tokenEnv] = 'ctfd-secret-key';

  let challengeServer;
  let platformServer;
  try {
    challengeServer = await startServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('challenge-alive:' + req.url);
    });

    platformServer = await startServer((req, res) => {
      if (req.url === '/instances' && req.method === 'POST') {
        assert.equal(req.headers.authorization, 'Token ctfd-secret-key');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          data: {
            id: 'inst-42',
            url: challengeServer.origin,
            connect: `nc 127.0.0.1 ${challengeServer.port}`,
          },
        }));
        return;
      }
      if (req.url === '/files/chall.bin') {
        if (req.headers.authorization !== 'Token ctfd-secret-key') {
          res.writeHead(401);
          res.end('unauthorized');
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
        res.end(Buffer.from('LAN_ATTACHMENT_BYTES'));
        return;
      }
      res.writeHead(404);
      res.end();
    });

    // 验证默认禁止 HTTP 携带令牌，显式 allowInsecurePlatformHttp: true 后允许并支持 Token scheme
    assert.deepEqual(platformAuthHeaders({ platformTokenEnv: tokenEnv, platformAuthScheme: 'Token' }), {
      Authorization: 'Token ctfd-secret-key',
    });
    await assert.rejects(platformRequest({
      platformUrl: platformServer.origin, platformTokenEnv: tokenEnv,
    }, undefined, 'GET', '/instances'), error => error.kind === 'permission');

    // 验证目标提取辅助函数
    const extracted = extractInstanceTargets({
      body: JSON.stringify({ host: '10.0.0.9', port: 31337, protocol: 'http', connect: 'nc 10.0.0.9 31338' }),
    });
    assert.ok(extracted.http.includes('http://10.0.0.9:31337'));
    assert.ok(extracted.tcp.some(t => t.host === '10.0.0.9' && t.port === 31338));

    // 未配置任何 networkOrigins，仅配置内网 platformUrl
    const { tools, execution } = liveContext(dir, {}, {
      platformUrl: platformServer.origin,
      platformTokenEnv: tokenEnv,
      platformAuthScheme: 'Token',
      allowInsecurePlatformHttp: true,
    });

    // 未创建实例前访问靶机被拒
    const before = JSON.parse(await tools.get('http_request').execute({ url: `${challengeServer.origin}/ping` }, execution));
    assert.equal(before.ok, false);

    // ctf_instance create 自动授权靶机 HTTP & TCP 地址
    const created = JSON.parse(await tools.get('ctf_instance').execute({ action: 'create', body: { challenge: 'web1' } }, execution));
    assert.equal(created.status, 'created', JSON.stringify(created));
    assert.ok(created.authorized_targets.http.includes(challengeServer.origin));
    assert.ok(created.authorized_targets.tcp.includes(`127.0.0.1:${challengeServer.port}`));

    // 紧接着直接访问刚创建的靶机无需重启或改配置！
    const after = JSON.parse(await tools.get('http_request').execute({ url: `${challengeServer.origin}/ping` }, execution));
    assert.equal(after.status, 200, JSON.stringify(after));
    assert.equal(after.body, 'challenge-alive:/ping');

    const otherSession = {
      ...execution,
      agent: { session: { header: { cwd: dir }, id: 'different-session' } },
    };
    const isolated = JSON.parse(await tools.get('http_request').execute({ url: `${challengeServer.origin}/ping` }, otherSession));
    assert.equal(isolated.ok, false);

    // 从内网 HTTP 平台下载需要 Token 认证的附件成功落盘
    const fetched = JSON.parse(await tools.get('fetch_attachment').execute({ url: `${platformServer.origin}/files/chall.bin` }, execution));
    assert.equal(fetched.status, 'imported', JSON.stringify(fetched));
    const saved = await readFile(join(dir, fetched.path), 'utf8');
    assert.equal(saved, 'LAN_ATTACHMENT_BYTES');
  } finally {
    await challengeServer?.close();
    await platformServer?.close();
    if (prevToken === undefined) delete process.env[tokenEnv];
    else process.env[tokenEnv] = prevToken;
    await rm(dir, { recursive: true, force: true });
  }
});

test('redactPlatformToken 与 platformAuthHeaders 覆盖自定义头、空方案、二进制正文与非法配置校验', () => {
  const untouched = { status: 200, body: 'plain', headers: { 'set-cookie': ['sid=abc'] } };
  assert.strictEqual(redactPlatformToken(untouched, ''), untouched);

  const cleaned = redactPlatformToken({
    status: 200,
    status_text: 'my-secret-tok',
    body: 'hello my-secret-tok world',
    body_hex: Buffer.from('xx my-secret-tok yy').toString('hex'),
    headers: { 'set-cookie': ['sid=abc', 'leak=my-secret-tok'], 'www-authenticate': 'Bearer realm="x"', 'x-echo': 'my-secret-tok' },
  }, 'my-secret-tok');
  assert.equal(cleaned.status_text, '[已脱敏]');
  assert.equal(cleaned.body, 'hello [已脱敏] world');
  assert.equal(cleaned.body_hex, undefined);
  assert.equal(cleaned.body_redacted, true);
  assert.deepEqual(cleaned.headers['set-cookie'], ['sid=abc', 'leak=[已脱敏]']);
  assert.equal(cleaned.headers['www-authenticate'], 'Bearer realm="x"');
  assert.equal(cleaned.headers['x-echo'], '[已脱敏]');

  const safeBinary = redactPlatformToken({ status: 200, body_hex: 'deadbeef', headers: {} }, 'other-secret');
  assert.equal(safeBinary.body_hex, 'deadbeef');
  assert.equal(safeBinary.body_redacted, undefined);

  const envName = 'CTF_TEST_AUTH_HEADER_TOK';
  const prev = process.env[envName];
  process.env[envName] = 'raw-key-123';
  try {
    assert.deepEqual(platformAuthHeaders({ platformTokenEnv: envName, platformAuthHeader: 'X-API-Key', platformAuthScheme: '' }), {
      'X-API-Key': 'raw-key-123',
    });
    assert.throws(() => platformAuthHeaders({ platformTokenEnv: envName, platformAuthHeader: 'Bad Header' }), /HTTP 头/u);
    assert.throws(() => platformAuthHeaders({ platformTokenEnv: envName, platformAuthScheme: 'Bad\r\nScheme' }), /换行/u);
  } finally {
    if (prev === undefined) delete process.env[envName];
    else process.env[envName] = prev;
  }
});

test('sandbox-runner Ghidra 脚本兼容 Jython 2.7 地址归一化，Dockerfile 向 UID 10001 复制 r2ghidra', async () => {
  const { DECOMPILE_SCRIPT } = await import('../sandbox-runner.js');
  assert.doesNotMatch(DECOMPILE_SCRIPT, /removeprefix\(/u, 'Ghidra Jython 2.7 脚本不得使用 Python 3.9 removeprefix');
  assert.match(DECOMPILE_SCRIPT, /def norm_addr\(raw\):/u);
  assert.match(DECOMPILE_SCRIPT, /target_norm = norm_addr\((?:target|one)\)/u);
  const dockerfile = await readFile(new URL('../docker/Dockerfile', import.meta.url), 'utf8');
  assert.match(dockerfile, /\/home\/ctf\/\.local\/share\/radare2/u);
  assert.match(dockerfile, /apt-get purge -y --auto-remove cmake ninja-build meson/u);
});

test('P1 回归：动态授权默认拦截回环地址，submit_flag 支持 retry_unknown，Docker 启用只读根文件系统', async () => {
  const { createNetworkBoundary } = await import('../network-boundary.js');
  const { handleSubmission } = await import('../submission.js');
  const { buildDockerArgs } = await import('../sandbox-runner.js');

  const session = {};
  const scope = { session, workspaceKey: 'ws-p1' };
  const strictNet = createNetworkBoundary(() => ({}));
  assert.equal(strictNet.grantHttp('http://127.0.0.1:2375', scope), undefined);
  assert.equal(strictNet.grantHttp('http://localhost:8080', scope), undefined);
  assert.equal(strictNet.grantTcp('127.0.0.1', 6379, scope), undefined);
  assert.equal(strictNet.grantTcp('::1', 6379, scope), undefined);
  await assert.rejects(() => strictNet.http('https://example.invalid', undefined, scope), err => err.kind === 'permission');

  const relaxedNet = createNetworkBoundary(() => ({ allowLoopbackDynamicGrant: true }));
  assert.equal(relaxedNet.grantHttp('http://127.0.0.1:8080', scope), 'http://127.0.0.1:8080');

  let stored = [];
  const files = {
    async read() { return { receipts: stored, document: { version: String(stored.length) } }; },
    async write(_doc, next) { stored = next; },
  };
  const first = await handleSubmission(
    { flag: 'flag{retry_unknown_429_case}', source: 'p1-test' },
    files,
    async () => ({ status: 429, body: JSON.stringify({ success: false }) }),
    'https://ctf.example',
  );
  assert.equal(first.verdict, 'unknown');
  const blocked = await handleSubmission(
    { flag: 'flag{retry_unknown_429_case}', source: 'p1-test' },
    files,
    async () => ({ status: 200, body: JSON.stringify({ correct: true }) }),
    'https://ctf.example',
  );
  assert.equal(blocked.verdict, 'rejected_local');
  const retried = await handleSubmission(
    { flag: 'flag{retry_unknown_429_case}', source: 'p1-test', retry_unknown: true },
    files,
    async () => ({ status: 200, body: JSON.stringify({ correct: true }) }),
    'https://ctf.example',
  );
  assert.equal(retried.verdict, 'accepted');

  const dockerArgs = buildDockerArgs(['id'], { cwd: '/tmp/w', containerName: 'c1', targetImage: 'dsh-ctf-sandbox:latest' });
  assert.ok(dockerArgs.includes('--read-only'));
  assert.ok(dockerArgs.includes('/tmp:rw,nosuid,size=512m'));
});
