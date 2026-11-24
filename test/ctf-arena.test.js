import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { lstat as fsLstat, mkdtemp, readFile, rm, stat as fsStat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { apply } from '../ctf-tools.js';
import { resolveAdapter } from '../ctf-arena.js';
import { platformRequest } from '../platform-request.js';

function createRealWorkspaceContext(cwd, config = {}, writable = true) {
  const tools = new Map();
  const resolveTarget = (name, options = {}) => {
    const base = (options.cwd ?? cwd).replace(/[\\/]$/u, '');
    const targetKey = options.cwd ? `${base}/${name}` : name;
    return { targetKey, displayPath: targetKey };
  };
  const ctx = {
    tools: { register(tool) { tools.set(tool.name, tool); } },
    effect() {},
    emit() {},
    workingDirectory: { async ensure() { return cwd; } },
    sandboxPolicy: { resolve() { return { mode: writable ? 'workspace-write' : 'read-only' }; } },
    fs: {
      async resolve(name, options) { return resolveTarget(name, options); },
      contains(parent, child) {
        return child.targetKey === parent.targetKey || child.targetKey.startsWith(parent.targetKey.replace(/[\\/]$/u, '') + '/');
      },
      async lstat(name, options) {
        const rel = resolveTarget(name, options).targetKey.slice(cwd.replace(/[\\/]$/u, '').length + 1);
        try {
          const info = await fsLstat(join(cwd, rel));
          return { type: info.isDirectory() ? 'directory' : info.isFile() ? 'file' : 'other' };
        } catch {
          return undefined;
        }
      },
      async stat(target) {
        const rel = target.targetKey.slice(cwd.replace(/[\\/]$/u, '').length + 1);
        try {
          const info = await fsStat(join(cwd, rel));
          return { type: info.isFile() ? 'file' : 'directory', size: info.size, version: `${info.mtimeMs}:${info.size}` };
        } catch {
          return null;
        }
      },
      async readBytes(target) {
        const rel = target.targetKey.slice(cwd.replace(/[\\/]$/u, '').length + 1);
        return readFile(join(cwd, rel));
      },
      async writeText(target, text, intent) {
        const rel = target.targetKey.slice(cwd.replace(/[\\/]$/u, '').length + 1);
        const full = join(cwd, rel);
        let existing;
        try {
          const info = await fsStat(full);
          existing = `${info.mtimeMs}:${info.size}`;
        } catch { /* absent */ }
        if (intent.kind === 'createIfAbsent' && existing !== undefined) throw new Error('exists');
        if (intent.kind === 'replaceIfVersion' && existing !== intent.version) throw new Error('conflict');
        await writeFile(full, text, 'utf8');
        const after = await fsStat(full);
        return { version: `${after.mtimeMs}:${after.size}` };
      },
    },
  };
  apply(ctx, config);
  const execution = { signal: new AbortController().signal, agent: { session: { header: { cwd }, id: 'arena-commander' } } };
  return { tools, execution };
}

test('platformRequest 真实 HTTP 请求只在有 JSON body 时发送 Content-Type', async t => {
  const received = [];
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    received.push({ method: req.method, contentType: req.headers['content-type'], body: Buffer.concat(chunks).toString('utf8') });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"ok":true}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const config = { platformUrl: `http://127.0.0.1:${server.address().port}`, allowInsecurePlatformHttp: true };
  await platformRequest(config, undefined, 'GET', '/status');
  await platformRequest(config, undefined, 'POST', '/submissions', { challenge: '7', flag: 'flag{ok}' });
  assert.equal(received[0].contentType, undefined);
  assert.equal(received[0].body, '');
  assert.equal(received[1].contentType, 'application/json');
  assert.deepEqual(JSON.parse(received[1].body), { challenge: '7', flag: 'flag{ok}' });
});

async function startServer(handler) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () => new Promise(resolve => server.close(resolve)),
  };
}

test('platformRequest 跟随同源 API 跳转并在授权前阻断跨来源跳转', async t => {
  let externalHits = 0;
  const external = await startServer((req, res) => {
    externalHits += 1;
    res.writeHead(200);
    res.end('should not be requested');
  });
  t.after(() => external.close());

  const tokenEnv = 'CTF_TEST_REDIRECT_TOKEN';
  const previousToken = process.env[tokenEnv];
  process.env[tokenEnv] = 'redirect_secret';
  t.after(() => {
    if (previousToken === undefined) delete process.env[tokenEnv];
    else process.env[tokenEnv] = previousToken;
  });
  const platform = await startServer((req, res) => {
    if (req.url === '/same-redirect') {
      res.writeHead(302, { Location: '/target' });
      res.end('redirecting');
      return;
    }
    if (req.url === '/cross-redirect') {
      res.writeHead(302, { Location: `${external.baseUrl}/secret` });
      res.end('redirecting');
      return;
    }
    if (req.url === '/target') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('same-origin target');
      return;
    }
    res.writeHead(404);
    res.end();
  });
  t.after(() => platform.close());

  const config = {
    platformUrl: platform.baseUrl,
    platformTokenEnv: tokenEnv,
    allowInsecurePlatformHttp: true,
  };
  const sameOrigin = await platformRequest(config, undefined, 'GET', '/same-redirect');
  assert.equal(sameOrigin.status, 200);
  assert.equal(sameOrigin.body, 'same-origin target');
  assert.equal(sameOrigin.redirects.length, 1);

  const crossOrigin = await platformRequest(config, undefined, 'GET', '/cross-redirect');
  assert.equal(crossOrigin.status, 302);
  assert.equal(crossOrigin.redirect_blocked, 'cross_origin_or_credentials');
  assert.equal(externalHits, 0);
});

test('平台自动探测真实 HTTP 认证拒绝时不静默降级为 generic', async t => {
  const server = await startServer((_req, res) => {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end('{"message":"login required"}');
  });
  t.after(() => server.close());
  const config = { platformUrl: server.baseUrl, allowInsecurePlatformHttp: true };
  await assert.rejects(resolveAdapter(config, 'auto'),
    error => error.kind === 'permission' && /认证拒绝/u.test(error.message));
  const controller = new AbortController();
  controller.abort(Object.assign(new Error('request cancelled'), { name: 'AbortError' }));
  await assert.rejects(resolveAdapter(config, 'auto', undefined, controller.signal),
    error => error.name === 'AbortError' || error.kind === 'abort');
});

test('ctf_status 只读会话可查看实时看板但不写入状态文件', async t => {
  const server = await startServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ me: { rank: 3, score: 240, solved: 4 } }));
  });
  t.after(() => server.close());
  const cwd = await mkdtemp(join(tmpdir(), 'ctf-status-readonly-'));
  try {
    const { tools, execution } = createRealWorkspaceContext(cwd, {
      platformUrl: server.baseUrl,
      allowInsecurePlatformHttp: true,
    }, false);
    const board = JSON.parse(await tools.get('ctf_status').execute({ action: 'board' }, execution));
    assert.equal(board.status, 'board');
    assert.deepEqual(board.board, { rank: 3, score: 240, solved: 4 });
    assert.equal(board.recorded, false);
    const progress = JSON.parse(await tools.get('ctf_progress').execute({
      action: 'save', revision: 'absent', progress: { confirmed: [], ruled_out: [], pending: [] },
    }, execution));
    assert.equal(progress.ok, false);
    assert.equal(progress.error.kind, 'permission');
    await assert.rejects(fsStat(join(cwd, '.ctf-status.json')));
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('ctf_arena 端到端适配 CTFd：自动探测、Token 认证、拉题、同步图谱幂等、下附件与提交 flag', async () => {
  const envKey = 'CTF_TEST_CTFD_TOKEN';
  const prev = process.env[envKey];
  process.env[envKey] = 'ctfd_secret_abc123';
  const fileBytes = Buffer.from('challenge attachment payload', 'utf8');
  const seenAuth = [];
  const server = await startServer((req, res) => {
    seenAuth.push({ url: req.url, auth: req.headers.authorization });
    if (req.method === 'GET' && req.url === '/api/v1/challenges') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        success: true,
        data: [
          { id: 101, name: 'Baby Web', category: 'Web', value: 100, solved_by_me: false, solves: 25 },
          { id: 102, name: 'Hard Heap', category: 'Pwn', value: 500, solved_by_me: false, solves: 2 },
          { id: 103, name: 'Done Misc', category: 'Misc', value: 50, solved_by_me: true, solves: 80 },
        ],
      }));
      return;
    }
    if (req.method === 'GET' && req.url === '/api/v1/challenges/101') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        success: true,
        data: {
          id: 101, name: 'Baby Web', category: 'Web', value: 100, solved_by_me: false,
          description: `Visit ${server.baseUrl}/untrusted-description-link`,
          connection_info: 'http://10.20.30.40:8080\nnc 10.20.30.40 31337',
          files: Array.from({ length: 9 }, (_value, index) => `/files/chall${index + 1}.zip`),
          hints: [{ content: 'Check JWT header' }],
        },
      }));
      return;
    }
    if (req.method === 'GET' && /^\/files\/chall\d+\.zip$/u.test(req.url)) {
      if (req.headers.authorization !== 'Token ctfd_secret_abc123') {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, message: 'CTFd token required' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
      res.end(fileBytes);
      return;
    }
    if (req.method === 'POST' && req.url === '/api/v1/challenges/attempt') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        const parsed = JSON.parse(body);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          data: { status: parsed.submission === 'flag{ctfd_ok}' ? 'correct' : 'incorrect' },
        }));
      });
      return;
    }
    res.writeHead(404);
    res.end();
  });

  const cwd = await mkdtemp(join(tmpdir(), 'ctf-arena-ctfd-'));
  try {
    const config = {
      platformUrl: server.baseUrl,
      platformTokenEnv: envKey,
      allowInsecurePlatformHttp: true,
    };
    const { tools, execution } = createRealWorkspaceContext(cwd, config, true);

    const status = JSON.parse(await tools.get('ctf_arena').execute({ action: 'status' }, execution));
    assert.equal(status.status, 'ok');
    assert.equal(status.detected_adapter, 'ctfd');
    assert.equal(status.token_present, true);
    assert.equal(JSON.stringify(status).includes('ctfd_secret_abc123'), false);

    // 验证自动使用 Authorization: Token ...
    assert.ok(seenAuth.some(entry => entry.auth === 'Token ctfd_secret_abc123'));

    const listed = JSON.parse(await tools.get('ctf_arena').execute({ action: 'challenges', unsolved_only: true }, execution));
    assert.equal(listed.status, 'ok');
    assert.equal(listed.total, 2);

    const detail = JSON.parse(await tools.get('ctf_arena').execute({ action: 'detail', challenge_id: '101' }, execution));
    assert.equal(detail.status, 'ok');
    assert.equal(detail.files[0], `${server.baseUrl}/files/chall1.zip`);
    assert.ok(detail.authorized_targets.http.includes('http://10.20.30.40:8080'));
    assert.ok(detail.authorized_targets.tcp.includes('10.20.30.40:31337'));
    const descriptionTarget = JSON.parse(await tools.get('http_request').execute({
      url: `${server.baseUrl}/untrusted-description-link`,
    }, execution));
    assert.equal(descriptionTarget.ok, false, 'description 中的 URL 不应成为网络授权');

    // sync_graph 导入并验证二次同步严格幂等
    const sync1 = JSON.parse(await tools.get('ctf_arena').execute({ action: 'sync_graph', unsolved_only: true }, execution));
    assert.equal(sync1.status, 'ok');
    assert.equal(sync1.imported_count, 2);
    assert.equal(sync1.imported[0].priority, 5); // 100pt 排优先

    const sync2 = JSON.parse(await tools.get('ctf_arena').execute({ action: 'sync_graph', unsolved_only: true }, execution));
    assert.equal(sync2.imported_count, 0);
    assert.equal(sync2.deduplicated_count, 2);

    // 紧接 dispatch_plan 产出并行分工简报
    const plan = JSON.parse(await tools.get('ctf_graph').execute({ action: 'dispatch_plan', max_workers: 2 }, execution));
    assert.equal(plan.assignments.length, 2);

    // fetch_files 下载附件并校验 SHA-256
    const fetched = JSON.parse(await tools.get('ctf_arena').execute({ action: 'fetch_files', challenge_id: '101' }, execution));
    assert.equal(fetched.status, 'partial');
    assert.equal(fetched.total_files, 9);
    assert.equal(fetched.omitted_file_count, 1);
    assert.equal(fetched.downloaded.length, 8);
    assert.equal(fetched.downloaded[0].sha256, createHash('sha256').update(fileBytes).digest('hex'));
    assert.ok(seenAuth.some(entry => /^\/files\/chall\d+\.zip$/u.test(entry.url) && entry.auth === 'Token ctfd_secret_abc123'));

    // submit 提交 flag
    const submitted = JSON.parse(await tools.get('ctf_arena').execute({
      action: 'submit', challenge_id: '101', flag: 'flag{ctfd_ok}', source: 'notes:F-1',
    }, execution));
    assert.equal(submitted.verdict, 'accepted', JSON.stringify(submitted));
  } finally {
    await server.close();
    await rm(cwd, { recursive: true, force: true, maxRetries: 5, retryDelay: 80 });
    if (prev === undefined) delete process.env[envKey];
    else process.env[envKey] = prev;
  }
});

test('ctf_arena 端到端适配 GZCTF：games、分组题单、容器启删自动授权、GZCTF 判题归一化与只读拦截', async () => {
  let submissionRequests = 0;
  const server = await startServer((req, res) => {
    if (req.method === 'GET' && req.url === '/api/game') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify([{ id: 7, title: 'Autumn CTF 2026' }]));
      return;
    }
    if (req.method === 'GET' && req.url === '/api/game/7/details') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        challenges: {
          Web: [{ id: 11, title: 'ez_flask', score: 200, solved: false }],
          Pwn: [{ id: 12, title: 'ez_stack', score: 400, solved: false }],
        },
      }));
      return;
    }
    if (req.method === 'POST' && req.url === '/api/game/7/challenges/12/container') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ip: '10.99.0.5', port: 23456, entry: '10.99.0.5:23456' }));
      return;
    }
    if (req.method === 'DELETE' && req.url === '/api/game/7/challenges/12/container') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    if (req.method === 'POST' && req.url === '/api/game/7/challenges/12') {
      submissionRequests += 1;
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        const parsed = JSON.parse(body);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(['flag{gz_win}', 'flag{gz_dynamic_win}'].includes(parsed.flag) ? 'Accepted' : 'WrongAnswer'));
      });
      return;
    }
    res.writeHead(404);
    res.end();
  });

  const cwd = await mkdtemp(join(tmpdir(), 'ctf-arena-gzctf-'));
  try {
    const config = {
      platformUrl: server.baseUrl,
      platformType: 'gzctf',
      platformGameId: '7',
      allowInsecurePlatformHttp: true,
    };
    const { tools, execution } = createRealWorkspaceContext(cwd, config, true);

    const games = JSON.parse(await tools.get('ctf_arena').execute({ action: 'games' }, execution));
    assert.equal(games.status, 'ok');
    assert.equal(games.games[0].id, '7');

    const chs = JSON.parse(await tools.get('ctf_arena').execute({ action: 'challenges', category: 'Pwn' }, execution));
    assert.equal(chs.total, 1);
    assert.equal(chs.challenges[0].name, 'ez_stack');

    const created = JSON.parse(await tools.get('ctf_arena').execute({
      action: 'container', challenge_id: '12', container_action: 'create',
    }, execution));
    assert.equal(created.status, 'created');
    assert.equal(created.instance_id, 'container:12');
    assert.equal(created.instance_recorded, true);
    assert.ok(created.authorized_targets.tcp.includes('10.99.0.5:23456'));

    const untrackedDynamic = JSON.parse(await tools.get('ctf_arena').execute({
      action: 'submit', challenge_id: '12', flag: 'flag{gz_win}', source: 'test', dynamic: true,
      instance: 'not-recorded', refreshed_at: new Date().toISOString(),
    }, execution));
    assert.equal(untrackedDynamic.verdict, 'rejected_local');
    assert.equal(submissionRequests, 0, '未登记实例不能把调用方时间戳当作新鲜度证明');

    const trackedDynamic = JSON.parse(await tools.get('ctf_arena').execute({
      action: 'submit', challenge_id: '12', flag: 'flag{gz_dynamic_win}', source: 'test', dynamic: true,
      instance: 'container:12', refreshed_at: '2020-01-01T00:00:00.000Z',
    }, execution));
    assert.equal(trackedDynamic.verdict, 'accepted', JSON.stringify(trackedDynamic));
    assert.equal(submissionRequests, 1, '账本中的刷新时间应覆盖伪造的旧时间戳');

    const deleted = JSON.parse(await tools.get('ctf_arena').execute({
      action: 'container', challenge_id: '12', container_action: 'delete',
    }, execution));
    assert.equal(deleted.status, 'deleted');

    const deletedDynamic = JSON.parse(await tools.get('ctf_arena').execute({
      action: 'submit', challenge_id: '12', flag: 'flag{gz_win}', source: 'test', dynamic: true,
      instance: 'container:12', refreshed_at: new Date().toISOString(),
    }, execution));
    assert.equal(deletedDynamic.verdict, 'rejected_local');
    assert.equal(submissionRequests, 1, '已删除实例不能提交，即使调用方传入当前时间');

    const bad = JSON.parse(await tools.get('ctf_arena').execute({
      action: 'submit', challenge_id: '12', flag: 'flag{wrong_try}', source: 'test',
    }, execution));
    assert.equal(bad.verdict, 'rejected');

    const win = JSON.parse(await tools.get('ctf_arena').execute({
      action: 'submit', challenge_id: '12', flag: 'flag{gz_win}', source: 'test',
    }, execution));
    assert.equal(win.verdict, 'accepted');

    // 只读会话拦截写操作 & 非法 challenge_id 路径穿越拦截
    const ro = createRealWorkspaceContext(cwd, config, false);
    const roDeny = JSON.parse(await ro.tools.get('ctf_arena').execute({ action: 'sync_graph' }, ro.execution));
    assert.equal(roDeny.ok, false);
    assert.equal(roDeny.error.kind, 'permission');

    const badId = JSON.parse(await tools.get('ctf_arena').execute({ action: 'detail', challenge_id: '../etc' }, execution));
    assert.equal(badId.ok, false);
    assert.equal(badId.error.kind, 'unsupported');
  } finally {
    await server.close();
    await rm(cwd, { recursive: true, force: true, maxRetries: 5, retryDelay: 80 });
  }
});

test('ctf_arena: GZCTF 自动 Cookie 鉴权、容器 extend 续期与同分按解出人数(solves)动态排序', async () => {
  const seenCookies = [];
  let extendedCalled = false;
  const server = await startServer((req, res) => {
    seenCookies.push(req.headers.cookie ?? '');
    if (req.headers.cookie !== 'GZCTF_Token=gz_cookie_secret_42') {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ title: 'Unauthorized' }));
      return;
    }
    if (req.method === 'GET' && req.url === '/api/game/9/details') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        challenges: {
          Web: [
            { id: 21, title: 'hard_same_score', score: 300, solvedCount: 1, solved: false },
            { id: 22, title: 'easy_same_score', score: 300, solvedCount: 45, solved: false },
            { id: 23, title: 'cheapest_one', score: 100, solvedCount: 5, solved: false },
          ],
        },
      }));
      return;
    }
    if (req.method === 'POST' && req.url === '/api/game/9/challenges/22/container/extend') {
      extendedCalled = true;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ expectStopAt: '2026-11-24T04:00:00Z' }));
      return;
    }
    res.writeHead(404);
    res.end();
  });

  const envKey = 'CTF_ARENA_TEST_GZ_COOKIE';
  const prev = process.env[envKey];
  process.env[envKey] = 'gz_cookie_secret_42';
  const cwd = await mkdtemp(join(tmpdir(), 'ctf-arena-gz-ext-'));
  try {
    const config = {
      platformUrl: server.baseUrl,
      platformType: 'gzctf',
      platformGameId: '9',
      platformTokenEnv: envKey,
      allowInsecurePlatformHttp: true,
    };
    const { tools, execution } = createRealWorkspaceContext(cwd, config, true);

    // 同步题单：校验 Cookie: GZCTF_Token=<raw> 自动拼装 + 同分按 solves 降序分配优先级
    const synced = JSON.parse(await tools.get('ctf_arena').execute({ action: 'sync_graph' }, execution));
    assert.equal(synced.status, 'ok', JSON.stringify(synced));
    assert.equal(synced.imported_count, 3);
    assert.ok(seenCookies.every(c => c === 'GZCTF_Token=gz_cookie_secret_42'));

    const board = JSON.parse(await tools.get('ctf_graph').execute({ action: 'board' }, execution));
    const byChallenge = new Map(board.intents.map(i => [i.challenge, i.priority]));
    assert.ok(byChallenge.get('web-cheapest_one') >= byChallenge.get('web-easy_same_score'), JSON.stringify([...byChallenge]));
    assert.ok(byChallenge.get('web-easy_same_score') > byChallenge.get('web-hard_same_score'),
      `solves 更多的同分题应优先于 solves 少的题: ${JSON.stringify([...byChallenge])}`);

    // 容器续期 container_action: extend
    const extended = JSON.parse(await tools.get('ctf_arena').execute({
      action: 'container', challenge_id: '22', container_action: 'extend',
    }, execution));
    assert.equal(extended.status, 'extended', JSON.stringify(extended));
    assert.equal(extendedCalled, true);
  } finally {
    await server.close();
    await rm(cwd, { recursive: true, force: true, maxRetries: 5, retryDelay: 80 });
    if (prev === undefined) delete process.env[envKey];
    else process.env[envKey] = prev;
  }
});

test('submit_flag 动态 flag 只信任新鲜实例账本，不接受调用方伪造 refreshed_at', async () => {
  let submitRequests = 0;
  const server = await startServer((req, res) => {
    if (req.method === 'POST' && req.url === '/instances') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data: { id: 'instance-42' } }));
      return;
    }
    if (req.method === 'DELETE' && req.url === '/instances/instance-42') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    if (req.method === 'POST' && req.url === '/submissions') {
      submitRequests += 1;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ correct: true }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  const cwd = await mkdtemp(join(tmpdir(), 'ctf-dynamic-submit-'));
  try {
    const config = { platformUrl: server.baseUrl, platformType: 'generic', allowInsecurePlatformHttp: true };
    const { tools, execution } = createRealWorkspaceContext(cwd, config, true);
    const forgedUntracked = JSON.parse(await tools.get('submit_flag').execute({
      challenge: 'web-1', flag: 'flag{dynamic_win}', source: 'test', dynamic: true,
      instance: 'instance-42', refreshed_at: new Date().toISOString(),
    }, execution));
    assert.equal(forgedUntracked.verdict, 'rejected_local');
    assert.equal(submitRequests, 0);

    const created = JSON.parse(await tools.get('ctf_instance').execute({ action: 'create' }, execution));
    assert.equal(created.id, 'instance-42');
    assert.equal(created.instance_recorded, true);
    const trusted = JSON.parse(await tools.get('submit_flag').execute({
      challenge: 'web-1', flag: 'flag{dynamic_win}', source: 'test', dynamic: true,
      instance: 'instance-42', refreshed_at: '2020-01-01T00:00:00.000Z',
    }, execution));
    assert.equal(trusted.verdict, 'accepted', JSON.stringify(trusted));
    assert.equal(submitRequests, 1);

    const deleted = JSON.parse(await tools.get('ctf_instance').execute({ action: 'delete', id: 'instance-42' }, execution));
    assert.equal(deleted.status, 'deleted');
    const afterDelete = JSON.parse(await tools.get('submit_flag').execute({
      challenge: 'web-1', flag: 'flag{different_dynamic}', source: 'test', dynamic: true,
      instance: 'instance-42', refreshed_at: new Date().toISOString(),
    }, execution));
    assert.equal(afterDelete.verdict, 'rejected_local');
    assert.equal(submitRequests, 1);
  } finally {
    await server.close();
    await rm(cwd, { recursive: true, force: true, maxRetries: 5, retryDelay: 80 });
  }
});
