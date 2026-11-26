import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { deflateSync } from 'node:zlib';
import {
  createArtifactStore,
  createCtfRuntime,
  createGdbSessionManager,
  createSandboxEgressProxy,
  createSandboxPool,
  detectSandbox,
  runSandbox,
  ToolError,
} from '../core/index.js';
import { inspectMedia } from '../media-reader.js';
import { createNetworkBoundary } from '../network-boundary.js';
import { apply } from '../ctf-tools.js';

const PYTHON = process.platform === 'win32' ? 'python' : 'python3';

function hasDockerImage(tag) {
  const probe = spawnSync('docker', ['image', 'inspect', tag], { stdio: 'ignore', windowsHide: true, timeout: 5000 });
  return probe.status === 0;
}

function buildGgufBytes(kvs) {
  const parts = [Buffer.from('GGUF'), Buffer.alloc(4), Buffer.alloc(8), Buffer.alloc(8)];
  parts[1].writeUInt32LE(3, 0);
  parts[2].writeBigUInt64LE(0n, 0);
  parts[3].writeBigUInt64LE(BigInt(kvs.length), 0);
  const strBuf = s => {
    const b = Buffer.from(s, 'utf8');
    const len = Buffer.alloc(8);
    len.writeBigUInt64LE(BigInt(b.length), 0);
    return Buffer.concat([len, b]);
  };
  for (const [k, v] of kvs) {
    parts.push(strBuf(k));
    const t = Buffer.alloc(4);
    t.writeUInt32LE(8, 0); // STRING
    parts.push(t, strBuf(v));
  }
  return Buffer.concat(parts);
}

function adler32(buf) {
  let a = 1;
  let b = 0;
  for (let i = 0; i < buf.length; i++) {
    a = (a + buf[i]) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

function buildMinimalValidDex() {
  const encodeStr = s => {
    const raw = Buffer.concat([Buffer.from([s.length]), Buffer.from(s + '\0', 'ascii')]);
    const pad = (4 - (raw.length % 4)) % 4;
    return Buffer.concat([raw, Buffer.alloc(pad)]);
  };
  const str0 = encodeStr('Lcom/ctf/Flag;');
  const str1 = encodeStr('Ljava/lang/Object;');
  const headerSize = 0x70;
  const stringIdsOff = headerSize; // 2 entries = 8 bytes
  const typeIdsOff = stringIdsOff + 8; // 2 entries = 8 bytes
  const classDefsOff = typeIdsOff + 8; // 1 entry = 32 bytes
  const dataOff = classDefsOff + 32; // 0xa0
  const str0Off = dataOff;
  const str1Off = dataOff + str0.length;
  const mapOff = str1Off + str1.length;
  const mapItems = [
    [0x0000, 1, 0],
    [0x0001, 2, stringIdsOff],
    [0x0002, 2, typeIdsOff],
    [0x0006, 1, classDefsOff],
    [0x2002, 2, dataOff],
    [0x1000, 1, mapOff],
  ];
  const mapBuf = Buffer.alloc(4 + mapItems.length * 12);
  mapBuf.writeUInt32LE(mapItems.length, 0);
  mapItems.forEach(([type, size, off], idx) => {
    const base = 4 + idx * 12;
    mapBuf.writeUInt16LE(type, base);
    mapBuf.writeUInt16LE(0, base + 2);
    mapBuf.writeUInt32LE(size, base + 4);
    mapBuf.writeUInt32LE(off, base + 8);
  });
  const dataSize = str0.length + str1.length + mapBuf.length;
  const fileSize = dataOff + dataSize;

  const dex = Buffer.alloc(fileSize);
  Buffer.from('dex\n035\0', 'ascii').copy(dex, 0);
  dex.writeUInt32LE(fileSize, 32);
  dex.writeUInt32LE(headerSize, 36);
  dex.writeUInt32LE(0x12345678, 40);
  dex.writeUInt32LE(mapOff, 52);
  dex.writeUInt32LE(2, 56); // string_ids_size
  dex.writeUInt32LE(stringIdsOff, 60);
  dex.writeUInt32LE(2, 64); // type_ids_size
  dex.writeUInt32LE(typeIdsOff, 68);
  dex.writeUInt32LE(1, 96); // class_defs_size
  dex.writeUInt32LE(classDefsOff, 100);
  dex.writeUInt32LE(dataSize, 104); // data_size
  dex.writeUInt32LE(dataOff, 108);

  dex.writeUInt32LE(str0Off, stringIdsOff);
  dex.writeUInt32LE(str1Off, stringIdsOff + 4);
  dex.writeUInt32LE(0, typeIdsOff);
  dex.writeUInt32LE(1, typeIdsOff + 4);
  dex.writeUInt32LE(0, classDefsOff); // class_idx
  dex.writeUInt32LE(1, classDefsOff + 4); // ACC_PUBLIC
  dex.writeUInt32LE(1, classDefsOff + 8); // superclass = Ljava/lang/Object;
  dex.writeUInt32LE(0xffffffff, classDefsOff + 16); // NO_INDEX source_file
  str0.copy(dex, str0Off);
  str1.copy(dex, str1Off);
  mapBuf.copy(dex, mapOff);

  const sha1 = createHash('sha1').update(dex.subarray(32)).digest();
  sha1.copy(dex, 12);
  dex.writeUInt32LE(adler32(dex.subarray(12)), 8);
  return dex;
}

function buildTinyApkBytes() {
  const entries = [
    ['AndroidManifest.xml', Buffer.from('<manifest package="com.ctf.test"/>')],
    ['classes.dex', buildMinimalValidDex()],
  ];
  const local = [];
  const central = [];
  let offset = 0;
  for (const [name, data] of entries) {
    const nb = Buffer.from(name, 'utf8');
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt32LE(data.length, 18);
    lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(nb.length, 26);
    local.push(lh, nb, data);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt32LE(data.length, 20);
    ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(nb.length, 28);
    ch.writeUInt32LE(offset, 42);
    central.push(ch, nb);
    offset += lh.length + nb.length + data.length;
  }
  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, cd, eocd]);
}

test('media-reader-worker AI scanners catch obfuscated GGUF Jinja2, large metadata truncation, and Proto 0 Pickle', async () => {
  // 1) Hex-escaped \x5f\x5fclass\x5f\x5f SSTI inside GGUF chat_template
  const ggufEvil = buildGgufBytes([
    ['tokenizer.chat_template', '{{ "".\\x5f\\x5fclass\\x5f\\x5f.mro() }}'],
  ]);
  const rEvil = await inspectMedia(ggufEvil, { kind: 'model' }, undefined, { async resolvePython() { return PYTHON; } });
  assert.equal(rEvil.format, 'gguf');
  assert.equal(rEvil.risk_level, 'high');
  assert.ok(rEvil.findings.some(f => f.kind === 'suspicious_metadata_template'));

  // 2) >64 KiB GGUF metadata triggers string_scan_truncated -> metadata_truncated: true
  const bigVal = 'A'.repeat(70 * 1024);
  const ggufLarge = buildGgufBytes([['general.name', 'big'], ['general.description', bigVal]]);
  const rLarge = await inspectMedia(ggufLarge, { kind: 'model' }, undefined, { async resolvePython() { return PYTHON; } });
  assert.equal(rLarge.format, 'gguf');
  assert.equal(rLarge.metadata_truncated, true);

  // 3) Protocol 0 Pickle BUILD/NEWOBJ & un-stopped truncated attack payloads detected as pickle (not invalid)
  const proto0Valid = Buffer.from('ccopy_reg\n_reconstructor\n(cbuiltins\nobject\nNtR(dS"a"\nI1\nsb.', 'latin1');
  const rPklValid = await inspectMedia(proto0Valid, { kind: 'model' }, undefined, { async resolvePython() { return PYTHON; } });
  assert.equal(rPklValid.format, 'pickle');
  assert.equal(rPklValid.status, 'ok');
  assert.equal(rPklValid.call_ops.BUILD, 1);

  const proto0Trunc = Buffer.from('cos\nsystem\n)\x81}S"k"\nS"v"\nsb', 'latin1');
  const rPklTrunc = await inspectMedia(proto0Trunc, { kind: 'model' }, undefined, { async resolvePython() { return PYTHON; } });
  assert.equal(rPklTrunc.format, 'pickle');
  assert.equal(rPklTrunc.risk_level, 'high');
});

test('egress-proxy authorizes granted HTTP/TCP targets and denies ungranted targets', async t => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok:' + req.url);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const upstreamPort = server.address().port;

  const boundary = createNetworkBoundary({ allowLoopbackDynamicGrant: true });
  const scope = { session: { id: 'proxy-test' }, workspaceKey: 'ws-proxy' };
  const proxy = await createSandboxEgressProxy({
    networkBoundary: boundary,
    scope,
    pin: async () => ({ address: '127.0.0.1', family: 4 }),
  });
  t.after(() => proxy.close());
  const proxyAuth = 'Basic ' + Buffer.from(`${proxy.username}:${proxy.password}`).toString('base64');

  // Without proxy credentials -> 407 Proxy Authentication Required
  const unauth = await new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port: proxy.port,
      method: 'GET',
      path: `http://127.0.0.1:${upstreamPort}/secret`,
      headers: { Host: `127.0.0.1:${upstreamPort}` },
    }, res => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject);
    req.end();
  });
  assert.equal(unauth, 407);

  // Valid proxy auth, ungranted target -> 403
  const blocked = await new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port: proxy.port,
      method: 'GET',
      path: `http://127.0.0.1:${upstreamPort}/secret`,
      headers: { Host: `127.0.0.1:${upstreamPort}`, 'Proxy-Authorization': proxyAuth },
    }, res => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject);
    req.end();
  });
  assert.equal(blocked, 403);

  // After grant -> 200
  boundary.grantHttp(`http://127.0.0.1:${upstreamPort}`, scope);
  const allowed = await new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port: proxy.port,
      method: 'GET',
      path: `http://127.0.0.1:${upstreamPort}/secret`,
      headers: { Host: `127.0.0.1:${upstreamPort}`, 'Proxy-Authorization': proxyAuth },
    }, res => {
      let body = '';
      res.on('data', c => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.end();
  });
  assert.equal(allowed.status, 200);
  assert.equal(allowed.body, 'ok:/secret');
});

test('backend: local respects host platform guard and ctf_sandbox unauthorized bridge gating works', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'ctf-local-sb-'));
  try {
    const detectedLocal = await detectSandbox({ sandboxBackend: 'local' }, undefined, { fresh: true });
    if (process.platform === 'win32') {
      assert.equal(detectedLocal.available, false);
    } else {
      assert.equal(detectedLocal.available, true);
      assert.equal(detectedLocal.backend, 'local');
      const localRun = await runSandbox({ action: 'exec', backend: 'local', command: 'python3 -c "print(40+2)"' }, {
        cwd, config: { sandboxBackend: 'local' }, writable: true,
      });
      assert.equal(localRun.backend, 'local');
      assert.equal(localRun.status, 'ok');
      assert.equal(localRun.stdout.trim(), '42');
    }

    // Unauthorized bridge without networkBoundary grants is denied with permission error
    const emptyNet = createNetworkBoundary({});
    await assert.rejects(
      runSandbox({ action: 'exec', command: 'echo hi', network: 'bridge' }, {
        cwd,
        config: {},
        writable: true,
        networkBoundary: emptyNet,
        networkScope: { session: { id: 's' }, workspaceKey: cwd },
      }),
      err => err instanceof ToolError && err.kind === 'permission',
    );
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('Live Docker sandbox benchmarks: r2ghidra, warm pool speedup, persistent gdb, heavy Ghidra cache, and mobile_apk signature', {
  skip: !hasDockerImage('dsh-ctf-sandbox:latest') ? 'dsh-ctf-sandbox:latest not present' : false,
  timeout: 120000,
}, async t => {
  const cwd = await mkdtemp(join(tmpdir(), 'ctf-docker-live-'));
  const pool = createSandboxPool();
  const gdbSessions = createGdbSessionManager();
  t.after(async () => {
    await gdbSessions.disposeAll();
    await pool.disposeAll();
    await rm(cwd, { recursive: true, force: true, maxRetries: 10, retryDelay: 80 });
  });

  // Compile tiny ELF inside container for live r2ghidra, Ghidra, and persistent GDB tests
  const cSrc = `#include <stdio.h>
int check_flag(int x) { return (x ^ 0x1337) == 0x4242; }
int main() { puts(check_flag(0x5175) ? "WIN" : "NO"); return 0; }
`;
  await writeFile(join(cwd, 'chall.c'), cSrc, 'utf8');
  const compiled = await runSandbox({
    action: 'exec',
    backend: 'docker',
    command: 'gcc -O0 -no-pie -o chall chall.c',
    timeout_ms: 30000,
  }, { cwd, config: {}, writable: true });
  assert.equal(compiled.status, 'ok', JSON.stringify(compiled));

  // 1) Warm container pool speedup vs cold run
  const coldStart = Date.now();
  const coldRun = await runSandbox({ action: 'exec', backend: 'docker', command: 'echo cold' }, { cwd, config: {}, writable: true });
  const coldMs = Date.now() - coldStart;
  assert.equal(coldRun.stdout.trim(), 'cold');

  const warm1 = await runSandbox({ action: 'exec', backend: 'docker', command: 'echo warm1' }, { cwd, config: {}, writable: true, sandboxPool: pool });
  assert.equal(warm1.stdout.trim(), 'warm1');
  const warmSamples = [];
  for (const tag of ['warm2', 'warm3', 'warm4']) {
    const res = await runSandbox({ action: 'exec', backend: 'docker', command: `echo ${tag}` }, { cwd, config: {}, writable: true, sandboxPool: pool });
    assert.equal(res.stdout.trim(), tag);
    assert.equal(res.pool_reused, true);
    warmSamples.push(res.elapsed_ms);
  }
  const warmMs = Math.min(...warmSamples);
  assert.ok(warmMs < 30, `expected best warm stdio pool exec < 30ms, got [${warmSamples.join(', ')}]ms`);
  t.diagnostic(`Docker timing -> cold: ${coldMs}ms, warm-reused: ${warmMs}ms (samples: ${warmSamples.join('/')})`);

  // 2) Live r2ghidra decompile on latest image
  const r2Dec = await runSandbox({
    action: 'decompile',
    backend: 'docker',
    profile: 'base',
    file_path: 'chall',
    function: 'check_flag',
    timeout_ms: 45000,
  }, { cwd, config: {}, writable: true, sandboxPool: pool });
  assert.equal(r2Dec.status, 'ok', JSON.stringify(r2Dec));
  assert.ok(['radare2', 'r2ghidra'].includes(r2Dec.engine), JSON.stringify(r2Dec));
  assert.match(r2Dec.pseudocode, /check_flag/u);

  // 3) Unauthorized network bridge fails even inside Docker check
  await assert.rejects(
    runSandbox({ action: 'exec', backend: 'docker', network: 'bridge', command: 'echo net' }, {
      cwd,
      config: {},
      writable: true,
      networkBoundary: createNetworkBoundary({}),
      networkScope: { session: { id: 'live-deny' }, workspaceKey: cwd },
    }),
    err => err instanceof ToolError && err.kind === 'permission',
  );

  await assert.rejects(
    runSandbox({ action: 'exec', backend: 'docker', network: 'bridge', command: 'echo net' }, {
      cwd,
      config: { allowUnrestrictedSandboxBridge: true },
      writable: true,
      networkBoundary: createNetworkBoundary({}),
      networkScope: { session: { id: 'live-deny-bypass' }, workspaceKey: cwd },
    }),
    err => err instanceof ToolError && err.kind === 'permission',
    'legacy allowUnrestrictedSandboxBridge must not bypass the proxy',
  );

  // Authorized bridge traffic must install the namespace firewall before the user command runs.
  const isolationNet = createNetworkBoundary({ networkOrigins: ['https://example.com'] });
  await writeFile(join(cwd, 'bridge-egress-probe.py'), [
    'import os, socket, urllib.request, urllib.error',
    'from urllib.parse import urlsplit',
    "sock = socket.socket(); sock.settimeout(2)",
    "raw = sock.connect_ex(('1.1.1.1', 443))",
    "print('RAW_TCP', raw)",
    "print('UID', os.getuid())",
    "print('CAPS', next(line.strip() for line in open('/proc/self/status') if line.startswith('CapEff:')))",
    "proxy = urlsplit(os.environ.get('HTTPS_PROXY', ''))",
    "probe = socket.socket(); probe.settimeout(2); print('PROXY_TCP', probe.connect_ex((proxy.hostname, proxy.port)))",
    "print('PROXY_ENV', proxy.scheme, proxy.hostname, proxy.port, bool(proxy.username), bool(proxy.password))",
    'try:',
    "    response = urllib.request.urlopen('https://1.1.1.1', timeout=4)",
    "    print('PROXY_HTTP', response.status)",
    'except urllib.error.HTTPError as error:',
    "    print('PROXY_HTTP', error.code)",
    'except Exception as error:',
    "    print('PROXY_ERROR', repr(error))",
  ].join('\n'), 'utf8');
  const bridgeProbe = await runSandbox({
    action: 'exec',
    backend: 'docker',
    network: 'bridge',
    command: 'python3 bridge-egress-probe.py',
    timeout_ms: 15000,
  }, {
    cwd,
    config: {},
    writable: true,
    networkBoundary: isolationNet,
    networkScope: { session: { id: 'live-proxy-firewall' }, workspaceKey: cwd },
  });
  assert.equal(bridgeProbe.status, 'ok', JSON.stringify(bridgeProbe));
  assert.match(bridgeProbe.stdout, /RAW_TCP\s+(?!0\b)[0-9]+/u, bridgeProbe.stdout);
  assert.match(bridgeProbe.stdout, /UID\s+10001/u, bridgeProbe.stdout);
  assert.match(bridgeProbe.stdout, /CapEff:\s+0000000000000000/u, bridgeProbe.stdout);
  assert.match(bridgeProbe.stdout, /PROXY_ERROR .*403/u, bridgeProbe.stdout);
  assert.match(bridgeProbe.stdout, /PROXY_TCP\s+0/u, bridgeProbe.stdout);

  const heavyBridgeProbe = await runSandbox({
    action: 'exec',
    backend: 'docker',
    profile: 'heavy',
    network: 'bridge',
    command: 'python3 bridge-egress-probe.py',
    timeout_ms: 15000,
  }, {
    cwd,
    config: {},
    writable: true,
    networkBoundary: isolationNet,
    networkScope: { session: { id: 'live-heavy-proxy-firewall' }, workspaceKey: cwd },
  });
  assert.equal(heavyBridgeProbe.status, 'ok', JSON.stringify(heavyBridgeProbe));
  assert.match(heavyBridgeProbe.stdout, /RAW_TCP\s+(?!0\b)[0-9]+/u, heavyBridgeProbe.stdout);
  assert.match(heavyBridgeProbe.stdout, /UID\s+10001/u, heavyBridgeProbe.stdout);
  assert.match(heavyBridgeProbe.stdout, /PROXY_ERROR .*403/u, heavyBridgeProbe.stdout);

  // 4) Persistent gdb_driver session (session_start -> session_cmd -> session_close) inside latest container
  const tools = new Map();
  const base = cwd.replaceAll('\\', '/').replace(/\/$/u, '');
  const resolveTarget = (name, opts = {}) => {
    const clean = name.replaceAll('\\', '/').replace(/\/$/u, '');
    if (opts.cwd === undefined && clean === base) return { targetKey: base, displayPath: base };
    const root = (opts.cwd ?? cwd).replaceAll('\\', '/').replace(/\/$/u, '');
    return { targetKey: `${root}/${clean}`, displayPath: name };
  };
  const fsP = await import('node:fs/promises');
  apply({
    tools: { register(def) { tools.set(def.name, def); } },
    effect() {},
    emit() {},
    workingDirectory: { async ensure() { return cwd; } },
    sandboxPolicy: { resolve() { return { mode: 'workspace-write' }; } },
    fs: {
      async resolve(name, opts) { return resolveTarget(name, opts); },
      contains(a, b) { return b.targetKey.startsWith(a.targetKey); },
      async lstat(name, opts) {
        const rel = resolveTarget(name, opts).targetKey.slice(base.length + 1);
        try { const st = await fsP.lstat(join(cwd, rel)); return { type: st.isDirectory() ? 'directory' : 'file' }; } catch { return undefined; }
      },
      async stat(target) {
        const rel = target.targetKey.slice(base.length + 1);
        try { const st = await fsP.stat(join(cwd, rel)); return { type: st.isDirectory() ? 'directory' : 'file', size: st.size, version: String(st.mtimeMs) }; } catch { return null; }
      },
      async readBytes(target) { return readFile(join(cwd, target.targetKey.slice(base.length + 1))); },
      async writeText(target, txt) { await writeFile(join(cwd, target.targetKey.slice(base.length + 1)), txt); return { version: '2' }; },
    },
  }, { enableExtendedAudit: true });
  const execution = { signal: new AbortController().signal, agent: { session: { id: 'live-gdb', header: { cwd } } } };

  // Directly verify gdb_driver persistent session via container on Linux/Windows
  const gStart = JSON.parse(await tools.get('gdb_driver').execute({ action: 'session_start', file_path: 'chall' }, execution));
  assert.equal(gStart.status, 'started', JSON.stringify(gStart));
  const gCmd = JSON.parse(await tools.get('gdb_driver').execute({
    action: 'session_cmd',
    session_id: gStart.session_id,
    commands: ['break check_flag', 'run', 'info registers', 'bt 2'],
  }, execution));
  assert.equal(gCmd.status, 'ok', JSON.stringify(gCmd));
  assert.ok(gCmd.results.some(r => /check_flag|Breakpoint/iu.test(r.output)));
  const gClose = JSON.parse(await tools.get('gdb_driver').execute({ action: 'session_close', session_id: gStart.session_id }, execution));
  assert.equal(gClose.status, 'closed');

  // 5) Heavy image: Ghidra 11.3.1 cache + mobile_apk signature bridge
  if (hasDockerImage('dsh-ctf-sandbox:heavy')) {
    const gh1 = await runSandbox({
      action: 'decompile',
      backend: 'docker',
      profile: 'heavy',
      file_path: 'chall',
      function: 'check_flag',
      timeout_ms: 90000,
    }, { cwd, config: {}, writable: true });
    assert.equal(gh1.status, 'ok', JSON.stringify(gh1));
    assert.equal(gh1.engine, 'ghidra');

    const gh2 = await runSandbox({
      action: 'decompile',
      backend: 'docker',
      profile: 'heavy',
      file_path: 'chall',
      function: 'main',
      timeout_ms: 90000,
    }, { cwd, config: {}, writable: true });
    assert.equal(gh2.status, 'ok', JSON.stringify(gh2));
    assert.equal(gh2.cached_project, true);

    await writeFile(join(cwd, 'sample.apk'), buildTinyApkBytes());
    const apkInfo = JSON.parse(await tools.get('mobile_apk').execute({
      file_path: 'sample.apk',
      action: 'info',
    }, execution));
    assert.equal(apkInfo.status, 'ok');
    assert.equal(apkInfo.has_manifest, true);
    const apkDec = JSON.parse(await tools.get('mobile_apk').execute({
      file_path: 'sample.apk',
      action: 'decompile',
      backend: 'docker',
      timeout_ms: 90000,
    }, execution));
    assert.equal(apkDec.status, 'ok', JSON.stringify(apkDec));
    assert.equal(apkDec.exit_code, 0, JSON.stringify(apkDec));
    assert.equal(apkDec.backend, 'docker');
    assert.equal(apkDec.tool, 'jadx');
    const outFiles = await readdir(join(cwd, '.apk-sample', 'sources', 'com', 'ctf'));
    assert.ok(outFiles.some(f => f.endsWith('.java')), `expected decompiled .java files, got ${outFiles.join(', ')}`);
    const apkSig = JSON.parse(await tools.get('mobile_apk').execute({
      file_path: 'sample.apk',
      action: 'signature',
      backend: 'docker',
    }, execution));
    assert.ok(['ok', 'failed'].includes(apkSig.status), JSON.stringify(apkSig));
    assert.equal(apkSig.backend, 'docker');
    assert.ok(['apksigner', 'jarsigner', 'keytool'].includes(apkSig.tool));
    const apkBad = JSON.parse(await tools.get('mobile_apk').execute({
      file_path: 'sample.apk',
      action: 'unknown_op',
    }, execution));
    assert.equal(apkBad.ok, false);
    assert.equal(apkBad.error.kind, 'unsupported');
    const zipInfo = JSON.parse(await tools.get('archive_crack').execute({
      file_path: 'sample.apk',
      action: 'info',
    }, execution));
    assert.equal(zipInfo.status, 'ok');
    assert.equal(zipInfo.encrypted_count, 0);
  }
});
