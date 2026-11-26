import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmod, lstat as fsLstat, mkdir, mkdtemp, open, readFile, rm, stat as fsStat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import test from 'node:test';
import { apply } from '../ctf-tools.js';
import {
  analyzeSandboxNeed,
  buildDockerArgs,
  chooseWslDistro,
  clearSandboxCache,
  DECOMPILE_SCRIPT,
  detectSandbox,
  parseWslList,
  resolveConfiguredImages,
  resolveExecutionPlan,
  runSandboxCommand,
  runSandbox,
} from '../sandbox-runner.js';
import { quoteGdbInputPath } from '../extra-tools.js';

function tinyStaticElf64({ withSections = true } = {}) {
  if (!withSections) {
    const buf = Buffer.alloc(0x90, 0x90);
    buf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
    buf.fill(0, 8, 16);
    buf.writeUInt16LE(2, 16); // ET_EXEC
    buf.writeUInt16LE(62, 18); // EM_X86_64
    buf.writeUInt32LE(1, 20);
    buf.writeBigUInt64LE(0x400078n, 24);
    buf.writeBigUInt64LE(0x40n, 32);
    buf.writeBigUInt64LE(0n, 40);
    buf.writeUInt32LE(0, 48);
    buf.writeUInt16LE(64, 52);
    buf.writeUInt16LE(56, 54);
    buf.writeUInt16LE(1, 56);
    buf.writeUInt16LE(64, 58);
    buf.writeUInt32LE(1, 64);
    buf.writeUInt32LE(5, 68);
    buf.writeBigUInt64LE(0n, 72);
    buf.writeBigUInt64LE(0x400000n, 80);
    buf.writeBigUInt64LE(0x400000n, 88);
    buf.writeBigUInt64LE(0x90n, 96);
    buf.writeBigUInt64LE(0x90n, 104);
    buf.writeBigUInt64LE(0x1000n, 112);
    Buffer.from('48c7c03c0000004831ff0f05', 'hex').copy(buf, 0x78);
    return buf;
  }
  const shstrtab = Buffer.from('\0.text\0.shstrtab\0', 'ascii');
  const codeOff = 0x78;
  const codeLen = 0x18;
  const shstrOff = 0x90;
  const shoff = 0xa8;
  const buf = Buffer.alloc(shoff + 3 * 64);
  buf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  buf.writeUInt16LE(2, 16); // ET_EXEC
  buf.writeUInt16LE(62, 18); // EM_X86_64
  buf.writeUInt32LE(1, 20);
  buf.writeBigUInt64LE(0x400078n, 24);
  buf.writeBigUInt64LE(0x40n, 32);
  buf.writeBigUInt64LE(BigInt(shoff), 40);
  buf.writeUInt16LE(64, 52);
  buf.writeUInt16LE(56, 54);
  buf.writeUInt16LE(1, 56);
  buf.writeUInt16LE(64, 58);
  buf.writeUInt16LE(3, 60);
  buf.writeUInt16LE(2, 62); // shstrndx
  // PT_LOAD
  buf.writeUInt32LE(1, 64);
  buf.writeUInt32LE(5, 68);
  buf.writeBigUInt64LE(0n, 72);
  buf.writeBigUInt64LE(0x400000n, 80);
  buf.writeBigUInt64LE(0x400000n, 88);
  buf.writeBigUInt64LE(BigInt(shstrOff), 96);
  buf.writeBigUInt64LE(BigInt(shstrOff), 104);
  buf.writeBigUInt64LE(0x1000n, 112);
  buf.fill(0x90, codeOff, codeOff + codeLen);
  Buffer.from('48c7c03c0000004831ff0f05', 'hex').copy(buf, codeOff);
  shstrtab.copy(buf, shstrOff);
  const writeSh64 = (idx, nameOff, type, flags, addr, off, size) => {
    const p = shoff + idx * 64;
    buf.writeUInt32LE(nameOff, p);
    buf.writeUInt32LE(type, p + 4);
    buf.writeBigUInt64LE(BigInt(flags), p + 8);
    buf.writeBigUInt64LE(BigInt(addr), p + 16);
    buf.writeBigUInt64LE(BigInt(off), p + 24);
    buf.writeBigUInt64LE(BigInt(size), p + 32);
  };
  writeSh64(1, 1, 1, 0x6, 0x400078, codeOff, codeLen); // .text
  writeSh64(2, 7, 3, 0, 0, shstrOff, shstrtab.length); // .shstrtab
  return buf;
}

function realDirContext(cwd, config = {}, writable = true) {
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
    },
  };
  apply(ctx, config);
  const execution = { signal: new AbortController().signal, agent: { session: { header: { cwd }, id: 'sandbox-test' } } };
  return { tools, execution };
}

test('parseWslList 正确解析 UTF-16LE 与 UTF-8 输出，chooseWslDistro 自动跳过 docker-desktop', () => {
  const utf16 = Buffer.from('\uFEFFdocker-desktop\r\ndocker-desktop-data\r\nUbuntu-22.04\r\n', 'utf16le');
  assert.deepEqual(parseWslList(utf16), ['docker-desktop', 'docker-desktop-data', 'Ubuntu-22.04']);
  assert.deepEqual(parseWslList(Buffer.from('Ubuntu-24.04\nKali\n', 'utf8')), ['Ubuntu-24.04', 'Kali']);
  assert.deepEqual(parseWslList(Buffer.alloc(0)), []);

  assert.equal(chooseWslDistro(['docker-desktop', 'docker-desktop-data', 'Ubuntu-22.04']), 'Ubuntu-22.04');
  assert.equal(chooseWslDistro(['Ubuntu-22.04', 'Debian'], 'debian'), 'Debian');
  assert.equal(chooseWslDistro(['docker-desktop']), undefined);
});

test('docker/Dockerfile 与 docker/Dockerfile.heavy 双层镜像定义完整且包含关键安全工具链', async () => {
  const baseDf = await readFile(new URL('../docker/Dockerfile', import.meta.url), 'utf8');
  const reqBase = await readFile(new URL('../docker/requirements-base.txt', import.meta.url), 'utf8');
  const baseSpec = `${baseDf}\n${reqBase}`;
  const heavyDf = await readFile(new URL('../docker/Dockerfile.heavy', import.meta.url), 'utf8');
  for (const token of ['ARG UBUNTU_BASE_IMAGE=ubuntu:24.04', 'FROM ${UBUNTU_BASE_IMAGE}', 'libc6:i386', 'qemu-user', 'gdb-multiarch', 'python3-fpylll', 'pwntools', 'volatility3', 'zsteg', '/opt/gef/gef.py', 'radare2', 'cpio', 'wabt', 'sleuthkit', 'pillow', 'numpy', 'scipy', 'scapy', 'xdis', 'WORKDIR /work']) {
    assert.ok(baseSpec.includes(token), `Dockerfile + requirements-base.txt should include ${token}`);
  }
  for (const token of ['ARG BASE_IMAGE=dsh-ctf-sandbox:latest', 'FROM ${BASE_IMAGE}', 'WITH_GHIDRA', 'WITH_ANGR', 'WITH_APK', 'WITH_SAGE', 'GHIDRA_HOME=/opt/ghidra', 'analyzeHeadless', 'jadx', 'apktool', 'WORKDIR /work']) {
    assert.ok(heavyDf.includes(token), `Dockerfile.heavy should include ${token}`);
  }
});

test('双层镜像自动识别与执行计划路由（base/heavy 自动升降级与降级回退）', async () => {
  assert.deepEqual(resolveConfiguredImages({}), {
    baseImage: 'dsh-ctf-sandbox:latest',
    heavyImage: 'dsh-ctf-sandbox:heavy',
  });
  assert.deepEqual(resolveConfiguredImages({ sandboxImage: 'myreg/ctf:latest' }), {
    baseImage: 'myreg/ctf:latest',
    heavyImage: 'myreg/ctf:heavy',
  });
  assert.deepEqual(resolveConfiguredImages({ sandboxImage: 'custom/pinned:v1' }), {
    baseImage: 'custom/pinned:v1',
    heavyImage: 'custom/pinned:v1',
  });
  assert.deepEqual(resolveConfiguredImages({ sandboxImage: 'custom/base:1', sandboxHeavyImage: 'custom/heavy:2' }), {
    baseImage: 'custom/base:1',
    heavyImage: 'custom/heavy:2',
  });

  const angrScript = analyzeSandboxNeed(
    { action: 'exec', script_path: 'solve.py' },
    { scriptPreview: 'import angr\nproj = angr.Project("./chall")\n' },
  );
  assert.equal(angrScript.preferDocker, true);
  assert.equal(angrScript.preferHeavy, true);
  assert.ok(angrScript.heavyReasons.includes('heavy_script_import'));

  const pwnScript = analyzeSandboxNeed(
    { action: 'exec', script_path: 'exp.py' },
    { scriptPreview: 'from pwn import *\n' },
  );
  assert.equal(pwnScript.preferDocker, true);
  assert.equal(pwnScript.preferHeavy, false);

  assert.equal(analyzeSandboxNeed({ action: 'exec', command: 'jadx -d out app.apk' }).preferHeavy, true);
  assert.equal(analyzeSandboxNeed({ action: 'exec', command: 'analyzeHeadless /tmp proj -import a.bin' }).preferHeavy, true);
  assert.equal(analyzeSandboxNeed({ action: 'exec', script_path: 'lattice.sage' }).preferHeavy, true);
  assert.equal(analyzeSandboxNeed({ action: 'decompile', file_path: 'chall', profile: 'heavy' }).preferHeavy, true);
  assert.equal(analyzeSandboxNeed({ action: 'decompile', file_path: 'chall' }).preferHeavy, false);

  const bothReady = {
    available: true,
    backend: 'docker',
    image: 'dsh-ctf-sandbox:latest',
    docker: {
      available: true,
      base: { image: 'dsh-ctf-sandbox:latest', available: true },
      heavy: { image: 'dsh-ctf-sandbox:heavy', available: true },
    },
  };
  const planBase = resolveExecutionPlan(bothReady, pwnScript, 'auto');
  assert.equal(planBase.profile, 'base');
  assert.equal(planBase.image, 'dsh-ctf-sandbox:latest');
  assert.equal(planBase.autoUpgraded, false);

  const planAutoHeavy = resolveExecutionPlan(bothReady, angrScript, 'auto');
  assert.equal(planAutoHeavy.profile, 'heavy');
  assert.equal(planAutoHeavy.image, 'dsh-ctf-sandbox:heavy');
  assert.equal(planAutoHeavy.autoUpgraded, true);
  assert.ok(planAutoHeavy.upgradeReasons.includes('heavy_script_import'));

  const planPinnedBase = resolveExecutionPlan(bothReady, angrScript, 'base');
  assert.equal(planPinnedBase.profile, 'base');
  assert.equal(planPinnedBase.image, 'dsh-ctf-sandbox:latest');

  const planExplicitHeavy = resolveExecutionPlan(bothReady, { preferHeavy: false, heavyReasons: [] }, 'heavy');
  assert.equal(planExplicitHeavy.profile, 'heavy');
  assert.equal(planExplicitHeavy.image, 'dsh-ctf-sandbox:heavy');
  assert.equal(planExplicitHeavy.autoUpgraded, false);
  assert.deepEqual(planExplicitHeavy.upgradeReasons, ['explicit_heavy']);

  const baseOnly = {
    available: true,
    backend: 'docker',
    image: 'dsh-ctf-sandbox:latest',
    docker: {
      available: true,
      base: { image: 'dsh-ctf-sandbox:latest', available: true },
      heavy: { image: 'dsh-ctf-sandbox:heavy', available: false },
    },
  };
  const planFallback = resolveExecutionPlan(baseOnly, angrScript, 'auto');
  assert.equal(planFallback.profile, 'base');
  assert.equal(planFallback.image, 'dsh-ctf-sandbox:latest');
  assert.match(planFallback.profileFallbackReason ?? '', /Dockerfile\.heavy/u);

  const heavyOnly = {
    available: true,
    backend: 'docker',
    image: 'dsh-ctf-sandbox:heavy',
    docker: {
      available: true,
      base: { image: 'dsh-ctf-sandbox:latest', available: false },
      heavy: { image: 'dsh-ctf-sandbox:heavy', available: true },
    },
  };
  const planHeavyOnly = resolveExecutionPlan(heavyOnly, pwnScript, 'auto');
  assert.equal(planHeavyOnly.profile, 'heavy');
  assert.equal(planHeavyOnly.image, 'dsh-ctf-sandbox:heavy');
  assert.equal(planHeavyOnly.autoUpgraded, true);
  assert.deepEqual(planHeavyOnly.upgradeReasons, ['heavy_only_available']);

  const wslOnly = {
    available: true,
    backend: 'wsl',
    distro: 'Ubuntu-22.04',
    docker: {
      available: false,
      base: { image: 'dsh-ctf-sandbox:latest', available: false },
      heavy: { image: 'dsh-ctf-sandbox:heavy', available: false },
    },
  };
  const planWslHeavy = resolveExecutionPlan(wslOnly, angrScript, 'auto');
  assert.equal(planWslHeavy.profile, 'wsl');
  assert.match(planWslHeavy.profileFallbackReason ?? '', /dsh-ctf-sandbox:heavy/u);

  await assert.rejects(
    runSandbox({ action: 'status', profile: 'turbo' }, { cwd: process.cwd(), writable: true, config: {} }),
    error => error.kind === 'unsupported',
  );
});

test('ctf_sandbox 智能需求识别、探测缓存、单次 backend 强制隔离与只读会话拦截', async () => {
  clearSandboxCache();
  assert.equal(analyzeSandboxNeed({ action: 'pwn_triage' }).preferDocker, true);
  assert.equal(analyzeSandboxNeed({ action: 'exec', command: 'ROPgadget --binary chall' }).preferDocker, true);
  assert.equal(analyzeSandboxNeed({ action: 'exec', command: 'wasm2wat app.wasm -o app.wat' }).preferDocker, true);
  assert.equal(analyzeSandboxNeed({ action: 'exec', command: 'fls -r disk.img' }).preferDocker, true);
  assert.equal(analyzeSandboxNeed({ action: 'exec', script_path: 'solve.py' }).preferDocker, true);
  assert.equal(analyzeSandboxNeed({ action: 'exec', script_path: 'chall' }).preferDocker, true);
  assert.equal(analyzeSandboxNeed({ action: 'exec', command: 'ls -la' }).preferDocker, false);

  const cfg = { sandboxBackend: 'docker', sandboxImage: 'dsh-nonexistent-image-xyz:999' };
  const missingDocker = await detectSandbox(cfg);
  assert.equal(missingDocker.available, false);
  assert.equal(missingDocker.backend, 'unavailable');
  assert.equal(missingDocker.cached, undefined);

  const cachedProbe = await detectSandbox(cfg);
  assert.equal(cachedProbe.cached, true);
  assert.equal(cachedProbe.backend, 'unavailable');

  const freshProbe = await detectSandbox(cfg, undefined, { fresh: true });
  assert.equal(freshProbe.cached, undefined);

  await assert.rejects(
    runSandbox({ action: 'exec', command: 'id', backend: 'invalid' }, { cwd: process.cwd(), writable: true, config: cfg }),
    error => error.kind === 'unsupported',
  );
  // 显式传 backend: 'docker' 在镜像缺失时拒绝静默降级至 WSL2
  await assert.rejects(
    runSandbox({ action: 'exec', command: 'id', backend: 'docker' }, {
      cwd: process.cwd(), writable: true, config: { sandboxBackend: 'auto', sandboxImage: 'dsh-nonexistent-image-xyz:999' },
    }),
    error => error.kind === 'dependency',
  );

  await assert.rejects(
    runSandbox({ action: 'exec', command: 'id' }, { cwd: process.cwd(), writable: false, config: cfg }),
    error => error.kind === 'permission',
  );
  await assert.rejects(
    runSandbox({ action: 'exec' }, { cwd: process.cwd(), writable: true, config: cfg }),
    error => error.kind === 'unsupported',
  );
  await assert.rejects(
    runSandbox({ action: 'decompile', file_path: 'a.bin', function: 'main;id' }, {
      cwd: process.cwd(), writable: true,
      config: cfg,
      checkWorkspaceFile: async rel => rel,
    }),
    error => error.kind === 'unsupported',
  );
});

test('auto 不会把要求隔离的命令静默交给 WSL2', async t => {
  const detected = await detectSandbox({ sandboxBackend: 'auto' }, undefined, { fresh: true });
  if (!detected.available || detected.backend !== 'wsl') {
    t.skip('需要真实探测到 WSL2 且 Docker 隔离后端不可用');
    return;
  }
  const workDir = await mkdtemp(join(tmpdir(), 'ctf-auto-isolation-'));
  try {
    await assert.rejects(runSandboxCommand(['sh', '-c', 'touch isolation-breach'], {
      cwd: workDir,
      config: { sandboxBackend: 'auto' },
      detected,
      requiresIsolation: true,
    }), error => error.kind === 'dependency' && /无法满足此任务的隔离要求/u.test(error.message));
    await assert.rejects(fsStat(join(workDir, 'isolation-breach')));
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
});

/**
 * 找到一个真正能跑的 POSIX shell。Windows 上优先 Git Bash（GitHub runner 自带），
 * 其次才是装了发行版的 WSL；两者都没有时返回 null，由调用方 skip —— 直接调
 * `wsl.exe --exec sh` 在没有发行版的机器上会报错，那是环境缺失而不是被测逻辑出错。
 */
function probePosixShell(binary, prefix) {
  try {
    execFileSync(binary, [...prefix, '-c', 'true'], { stdio: 'ignore', timeout: 3000 });
    return true;
  } catch {
    return false;
  }
}

function findPosixShell() {
  if (process.platform !== 'win32') return { binary: '/bin/sh', prefix: [] };
  const candidates = [];
  try {
    const found = execFileSync('where', ['bash'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    for (const line of found.split(/\r?\n/u).map(s => s.trim()).filter(Boolean)) {
      candidates.push(line);
    }
  } catch {
    // where bash failed; fall through to known Git Bash locations
  }
  for (const fallback of ['D:/Git/bin/bash.exe', 'C:/Program Files/Git/bin/bash.exe', 'C:/Program Files (x86)/Git/bin/bash.exe']) {
    if (!candidates.some(item => item.toLowerCase() === fallback.toLowerCase())) {
      candidates.push(fallback);
    }
  }
  for (const candidate of candidates) {
    if (probePosixShell(candidate, [])) return { binary: candidate, prefix: [] };
  }
  try {
    const listed = execFileSync('wsl.exe', ['-l', '-q'], {
      encoding: 'buffer',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    const distros = parseWslList(listed);
    const chosen = chooseWslDistro(distros);
    if (chosen && probePosixShell('wsl.exe', ['-d', chosen, '--exec', 'sh'])) {
      return { binary: 'wsl.exe', prefix: ['-d', chosen, '--exec', 'sh'] };
    }
  } catch {
    // 没有 WSL 或没有可用发行版。
  }
  return null;
}

test('GDB stdin 路径在真实 POSIX shell 中不会执行 $(...) 文件名载荷', async t => {
  const target = quoteGdbInputPath('./input$(touch pwned)', true);
  const command = `set -eu; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT; cd "$tmp"; printf fixture > ${target}; cat < ${target} >/dev/null; test ! -e pwned`;
  const shell = findPosixShell();
  if (!shell) {
    t.skip('当前宿主没有可用的 POSIX shell（Windows 需要 Git Bash 或已安装发行版的 WSL）');
    return;
  }
  execFileSync(shell.binary, [...shell.prefix, '-c', command], { stdio: 'pipe' });
});

test('WSL2/Linux 沙箱集成测试：status、中文路径 exec、decompile、pwn_triage 与 gdb_driver 自动桥接 Linux ELF', async t => {
  const detected = await detectSandbox({ sandboxBackend: 'auto' });
  if (!detected.available) {
    t.skip('当前宿主未检测到可用的 Docker 镜像或 WSL2 发行版');
    return;
  }

  const baseDir = await mkdtemp(join(tmpdir(), 'ctf-sandbox-'));
  const cwd = join(baseDir, '测试中文目录');
  await mkdir(cwd, { recursive: true });
  try {
    await writeFile(join(cwd, 'tiny_elf'), tinyStaticElf64({ withSections: true }));
    await writeFile(join(cwd, 'sectionless_elf'), tinyStaticElf64({ withSections: false }));
    await writeFile(join(cwd, 'hello.py'), 'print("sandbox-py-ok:" + str(21 * 2))\n', 'utf8');
    await writeFile(join(cwd, 'angr_probe.py'), 'try:\n  import angr\n  print("has-angr")\nexcept ImportError:\n  print("no-angr-graceful")\n', 'utf8');
    await writeFile(join(cwd, 'crlf.sh'), Buffer.from('#!/bin/bash\r\nif true; then\r\n  printf "crlf-script-ok\\n"\r\nelse\r\n  exit 7\r\nfi\r\n', 'utf8'));

    const sandboxBackend = detected.backend === 'wsl' ? 'wsl' : 'auto';
    const { tools, execution } = realDirContext(cwd, { sandboxBackend }, true);

    const status = JSON.parse(await tools.get('ctf_sandbox').execute({ action: 'status' }, execution));
    assert.equal(status.status, 'ok', JSON.stringify(status));
    assert.ok(['docker', 'wsl'].includes(status.backend));
    assert.ok(['base', 'heavy', 'wsl'].includes(status.probed_profile));
    assert.equal(typeof status.profiles?.base?.image, 'string');
    assert.equal(typeof status.profiles?.heavy?.image, 'string');
    assert.equal(status.environment.tools.python3, true);
    assert.equal(status.environment.tools.readelf, true);

    const execCmd = JSON.parse(await tools.get('ctf_sandbox').execute({
      action: 'exec', command: 'ls -1 && echo ctf-ok',
    }, execution));
    assert.equal(execCmd.status, 'ok', JSON.stringify(execCmd));
    assert.match(execCmd.stdout, /tiny_elf/u);
    assert.match(execCmd.stdout, /ctf-ok/u);

    const execPy = JSON.parse(await tools.get('ctf_sandbox').execute({
      action: 'exec', script_path: 'hello.py',
    }, execution));
    assert.equal(execPy.status, 'ok', JSON.stringify(execPy));
    assert.match(execPy.stdout, /sandbox-py-ok:42/u);
    if (execPy.backend === 'wsl') {
      assert.equal(execPy.network, 'host_shared_wsl');
    }

    const execCrlf = JSON.parse(await tools.get('ctf_sandbox').execute({
      action: 'exec', script_path: 'crlf.sh',
    }, execution));
    assert.equal(execCrlf.status, 'ok', JSON.stringify(execCrlf));
    assert.match(execCrlf.stdout, /crlf-script-ok/u);

    const execHeavyProbe = JSON.parse(await tools.get('ctf_sandbox').execute({
      action: 'exec', script_path: 'angr_probe.py',
    }, execution));
    assert.equal(execHeavyProbe.status, 'ok', JSON.stringify(execHeavyProbe));
    assert.match(execHeavyProbe.stdout, /has-angr|no-angr-graceful/u);
    if (execHeavyProbe.profile === 'heavy') {
      assert.equal(execHeavyProbe.auto_upgraded, true);
      assert.ok(execHeavyProbe.upgrade_reasons.includes('heavy_script_import'));
    } else {
      assert.match(execHeavyProbe.profile_fallback_reason ?? '', /dsh-ctf-sandbox:heavy/u);
    }

    const decomp = JSON.parse(await tools.get('ctf_sandbox').execute({
      action: 'decompile', file_path: 'tiny_elf', function: '0x400078',
    }, execution));
    assert.equal(decomp.status, 'ok', JSON.stringify(decomp));
    assert.match(decomp.pseudocode || decomp.disassembly, /syscall|0x3c/iu);

    const decompRaw = JSON.parse(await tools.get('ctf_sandbox').execute({
      action: 'decompile', file_path: 'sectionless_elf', function: '0x400078',
    }, execution));
    assert.equal(decompRaw.status, 'ok', JSON.stringify(decompRaw));
    assert.match(decompRaw.pseudocode || decompRaw.disassembly, /syscall|0x3c/iu);

    const triage = JSON.parse(await tools.get('ctf_sandbox').execute({
      action: 'pwn_triage', file_path: 'tiny_elf',
    }, execution));
    assert.equal(triage.status, 'ok', JSON.stringify(triage));
    assert.match(triage.file ?? '', /ELF 64-bit/u);

    // gdb_driver 只读白名单拒绝危险命令
    for (const badCmd of ['shell id', 'python import os', 'p $rax = 0', 'call exit(0)', 'b *0x400078; shell id']) {
      const blocked = JSON.parse(await tools.get('gdb_driver').execute({
        file_path: 'tiny_elf', action: 'debug', commands: [badCmd],
      }, execution));
      assert.equal(blocked.ok, false, `expected reject for ${badCmd}`);
      assert.equal(blocked.error.kind, 'unsupported');
    }

    if (status.environment.tools.gdb) {
      const inspected = JSON.parse(await tools.get('gdb_driver').execute({
        file_path: 'tiny_elf', action: 'inspect', kind: 'files',
      }, execution));
      assert.equal(inspected.status, 'ok', JSON.stringify(inspected));
      assert.match(inspected.stdout, /0x400078/iu);

      const debugged = JSON.parse(await tools.get('gdb_driver').execute({
        file_path: 'tiny_elf',
        action: 'debug',
        args: ['arg1', 'hello world'],
        commands: ['b *0x400078', 'run', 'x/4gx $rsp', 'p/x $rip-0x400078', 'si', 'i r rax rdi', 'c'],
      }, execution));
      assert.equal(debugged.status, 'ok', JSON.stringify(debugged));
      assert.match(debugged.stdout, /Breakpoint 1/u);
      assert.match(debugged.stdout, /\$1 = 0x0/u);
      assert.match(debugged.stdout, /0x3c/iu);
      if (process.platform === 'win32') {
        assert.ok(['wsl', 'docker'].includes(debugged.backend));
      }
    }
  } finally {
    await rm(baseDir, { recursive: true, force: true, maxRetries: 8, retryDelay: 120 });
  }
});

test('DECOMPILE_SCRIPT：r2 单次进程分析回退 pdc，Ghidra 按二进制 SHA-256 持久化缓存并命中复读', async () => {
  const python = process.platform === 'win32' ? 'python' : 'python3';
  const workDir = await mkdtemp(join(tmpdir(), 'ctf-decomp-cache-'));
  const binDir = join(workDir, 'fakebin');
  const ghidraDir = join(workDir, 'fakeghidra');
  await mkdir(binDir, { recursive: true });
  await mkdir(ghidraDir, { recursive: true });
  try {
    const samplePath = join(workDir, 'sample.bin');
    await writeFile(samplePath, Buffer.from('FAKE_ELF_V1'));

    // 1) Mock r2：验证单次调用合并 pdg/pdc/pdf/axt，pdg 不可用时平滑回退 pdc
    const r2Log = join(workDir, 'r2-calls.log');
    const r2Py = join(binDir, 'fake_r2.py');
    await writeFile(r2Py, [
      'import os, sys',
      `with open(${JSON.stringify(r2Log)}, "a", encoding="utf-8") as fh:`,
      '    fh.write(" ".join(sys.argv[1:]) + "\\n")',
      'print("__DSH_R2_PDG__")',
      'print("Cannot find function")',
      'print("__DSH_R2_PDC__")',
      'print("int main(void) { return 42; }")',
      'print("__DSH_R2_ASM__")',
      'print("0x401000: mov eax, 42\\n0x401005: ret")',
    ].join('\n'), 'utf8');
    if (process.platform === 'win32') {
      await writeFile(join(binDir, 'r2.cmd'), `@echo off\r\n"${python}" "${r2Py}" %*\r\n`, 'utf8');
    } else {
      const r2Sh = join(binDir, 'r2');
      await writeFile(r2Sh, `#!/bin/sh\nexec "${python}" "${r2Py}" "$@"\n`, 'utf8');
      await chmod(r2Sh, 0o755);
    }

    const r2Out = execFileSync(python, ['-c', DECOMPILE_SCRIPT, 'sample.bin', 'main', 'auto'], {
      cwd: workDir,
      encoding: 'utf8',
      env: { ...process.env, PATH: binDir + delimiter + (process.env.PATH ?? '') },
    });
    const r2Json = JSON.parse(r2Out.trim());
    assert.equal(r2Json.engine, 'radare2');
    assert.equal(r2Json.pseudocode, 'int main(void) { return 42; }');
    assert.match(r2Json.disassembly, /mov eax, 42/u);
    const r2Calls = (await readFile(r2Log, 'utf8')).trim().split(/\r?\n/u);
    assert.equal(r2Calls.length, 1, 'r2 function decompile should invoke r2 only once');

    // r2 非零退出和空成功结果都必须被报告为失败，不能交给外层包装成 status: ok。
    const badR2Dir = join(workDir, 'bad-r2-bin');
    await mkdir(badR2Dir, { recursive: true });
    const badR2Py = join(badR2Dir, 'bad_r2.py');
    await writeFile(badR2Py, 'import os, sys\nprint("synthetic r2 failure", file=sys.stderr)\nsys.exit(int(os.environ.get("FAKE_R2_EXIT", "0")))\n', 'utf8');
    if (process.platform === 'win32') {
      await writeFile(join(badR2Dir, 'r2.cmd'), `@echo off\r\n"${python}" "${badR2Py}" %*\r\n`, 'utf8');
    } else {
      const badR2Sh = join(badR2Dir, 'r2');
      await writeFile(badR2Sh, `#!/bin/sh\nexec "${python}" "${badR2Py}" "$@"\n`, 'utf8');
      await chmod(badR2Sh, 0o755);
    }
    const failedR2 = JSON.parse(execFileSync(python, ['-c', DECOMPILE_SCRIPT, 'sample.bin', 'main', 'auto'], {
      cwd: workDir, encoding: 'utf8',
      env: { ...process.env, PATH: badR2Dir + delimiter + (process.env.PATH ?? ''), FAKE_R2_EXIT: '7' },
    }).trim());
    assert.match(failedR2.error, /退出码 7/u);
    const emptyR2 = JSON.parse(execFileSync(python, ['-c', DECOMPILE_SCRIPT, 'sample.bin', 'main', 'auto'], {
      cwd: workDir, encoding: 'utf8',
      env: { ...process.env, PATH: badR2Dir + delimiter + (process.env.PATH ?? ''), FAKE_R2_EXIT: '0' },
    }).trim());
    assert.match(emptyR2.error, /没有返回伪代码或反汇编/u);

    // 2) Mock analyzeHeadless：验证首次 -import 建缓存、二次 -process -noanalysis -readOnly 命中缓存、文件改动后失效重建
    const ghLog = join(workDir, 'ghidra-calls.log');
    const ghPy = join(ghidraDir, 'fake_ghidra.py');
    await writeFile(ghPy, [
      'import json, os, sys',
      `with open(${JSON.stringify(ghLog)}, "a", encoding="utf-8") as fh:`,
      '    fh.write(json.dumps(sys.argv[1:]) + "\\n")',
      'proj_dir = sys.argv[1]',
      'if "-import" in sys.argv:',
      '    open(os.path.join(proj_dir, "proj.gpr"), "w").write("gpr")',
      '    os.makedirs(os.path.join(proj_dir, "proj.rep"), exist_ok=True)',
      'target = os.environ.get("DSH_TARGET") or ""',
      'pseudocode = "" if os.environ.get("FAKE_GHIDRA_EMPTY") == "1" else "void check() {}"',
      'res = {"engine": "ghidra", "mode": "function" if target else "list", "program_name": "sample.bin", "target": target, "pseudocode": pseudocode, "disassembly": ""}',
      'with open(os.environ["DSH_OUT"], "w", encoding="utf-8") as fh:',
      '    fh.write(json.dumps(res))',
      'if os.environ.get("FAKE_GHIDRA_EXIT"): sys.exit(int(os.environ["FAKE_GHIDRA_EXIT"]))',
    ].join('\n'), 'utf8');
    if (process.platform === 'win32') {
      await writeFile(join(ghidraDir, 'analyzeHeadless.cmd'), `@echo off\r\n"${python}" "${ghPy}" %*\r\n`, 'utf8');
    } else {
      const ghSh = join(ghidraDir, 'analyzeHeadless');
      await writeFile(ghSh, `#!/bin/sh\nexec "${python}" "${ghPy}" "$@"\n`, 'utf8');
      await chmod(ghSh, 0o755);
    }

    const ghEnv = { ...process.env, PATH: ghidraDir + delimiter + (process.env.PATH ?? '') };
    const first = JSON.parse(execFileSync(python, ['-c', DECOMPILE_SCRIPT, 'sample.bin', 'check', 'ghidra'], {
      cwd: workDir, encoding: 'utf8', env: ghEnv,
    }).trim());
    assert.equal(first.engine, 'ghidra', JSON.stringify(first));
    assert.equal(first.cached_project, false, JSON.stringify(first));
    assert.equal(first.program_name, undefined);

    const emptyGhidra = JSON.parse(execFileSync(python, ['-c', DECOMPILE_SCRIPT, 'sample.bin', 'check', 'ghidra'], {
      cwd: workDir, encoding: 'utf8', env: { ...ghEnv, FAKE_GHIDRA_EMPTY: '1' },
    }).trim());
    assert.match(emptyGhidra.fallback_warning, /没有伪代码或反汇编/u);
    const failedGhidra = JSON.parse(execFileSync(python, ['-c', DECOMPILE_SCRIPT, 'sample.bin', 'check', 'ghidra'], {
      cwd: workDir, encoding: 'utf8', env: { ...ghEnv, FAKE_GHIDRA_EXIT: '9' },
    }).trim());
    assert.match(failedGhidra.fallback_warning, /退出码 9/u);

    const second = JSON.parse(execFileSync(python, ['-c', DECOMPILE_SCRIPT, 'sample.bin', 'check', 'ghidra'], {
      cwd: workDir, encoding: 'utf8', env: ghEnv,
    }).trim());
    assert.equal(second.engine, 'ghidra', JSON.stringify(second));
    assert.equal(second.cached_project, true, JSON.stringify(second));

    await writeFile(samplePath, Buffer.from('FAKE_ELF_V2_MODIFIED'));
    const third = JSON.parse(execFileSync(python, ['-c', DECOMPILE_SCRIPT, 'sample.bin', 'check', 'ghidra'], {
      cwd: workDir, encoding: 'utf8', env: ghEnv,
    }).trim());
    assert.equal(third.engine, 'ghidra');
    assert.equal(third.cached_project, false);

    // 64 MiB 前缀相同而尾字节不同的真实大文件必须使用不同缓存键。
    const large = await open(samplePath, 'w');
    const largeSize = 64 * 1024 * 1024 + 1;
    try {
      await large.truncate(largeSize);
      await large.write(Buffer.from('A'), 0, 1, largeSize - 1);
    } finally { await large.close(); }
    const largeFirst = JSON.parse(execFileSync(python, ['-c', DECOMPILE_SCRIPT, 'sample.bin', 'check', 'ghidra'], {
      cwd: workDir, encoding: 'utf8', env: ghEnv,
    }).trim());
    assert.equal(largeFirst.cached_project, false);
    const tailEdit = await open(samplePath, 'r+');
    try { await tailEdit.write(Buffer.from('B'), 0, 1, largeSize - 1); }
    finally { await tailEdit.close(); }
    const largeSecond = JSON.parse(execFileSync(python, ['-c', DECOMPILE_SCRIPT, 'sample.bin', 'check', 'ghidra'], {
      cwd: workDir, encoding: 'utf8', env: ghEnv,
    }).trim());
    assert.equal(largeSecond.cached_project, false);

    // Execute the real worker with a caller deadline and pin the timeout contract.
    const deadlineRun = JSON.parse(execFileSync(python, ['-c', DECOMPILE_SCRIPT, 'sample.bin', 'check', 'ghidra', '2000'], {
      cwd: workDir, encoding: 'utf8', env: ghEnv,
    }).trim());
    assert.equal(deadlineRun.engine, 'ghidra');
    assert.match(DECOMPILE_SCRIPT, /headless_timeout = max\(1, int\(sys\.argv\[4\]\) \/\/ 1000 - 2\)/u);
    assert.match(DECOMPILE_SCRIPT, /timeout=headless_timeout/u);
    assert.doesNotMatch(DECOMPILE_SCRIPT, /timeout=90/u);

    assert.doesNotMatch(DECOMPILE_SCRIPT, /removeprefix\(/u);
    assert.match(DECOMPILE_SCRIPT, /def norm_addr\(raw\):.*s\.lstrip\('0'\) or '0'.*target_norm = norm_addr\((?:target|one)\)/su);

    const ghCalls = (await readFile(ghLog, 'utf8')).trim().split(/\r?\n/u).map(line => JSON.parse(line));
    assert.equal(ghCalls.length, 8);
    assert.ok(ghCalls[0].includes('-import'));
    assert.ok(!ghCalls[0].includes('-deleteProject'));
    assert.ok(ghCalls[1].includes('-process'));
    assert.ok(ghCalls[2].includes('-process'));
    assert.ok(ghCalls[3].includes('-process'));
    assert.ok(ghCalls[4].includes('-import'));
    assert.ok(ghCalls[5].includes('-import'));
    assert.ok(ghCalls[6].includes('-import'));
    assert.ok(ghCalls[7].includes('-process'));
    assert.ok(ghCalls[3].includes('-noanalysis'));
    assert.ok(ghCalls[3].includes('-readOnly'));

    // Windows runner 的 ANSI 代码页是 cp1252，脚本里的中文会让默认编码的 write() 抛
    // UnicodeEncodeError，上层当成 Ghidra 失败后静默回退 objdump。Linux 上把本地化
    // 降到 C 就能复现同一条路径，用来锁住「必须显式 UTF-8 写脚本」这个修复。
    if (process.platform !== 'win32') {
      // 脚本里有中文；直接把脚本经 `-c` 传给 C locale 的 python 会在 argv 解码阶段就失败，
      // 所以落成文件再执行，才能让「默认编码的 open()」成为唯一的失败点。
      const asciiScript = join(workDir, 'decompile_ascii.py');
      await writeFile(asciiScript, DECOMPILE_SCRIPT, 'utf8');
      let asciiText;
      try {
        asciiText = execFileSync(python, [asciiScript, 'sample.bin', 'check', 'ghidra'], {
          cwd: workDir,
          encoding: 'utf8',
          env: { ...ghEnv, PYTHONUTF8: '0', LC_ALL: 'C', LANG: 'C' },
        });
      } catch (error) {
        assert.fail(`ASCII locale 运行失败：${String(error.stderr ?? error.message).slice(-1200)}`);
      }
      const asciiLocale = JSON.parse(asciiText.trim());
      assert.equal(asciiLocale.engine, 'ghidra', JSON.stringify(asciiLocale));
    }
  } finally {
    await rm(workDir, { recursive: true, force: true, maxRetries: 8, retryDelay: 120 });
  }
});

test('buildDockerArgs 容器加固（cap-drop/no-new-privileges/只读挂载）与 Dockerfile 兵器库版本锁定', async () => {
  const baseArgs = buildDockerArgs(['id'], {
    cwd: '/tmp/ws',
    containerName: 'dsh-test-base',
    targetImage: 'dsh-ctf-sandbox:latest',
    readOnlyWork: true,
    network: 'none',
    ptrace: false,
    isHeavy: false,
  });
  assert.ok(baseArgs.includes('--cap-drop=ALL'));
  assert.ok(baseArgs.includes('--security-opt=no-new-privileges:true'));
  assert.equal(baseArgs[baseArgs.indexOf('--network') + 1], 'none');
  assert.ok(baseArgs.includes('/tmp/ws:/work:ro'));
  assert.ok(!baseArgs.includes('--cap-add=SYS_PTRACE'));
  assert.ok(baseArgs.includes('--memory=2g'));
  assert.ok(baseArgs.includes('--memory-swap=2g'), 'swap must be capped at the same limit as RAM');

  const heavyPwnArgs = buildDockerArgs(['gdb', '--version'], {
    cwd: '/tmp/ws',
    containerName: 'dsh-test-heavy',
    targetImage: 'dsh-ctf-sandbox:heavy',
    readOnlyWork: false,
    network: 'bridge',
    ptrace: true,
    isHeavy: true,
    egressProxyPort: 12345,
  });
  assert.ok(heavyPwnArgs.includes('--cap-drop=ALL'));
  assert.ok(heavyPwnArgs.includes('--cap-add=SYS_PTRACE'));
  assert.ok(heavyPwnArgs.includes('--cap-add=NET_ADMIN'));
  assert.ok(heavyPwnArgs.includes('--user=0:0'));
  assert.equal(heavyPwnArgs[heavyPwnArgs.indexOf('--network') + 1], 'bridge');
  assert.equal(heavyPwnArgs[heavyPwnArgs.indexOf('dsh-ctf-sandbox:heavy') + 1], '/usr/local/bin/dsh-ctf-bridge-entrypoint');
  assert.ok(heavyPwnArgs.includes('CTF_EGRESS_PROXY_PORT=12345'));
  assert.ok(heavyPwnArgs.includes('/tmp/ws:/work'));
  assert.ok(heavyPwnArgs.includes('--memory=4g'));
  assert.ok(heavyPwnArgs.includes('--memory-swap=4g'));
  assert.throws(
    () => buildDockerArgs(['id'], {
      cwd: '/tmp/ws', containerName: 'dsh-test-unfiltered', targetImage: 'dsh-ctf-sandbox:latest', network: 'bridge',
    }),
    error => error.kind === 'permission',
  );

  // 新增高频 CLI 识别
  for (const cmd of ['bkcrack -C a.zip -c f.txt -p plain', 'ffuf -u http://x/FUZZ', 'sqlmap -u http://x', 'john hash.txt', 'tesseract img.png stdout', 'pyinstxtractor-ng app.exe', 'pwninit']) {
    assert.equal(analyzeSandboxNeed({ action: 'exec', command: cmd }).preferDocker, true, `should route to sandbox: ${cmd}`);
  }

  // 非布尔 read_only_work 拒绝
  await assert.rejects(
    runSandbox({ action: 'exec', command: 'id', read_only_work: 'yes' }, { cwd: process.cwd(), writable: true, config: {} }),
    error => error.kind === 'unsupported',
  );

  // Dockerfile 版本锁定与新增工具校验
  const dockerfile = await readFile(new URL('../docker/Dockerfile', import.meta.url), 'utf8');
  const reqBase = await readFile(new URL('../docker/requirements-base.txt', import.meta.url), 'utf8');
  const dockerSpec = `${dockerfile}\n${reqBase}`;
  for (const token of [
    'ARG RADARE2_VERSION=', 'ARG GEF_VERSION=', 'ARG BKCRACK_VERSION=',
    'ARG FFUF_VERSION=', 'ARG PWNINIT_VERSION=',
    'tesseract-ocr', 'john', 'sqlmap', 'pyinstxtractor-ng', 'bkcrack', 'ffuf', 'pwninit',
  ]) {
    assert.ok(dockerSpec.includes(token), `docker/Dockerfile (+ requirements-base.txt) 应包含 ${token}`);
  }
  assert.match(dockerfile, /USER 10001:10001/u);
  assert.match(dockerfile, /ARG APT_MIRROR=/u);
  assert.match(dockerfile, /ARG GITHUB_BASE_URL=/u);
  assert.match(dockerfile, /ARG GITHUB_RAW_BASE_URL=/u);
  assert.match(dockerfile, /ARG RUBYGEMS_SOURCE_URL=/u);
  assert.doesNotMatch(dockerfile, /r2ghidra optional plugin install failed/u);
  // r2 与 r2ghidra 必须成对锁定，且不能走 `r2pm -ci`（取 master，会撞 r2 的 ABI 变动）。
  assert.match(dockerfile, /ARG R2GHIDRA_VERSION=/u);
  assert.doesNotMatch(dockerfile, /r2pm -ci r2ghidra/u);
  assert.match(dockerfile, /--branch "\$\{R2GHIDRA_VERSION\}"/u);
  assert.match(dockerfile, /\.\/configure --prefix=\/usr\/local && make -j"\$\(nproc\)" && make install/u);
  assert.match(dockerfile, /ldconfig && r2 -v/u);
  const heavyDockerfile = await readFile(new URL('../docker/Dockerfile.heavy', import.meta.url), 'utf8');
  assert.match(heavyDockerfile, /USER root[\s\S]*USER 10001:10001/u);
  assert.match(heavyDockerfile, /ARG APT_MIRROR=/u);
});
