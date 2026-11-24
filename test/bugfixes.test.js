import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { lstat as fsLstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { apply } from '../ctf-tools.js';
import { summarizeStatus } from '../ctf-status.js';
import { createWorkbenchEnvironment } from '../workbench-config.js';

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let v = i;
    for (let bit = 0; bit < 8; bit += 1) v = v & 1 ? (v >>> 1) ^ 0xedb88320 : v >>> 1;
    table[i] = v >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let v = 0xffffffff;
  for (let i = 0; i < buffer.length; i += 1) v = CRC_TABLE[(v ^ buffer[i]) & 0xff] ^ (v >>> 8);
  return (v ^ 0xffffffff) >>> 0;
}

function encryptedStoredZip(name, content, password) {
  const nameBytes = Buffer.from(name, 'utf8');
  const plain = Buffer.from(content, 'utf8');
  const crc = crc32(plain);
  let k0 = 0x12345678;
  let k1 = 0x23456789;
  let k2 = 0x34567890;
  const update = byte => {
    k0 = (CRC_TABLE[(k0 ^ byte) & 0xff] ^ (k0 >>> 8)) >>> 0;
    k1 = (((k1 + (k0 & 0xff)) >>> 0) * 134775813 + 1) >>> 0;
    k2 = (CRC_TABLE[(k2 ^ (k1 >>> 24)) & 0xff] ^ (k2 >>> 8)) >>> 0;
  };
  for (const byte of Buffer.from(password, 'latin1')) update(byte);
  const encHeader = Buffer.alloc(12);
  const headerPlain = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, (crc >>> 24) & 0xff]);
  for (let i = 0; i < 12; i += 1) {
    const temp = (k2 | 2) >>> 0;
    const stream = ((temp * (temp ^ 1)) >>> 8) & 0xff;
    encHeader[i] = headerPlain[i] ^ stream;
    update(headerPlain[i]);
  }
  const encBody = Buffer.alloc(plain.length);
  for (let i = 0; i < plain.length; i += 1) {
    const temp = (k2 | 2) >>> 0;
    const stream = ((temp * (temp ^ 1)) >>> 8) & 0xff;
    encBody[i] = plain[i] ^ stream;
    update(plain[i]);
  }
  const payload = Buffer.concat([encHeader, encBody]);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0x0001, 6);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(payload.length, 18);
  local.writeUInt32LE(plain.length, 22);
  local.writeUInt16LE(nameBytes.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0x0001, 8);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(payload.length, 20);
  central.writeUInt32LE(plain.length, 24);
  central.writeUInt16LE(nameBytes.length, 28);
  const dirOffset = local.length + nameBytes.length + payload.length;
  const dirSize = central.length + nameBytes.length;
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(dirSize, 12);
  end.writeUInt32LE(dirOffset, 16);
  return Buffer.concat([local, nameBytes, payload, central, nameBytes, end]);
}

function mockContext(files, config = {}, cwd = process.cwd()) {
  const entries = new Map(Object.entries(files).map(([name, bytes]) => [name, {
    bytes: Buffer.from(bytes), version: 'v1',
  }]));
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
    sandboxPolicy: { resolve() { return { mode: 'workspace-write' }; } },
    fs: {
      async resolve(name, options) { return resolveTarget(name, options); },
      contains(parent, child) {
        return child.targetKey === parent.targetKey || child.targetKey.startsWith(parent.targetKey.replace(/[\\/]$/u, '') + '/');
      },
      async lstat(name, options) {
        const relative = resolveTarget(name, options).targetKey.slice(cwd.replace(/[\\/]$/u, '').length + 1);
        if (entries.has(relative)) return { type: 'file' };
        if ([...entries.keys()].some(file => file.startsWith(relative.replace(/[\\/]$/u, '') + '/'))) return { type: 'directory' };
        return undefined;
      },
      async stat(target) {
        const name = target.targetKey.slice(cwd.replace(/[\\/]$/u, '').length + 1);
        const entry = entries.get(name);
        return entry ? { type: 'file', size: entry.bytes.length, version: entry.version } : null;
      },
      async readBytes(target) {
        const name = target.targetKey.slice(cwd.replace(/[\\/]$/u, '').length + 1);
        return entries.get(name)?.bytes;
      },
    },
  };
  apply(ctx, config);
  const execution = { signal: new AbortController().signal, agent: { session: { header: { cwd }, id: 'bugfix-fixture' } } };
  return { tools, execution };
}

test('compact: false 配置在工作台配置与插件节点中均可生效且节点优先', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ctf-compact-test-'));
  const file = join(dir, 'ctf-workbench.json');
  try {
    await writeFile(file, JSON.stringify({ compact: false }));
    assert.equal(createWorkbenchEnvironment({}, file).presetConfig().compact, false);
    assert.equal(createWorkbenchEnvironment({ compact: true }, file).presetConfig().compact, true);
    await writeFile(file, JSON.stringify({ compact: 'invalid' }));
    assert.equal(createWorkbenchEnvironment({}, file).presetConfig().compact, undefined);

    const pretty = mockContext({}, { compact: false, enableExtendedAudit: true });
    const coreOut = await pretty.tools.get('pwn_cyclic').execute({ operation: 'create', length: 8 }, pretty.execution);
    assert.ok(coreOut.includes('\n  '), 'core tool should emit indented JSON when compact: false');
    const extraOut = await pretty.tools.get('cloud_metadata').execute({ action: 'probe' }, pretty.execution);
    assert.ok(extraOut.includes('\n  '), 'extra tool should emit indented JSON when compact: false');
    const coreDefault = mockContext({}, { compact: false });
    const graphOut = await coreDefault.tools.get('ctf_graph').execute({ action: 'board' }, coreDefault.execution);
    assert.ok(graphOut.includes('\n  '), 'default core tier tool should emit indented JSON when compact: false');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('archive_crack 使用 wordlist 正常破解 ZipCrypto 并支持取消信号与非法 action 拦截', async () => {
  const zip = encryptedStoredZip('flag.txt', 'flag{wordlist-ok}', 'hunter42');
  const wordlist = Buffer.from('alpha\nbeta\nhunter42\ngamma\n', 'utf8');
  const { tools, execution } = mockContext({ 'secret.zip': zip, 'words.txt': wordlist });
  const cracked = JSON.parse(await tools.get('archive_crack').execute({
    file_path: 'secret.zip', action: 'crack', wordlist: 'words.txt',
  }, execution));
  assert.equal(cracked.status, 'found', JSON.stringify(cracked));
  assert.equal(cracked.password, 'hunter42');
  assert.equal(cracked.tried, 3);

  const aborted = JSON.parse(await tools.get('archive_crack').execute({
    file_path: 'secret.zip', action: 'crack', wordlist: 'words.txt',
  }, { ...execution, signal: AbortSignal.abort() }));
  assert.equal(aborted.ok, false);
  assert.equal(aborted.error.kind, 'abort');

  const invalid = JSON.parse(await tools.get('archive_crack').execute({
    file_path: 'secret.zip', action: 'invalid',
  }, execution));
  assert.equal(invalid.ok, false);
  assert.equal(invalid.error.kind, 'unsupported');
});

test('ctf_status 与 summarizeStatus 统一告警口径，scoreboard 记录不误报 next_step_missing', async () => {
  const now = new Date().toISOString();
  const boardSummary = summarizeStatus([{ at: now, phase: 'scoreboard', board: { rank: 3, score: 500 } }]);
  assert.equal(boardSummary.warnings.some(w => w.code === 'next_step_missing'), false);
  assert.equal(boardSummary.warnings.some(w => w.code === 'status_records_low'), true);

  const stale = new Date(Date.now() - 65 * 60000).toISOString();
  const staleSummary = summarizeStatus([
    { at: stale, phase: 'init', next_step: 'scan' },
    { at: stale, phase: 'rev' },
  ]);
  assert.deepEqual(staleSummary.warnings.map(w => w.code), ['timebox_60', 'next_step_missing']);

  const statusJson = JSON.stringify({ entries: [{ at: now, phase: 'scoreboard', board: { rank: 3, score: 500 } }] });
  const { tools, execution } = mockContext({ '.ctf-status.json': statusJson });
  const shown = JSON.parse(await tools.get('ctf_status').execute({ action: 'show' }, execution));
  assert.equal(shown.warnings.some(w => w.code === 'next_step_missing'), false);
  assert.equal(shown.warnings.some(w => w.code === 'status_records_low'), true);
});

test('ctf_doctor 探测本机原生 libarchive 而非 pip libarchive-c，并安全报告非法 libarchivePath', async () => {
  const python = execFileSync(process.platform === 'win32' ? 'python' : 'python3',
    ['-c', 'import sys; print(sys.executable)'], { encoding: 'utf8' }).trim();
  const { tools, execution } = mockContext({}, { pythonPath: python });
  const report = JSON.parse(await tools.get('ctf_doctor').execute({ action: 'check' }, execution));
  assert.equal(report.checks.some(c => c.name === 'python:libarchive'), false);
  const libCheck = report.checks.find(c => c.name === 'libarchive');
  assert.ok(libCheck, 'ctf_doctor should report native libarchive check');
  if (process.platform === 'win32') assert.equal(libCheck.ok, true);
  assert.ok(report.sandbox_summary, 'ctf_doctor should include sandbox_summary');
  assert.equal(report.sandbox_summary.docker_base.image, 'dsh-ctf-sandbox:latest');
  assert.equal(report.sandbox_summary.docker_heavy.image, 'dsh-ctf-sandbox:heavy');
  assert.ok(report.checks.some(c => c.name === 'sandbox:docker_base'));
  assert.ok(report.checks.some(c => c.name === 'sandbox:docker_heavy'));

  const bad = mockContext({}, { pythonPath: python, libarchivePath: 'relative/libarchive.so' });
  const badReport = JSON.parse(await bad.tools.get('ctf_doctor').execute({ action: 'check' }, bad.execution));
  const badLib = badReport.checks.find(c => c.name === 'libarchive');
  assert.equal(badLib.ok, false);
  assert.match(badLib.detail, /绝对路径/u);
});

test('只读权限错误统一归为 permission，且文件已存在（EEXIST）归为 conflict', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ctf-errkind-'));
  try {
    const buildCtx = writable => {
      const tools = new Map();
      const resolveTarget = (name, options = {}) => {
        const base = (options.cwd ?? dir).replace(/[\\/]$/u, '');
        const targetKey = options.cwd ? `${base}/${name}` : name;
        return { targetKey, displayPath: targetKey };
      };
      const ctx = {
        tools: { register(tool) { tools.set(tool.name, tool); } },
        effect() {},
        emit() {},
        workingDirectory: { async ensure() { return dir; } },
        sandboxPolicy: { resolve() { return { mode: writable ? 'workspace-write' : 'read-only' }; } },
        fs: {
          async resolve(name, options) { return resolveTarget(name, options); },
          contains(parent, child) { return child.targetKey === parent.targetKey || child.targetKey.startsWith(parent.targetKey.replace(/[\\/]$/u, '') + '/'); },
          async lstat(name, options) {
            const rel = resolveTarget(name, options).targetKey.slice(dir.replace(/[\\/]$/u, '').length + 1);
            try {
              const info = await fsLstat(join(dir, rel));
              return { type: info.isDirectory() ? 'directory' : info.isFile() ? 'file' : 'other' };
            } catch {
              return undefined;
            }
          },
          async stat() { return null; },
          async readBytes() { return Buffer.alloc(0); },
        },
      };
      apply(ctx, {});
      const execution = { signal: new AbortController().signal, agent: { session: { header: { cwd: dir }, id: 'errkind-test' } } };
      return { tools, execution };
    };

    const ro = buildCtx(false);
    const tplRo = JSON.parse(await ro.tools.get('crypto_solver').execute({ action: 'template', kind: 'z3_bitvec' }, ro.execution));
    assert.equal(tplRo.ok, false);
    assert.equal(tplRo.error.kind, 'permission');

    const boardRo = JSON.parse(await ro.tools.get('ctf_status').execute({ action: 'board' }, ro.execution));
    assert.equal(boardRo.ok, false);
    assert.equal(boardRo.error.kind, 'permission');

    const rw = buildCtx(true);
    const first = JSON.parse(await rw.tools.get('crypto_solver').execute({ action: 'template', kind: 'z3_bitvec' }, rw.execution));
    assert.equal(first.status, 'ok');
    const second = JSON.parse(await rw.tools.get('crypto_solver').execute({ action: 'template', kind: 'z3_bitvec' }, rw.execution));
    assert.equal(second.ok, false);
    assert.equal(second.error.kind, 'conflict');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('ctf_doctor 正确检测 enableExtendedAudit 热重载分层漂移与 SKILL.md 同步状态', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ctf-doctor-sync-'));
  const fakeHome = join(dir, 'dsh-home');
  const workDir = join(dir, 'ws');
  const prevHome = process.env.DSH_HOME;
  await mkdir(fakeHome, { recursive: true });
  await mkdir(workDir, { recursive: true });
  process.env.DSH_HOME = fakeHome;
  try {
    const configPath = join(fakeHome, 'ctf-workbench.json');
    await writeFile(configPath, JSON.stringify({ enableExtendedAudit: false }), 'utf8');
    const { tools, execution } = mockContext({}, {}, workDir);

    // 1) 未安装 SKILL.md 且分层一致
    const initial = JSON.parse(await tools.get('ctf_doctor').execute({ action: 'check' }, execution));
    assert.equal(initial.tool_tier, 'core');
    assert.equal(initial.configured_tool_tier, 'core');
    assert.equal(initial.checks.find(c => c.name === 'tool_tier_sync').ok, true);
    assert.equal(initial.checks.find(c => c.name === 'skill_sync').ok, false);

    // 2) 热修改 enableExtendedAudit=true 但未重载进程 -> tool_tier 保持 core 且 tool_tier_sync 告警
    await new Promise(resolve => setTimeout(resolve, 25));
    await writeFile(configPath, JSON.stringify({ enableExtendedAudit: true, compact: true }), 'utf8');
    const skillDir = join(fakeHome, 'skills', 'ctf');
    await mkdir(skillDir, { recursive: true });
    await writeFile(join(skillDir, 'SKILL.md'), 'outdated skill content\n', 'utf8');

    const drifted = JSON.parse(await tools.get('ctf_doctor').execute({ action: 'check' }, execution));
    assert.equal(drifted.tool_tier, 'core');
    assert.equal(drifted.configured_tool_tier, 'full');
    const tierCheck = drifted.checks.find(c => c.name === 'tool_tier_sync');
    assert.equal(tierCheck.ok, false);
    assert.match(tierCheck.detail, /重启|重载/u);
    const skillDrift = drifted.checks.find(c => c.name === 'skill_sync');
    assert.equal(skillDrift.ok, false);
    assert.match(skillDrift.detail, /不一致/u);

    // 3) 写入与包内一致的 SKILL.md（刻意转为 LF 验证跨平台换行兼容）-> skill_sync 通过
    const bundledSkill = await readFile(new URL('../SKILL.md', import.meta.url), 'utf8');
    await writeFile(join(skillDir, 'SKILL.md'), bundledSkill.replace(/\r\n/gu, '\n'), 'utf8');
    const synced = JSON.parse(await tools.get('ctf_doctor').execute({ action: 'check' }, execution));
    assert.equal(synced.checks.find(c => c.name === 'skill_sync').ok, true);
  } finally {
    if (prevHome === undefined) delete process.env.DSH_HOME;
    else process.env.DSH_HOME = prevHome;
    await rm(dir, { recursive: true, force: true });
  }
});
