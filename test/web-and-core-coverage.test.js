import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import { lstat as fsLstat, mkdtemp, open as fsOpen, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { inspectAudioMetadata } from '../audio-metadata.js';
import { browserGateway } from '../browser-gateway.js';
import { createBrowserSession, handleCdpEvent } from '../browser-session.js';
import { apply } from '../ctf-tools.js';
import { inspectElf, verifyElf } from '../elf.js';
import { inspectMedia, parseMediaRequest } from '../media-reader.js';
import { createNetSessionManager } from '../net-session.js';
import { buildPwnPayload } from '../pwn-payload.js';

const PYTHON = process.platform === 'win32' ? 'python' : 'python3';

function createWorkbenchMock() {
  return { async resolvePython() { return PYTHON; } };
}

function createWorkspaceCtx(cwd, { writable = true, config = {} } = {}) {
  const tools = new Map();
  const cleanCwd = cwd.replaceAll('\\', '/').replace(/[\\/]$/u, '');
  const resolveTarget = (name, options = {}) => {
    if (typeof name === 'object' && name !== null && typeof name.targetKey === 'string') return name;
    const norm = String(name).replaceAll('\\', '/');
    if (/^[A-Za-z]:\//u.test(norm) || norm.startsWith('/')) return { targetKey: norm, displayPath: norm };
    const base = (options.cwd ?? cleanCwd).replaceAll('\\', '/').replace(/[\\/]$/u, '');
    const targetKey = `${base}/${norm}`;
    return { targetKey, displayPath: targetKey };
  };
  const toFull = (name, options) => {
    const key = resolveTarget(name, options).targetKey;
    return key.startsWith(cleanCwd + '/') ? join(cwd, key.slice(cleanCwd.length + 1)) : key;
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
        const base = parent.targetKey.replace(/[\\/]$/u, '');
        return child.targetKey === base || child.targetKey.startsWith(base + '/');
      },
      async lstat(name, options) {
        try {
          const info = await fsLstat(toFull(name, options));
          return {
            type: info.isDirectory() ? 'directory' : info.isSymbolicLink() ? 'symlink' : 'file',
            size: info.size,
            version: `${info.size}:${Math.trunc(info.mtimeMs)}`,
          };
        } catch {
          return undefined;
        }
      },
      async stat(resolved) {
        try {
          const info = await fsLstat(toFull(resolved));
          return {
            type: info.isDirectory() ? 'directory' : info.isSymbolicLink() ? 'symlink' : 'file',
            size: info.size,
            version: `${info.size}:${Math.trunc(info.mtimeMs)}`,
          };
        } catch {
          return null;
        }
      },
      async readBytes(resolved) {
        return readFile(toFull(resolved));
      },
      async readByteRange(resolved, { offset, length }) {
        const fh = await fsOpen(toFull(resolved), 'r');
        try {
          const buf = Buffer.alloc(length);
          const { bytesRead } = await fh.read(buf, 0, length, offset);
          return buf.subarray(0, bytesRead);
        } finally {
          await fh.close();
        }
      },
    },
  };
  apply(ctx, { enableExtendedAudit: true, pythonPath: execFileSync(PYTHON, ['-c', 'import sys; print(sys.executable)'], { encoding: 'utf8' }).trim(), ...config });
  const execution = {
    signal: new AbortController().signal,
    agent: { session: { header: { cwd }, id: 'cov-' + Math.random().toString(36).slice(2, 8) } },
  };
  return { tools, execution };
}

function buildZipStore(files) {
  // Pure JS STORED ZIP builder for PyTorch / archive-chaining tests.
  const crcTable = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let v = i;
    for (let b = 0; b < 8; b++) v = (v & 1) ? (0xedb88320 ^ (v >>> 1)) : (v >>> 1);
    crcTable[i] = v >>> 0;
  }
  const crc32 = buf => {
    let c = 0xffffffff;
    for (let i = 0; i < buf.length; i++) c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const { name, data } of files) {
    const nameBuf = Buffer.from(name, 'utf8');
    const body = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
    const crc = crc32(body);
    const local = Buffer.alloc(30 + nameBuf.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(body.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    nameBuf.copy(local, 30);
    locals.push(local, body);

    const central = Buffer.alloc(46 + nameBuf.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(body.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);
    nameBuf.copy(central, 46);
    centrals.push(central);
    offset += local.length + body.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

function buildCraftedElf64() {
  // Craft a rich ELF64 x86-64 binary with PT_LOAD, PT_GNU_STACK (NX), PT_GNU_RELRO,
  // .text (pop rdi; ret + syscall; ret), .rodata (/bin/sh), .dynsym, .dynstr, .dynamic (DT_BIND_NOW).
  const shstrtab = Buffer.from('\0.text\0.rodata\0.dynstr\0.dynsym\0.dynamic\0.shstrtab\0', 'ascii');
  const dynstr = Buffer.from('\0libc.so.6\0__stack_chk_fail_local\0system\0gets\0printf\0user_chk\0', 'ascii');
  const text = Buffer.from([
    0x5f, 0xc3, // pop rdi; ret
    0x5e, 0xc3, // pop rsi; ret
    0x0f, 0x05, 0xc3, // syscall; ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
  ]);
  const rodata = Buffer.from('hello\0/bin/sh\0padding_bytes_00', 'ascii');

  // 6 Elf64_Sym entries: local stack protector import, regular imports, one defined *_chk decoy.
  const dynsym = Buffer.alloc(24 * 6);
  const writeSym = (idx, nameOff, info, shndx, value, size) => {
    const o = idx * 24;
    dynsym.writeUInt32LE(nameOff, o);
    dynsym[o + 4] = info;
    dynsym[o + 5] = 0;
    dynsym.writeUInt16LE(shndx, o + 6);
    dynsym.writeBigUInt64LE(value, o + 8);
    dynsym.writeBigUInt64LE(size, o + 16);
  };
  writeSym(1, dynstr.indexOf('__stack_chk_fail_local'), (1 << 4) | 2, 0, 0n, 0n);
  writeSym(2, dynstr.indexOf('system'), (1 << 4) | 2, 0, 0n, 0n);
  writeSym(3, dynstr.indexOf('gets'), (1 << 4) | 2, 0, 0n, 0n);
  writeSym(4, dynstr.indexOf('printf'), (1 << 4) | 2, 1, 0x401000n, 16n);
  writeSym(5, dynstr.indexOf('user_chk'), (1 << 4) | 2, 1, 0x401010n, 8n);

  // .dynamic: DT_NEEDED(1) -> libc.so.6, DT_BIND_NOW(24), DT_NULL(0)
  const dynamic = Buffer.alloc(16 * 5);
  dynamic.writeBigInt64LE(1n, 0);
  dynamic.writeBigUInt64LE(BigInt(dynstr.indexOf('libc.so.6')), 8);
  dynamic.writeBigInt64LE(24n, 16);
  dynamic.writeBigUInt64LE(0n, 24);
  dynamic.writeBigInt64LE(5n, 32); // DT_STRTAB
  dynamic.writeBigUInt64LE(0x400280n, 40);
  dynamic.writeBigInt64LE(10n, 48); // DT_STRSZ
  dynamic.writeBigUInt64LE(BigInt(dynstr.length), 56);
  dynamic.writeBigInt64LE(0n, 64);

  const phoff = 64;
  const phnum = 4; // PT_LOAD, PT_GNU_STACK, PT_GNU_RELRO, PT_DYNAMIC
  const textOff = 0x200;
  const rodataOff = 0x240;
  const dynstrOff = 0x280;
  const dynsymOff = 0x2c0;
  const dynamicOff = 0x360;
  const shstrtabOff = 0x3a0;
  const shoff = 0x400;
  const shnum = 7; // NULL + 6 sections
  const totalSize = shoff + shnum * 64;
  const buf = Buffer.alloc(totalSize);

  // ELF64 header
  buf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  buf.writeUInt16LE(2, 16); // ET_EXEC
  buf.writeUInt16LE(62, 18); // EM_X86_64
  buf.writeUInt32LE(1, 20);
  buf.writeBigUInt64LE(0x400000n + BigInt(textOff), 24); // e_entry
  buf.writeBigUInt64LE(BigInt(phoff), 32);
  buf.writeBigUInt64LE(BigInt(shoff), 40);
  buf.writeUInt16LE(64, 52);
  buf.writeUInt16LE(56, 54);
  buf.writeUInt16LE(phnum, 56);
  buf.writeUInt16LE(64, 58);
  buf.writeUInt16LE(shnum, 60);
  buf.writeUInt16LE(6, 62); // e_shstrndx -> .shstrtab

  // Program headers
  const writePh = (idx, type, flags, off, vaddr, filesz, memsz, align) => {
    const o = phoff + idx * 56;
    buf.writeUInt32LE(type, o);
    buf.writeUInt32LE(flags, o + 4);
    buf.writeBigUInt64LE(off, o + 8);
    buf.writeBigUInt64LE(vaddr, o + 16);
    buf.writeBigUInt64LE(vaddr, o + 24);
    buf.writeBigUInt64LE(filesz, o + 32);
    buf.writeBigUInt64LE(memsz, o + 40);
    buf.writeBigUInt64LE(align, o + 48);
  };
  writePh(0, 1, 5, 0n, 0x400000n, BigInt(shoff), BigInt(shoff), 0x1000n); // PT_LOAD R|X
  writePh(1, 0x6474e551, 6, 0n, 0n, 0n, 0n, 0x10n); // PT_GNU_STACK RW (NX enabled)
  writePh(2, 0x6474e552, 4, BigInt(dynamicOff), 0x400000n + BigInt(dynamicOff), BigInt(dynamic.length), BigInt(dynamic.length), 1n);
  writePh(3, 2, 6, BigInt(dynamicOff), 0x400000n + BigInt(dynamicOff), BigInt(dynamic.length), BigInt(dynamic.length), 8n);

  // Copy section payloads
  text.copy(buf, textOff);
  rodata.copy(buf, rodataOff);
  dynstr.copy(buf, dynstrOff);
  dynsym.copy(buf, dynsymOff);
  dynamic.copy(buf, dynamicOff);
  shstrtab.copy(buf, shstrtabOff);

  // Section headers
  const writeSh = (idx, name, type, flags, addr, off, size, link, entsize) => {
    const o = shoff + idx * 64;
    buf.writeUInt32LE(shstrtab.indexOf(name), o);
    buf.writeUInt32LE(type, o + 4);
    buf.writeBigUInt64LE(flags, o + 8);
    buf.writeBigUInt64LE(addr, o + 16);
    buf.writeBigUInt64LE(off, o + 24);
    buf.writeBigUInt64LE(size, o + 32);
    buf.writeUInt32LE(link, o + 40);
    buf.writeBigUInt64LE(1n, o + 48);
    buf.writeBigUInt64LE(entsize, o + 56);
  };
  writeSh(1, '.text', 1, 6n, 0x400000n + BigInt(textOff), BigInt(textOff), BigInt(text.length), 0, 0n);
  writeSh(2, '.rodata', 1, 2n, 0x400000n + BigInt(rodataOff), BigInt(rodataOff), BigInt(rodata.length), 0, 0n);
  writeSh(3, '.dynstr', 3, 2n, 0x400000n + BigInt(dynstrOff), BigInt(dynstrOff), BigInt(dynstr.length), 0, 0n);
  writeSh(4, '.dynsym', 11, 2n, 0x400000n + BigInt(dynsymOff), BigInt(dynsymOff), BigInt(dynsym.length), 3, 24n);
  writeSh(5, '.dynamic', 6, 3n, 0x400000n + BigInt(dynamicOff), BigInt(dynamicOff), BigInt(dynamic.length), 3, 16n);
  writeSh(6, '.shstrtab', 3, 0n, 0n, BigInt(shstrtabOff), BigInt(shstrtab.length), 0, 0n);
  return buf;
}

test('inspect_media(kind: "model") 覆盖 Pickle/PyTorch ZIP/Safetensors/GGUF/ONNX 静态安全体检与 ZIP 链式传递', async () => {
  assert.deepEqual(parseMediaRequest({ kind: 'model' }), { kind: 'model' });
  assert.throws(() => parseMediaRequest({ kind: 'model', page_offset: 1 }));

  const wb = createWorkbenchMock();

  // 1) 恶意 Pickle（protocol 4 STACK_GLOBAL + os.system + 尾部隐藏字节），静态扫描绝不执行
  const maliciousPickle = Buffer.from(execFileSync(PYTHON, [
    '-B', '-c',
    'import base64, os, pickle\nclass E:\n    def __reduce__(self): return (os.system, ("echo SHOULD_NEVER_RUN",))\nprint(base64.b64encode(pickle.dumps(E(), protocol=4) + b"HIDDEN_TAIL").decode())',
  ], { encoding: 'utf8' }).trim(), 'base64');
  const pklReport = await inspectMedia(maliciousPickle, { kind: 'model' }, undefined, wb);
  assert.equal(pklReport.status, 'ok');
  assert.equal(pklReport.format, 'pickle');
  assert.equal(pklReport.risk_level, 'high');
  assert.equal(pklReport.trailing_bytes, 'HIDDEN_TAIL'.length);
  assert.ok(pklReport.findings.some(f => f.severity === 'high' && /system/u.test(f.target ?? '')));
  assert.ok(pklReport.string_samples.some(s => s.includes('SHOULD_NEVER_RUN')));

  // 2) 安全纯数据 Pickle -> risk_level: low
  const benignPickle = Buffer.from(execFileSync(PYTHON, [
    '-B', '-c', 'import base64, pickle; print(base64.b64encode(pickle.dumps({"weights": [1, 2, 3]}, protocol=4)).decode())',
  ], { encoding: 'utf8' }).trim(), 'base64');
  const safeReport = await inspectMedia(benignPickle, { kind: 'model' }, undefined, wb);
  assert.equal(safeReport.status, 'ok');
  assert.equal(safeReport.format, 'pickle');
  assert.equal(safeReport.risk_level, 'low');

  // 不完整 Pickle 扫描不能把尚未检查的尾部当作低风险。
  const hubLoadPickle = Buffer.from('ctorch.hub\nload\n.', 'latin1');
  const hubLoadReport = await inspectMedia(hubLoadPickle, { kind: 'model' }, undefined, wb);
  assert.equal(hubLoadReport.format, 'pickle');
  assert.equal(hubLoadReport.risk_level, 'high');
  assert.ok(hubLoadReport.findings.some(f => f.kind === 'pickle_global' && /torch\.hub\.load/u.test(f.target ?? '')));

  const cappedPickle = Buffer.concat([Buffer.from([0x80, 0x04]), Buffer.alloc(200_001, 0x4e), hubLoadPickle]);
  const cappedReport = await inspectMedia(cappedPickle, { kind: 'model' }, undefined, wb);
  assert.equal(cappedReport.status, 'incomplete');
  assert.equal(cappedReport.risk_level, 'medium');
  assert.ok(cappedReport.findings.some(f => f.kind === 'incomplete_pickle_scan'));

  // 3) PyTorch ZIP（含恶意 data.pkl 与 TorchScript code/net.py）
  const ptZip = buildZipStore([
    { name: 'archive/version', data: '3\n' },
    { name: 'archive/data.pkl', data: maliciousPickle },
    { name: 'archive/code/net.py', data: 'def forward(x):\n    return eval(x)\n' },
  ]);
  const ptReport = await inspectMedia(ptZip, { kind: 'model' }, undefined, wb);
  assert.equal(ptReport.status, 'ok');
  assert.equal(ptReport.format, 'pytorch_zip');
  assert.equal(ptReport.risk_level, 'high');
  assert.equal(ptReport.pickle_members.length, 1);
  assert.equal(ptReport.code_files.length, 1);
  assert.ok(ptReport.findings.some(f => f.kind === 'dangerous_call' && f.member === 'archive/code/net.py'));

  const cappedPtZip = buildZipStore([
    ...Array.from({ length: 8 }, (_, i) => ({ name: `archive/weight-${i}.pkl`, data: Buffer.from('N.') })),
    { name: 'archive/weight-hidden.pkl', data: hubLoadPickle },
  ]);
  const cappedPtReport = await inspectMedia(cappedPtZip, { kind: 'model' }, undefined, wb);
  assert.equal(cappedPtReport.format, 'pytorch_zip');
  assert.equal(cappedPtReport.status, 'incomplete');
  assert.equal(cappedPtReport.risk_level, 'medium');
  assert.equal(cappedPtReport.skipped_pickle_members, 1);

  // 4) Safetensors（__metadata__ + tensor 描述 + 尾部隐写数据检测）
  const stHeader = Buffer.from(JSON.stringify({
    __metadata__: { author: 'ctf-author', note: 'flag_hint_here' },
    'layer.weight': { dtype: 'F32', shape: [2, 2], data_offsets: [0, 16] },
  }), 'utf8');
  const stLen = Buffer.alloc(8);
  stLen.writeBigUInt64LE(BigInt(stHeader.length), 0);
  const stBytes = Buffer.concat([stLen, stHeader, Buffer.alloc(16), Buffer.from('SECRET_APPEND')]);
  const stReport = await inspectMedia(stBytes, { kind: 'model' }, undefined, wb);
  assert.equal(stReport.status, 'ok');
  assert.equal(stReport.format, 'safetensors');
  assert.equal(stReport.tensor_count, 1);
  assert.equal(stReport.metadata.note, 'flag_hint_here');
  assert.equal(stReport.trailing_bytes, 'SECRET_APPEND'.length);
  assert.equal(stReport.risk_level, 'medium');

  // 5) GGUF v3（含字符串、uint32、数组 KV 及可疑模板）
  const ggufStr = s => {
    const b = Buffer.from(s, 'utf8');
    const l = Buffer.alloc(8);
    l.writeBigUInt64LE(BigInt(b.length), 0);
    return Buffer.concat([l, b]);
  };
  const u32 = v => { const b = Buffer.alloc(4); b.writeUInt32LE(v, 0); return b; };
  const u64 = v => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v), 0); return b; };
  const ggufBytes = Buffer.concat([
    Buffer.from('GGUF', 'ascii'), u32(3), u64(2), u64(3),
    ggufStr('general.name'), u32(8), ggufStr('tiny-ctf-llm'),
    ggufStr('general.quant'), u32(4), u32(7),
    ggufStr('tokenizer.chat_template'), u32(8), ggufStr('{{ cycler.__init__.__globals__.os.popen("id") }}'),
  ]);
  const ggufReport = await inspectMedia(ggufBytes, { kind: 'model' }, undefined, wb);
  assert.equal(ggufReport.status, 'ok');
  assert.equal(ggufReport.format, 'gguf');
  assert.equal(ggufReport.version, 3);
  assert.equal(ggufReport.metadata['general.name'], 'tiny-ctf-llm');
  assert.equal(ggufReport.metadata['general.quant'], 7);
  assert.equal(ggufReport.risk_level, 'high');

  const manyGgufFields = Array.from({ length: 65 }, (_, i) => [
    ggufStr(i === 64 ? 'tokenizer.chat_template' : `meta.${i}`),
    u32(8),
    ggufStr(i === 64 ? '{{ cycler.__init__.__globals__.os.popen("id") }}' : `value-${i}`),
  ]);
  const cappedGguf = Buffer.concat([
    Buffer.from('GGUF', 'ascii'), u32(3), u64(0), u64(manyGgufFields.length), ...manyGgufFields.flat(),
  ]);
  const cappedGgufReport = await inspectMedia(cappedGguf, { kind: 'model' }, undefined, wb);
  assert.equal(cappedGgufReport.format, 'gguf');
  assert.equal(cappedGgufReport.status, 'incomplete');
  assert.equal(cappedGgufReport.risk_level, 'medium');
  assert.ok(cappedGgufReport.findings.some(f => f.kind === 'gguf_metadata_scan_incomplete'));

  // 6) ONNX protobuf（ir_version + producer_name + 自定义 domain + 外部路径穿越）
  const pbStr = (field, s) => {
    const b = Buffer.from(s, 'utf8');
    return Buffer.concat([Buffer.from([(field << 3) | 2, b.length]), b]);
  };
  const onnxBytes = Buffer.concat([
    Buffer.from([0x08, 0x09]), // field 1: ir_version = 9
    pbStr(2, 'pytorch'),
    pbStr(4, 'evil.custom.domain'),
    pbStr(6, '../../etc/passwd'),
  ]);
  const onnxReport = await inspectMedia(onnxBytes, { kind: 'model' }, undefined, wb);
  assert.equal(onnxReport.status, 'incomplete');
  assert.equal(onnxReport.format, 'onnx');
  assert.equal(onnxReport.ir_version, 9);
  assert.equal(onnxReport.producer_name, 'pytorch');
  assert.equal(onnxReport.risk_level, 'high');
  assert.ok(onnxReport.findings.some(f => f.kind === 'custom_onnx_domain'));
  assert.ok(onnxReport.findings.some(f => f.kind === 'suspicious_external_path'));
  assert.ok(onnxReport.findings.some(f => f.kind === 'onnx_graph_scan_incomplete'));

  const longGraph = Buffer.alloc(2 * 1024 * 1024 + 64, 0x41);
  Buffer.from('../etc/shadow', 'ascii').copy(longGraph, 2 * 1024 * 1024);
  const longOnnx = Buffer.concat([Buffer.from([0x08, 0x09]), pbStr(7, longGraph)]);
  const longOnnxReport = await inspectMedia(longOnnx, { kind: 'model' }, undefined, wb);
  assert.equal(longOnnxReport.status, 'incomplete');
  assert.equal(longOnnxReport.risk_level, 'high');
  assert.ok(longOnnxReport.findings.some(f => f.kind === 'suspicious_external_path' && f.sample.includes('../etc/shadow')));

  // 7) 通过完整工具链路：read_archive_member -> inspect_media(kind: "model", source_result_id)
  const cwd = await mkdtemp(join(tmpdir(), 'ctf-model-chain-'));
  try {
    const bundleZip = buildZipStore([{ name: 'weights.pkl', data: maliciousPickle }]);
    await writeFile(join(cwd, 'bundle.zip'), bundleZip);
    const { tools, execution } = createWorkspaceCtx(cwd, { writable: false });
    const member = JSON.parse(await tools.get('read_archive_member').execute({
      file_path: 'bundle.zip', member_index: 0,
    }, execution));
    assert.ok(member.result_id, JSON.stringify(member));
    const chained = JSON.parse(await tools.get('inspect_media').execute({
      kind: 'model', source_result_id: member.result_id,
    }, execution));
    assert.equal(chained.status, 'ok', JSON.stringify(chained));
    assert.equal(chained.format, 'pickle');
    assert.equal(chained.risk_level, 'high');
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('browser-session CDP 事件处理（含弹窗自动捕获/放行）与 browser_session 新增动作校验', async () => {
  const sent = [];
  const mockBrowser = {
    sessionId: 'sess-1',
    nextId: 10,
    socket: { readyState: 1, send(payload) { sent.push(JSON.parse(payload)); } },
    networkLogs: [],
    networkById: new Map(),
    consoleLogs: [],
    dialogLogs: [],
  };

  handleCdpEvent(mockBrowser, {
    sessionId: 'sess-1',
    method: 'Network.requestWillBeSent',
    params: { requestId: 'req-1', request: { url: 'http://target/api', method: 'POST', postData: 'a=1' }, type: 'Fetch' },
  });
  handleCdpEvent(mockBrowser, {
    sessionId: 'sess-1',
    method: 'Network.responseReceived',
    params: {
      requestId: 'req-1',
      response: { status: 200, statusText: 'OK', mimeType: 'application/json', headers: { 'Content-Type': 'application/json', 'X-Ignored': '1' } },
    },
  });
  handleCdpEvent(mockBrowser, {
    sessionId: 'sess-1',
    method: 'Network.loadingFailed',
    params: { requestId: 'req-1', errorText: 'net::ERR_ABORTED' },
  });
  handleCdpEvent(mockBrowser, {
    sessionId: 'sess-1',
    method: 'Runtime.consoleAPICalled',
    params: { type: 'warn', args: [{ type: 'string', value: 'hello' }, { type: 'number', value: 42 }, { type: 'undefined' }] },
  });
  handleCdpEvent(mockBrowser, {
    sessionId: 'sess-1',
    method: 'Runtime.exceptionThrown',
    params: { exceptionDetails: { text: 'TypeError', url: 'http://target/app.js', lineNumber: 4 } },
  });
  handleCdpEvent(mockBrowser, {
    sessionId: 'sess-1',
    method: 'Page.javascriptDialogOpening',
    params: { type: 'alert', message: 'xss_fired_1337', url: 'http://target/xss' },
  });
  // 其他 sessionId 的事件应被忽略
  handleCdpEvent(mockBrowser, {
    sessionId: 'other-sess',
    method: 'Page.javascriptDialogOpening',
    params: { type: 'alert', message: 'ignored' },
  });

  assert.equal(mockBrowser.networkLogs.length, 1);
  assert.equal(mockBrowser.networkLogs[0].status, 200);
  assert.equal(mockBrowser.networkLogs[0].headers['content-type'], 'application/json');
  assert.equal(mockBrowser.networkLogs[0].headers['x-ignored'], undefined);
  assert.equal(mockBrowser.networkLogs[0].failed, true);
  assert.equal(mockBrowser.consoleLogs.length, 2);
  assert.equal(mockBrowser.consoleLogs[0].text, 'hello 42 undefined');
  assert.equal(mockBrowser.consoleLogs[1].line, 5);
  assert.equal(mockBrowser.dialogLogs.length, 1);
  assert.equal(mockBrowser.dialogLogs[0].message, 'xss_fired_1337');
  assert.equal(mockBrowser.dialogLogs[0].handled, 'accepted');
  assert.equal(sent.length, 1);
  assert.equal(sent[0].method, 'Page.handleJavaScriptDialog');
  assert.equal(sent[0].params.accept, true);

  // 工具层参数校验与只读权限拦截
  const cwd = await mkdtemp(join(tmpdir(), 'ctf-browser-val-'));
  try {
    const ro = createWorkspaceCtx(cwd, { writable: false });
    for (const req of [
      { action: 'evaluate', expression: 'document.title' },
      { action: 'set_cookie', url: 'http://127.0.0.1:8080/', name: 'sid', value: '1' },
      { action: 'set_headers', headers: { 'X-Test': '1' } },
      { action: 'upload_file', selector: '#f', file_path: 'a.txt' },
    ]) {
      const res = JSON.parse(await ro.tools.get('browser_session').execute(req, ro.execution));
      assert.equal(res.ok, false);
      assert.equal(res.error.kind, 'permission', `read-only should block ${req.action}`);
    }

    const rw = createWorkspaceCtx(cwd, { writable: true });
    const badCookie = JSON.parse(await rw.tools.get('browser_session').execute({
      action: 'set_cookie', url: 'http://127.0.0.1/', name: 'bad;name', value: 'x',
    }, rw.execution));
    assert.equal(badCookie.error.kind, 'unsupported');
    const badHeader = JSON.parse(await rw.tools.get('browser_session').execute({
      action: 'set_headers', headers: { 'Bad Header': '1' },
    }, rw.execution));
    assert.equal(badHeader.error.kind, 'unsupported');
    const emptyEval = JSON.parse(await rw.tools.get('browser_session').execute({
      action: 'evaluate', expression: '   ',
    }, rw.execution));
    assert.equal(emptyEval.error.kind, 'unsupported');
    const emptyUpload = JSON.parse(await rw.tools.get('browser_session').execute({
      action: 'upload_file', selector: '#file',
    }, rw.execution));
    assert.equal(emptyUpload.error.kind, 'unsupported');
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('browser-gateway 本地 HTTP 代理与 CONNECT 隧道授权放行/拒绝', async () => {
  const upstream = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain', 'X-Backend': 'ok' });
    if (req.url === '/slow') {
      res.write('first');
      setTimeout(() => res.end('second'), 30);
    } else res.end('proxied:' + req.url);
  });
  await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
  const upstreamPort = upstream.address().port;
  const tunnel = net.createServer(socket => setTimeout(() => socket.write('late-pong'), 100));
  await new Promise(resolve => tunnel.listen(0, '127.0.0.1', resolve));
  const tunnelPort = tunnel.address().port;

  const gateway = await browserGateway(async url => {
    if (url.hostname === '127.0.0.1' && [upstreamPort, tunnelPort].includes(Number(url.port))) {
      return { address: '127.0.0.1', family: 4 };
    }
    throw new Error('origin denied');
  }, { timeoutMs: 50 });
  const proxyUrl = new URL(gateway.address);

  try {
    // 1) 放行已授权 HTTP 请求
    const allowed = await new Promise((resolve, reject) => {
      const req = http.request({
        host: '127.0.0.1',
        port: Number(proxyUrl.port),
        method: 'GET',
        path: `http://127.0.0.1:${upstreamPort}/hello`,
        headers: { Host: `127.0.0.1:${upstreamPort}`, Connection: 'close' },
      }, res => {
        let body = '';
        res.on('data', c => { body += c; });
        res.on('end', () => resolve({ status: res.statusCode, body, backend: res.headers['x-backend'] }));
      });
      req.on('error', reject);
      req.end();
    });
    assert.equal(allowed.status, 200);
    assert.equal(allowed.body, 'proxied:/hello');
    assert.equal(allowed.backend, 'ok');

    // The total response lasts longer than timeoutMs, but regular body traffic must keep it alive.
    const slow = await new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port: Number(proxyUrl.port), method: 'GET',
        path: `http://127.0.0.1:${upstreamPort}/slow`, headers: { Host: `127.0.0.1:${upstreamPort}` } }, res => {
        let body = '';
        res.on('data', chunk => { body += chunk; });
        res.on('end', () => resolve(body));
      });
      req.on('error', reject);
      req.end();
    });
    assert.equal(slow, 'firstsecond');

    // 2) 拦截未授权 HTTP 请求 -> 403
    const denied = await new Promise((resolve, reject) => {
      const req = http.request({
        host: '127.0.0.1',
        port: Number(proxyUrl.port),
        method: 'GET',
        path: 'http://127.0.0.1:1/forbidden',
      }, res => {
        res.resume();
        res.on('end', () => resolve(res.statusCode));
      });
      req.on('error', reject);
      req.end();
    });
    assert.equal(denied, 403);

    // 3) 拦截未授权 CONNECT 隧道 -> 403
    const deniedConnect = await new Promise((resolve, reject) => {
      const sock = net.connect(Number(proxyUrl.port), '127.0.0.1', () => {
        sock.write('CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n');
      });
      let text = '';
      sock.on('data', chunk => { text += chunk.toString('utf8'); });
      sock.on('end', () => resolve(text));
      sock.on('error', reject);
    });
    assert.match(deniedConnect, /403 Forbidden/u);

    // 4) 放行已授权 CONNECT 隧道 -> 200 Connection Established
    const okConnect = await new Promise((resolve, reject) => {
      const sock = net.connect(Number(proxyUrl.port), '127.0.0.1', () => {
        sock.write(`CONNECT 127.0.0.1:${upstreamPort} HTTP/1.1\r\nHost: 127.0.0.1:${upstreamPort}\r\n\r\n`);
      });
      let text = '';
      sock.on('data', chunk => {
        text += chunk.toString('utf8');
        if (text.includes('\r\n\r\n')) {
          sock.destroy();
          resolve(text);
        }
      });
      sock.on('error', reject);
    });
    assert.match(okConnect, /200 Connection Established/u);

    // An established tunnel survives beyond the connection establishment deadline.
    const longConnect = await new Promise((resolve, reject) => {
      const sock = net.connect(Number(proxyUrl.port), '127.0.0.1', () => {
        sock.write(`CONNECT 127.0.0.1:${tunnelPort} HTTP/1.1\r\nHost: 127.0.0.1:${tunnelPort}\r\n\r\n`);
      });
      let text = '';
      const timer = setTimeout(() => { sock.destroy(); reject(new Error('tunnel data timed out')); }, 1000);
      sock.on('data', chunk => {
        text += chunk.toString('utf8');
        if (text.includes('late-pong')) { clearTimeout(timer); sock.destroy(); resolve(text); }
      });
      sock.on('error', error => { clearTimeout(timer); reject(error); });
    });
    assert.match(longConnect, /200 Connection Established/u);
    assert.match(longConnect, /late-pong/u);
  } finally {
    gateway.dispose();
    await new Promise(resolve => upstream.close(resolve));
    await new Promise(resolve => tunnel.close(resolve));
  }
});

test('browser-session 单次操作超时后保留会话，不触发全局清理', async () => {
  let stopped = 0;
  const session = createBrowserSession({
    resolveBinary: async () => undefined,
    authorize: async () => undefined,
    environment: () => process.env,
    onStart() {},
    onStop() { stopped++; },
  });
  await assert.rejects(session.run(20, undefined, signal => new Promise((_, reject) => {
    signal.addEventListener('abort', () => reject(signal.reason), { once: true });
  })), /浏览器操作超时/u);
  assert.equal(stopped, 0);
  await session.close();
  assert.equal(stopped, 1);
});

test('net-session 长连接 TCP 全流程（connect/list/read_until/send/recv/二进制 hexdump/close/权限拦截）', async () => {
  const server = net.createServer(socket => {
    socket.write('WELCOME> ');
    socket.on('data', chunk => {
      const text = chunk.toString('utf8');
      if (text.startsWith('BIN')) {
        socket.write(Buffer.from([0x00, 0xde, 0xad, 0xbe, 0xef]));
      } else if (text.startsWith('BYE')) {
        socket.end('GOODBYE\n');
      } else {
        socket.write('ECHO:' + text);
      }
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  const manager = createNetSessionManager({
    maxSessions: 2,
    idleMs: 60000,
    async authorize(host, targetPort) {
      if (host !== '127.0.0.1' || targetPort !== port) throw new Error('blocked tcp target');
      return { address: '127.0.0.1', family: 4 };
    },
  });

  try {
    await assert.rejects(manager.execute({ operation: 'connect', host: '10.0.0.1', port: 9999 }), /blocked tcp target/u);
    await assert.rejects(manager.execute({ operation: 'unknown' }), /operation/u);
    await assert.rejects(manager.execute({ operation: 'list', host: '127.0.0.1' }), /不接受参数/u);

    const conn = await manager.execute({ operation: 'connect', host: '127.0.0.1', port });
    assert.ok(conn.session_id);
    const listed = await manager.execute({ operation: 'list' });
    assert.equal(listed.length, 1);
    assert.equal(listed[0].session_id, conn.session_id);

    const banner = await manager.execute({ operation: 'read_until', session_id: conn.session_id, delimiter: '> ' });
    assert.equal(banner.matched, true);
    assert.equal(banner.data, 'WELCOME> ');

    // utf8 send + recv
    await manager.execute({ operation: 'send', session_id: conn.session_id, data: 'PING\n' });
    const pong = await manager.execute({ operation: 'read_until', session_id: conn.session_id, delimiter: '0a', delimiter_encoding: 'hex' });
    assert.equal(pong.matched, true);
    assert.equal(pong.data, 'ECHO:PING\n');

    // hex send -> 二进制响应自动转 hex + hexdump
    await manager.execute({ operation: 'send', session_id: conn.session_id, data: Buffer.from('BIN').toString('hex'), data_encoding: 'hex' });
    const bin = await manager.execute({ operation: 'recv', session_id: conn.session_id, max_bytes: 16 });
    assert.equal(bin.data_encoding, 'hex');
    assert.equal(bin.data, '00deadbeef');
    assert.ok(bin.hexdump.includes('de ad be ef'));

    // base64 send -> 对端关闭 EOF
    await manager.execute({ operation: 'send', session_id: conn.session_id, data: Buffer.from('BYE').toString('base64'), data_encoding: 'base64' });
    const bye = await manager.execute({ operation: 'recv', session_id: conn.session_id, max_bytes: 32 });
    assert.equal(bye.data, 'GOODBYE\n');

    const closed = await manager.execute({ operation: 'close', session_id: conn.session_id });
    assert.equal(closed.closed, true);
    assert.equal(manager.size(), 0);
  } finally {
    manager.dispose();
    await new Promise(resolve => server.close(resolve));
  }
});

test('elf.js: inspectElf / verifyElf 完整校验 checksec、导入、gadget、/bin/sh 与分节回退', () => {
  const elf = buildCraftedElf64();
  const report = inspectElf(elf, { offset: 0, limit: 2 });
  assert.equal(report.format, 'ELF64');
  assert.equal(report.machine, 'x86-64');
  assert.equal(report.entry, '0x400200');
  assert.equal(report.security.nx.enabled, true);
  assert.equal(report.security.pie.enabled, false);
  assert.equal(report.security.relro.status, 'full');
  assert.equal(report.security.canary, true);
  assert.equal(report.security.fortify, false, 'a defined user symbol ending in _chk is not a fortified import');
  assert.ok(report.security.needed.includes('libc.so.6'));
  assert.ok(report.security.imports.notable.includes('system'));
  assert.ok(report.security.imports.notable.includes('gets'));
  assert.ok(report.security.gadgets.patterns.some(g => g.name === 'pop rdi; ret' && g.count > 0));
  assert.ok(report.security.gadgets.patterns.some(g => g.name === 'syscall; ret' && g.count > 0));
  assert.ok(report.pwn.strings.bin_sh);
  assert.equal(report.pwn.strings.bin_sh.section, '.rodata');
  assert.equal(report.layout.rows.length, 2);
  assert.equal(report.layout.next_offset, 2);

  const sectionless = Buffer.from(elf);
  sectionless.writeBigUInt64LE(0n, 40); // e_shoff
  sectionless.writeUInt16LE(0, 60); // e_shnum
  sectionless.writeUInt16LE(0, 62); // e_shstrndx
  const sectionlessReport = inspectElf(sectionless);
  assert.equal(sectionlessReport.section_headers, 0);
  assert.equal(sectionlessReport.security.relro.status, 'full');
  assert.ok(sectionlessReport.security.needed.includes('libc.so.6'));

  const sha = createHash('sha256').update(elf).digest('hex');
  const verified = verifyElf(elf, {
    entry: 0x400200n,
    sha256: sha,
    symbol_label: { base: 0x401000n, displacement: 0x10n, address: 0x401010n },
  });
  assert.equal(verified.checks.entry.status, 'match');
  assert.equal(verified.checks.sha256.status, 'match');
  assert.equal(verified.checks.symbol_label.status, 'match');

  assert.throws(() => inspectElf(Buffer.from('NOT_ELF_AT_ALL')), /不是 ELF/u);
});

test('pwn-payload.js: libc_base/pie_base 基址反推与 ret2libc_x64 组装及参数校验', () => {
  const base = buildPwnPayload({
    operation: 'libc_base',
    leak: '0x7ffff7a64420',
    symbol_offset: '0x84420',
    target_offsets: { system: '0x50d70', bin_sh: '0x1d8678' },
  });
  assert.equal(base.libc_base, '0x7ffff79e0000');
  assert.equal(base.page_aligned, true);
  assert.equal(base.target_addresses.system, '0x7ffff7a30d70');

  const pie = buildPwnPayload({ operation: 'pie_base', leak: '0x555555555200', symbol_offset: '0x1200' });
  assert.equal(pie.pie_base, '0x555555554000');
  assert.equal(pie.page_aligned, true);

  const rop = buildPwnPayload({
    operation: 'ret2libc_x64',
    offset: 16,
    padding_byte: '42',
    pop_rdi_ret: '0x4011a3',
    bin_sh: '0x7ffff7bb8678',
    alignment_ret: '0x40101a',
    system: '0x7ffff7a30d70',
    exit: '0x7ffff7a255f0',
  });
  assert.equal(rop.payload_bytes, 16 + 5 * 8);
  assert.equal(rop.words.length, 5);
  assert.ok(rop.payload_hex.startsWith('42'.repeat(16)));

  assert.throws(() => buildPwnPayload({ operation: 'bad' }), /operation/u);
  assert.throws(() => buildPwnPayload({ operation: 'libc_base', leak: '0x10', symbol_offset: '0x20' }), /大于或等于/u);
  assert.throws(() => buildPwnPayload({ operation: 'libc_base', leak: '0x1000', symbol_offset: '0x0', offset: 8 }), /不支持参数/u);
});

test('audio-metadata.js: WAV/FLAC/ID3v2+ID3v1 元数据解析与异常拦截', () => {
  // 1) WAV (RIFF) + LIST/INFO tag + trailing bytes
  const fmtBody = Buffer.alloc(16);
  fmtBody.writeUInt16LE(1, 0);
  fmtBody.writeUInt16LE(1, 2);
  fmtBody.writeUInt32LE(8000, 4);
  fmtBody.writeUInt32LE(16000, 8);
  fmtBody.writeUInt16LE(2, 12);
  fmtBody.writeUInt16LE(16, 14);
  const infoText = Buffer.from('ctf_wav_flag\0', 'utf8');
  const infoSub = Buffer.concat([Buffer.from('ICMT'), Buffer.alloc(4), infoText, Buffer.alloc(infoText.length & 1)]);
  infoSub.writeUInt32LE(infoText.length, 4);
  const listChunk = Buffer.concat([Buffer.from('LIST'), Buffer.alloc(4), Buffer.from('INFO'), infoSub]);
  listChunk.writeUInt32LE(4 + infoSub.length, 4);
  const dataChunk = Buffer.concat([Buffer.from('data'), Buffer.alloc(4), Buffer.alloc(16)]);
  dataChunk.writeUInt32LE(16, 4);
  const fmtChunk = Buffer.concat([Buffer.from('fmt '), Buffer.alloc(4), fmtBody]);
  fmtChunk.writeUInt32LE(fmtBody.length, 4);
  const riffBody = Buffer.concat([Buffer.from('WAVE'), fmtChunk, listChunk, dataChunk]);
  const wavHeader = Buffer.concat([Buffer.from('RIFF'), Buffer.alloc(4)]);
  wavHeader.writeUInt32LE(riffBody.length, 4);
  const wavReport = inspectAudioMetadata(Buffer.concat([wavHeader, riffBody, Buffer.from('TAIL')]));
  assert.equal(wavReport.status, 'ok');
  assert.equal(wavReport.format, 'WAV');
  assert.equal(wavReport.tags[0].text, 'ctf_wav_flag');
  assert.equal(wavReport.trailing_size, 4);

  // 2) FLAC (STREAMINFO + VORBIS_COMMENT)
  const streamInfo = Buffer.alloc(34);
  const packed = (44100n << 44n) | (1n << 41n) | (15n << 36n) | 44100n;
  streamInfo.writeBigUInt64BE(packed, 10);
  const vendor = Buffer.from('ctf-enc', 'utf8');
  const comment = Buffer.from('COMMENT=flac_secret', 'utf8');
  const vc = Buffer.alloc(4 + vendor.length + 4 + 4 + comment.length);
  vc.writeUInt32LE(vendor.length, 0);
  vendor.copy(vc, 4);
  vc.writeUInt32LE(1, 4 + vendor.length);
  vc.writeUInt32LE(comment.length, 8 + vendor.length);
  comment.copy(vc, 12 + vendor.length);
  const flacBlock = (last, type, body) => {
    const h = Buffer.alloc(4);
    h[0] = (last ? 0x80 : 0) | type;
    h.writeUIntBE(body.length, 1, 3);
    return Buffer.concat([h, body]);
  };
  const flacBytes = Buffer.concat([Buffer.from('fLaC'), flacBlock(false, 0, streamInfo), flacBlock(true, 4, vc)]);
  const flacReport = inspectAudioMetadata(flacBytes);
  assert.equal(flacReport.status, 'ok');
  assert.equal(flacReport.format, 'FLAC');
  assert.equal(flacReport.sample_rate, 44100);
  assert.equal(flacReport.tags[0].name, 'COMMENT');
  assert.equal(flacReport.tags[0].text, 'flac_secret');

  // 3) ID3v2.3 + ID3v1.1
  const framePayload = Buffer.concat([Buffer.from([3]), Buffer.from('id3_title', 'utf8')]);
  const frame = Buffer.concat([Buffer.from('TIT2'), Buffer.alloc(4), Buffer.from([0, 0]), framePayload]);
  frame.writeUInt32BE(framePayload.length, 4);
  const id3Header = Buffer.from([0x49, 0x44, 0x33, 3, 0, 0, 0, 0, 0, frame.length]);
  const id3v1 = Buffer.alloc(128);
  id3v1.write('TAG', 0, 'latin1');
  id3v1.write('OldTitle', 3, 'latin1');
  id3v1[125] = 0;
  id3v1[126] = 7;
  const id3Report = inspectAudioMetadata(Buffer.concat([id3Header, frame, id3v1]));
  assert.equal(id3Report.status, 'ok');
  assert.equal(id3Report.id3v2.tags[0].text, 'id3_title');
  assert.equal(id3Report.id3v1.track, 7);

  assert.equal(inspectAudioMetadata(Buffer.from('RANDOM_BYTES')).status, 'unsupported');
});
