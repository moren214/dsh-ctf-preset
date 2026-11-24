import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deflateSync } from 'node:zlib';
import test from 'node:test';
import { apply } from '../ctf-tools.js';
import { runCryptoSolve, temperMt19937, untemperMt19937 } from '../crypto-toolbox.js';
import { runRevQuery } from '../rev-query.js';

function b64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
  return buf.toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function signJwt(header, payload, secret, alg = 'HS256') {
  const map = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' };
  const head = b64url(JSON.stringify({ ...header, alg }));
  const body = b64url(JSON.stringify(payload));
  const sig = alg === 'none' ? '' : b64url(createHmac(map[alg], secret).update(`${head}.${body}`).digest());
  return `${head}.${body}.${sig}`;
}

function signFlaskSession(payloadObj, secret, { compress = false, salt = 'cookie-session', timestamp = 1700000000 } = {}) {
  const rawJson = Buffer.from(JSON.stringify(payloadObj), 'utf8');
  const payloadSeg = compress ? '.' + b64url(deflateSync(rawJson)) : b64url(rawJson);
  const tsBuf = Buffer.alloc(4);
  tsBuf.writeUInt32BE(timestamp, 0);
  const signedVal = `${payloadSeg}.${b64url(tsBuf)}`;
  const derived = createHmac('sha1', secret).update(salt).digest();
  const sig = b64url(createHmac('sha1', derived).update(signedVal).digest());
  return `${signedVal}.${sig}`;
}

function buildElf32X86WithPayload(rodataBytes) {
  // Minimal valid ELF32 (x86) with .text, .rodata, .shstrtab + 1 PT_LOAD
  const code = Buffer.from([0x55, 0x89, 0xe5, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0x5d, 0xc3]); // push ebp; mov ebp,esp; mov eax,42; pop ebp; ret
  const shstrtab = Buffer.from('\0.text\0.rodata\0.shstrtab\0', 'ascii');
  const ehdrSize = 52;
  const phdrSize = 32;
  const textOff = 0x60;
  const rodataOff = 0x80;
  const shstrOff = rodataOff + rodataBytes.length;
  const shoff = (shstrOff + shstrtab.length + 3) & ~3;
  const totalSize = shoff + 4 * 40;
  const buf = Buffer.alloc(totalSize);
  buf.set([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1, 0], 0); // ELFCLASS32, LSB
  buf.writeUInt16LE(2, 16); // ET_EXEC
  buf.writeUInt16LE(3, 18); // EM_386
  buf.writeUInt32LE(1, 20);
  buf.writeUInt32LE(0x08048000 + textOff, 24); // e_entry
  buf.writeUInt32LE(ehdrSize, 28); // e_phoff
  buf.writeUInt32LE(shoff, 32); // e_shoff
  buf.writeUInt32LE(0, 36);
  buf.writeUInt16LE(ehdrSize, 40);
  buf.writeUInt16LE(phdrSize, 42);
  buf.writeUInt16LE(1, 44);
  buf.writeUInt16LE(40, 46);
  buf.writeUInt16LE(4, 48);
  buf.writeUInt16LE(3, 50); // shstrndx
  // Elf32_Phdr: type, offset, vaddr, paddr, filesz, memsz, flags, align
  buf.writeUInt32LE(1, ehdrSize);
  buf.writeUInt32LE(0, ehdrSize + 4);
  buf.writeUInt32LE(0x08048000, ehdrSize + 8);
  buf.writeUInt32LE(0x08048000, ehdrSize + 12);
  buf.writeUInt32LE(shoff, ehdrSize + 16);
  buf.writeUInt32LE(shoff, ehdrSize + 20);
  buf.writeUInt32LE(5, ehdrSize + 24); // PF_R | PF_X
  buf.writeUInt32LE(0x1000, ehdrSize + 28);

  code.copy(buf, textOff);
  rodataBytes.copy(buf, rodataOff);
  shstrtab.copy(buf, shstrOff);

  const writeShdr = (idx, nameOff, type, flags, addr, off, size) => {
    const p = shoff + idx * 40;
    buf.writeUInt32LE(nameOff, p);
    buf.writeUInt32LE(type, p + 4);
    buf.writeUInt32LE(flags, p + 8);
    buf.writeUInt32LE(addr, p + 12);
    buf.writeUInt32LE(off, p + 16);
    buf.writeUInt32LE(size, p + 20);
  };
  writeShdr(1, 1, 1, 0x6, 0x08048000 + textOff, textOff, code.length);
  writeShdr(2, 7, 1, 0x2, 0x08048000 + rodataOff, rodataOff, rodataBytes.length);
  writeShdr(3, 15, 3, 0, 0, shstrOff, shstrtab.length);
  return buf;
}

function buildPe64WithPayload(rdataBytes) {
  // Minimal PE32+ (AMD64) with .text and .rdata
  const lfanew = 0x80;
  const optSize = 240;
  const textRawOff = 0x200;
  const rdataRawOff = 0x400;
  const rdataSize = Math.max(0x200, ((rdataBytes.length + 0x1ff) & ~0x1ff));
  const buf = Buffer.alloc(rdataRawOff + rdataSize);
  buf.write('MZ', 0, 'ascii');
  buf.writeUInt32LE(lfanew, 0x3c);
  buf.write('PE\0\0', lfanew, 'ascii');
  // COFF header
  buf.writeUInt16LE(0x8664, lfanew + 4); // AMD64
  buf.writeUInt16LE(2, lfanew + 6); // 2 sections
  buf.writeUInt16LE(optSize, lfanew + 20);
  // Optional header PE32+
  const opt = lfanew + 24;
  buf.writeUInt16LE(0x20b, opt); // PE32+
  buf.writeUInt32LE(0x1000, opt + 16); // AddressOfEntryPoint
  buf.writeBigUInt64LE(0x140000000n, opt + 24); // ImageBase
  // Sections
  const sec = opt + optSize;
  buf.write('.text', sec, 'ascii');
  buf.writeUInt32LE(0x100, sec + 8); // vsize
  buf.writeUInt32LE(0x1000, sec + 12); // vaddr
  buf.writeUInt32LE(0x200, sec + 16); // raw size
  buf.writeUInt32LE(textRawOff, sec + 20); // raw ptr
  buf.writeUInt32LE(0x60000020, sec + 36); // EXEC | READ | CODE

  buf.write('.rdata', sec + 40, 'ascii');
  buf.writeUInt32LE(rdataBytes.length, sec + 48);
  buf.writeUInt32LE(0x2000, sec + 52);
  buf.writeUInt32LE(rdataSize, sec + 56);
  buf.writeUInt32LE(rdataRawOff, sec + 60);
  buf.writeUInt32LE(0x40000040, sec + 76); // READ | INITIALIZED_DATA

  // x86-64 code: mov eax, 0x1337; ret
  Buffer.from('b837130000c3', 'hex').copy(buf, textRawOff);
  rdataBytes.copy(buf, rdataRawOff);
  return buf;
}

test('crypto-toolbox: jwt_inspect 与 jwt_crack 支持弱算法识别、字典与自定义候选破解', async () => {
  const noneTok = signJwt({ typ: 'JWT', kid: '../key.pem' }, { sub: 'admin', exp: 1000000000 }, '', 'none');
  const inspected = await runCryptoSolve({ operation: 'jwt_inspect', token: noneTok });
  assert.equal(inspected.status, 'ok');
  assert.equal(inspected.alg, 'none');
  assert.ok(inspected.findings.some(f => f.code === 'alg_none'));
  assert.ok(inspected.findings.some(f => f.code === 'kid_present'));
  assert.equal(inspected.timing.expired, true);

  const hs256Tok = signJwt({ typ: 'JWT' }, { role: 'user' }, 'supersecret', 'HS256');
  const crackedBuiltin = await runCryptoSolve({ operation: 'jwt_crack', token: hs256Tok });
  assert.equal(crackedBuiltin.status, 'found');
  assert.equal(crackedBuiltin.secret, 'supersecret');

  const hs512Tok = signJwt({ typ: 'JWT' }, { role: 'ctf' }, 'my_wordlist_secret_99', 'HS512');
  const crackedWordlist = await runCryptoSolve(
    { operation: 'jwt_crack', token: hs512Tok, wordlist: 'words.txt' },
    { readWordlist: async () => 'nope1\nmy_wordlist_secret_99\nnope2\n' },
  );
  assert.equal(crackedWordlist.status, 'found');
  assert.equal(crackedWordlist.secret, 'my_wordlist_secret_99');
  assert.equal(crackedWordlist.tried, 2);
});

test('crypto-toolbox: flask_session 解码未压缩与 zlib 压缩 Cookie 并恢复 SECRET_KEY', async () => {
  const plainCookie = signFlaskSession({ user: 'alice', admin: false }, 'secret', { compress: false });
  const r1 = await runCryptoSolve({ operation: 'flask_session', token: plainCookie });
  assert.equal(r1.status, 'found');
  assert.equal(r1.compressed, false);
  assert.deepEqual(r1.payload, { user: 'alice', admin: false });
  assert.equal(r1.secret, 'secret');

  const bigObj = { user: 'bob', bio: 'A'.repeat(200), admin: true };
  const compCookie = signFlaskSession(bigObj, 'custom_flask_key', { compress: true });
  const r2 = await runCryptoSolve({
    operation: 'flask_session', token: compCookie, passwords: ['wrong', 'custom_flask_key'],
  });
  assert.equal(r2.status, 'found');
  assert.equal(r2.compressed, true);
  assert.deepEqual(r2.payload, bigObj);
  assert.equal(r2.secret, 'custom_flask_key');

  const decodeOnly = await runCryptoSolve({ operation: 'flask_session', token: compCookie, crack: false });
  assert.equal(decodeOnly.status, 'ok');
  assert.equal(decodeOnly.secret, undefined);
});

test('crypto-toolbox: lcg_recover 从未知模数与已知模数反推参数并精准预测后续输出', async () => {
  // 未知 64 位素数模数
  const m = 4294967291n;
  const a = 1103515245n;
  const c = 12345n;
  const seq = [987654321n];
  for (let i = 0; i < 12; i += 1) seq.push((a * seq.at(-1) + c) % m);

  const recovered = await runCryptoSolve({
    operation: 'lcg_recover',
    outputs: seq.slice(0, 8).map(v => v.toString()),
    predict_count: 5,
  });
  assert.equal(recovered.status, 'ok');
  assert.equal(recovered.modulus_recovered, true);
  assert.equal(recovered.modulus, m.toString());
  assert.equal(recovered.multiplier, a.toString());
  assert.equal(recovered.increment, c.toString());
  assert.deepEqual(recovered.predictions, seq.slice(8, 13).map(v => v.toString()));

  // 已知模数仅需 3 个输出
  const knownM = await runCryptoSolve({
    operation: 'lcg_recover',
    modulus: m.toString(),
    outputs: seq.slice(0, 3).map(v => v.toString()),
    predict_count: 3,
  });
  assert.equal(knownM.modulus_recovered, false);
  assert.deepEqual(knownM.predictions, seq.slice(3, 6).map(v => v.toString()));
});

test('crypto-toolbox: mt19937_recover 与 Python random.Random 逐比特一致', async () => {
  assert.equal(temperMt19937(untemperMt19937(0xdeadbeef)), 0xdeadbeef);
  assert.equal(temperMt19937(untemperMt19937(0x12345678)), 0x12345678);

  const python = process.platform === 'win32' ? 'python' : 'python3';
  const raw = execFileSync(python, [
    '-c', 'import json, random; r = random.Random(20261124); print(json.dumps([r.getrandbits(32) for _ in range(634)]))',
  ], { encoding: 'utf8' });
  const all = JSON.parse(raw);
  const res = await runCryptoSolve({
    operation: 'mt19937_recover',
    outputs: all.slice(0, 624),
    predict_count: 10,
  });
  assert.equal(res.status, 'ok');
  assert.deepEqual(res.predictions, all.slice(624, 634));
});

test('crypto_solver template 生成的 4 个脚手架均无 NotImplementedError 且通过 Python 语法编译', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'ctf-templates-'));
  try {
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
        contains(parent, child) { return child.targetKey === parent.targetKey || child.targetKey.startsWith(parent.targetKey + '/'); },
        async lstat(name, options) {
          const { lstat } = await import('node:fs/promises');
          const rel = resolveTarget(name, options).targetKey.slice(cwd.replace(/[\\/]$/u, '').length + 1);
          try {
            const info = await lstat(join(cwd, rel));
            return { type: info.isDirectory() ? 'directory' : 'file' };
          } catch { return undefined; }
        },
      },
    };
    apply(ctx, {});
    const execution = { signal: new AbortController().signal, agent: { session: { header: { cwd }, id: 'tpl-test' } } };
    const python = process.platform === 'win32' ? 'python' : 'python3';

    for (const kind of ['z3_bitvec', 'coppersmith', 'lattice', 'aes_mode']) {
      const out = JSON.parse(await tools.get('crypto_solver').execute({ action: 'template', kind }, execution));
      assert.equal(out.status, 'ok', JSON.stringify(out));
      const src = await readFile(out.file, 'utf8');
      assert.equal(src.includes('NotImplementedError'), false, `${kind} should not contain NotImplementedError`);
      execFileSync(python, ['-c', 'import sys; compile(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1], "exec")', out.file]);
    }

    const checkOut = JSON.parse(await tools.get('crypto_solver').execute({ action: 'check' }, execution));
    assert.equal(checkOut.status, 'ok', JSON.stringify(checkOut));
    const anyMissing = Object.values(checkOut.modules).some(m => !m.ok);
    if (anyMissing) {
      assert.ok(checkOut.sandbox_fallback && typeof checkOut.sandbox_fallback.hint === 'string');
    }
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('rev_query 支持 ELF32(x86)、PE32+(x86-64) 及无 Capstone 的 triage 特征快检', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'ctf-rev-upgrade-'));
  try {
    const aesSboxPrefix = Buffer.from([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]);
    const teaDelta = Buffer.alloc(4);
    teaDelta.writeUInt32LE(0x9e3779b9, 0);
    const customB64 = Buffer.from('ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/', 'ascii');
    const rodata = Buffer.concat([
      Buffer.from('UPX!hello_ctf_string\0', 'ascii'),
      aesSboxPrefix,
      teaDelta,
      Buffer.from('\0', 'ascii'),
      customB64,
      Buffer.from('\0', 'ascii'),
    ]);

    await writeFile(join(cwd, 'sample32.elf'), buildElf32X86WithPayload(rodata));
    await writeFile(join(cwd, 'sample64.exe'), buildPe64WithPayload(rodata));

    const triageElf = await runRevQuery({ file_path: 'sample32.elf', operation: 'triage' }, { cwd });
    assert.equal(triageElf.format, 'elf32');
    assert.equal(triageElf.architecture, 'x86');
    assert.ok(triageElf.markers.some(m => m.name === 'UPX'));
    assert.ok(triageElf.crypto_constants.some(c => c.algorithm === 'AES_SBOX'));
    assert.ok(triageElf.crypto_constants.some(c => c.algorithm === 'TEA_DELTA_LE'));
    assert.ok(triageElf.base64_candidates.some(b => b.kind === 'custom_alphabet'));

    const stringsElf = await runRevQuery({ file_path: 'sample32.elf', operation: 'strings', min_length: 8 }, { cwd });
    assert.ok(stringsElf.strings.some(s => s.text.includes('hello_ctf_string')));

    const triagePe = await runRevQuery({ file_path: 'sample64.exe', operation: 'triage' }, { cwd });
    assert.equal(triagePe.format, 'pe32+');
    assert.equal(triagePe.architecture, 'x86-64');
    assert.equal(triagePe.entry, '0x140001000');
    assert.ok(triagePe.crypto_constants.some(c => c.algorithm === 'AES_SBOX'));

    const stringsPe = await runRevQuery({ file_path: 'sample64.exe', operation: 'strings', min_length: 8 }, { cwd });
    assert.ok(stringsPe.strings.some(s => s.text.includes('hello_ctf_string')));
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
