import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, isAbsolute } from 'node:path';
import test from 'node:test';
import { inspectNativeArchive, nativeArchiveFormat, readNativeArchiveMember } from '../archive-directory.js';
import { readZipWithKnownPassword } from '../archive-password.js';
import { readCtfFiles } from '../batch-text.js';
import { compressedStreamFormat, decompressCompressedStream } from '../compressed-stream.js';
import { traceFlaskRoute } from '../flask-route.js';
import { hexAddress, revAddress, revText } from '../rev-evidence.js';
import { queryRevExport } from '../rev-export.js';
import { mapRevAddress } from '../rev-address.js';
import { verifyRevMachine } from '../rev-machine.js';
import { compareRevTrace } from '../rev-trace.js';

const PYTHON = process.platform === 'win32' ? 'python' : 'python3';
const workbench = {
  async resolvePython() { return PYTHON; },
  library() { return ''; },
};

function diskFiles(root) {
  const resolve = path => isAbsolute(path) ? path : join(root, path);
  return {
    normalizePath(path) { return resolve(path); },
    async read(path) {
      const resolved = resolve(path);
      return { bytes: await readFile(resolved), targetKey: resolved };
    },
    async snapshot(path) {
      const resolved = resolve(path);
      try { return { bytes: await readFile(resolved), targetKey: resolved }; }
      catch { return null; }
    },
  };
}

test('此前 0% 覆盖的模块通过真实字节、磁盘文件和 Python worker 路径', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ctf-uncovered-real-'));
  try {
    // 归档路径调用真正的 Python/libarchive worker；坏归档必须返回诊断而非崩溃。
    const sevenZip = Buffer.from('377abcaf271c', 'hex');
    assert.equal(nativeArchiveFormat(sevenZip)?.variant, '7z');
    const badArchive = Buffer.from('not a 7z archive');
    const archiveReport = await inspectNativeArchive(badArchive, { format: '7z', variant: '7z' },
      { offset: 0, limit: 4 }, undefined, workbench);
    assert.ok(['invalid', 'dependency_missing'].includes(archiveReport.status), JSON.stringify(archiveReport));
    const member = await readNativeArchiveMember(badArchive, { format: '7z', variant: '7z' }, 0,
      { offset: 0, length: 8 }, undefined, workbench).catch(error => ({ status: 'unreadable', detail: error.message }));
    assert.ok(['unreadable', 'dependency_missing'].includes(member.status));

    // ZIP 口令 worker 接收真实畸形输入并以结构化错误收敛。
    await assert.rejects(readZipWithKnownPassword(badArchive, 0, 'fixture-password', workbench), /ZIP|口令|读取/u);

    // 批量文本从磁盘读取，并保留行号与原件摘要。
    await writeFile(join(dir, 'notes.txt'), '第一行\r\n第二行\r\n第三行\r\n');
    const files = diskFiles(dir);
    const batch = await readCtfFiles({ files: [{ file_path: 'notes.txt', start_line: 2, line_count: 2 }] }, files);
    assert.equal(batch.status, 'ok');
    assert.equal(batch.items[0].text, '第二行\r\n第三行\r\n');
    assert.match(batch.sources[0].sha256, /^[a-f0-9]{64}$/u);

    // bzip2/xz 由本机 Python 标准库生成，再由受限 worker 真解压。
    const source = Buffer.from('real compressed worker payload\n');
    for (const [format, encoder] of [['bzip2', 'bz2.compress'], ['xz', 'lzma.compress']]) {
      const encoded = execFileSync(PYTHON, ['-c', `import ${format === 'bzip2' ? 'bz2' : 'lzma'},sys;sys.stdout.buffer.write(${encoder}(sys.stdin.buffer.read()))`], { input: source });
      assert.equal(compressedStreamFormat(encoded), format);
      const decoded = await decompressCompressedStream(encoded, format, undefined, workbench);
      assert.equal(decoded.status, 'ok');
      assert.deepEqual(decoded.bytes, source);
    }

    // Flask AST worker 只解析磁盘源码，不导入或执行赛题模块。
    const flaskSource = [
      'from flask import Flask',
      'app = Flask(__name__)',
      "@app.get('/items/<int:item_id>')",
      'def item(item_id):',
      '    return str(item_id)',
      '',
    ].join('\n');
    await writeFile(join(dir, 'app.py'), flaskSource);
    const flaskFiles = { ...files, normalizePath(path) { return path; } };
    const flask = await traceFlaskRoute({ entry_file: 'app.py', request: { method: 'GET', path: '/items/7' } }, flaskFiles, undefined, workbench);
    assert.equal(flask.status, 'matched', JSON.stringify(flask));
    assert.equal(flask.request.path, '/items/7');

    // Reverse evidence readers consume UTF-8 bytes with stable address/hash handling.
    assert.equal(revAddress('0x1000'), 0x1000n);
    assert.equal(hexAddress(0x1000n), '0x1000');
    assert.equal([...revText(Buffer.from('line\n'), 'fixture.txt').rows][0].content, 'line');

    const exportBytes = Buffer.from([
      JSON.stringify({ kind: 'function', address: '0x1000', name: 'entry', size: 4 }),
      JSON.stringify({ kind: 'function', address: '0x2000', name: 'worker' }),
      JSON.stringify({ kind: 'call', address: '0x1002', from: '0x1000', to: '0x2000' }),
    ].join('\n'));
    const exported = queryRevExport(exportBytes, 'listing.jsonl', 'jsonl', { kind: 'function', value: 'entry' });
    assert.equal(exported.status, 'matched');
    assert.equal(exported.matches[0].outgoing_count, 1);

    const wasm = Buffer.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0, 0, 3, 1, 0x78, 0x41]);
    const mapped = mapRevAddress(wasm, 'fixture.wasm', { queries: [
      { kind: 'section_offset', value: '0x0', section_index: 0 },
    ] });
    assert.equal(mapped.status, 'ok');
    assert.equal(mapped.mappings[0].file_offset, 10);

    const machineRules = Buffer.from([
      JSON.stringify({ kind: 'start', state: 's', width: 8, value: '0' }),
      JSON.stringify({ kind: 'rule', state: 's', byte: '*', next: 's', operation: 'word_add', operand: 'input', emit: true }),
    ].join('\n'));
    const machine = verifyRevMachine(machineRules, 'rules.jsonl', {
      input_hex: '02', expected_state: 's', expected_value: '2',
    });
    assert.equal(machine.status, 'ok');
    assert.equal(machine.output[0], '2');

    await writeFile(join(dir, 'observed.jsonl'), `${JSON.stringify({ step: 1, state: 's', value: '2' })}\n`);
    await writeFile(join(dir, 'reference.jsonl'), `${JSON.stringify({ step: 1, state: 's', value: '2' })}\n`);
    const trace = await compareRevTrace({ file_path: 'observed.jsonl', reference_path: 'reference.jsonl', fields: ['state', 'value'] }, files);
    assert.equal(trace.status, 'match');
    assert.equal(trace.matched_steps, 1);
  } finally {
    await rm(dir, { recursive: true, force: true, maxRetries: 8, retryDelay: 120 });
  }
});
