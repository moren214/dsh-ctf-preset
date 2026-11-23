import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { createHash } from 'node:crypto';
import { mkdtemp, writeFile, unlink, rmdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { readResponseBody, redirectBlockReason, httpRequest } from '../http-client.js';
import { classifyVerdict, handleSubmission } from '../submission.js';
import { calculateSteps } from '../offline-calculation.js';
import { inspectExif } from '../exif.js';
import { createWorkbenchEnvironment } from '../workbench-config.js';
import { downloadAttachment } from '../attachment-transfer.js';

test('同主机 HTTPS 升级允许重新授权，其他域及带凭证的地址仍被拒绝', async () => {
  const source = new URL('http://example.test/local');
  assert.equal(redirectBlockReason(source, new URL('https://example.test/local'), 'GET', 0), undefined);
  assert.equal(redirectBlockReason(source, new URL('https://example.test/local'), 'POST', 0), 'request_replay');
  assert.equal(redirectBlockReason(source, new URL('https://other.test/'), 'GET', 0), 'cross_origin_or_credentials');
  await assert.rejects(httpRequest({ url: 'http://account:dummy@host.test/' }),
    error => /用户名或密码/u.test(error.message) && !error.message.includes('dummy'));
});

test('HTTP 正文中途失败保留已经读取的字节', async () => {
  const source = Readable.from((async function* () {
    yield Buffer.from('observed bytes');
    await new Promise(resolve => setImmediate(resolve));
    throw new Error('synthetic input ended early');
  })());
  const result = await readResponseBody(source, { method: 'GET', status: 200, limit: 128, retainPartial: true });
  assert.equal(result.buffer.toString(), 'observed bytes');
  assert.ok(result.readError);
});

test('平台普通确认消息与不完整响应不能视为提交成功', () => {
  assert.equal(classifyVerdict({ status: 200, body: '{"ok":true,"message":"ok"}' }), 'unknown');
  assert.equal(classifyVerdict({ status: 200, body: '{"correct":true}', body_error: { code: 'response_incomplete' } }), 'unknown');
  assert.equal(classifyVerdict({ status: 200, body: '{"data":{"accepted":true}}' }), 'accepted');
});

test('自定义预检格式可校验，并在取消时释放工作线程', async () => {
  const files = { async read() { return { document: {}, receipts: [] }; } };
  const args = { flag: 'demo{fixture}', source: 'fixture', pattern: '^demo\\{[a-z]+\\}$' };
  assert.equal((await handleSubmission(args, files)).ready, true);
  assert.equal((await handleSubmission({ ...args, pattern: '[' }, files)).ready, false);
  const abort = new AbortController();
  const pending = handleSubmission(args, files, undefined, undefined, abort.signal);
  abort.abort();
  await assert.rejects(pending, { name: 'AbortError' });
});

test('MIME 换行、二进制 URL 和表单及 HTML 字节编码可往返', () => {
  const report = calculateSteps([
    { operation: 'convert_encoding', inputs: [' YWJj\r\nZA== '], from_encoding: 'base64', to_encoding: 'utf8', expected: 'abcd' },
    { operation: 'encode', inputs: ['00ff202b'], scheme: 'url', from_encoding: 'hex', expected: '%00%FF%20%2B' },
    { operation: 'decode', inputs: [{ step: 2 }], scheme: 'url', to_encoding: 'hex', expected: '00ff202b' },
    { operation: 'encode', inputs: ['00ff202b'], scheme: 'form', from_encoding: 'hex', expected: '%00%FF+%2B' },
    { operation: 'decode', inputs: [{ step: 4 }], scheme: 'form', to_encoding: 'hex', expected: '00ff202b' },
    { operation: 'encode', inputs: ['00ff'], scheme: 'html_bytes', from_encoding: 'hex', expected: '&#x00;&#xff;' },
    { operation: 'decode', inputs: [{ step: 6 }], scheme: 'html_bytes', to_encoding: 'hex', expected: '00ff' },
  ]);
  assert.equal(report.status, 'ok');
  const invalid = calculateSteps([{ operation: 'convert_encoding', inputs: ['YW@Jj'], from_encoding: 'base64', to_encoding: 'hex' }]);
  assert.equal(invalid.steps[0].status, 'error');
});

test('长计算结果分页并参与后续步骤的完整计算', () => {
  const text = '界'.repeat(1800);
  const expected = '%E7%95%8C'.repeat(1800);
  const output = calculateSteps([
    { operation: 'encode', inputs: [text], scheme: 'url', result_offset: 4096 },
    { operation: 'decode', inputs: [{ step: 1 }], scheme: 'url', expected: text },
  ]);
  assert.equal(output.status, 'ok');
  assert.equal(output.steps[0].result, expected.slice(4096, 8192));
  assert.equal(output.steps[0].next_result_offset, 8192);
  assert.equal(output.steps[0].result_sha256, createHash('sha256').update(expected).digest('hex'));
  assert.equal(output.steps[1].result, text);
});

test('复合因子的算术夹具不返回被误判为有效的明文', () => {
  const output = calculateSteps([{ operation: 'rsa_attack', rsa_mode: 'factor', inputs: ['30', '7', '0'] }]);
  assert.equal(output.steps[0].status, 'error');
  assert.match(output.steps[0].reason, /两个不同的素数/u);
  assert.equal(output.steps[0].result, undefined);
});

test('附件下载以调用方选择的上限判断内容长度', async () => {
  const response = Object.assign(Readable.from([]), { statusCode: 200, headers: { 'content-length': '9' } });
  await assert.rejects(downloadAttachment('https://fixture.example.test/', 'not-created', {
    limit: 8,
    resolveAddress: async () => [{ address: '8.8.8.8', family: 4 }],
    request: async () => response,
  }), /大小上限/u);
  assert.ok(response.destroyed);
});

test('EXIF 相机字段带原件的准确偏移', () => {
  const data = Buffer.alloc(44);
  data.write('II');
  data.writeUInt16LE(42, 2);
  data.writeUInt32LE(8, 4);
  data.writeUInt16LE(2, 8);
  data.writeUInt16LE(0x0112, 10);
  data.writeUInt16LE(3, 12);
  data.writeUInt32LE(1, 14);
  data.writeUInt16LE(6, 18);
  data.writeUInt16LE(0x010f, 22);
  data.writeUInt16LE(2, 24);
  data.writeUInt32LE(8, 26);
  data.writeUInt32LE(36, 30);
  data.write('fixture\0', 36);
  const exif = inspectExif(data, 100);
  assert.equal(exif.status, 'ok');
  assert.deepEqual(exif.orientation, { value: 6, file_offset: 118 });
  assert.deepEqual(exif.make, { value: 'fixture', file_offset: 136 });
});

test('用户配置和插件节点使用同一合并结果，优先采用显式节点值', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ctf-config-test-'));
  const file = join(directory, 'ctf-workbench.json');
  try {
    await writeFile(file, JSON.stringify({ platformTeamId: 'fixture', libarchivePath: join(directory, 'libarchive'),
      platformInstancesPath: '/my-instances', browserPath: 'default-browser' }));
    const environment = createWorkbenchEnvironment({ browserPath: 'overridden-browser', platformInstancesPath: undefined }, file);
    const config = environment.presetConfig();
    assert.equal(config.platformTeamId, 'fixture');
    assert.equal(config.platformInstancesPath, '/my-instances');
    assert.equal(config.browserPath, 'overridden-browser');
    assert.equal(environment.library(), join(directory, 'libarchive'));
    assert.equal(environment.configurationIssue(), undefined);
  } finally {
    await unlink(file);
    await rmdir(directory);
  }
});
