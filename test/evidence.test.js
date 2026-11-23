import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { verifyEvidence } from '../evidence.js';

const bytes = Buffer.from('FLAG{abc}\nnext line\n', 'utf8');
const rangeSha = createHash('sha256').update(bytes.subarray(0, 9)).digest('hex');

function readFile(name) {
  return Promise.resolve({ bytes, targetKey: name });
}

test('result_id 记录（byte_offset + 片段 SHA-256）可复核一致', async () => {
  const sources = [
    { file_path: 'a.bin', byte_offset: 0, byte_length: 9, expected_range_sha256: rangeSha },
    { file_path: 'b.bin', byte_offset: 0, byte_length: 9, expected_range_sha256: rangeSha },
  ];
  const report = await verifyEvidence(sources, 'FLAG{abc}', readFile);
  assert.equal(report.status, 'consistent');
  assert.equal(report.observations.every(item => item.status === 'observed'), true);
  assert.equal(report.recomputed, true);
});

test('片段 SHA-256 不符时不可用', async () => {
  const sources = [
    { file_path: 'a.bin', byte_offset: 0, byte_length: 9, expected_range_sha256: '0'.repeat(64) },
    { file_path: 'b.bin', byte_offset: 0, byte_length: 9, expected_range_sha256: '0'.repeat(64) },
  ];
  const report = await verifyEvidence(sources, 'FLAG{abc}', readFile);
  assert.equal(report.status, 'insufficient');
  assert.equal(report.observations.every(item => item.status === 'missing'), true);
});

test('少于两个文件时不足以一致', async () => {
  const sources = [{ file_path: 'a.bin', byte_offset: 0, byte_length: 9, expected_range_sha256: rangeSha }];
  const report = await verifyEvidence(sources, 'FLAG{abc}', readFile);
  assert.equal(report.status, 'insufficient');
});

test('期望值不一致时报告冲突', async () => {
  const sources = [
    { file_path: 'a.bin', byte_offset: 0, byte_length: 9, expected_range_sha256: rangeSha },
    { file_path: 'b.bin', byte_offset: 0, byte_length: 5, expected_range_sha256: createHash('sha256').update(bytes.subarray(0, 5)).digest('hex') },
  ];
  const report = await verifyEvidence(sources, 'FLAG{abc}', readFile);
  assert.equal(report.status, 'conflict');
});

test('原件哈希正确也不能把超出文件的范围当作完整证据', async () => {
  const expected_file_sha256 = createHash('sha256').update(bytes).digest('hex');
  const sources = ['a', 'b'].map(file_path => ({ file_path, byte_offset: 0, byte_length: bytes.length + 1, expected_file_sha256 }));
  const report = await verifyEvidence(sources, undefined, readFile);
  assert.equal(report.status, 'insufficient');
  assert.equal(report.recomputed, undefined);
  assert.ok(report.observations.every(item => item.status === 'missing'));
});
