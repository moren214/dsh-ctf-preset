import test from 'node:test';
import assert from 'node:assert/strict';
import { pathParts } from '../ctf-tools.js';

test('接受嵌套路径与中文文件名', () => {
  assert.deepEqual(pathParts('attachments/题目 1.zip'), ['attachments', '题目 1.zip']);
  assert.deepEqual(pathParts('a\\b.txt'), ['a', 'b.txt']);
  assert.deepEqual(pathParts('./a.txt'), ['a.txt']);
});

test('拒绝绝对路径（Windows 盘符、POSIX、UNC）', () => {
  assert.throws(() => pathParts('C:\\Users\\x.zip'), /相对路径/);
  assert.throws(() => pathParts('/tmp/x'), /相对路径/);
  assert.throws(() => pathParts('\\\\server\\share\\x'), /相对路径/);
  assert.throws(() => pathParts('a:b.txt'), /相对路径/);
});

test('拒绝目录穿越与空路径', () => {
  assert.throws(() => pathParts('../x'), /普通附件文件/);
  assert.throws(() => pathParts('a/../b'), /普通附件文件/);
  assert.throws(() => pathParts('a//b'), /普通附件文件/);
  assert.throws(() => pathParts(''), /普通附件文件/);
  assert.throws(() => pathParts('a/b./c'), /普通附件文件/);
});

test('拒绝控制字符与超长路径', () => {
  assert.throws(() => pathParts('a\u0000b'), /相对路径/);
  assert.throws(() => pathParts('a\nb'), /相对路径/);
  assert.throws(() => pathParts('a/'.repeat(49) + 'x'), /普通附件文件/);
});
