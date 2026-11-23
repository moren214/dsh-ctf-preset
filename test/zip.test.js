import test from 'node:test';
import assert from 'node:assert/strict';
import { crc32 } from 'node:zlib';
import { isZip, inspectZip, readZipMember } from '../zip-directory.js';

function storedZip(name, content) {
  const nameBytes = Buffer.from(name);
  const data = Buffer.from(content, 'utf8');
  const crc = crc32(data);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0x0800, 6);
  local.writeUInt16LE(0x21, 12);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(nameBytes.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0x0800, 8);
  central.writeUInt16LE(0x21, 14);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(nameBytes.length, 28);
  const cdOffset = local.length + nameBytes.length + data.length;
  const cdSize = central.length + nameBytes.length;
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(cdSize, 12);
  eocd.writeUInt32LE(cdOffset, 16);
  return Buffer.concat([local, nameBytes, data, central, nameBytes, eocd]);
}

test('识别 ZIP 并列出中文成员目录', () => {
  const zip = storedZip('题目/说明.txt', 'hello');
  assert.equal(isZip(zip), true);
  const report = inspectZip(zip, { offset: 0, limit: 16 });
  assert.equal(report.status, 'ok');
  assert.equal(report.layout.total, 1);
  assert.equal(report.layout.rows[0].name, '题目/说明.txt');
  assert.equal(report.layout.rows[0].uncompressed_size, 5);
});

test('非 ZIP 数据与截断归档被拒绝', () => {
  const plain = Buffer.from('not a zip at all');
  assert.equal(isZip(plain), false);
  const truncated = storedZip('a.txt', 'x').subarray(0, 20);
  assert.throws(() => inspectZip(truncated, { offset: 0, limit: 8 }), /附件结构无效|ZIP|目录/u);
});

test('ZIP 长 GBK 名及单独设置的加密标记需通过原件 CRC 校验', async () => {
  const name = Buffer.concat([Buffer.from([0xd6, 0xd0, 0xce, 0xc4]), Buffer.from('a'.repeat(128) + '.txt')]);
  const zip = storedZip(name, 'sample contents');
  const central = zip.readUInt32LE(zip.length - 6);
  zip.writeUInt16LE(0, 6);
  zip.writeUInt16LE(1, central + 8);
  const listed = inspectZip(zip, { offset: 0, limit: 5 }).layout.rows[0];
  assert.equal(listed.name, '中文' + 'a'.repeat(128) + '.txt');
  assert.equal(listed.name_encoding, 'GB18030');
  const reader = { size: zip.length, read: async (offset, length) => zip.subarray(offset, offset + length) };
  const member = await readZipMember(reader, 0);
  assert.equal(member.encryption_flag_only, true);
  assert.equal(member.bytes.toString(), 'sample contents');
  zip[30 + name.length] ^= 1;
  await assert.rejects(readZipMember(reader, 0), /校验/u);
});
