import { execFile } from 'node:child_process';
import { dirname } from 'node:path';
import { MAX_ARCHIVE_MEMBER_BYTES, MAX_ATTACHMENT_BYTES } from './attachment-layout.js';
import { WorkbenchDependencyError } from './workbench-config.js';
import { ToolError } from './tool-errors.js';

const worker = String.raw`
import base64, io, json, stat, sys, zipfile

def read():
    opts = json.loads(sys.stdin.buffer.readline(8192))
    data = sys.stdin.buffer.read(opts["max_archive"] + 1)
    if len(data) > opts["max_archive"]:
        raise ValueError("archive size")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if opts["index"] >= len(entries):
            return {"status": "invalid_member"}
        entry = entries[opts["index"]]
        mode = stat.S_IFMT(entry.external_attr >> 16)
        if entry.is_dir() or mode not in (0, stat.S_IFREG):
            return {"status": "invalid_member"}
        if entry.file_size > opts["max_member"]:
            return {"status": "oversize"}
        with archive.open(entry, pwd=opts["password"].encode("utf-8")) as stream:
            contents = stream.read(opts["max_member"] + 1)
        if len(contents) != entry.file_size:
            return {"status": "invalid_archive"}
        return {"status": "ok", "name": entry.filename[:1024], "bytes": base64.b64encode(contents).decode("ascii")}

try:
    result = read()
except NotImplementedError:
    result = {"status": "unsupported"}
except (RuntimeError, zipfile.BadZipFile, ValueError, OSError):
    result = {"status": "unreadable"}
print(json.dumps(result))
`;

export async function readZipWithKnownPassword(bytes, index, password, workbench, signal) {
  if (typeof password !== 'string' || !password || Buffer.byteLength(password, 'utf8') > 512) {
    throw new ToolError('encoding', '需提供一个已知 ZIP 口令，UTF-8 长度限 512 字节。');
  }
  let python;
  try {
    python = await workbench.resolvePython(signal);
  } catch (error) {
    if (!(error instanceof WorkbenchDependencyError)) throw error;
    return { status: 'dependency_missing', reason: error.message };
  }
  const input = JSON.stringify({ index, password, max_archive: MAX_ATTACHMENT_BYTES, max_member: MAX_ARCHIVE_MEMBER_BYTES }) + '\n';
  return new Promise((resolve, reject) => {
    const child = execFile(python, ['-I', '-S', '-B', '-c', worker], {
      cwd: dirname(python), encoding: 'utf8', windowsHide: true, signal,
      timeout: 15000, maxBuffer: MAX_ARCHIVE_MEMBER_BYTES * 2,
    }, (error, stdout) => {
      if (error) return reject(signal?.aborted ? signal.reason : new ToolError('dependency', 'ZIP 口令读取器运行失败或超时。'));
      try {
        const result = JSON.parse(stdout);
        if (result.status !== 'ok') {
          if (result.status === 'unsupported') throw new ToolError('unsupported', '当前 ZIP 读取器不支持此加密类型或压缩方式。');
          if (result.status === 'oversize') throw new ToolError('size', '成员解压后超过 1 MiB。');
          throw new ToolError('unsupported', '无法用给定口令读取此普通成员，请核对归档、成员编号和口令。');
        }
        resolve({ format: 'ZIP', name: result.name, bytes: Buffer.from(result.bytes, 'base64') });
      } catch (failure) {
        reject(failure);
      }
    });
    child.stdin.on('error', () => {});
    child.stdin.write(input);
    child.stdin.end(bytes);
  });
}
