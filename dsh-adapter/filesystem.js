import { createHash, randomUUID } from 'node:crypto';
import { constants, createReadStream } from 'node:fs';
import { copyFile, lstat, mkdir, realpath, unlink } from 'node:fs/promises';
import { isAbsolute, relative, join } from 'node:path';
import { MAX_ATTACHMENT_BYTES } from '../attachment-layout.js';
import { checkAttachmentHash, requireCurrentFile, WorkspaceFileError } from '../attachment-ranges.js';
import { downloadAttachment, MAX_TRANSFER_BYTES, provenanceUrl, stageAttachment } from '../attachment-transfer.js';
import { appendEvidenceIndex, decodeEvidenceIndex, encodeEvidenceEntry } from '../evidence-index.js';
import { RESULT_HASH } from '../ctf-result-values.js';
import { ToolError } from '../core/contracts/errors.js';

export const IMPORT_DIR = '.ctf-attachments';
export const EVIDENCE_INDEX = '.ctf/results.json';

export function objectWithKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).every(key => keys.includes(key));
}

export function pathParts(filePath) {
  if (typeof filePath !== 'string' || filePath.length > 2048 || /^[\\/]/u.test(filePath)
    || /[:\u0000-\u001f\u007f]/u.test(filePath)) {
    throw new ToolError('path', 'file_path 必须是会话工作目录下的相对路径。');
  }
  const parts = filePath.split(/[\\/]/u).filter(part => part !== '.');
  if (parts.length === 0 || parts.length > 48
    || parts.some(part => part.trim() === '' || part === '..' || /[. ]$/u.test(part))) {
    throw new ToolError('path', 'file_path 必须指向工作目录下的普通附件文件。');
  }
  return parts;
}

export async function workspaceLocation(ctx, execution) {
  const { agent, signal } = execution;
  const rootPath = agent?.session?.header?.cwd;
  if (typeof rootPath !== 'string') throw new ToolError('path', '请先为 CTF 会话选择一个题目工作区。');
  const cwd = await ctx.workingDirectory.ensure(agent, signal);
  if (/^[\\/]{2}/u.test(rootPath) || /^[\\/]{2}/u.test(cwd)) {
    throw new ToolError('path', '请从本地题目工作区选择附件。');
  }
  const root = await ctx.fs.resolve(rootPath, { signal });
  const current = await ctx.fs.resolve(cwd, { signal });
  if (!ctx.fs.contains(root, current)) throw new ToolError('path', '当前目录超出了本会话的题目工作区。');
  return { cwd, root, directoryKey: current.targetKey, signal };
}

export function networkScopeFor(execution, location, leaseId) {
  const session = execution.agent?.session;
  if (!session || typeof session !== 'object' || typeof location?.directoryKey !== 'string') return undefined;
  return { session, workspaceKey: location.directoryKey, ...(leaseId ? { leaseId } : {}) };
}

export async function openWorkspaceFile(ctx, parts, { cwd, root, signal }) {
  let relativePath = '';
  for (const [index, part] of parts.entries()) {
    relativePath = relativePath ? `${relativePath}/${part}` : part;
    const info = await ctx.fs.lstat(relativePath, { cwd }, signal);
    const expectedType = index === parts.length - 1 ? 'file' : 'directory';
    if (info?.type !== expectedType) throw new WorkspaceFileError(`请选择普通文件路径。无法读取 ${relativePath}。`);
  }
  const target = await ctx.fs.resolve(relativePath, { cwd, signal });
  if (!ctx.fs.contains(root, target)) throw new WorkspaceFileError('附件超出了本会话的题目工作区。');
  const before = await ctx.fs.stat(target, signal);
  if (before?.type !== 'file') throw new WorkspaceFileError('请选择工作区内的普通附件文件。');
  return { target, targetKey: target.targetKey, size: before.size, version: before.version };
}

export function attachmentSnapshot(file) {
  return createHash('sha256').update(JSON.stringify([file.size, file.version])).digest('hex');
}

export async function readOpenedFile(ctx, file, signal, limit = MAX_ATTACHMENT_BYTES) {
  if (file.size > limit) {
    throw new WorkspaceFileError(`请选择不超过 ${limit / (1024 * 1024)} MiB 的普通附件文件。`);
  }
  const bytes = Buffer.from(await ctx.fs.readBytes(file.target, signal, limit));
  if (bytes.length !== file.size) {
    throw new WorkspaceFileError('附件在读取期间发生变化，请确认文件保存完毕再核验。', 'conflict');
  }
  await requireCurrentFile(ctx.fs, file, signal);
  return bytes;
}

export function isAbsolutePath(filePath) {
  return typeof filePath === 'string' && (/^[A-Za-z]:[\\/]/u.test(filePath) || /^[\\/]{1,2}/u.test(filePath));
}

function importFileName(filePath) {
  const raw = String(filePath).split(/[\\/]/u).filter(part => part !== '').pop() ?? '';
  let name = raw.replace(/[^\w.\-+()\u4e00-\u9fff]/gu, '_').replace(/^[\s.]+/u, '').replace(/[. ]+$/u, '');
  if (name.length === 0) name = 'attachment';
  if (name.length > 80) {
    const dot = name.lastIndexOf('.');
    const extension = dot > 0 && name.length - dot <= 16 ? name.slice(dot) : '';
    name = name.slice(0, 80 - extension.length) + extension;
  }
  return name;
}

export function writablePolicy(ctx, execution) {
  const policy = ctx.sandboxPolicy.resolve({ session: execution.agent?.session });
  if (!policy || policy.mode === 'read-only') throw new ToolError('permission', '当前会话为只读权限，无法修改文件或比赛状态。');
  return policy;
}

export async function checkedOutput(ctx, location, name, directory = false) {
  const parts = pathParts(name);
  const { cwd, root, signal } = location;
  for (let index = 0; index < parts.length; index++) {
    const step = parts.slice(0, index + 1).join('/');
    const wantDirectory = directory || index < parts.length - 1;
    let info = await ctx.fs.lstat(step, { cwd }, signal);
    const target = await ctx.fs.resolve(step, { cwd, signal });
    if (!ctx.fs.contains(root, target)) throw new WorkspaceFileError('输出路径超出题目工作区。');
    if (info === undefined && wantDirectory) {
      try { await mkdir(join(cwd, step)); }
      catch (error) { if (error.code !== 'EEXIST') throw error; }
      info = await ctx.fs.lstat(step, { cwd }, signal);
    }
    if ((wantDirectory || info !== undefined) && info?.type !== (wantDirectory ? 'directory' : 'file')) {
      throw new WorkspaceFileError('输出路径含链接或非预期类型。');
    }
  }
  return join(cwd, ...parts);
}

function underDirectory(directory, file) {
  const rel = relative(directory, file);
  return rel !== '' && rel !== '..' && !rel.startsWith('../') && !rel.startsWith('..\\') && !isAbsolute(rel);
}

export function detectAttachmentType(name, bytes) {
  const filePath = String(name ?? '');
  const ext = filePath.includes('.') ? filePath.slice(filePath.lastIndexOf('.') + 1).toLowerCase() : '';
  const head = bytes.subarray(0, 8);
  const hex = head.toString('hex');
  if (hex.startsWith('504b0304') || hex.startsWith('504b0506') || hex.startsWith('504b0708')) return 'zip';
  if (hex.startsWith('7f454c46')) return 'elf';
  if (hex.startsWith('4d5a')) return 'pe';
  if (hex.startsWith('89504e47')) return 'png';
  if (hex.startsWith('ffd8ff')) return 'jpeg';
  if (hex.startsWith('47494638')) return 'gif';
  if (bytes.subarray(0, 4).toString('latin1') === '%PDF') return 'pdf';
  if (bytes.subarray(0, 4).toString('latin1') === 'RIFF' && bytes.subarray(8, 12).toString('latin1') === 'WAVE') return 'wav';
  if (hex.startsWith('1f8b')) return 'gzip';
  if (hex.startsWith('425a68')) return 'bzip2';
  if (ext === 'apk') return 'apk';
  if (['tar', 'tgz', 'gz', 'bz2', 'xz', '7z', 'rar', 'py', 'txt', 'json', 'js', 'png', 'jpg', 'zip'].includes(ext)) return ext;
  return 'unknown';
}

export async function storeAttachment(ctx, location, execution, name, sourceFields, transfer) {
  const policy = writablePolicy(ctx, execution);
  const folder = await checkedOutput(ctx, location, IMPORT_DIR, true);
  const temp = join(folder, '.incoming-' + randomUUID());
  let copied;
  try {
    const received = await transfer(temp);
    const wanted = importFileName(name);
    const filename = wanted === 'manifest.jsonl' ? 'attachment-' + wanted : wanted;
    let published;
    for (const candidate of [filename, received.sha256.slice(0, 12) + '-' + filename, randomUUID() + '-' + filename]) {
      location.signal?.throwIfAborted();
      const relPath = IMPORT_DIR + '/' + candidate;
      const target = await checkedOutput(ctx, location, relPath);
      try {
        await copyFile(temp, target, constants.COPYFILE_EXCL);
        copied = target;
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
        continue;
      }
      published = {
        path: relPath,
        name: candidate,
        size: received.size,
        sha256: received.sha256,
        ...sourceFields,
        ...(received.finalUrl === undefined ? {} : { final_url: received.finalUrl }),
        ...(received.contentType ? { content_type: received.contentType } : {}),
        imported_at: new Date().toISOString(),
        reused: false,
      };
      break;
    }
    if (!published) throw new ToolError('conflict', '找不到可用的附件文件名。');
    const manifest = IMPORT_DIR + '/manifest.jsonl';
    for (let attempt = 0; attempt < 3; attempt++) {
      const document = await progressDocument(ctx, manifest, location);
      const addition = (document.text && !document.text.endsWith('\n') ? '\n' : '') + JSON.stringify(published) + '\n';
      const intent = document.version === undefined ? { kind: 'createIfAbsent' }
        : { kind: 'replaceIfVersion', version: document.version };
      try {
        await ctx.fs.writeText(document.target, document.text + addition, intent, location.signal, policy);
        return {
          ...published,
          ...(received.head === undefined ? {} : { detected_type: detectAttachmentType(name, received.head) }),
          ...(received.status === undefined ? {} : { http_status: received.status }),
        };
      } catch (error) {
        if (attempt === 2 || location.signal?.aborted) throw error;
      }
    }
  } catch (error) {
    if (copied) await unlink(copied).catch(() => {});
    throw error;
  } finally {
    await unlink(temp).catch(() => {});
  }
}

export async function importExternalFile(ctx, sourcePath, location, execution, config) {
  if (!isAbsolute(sourcePath) || /^[\\/]{2}/u.test(sourcePath)) throw new WorkspaceFileError('请使用本机已授权附件路径。');
  const source = await realpath(sourcePath);
  const current = await realpath(location.cwd);
  if (underDirectory(current, source) && underDirectory(location.cwd, sourcePath)) {
    const relPath = pathParts(relative(location.cwd, sourcePath)).join('/');
    await openWorkspaceFile(ctx, pathParts(relPath), location);
    return { path: relPath, reused: true, local: true };
  }
  writablePolicy(ctx, execution);
  let allowed = false;
  for (const folder of Array.isArray(config?.attachmentImportRoots) ? config.attachmentImportRoots : []) {
    if (!isAbsolute(folder) || /^[\\/]{2}/u.test(folder)) continue;
    const base = await realpath(folder).catch(() => undefined);
    if (base && underDirectory(base, source) && underDirectory(folder, sourcePath)) allowed = true;
  }
  if (!allowed) throw new WorkspaceFileError('附件不在工作区或 attachmentImportRoots 授权目录内。');
  const info = await lstat(source);
  if (!info.isFile() || info.size > MAX_TRANSFER_BYTES) throw new WorkspaceFileError('请选择不超过 256 MiB 的普通文件。');
  return storeAttachment(ctx, location, execution, sourcePath, { source_path: sourcePath }, async temp => {
    const result = await stageAttachment(createReadStream(source, { signal: location.signal }), temp, { signal: location.signal });
    const after = await lstat(source);
    if (result.size !== info.size || after.size !== info.size || after.mtimeMs !== info.mtimeMs || after.ino !== info.ino) {
      throw new WorkspaceFileError('导入期间原件发生变化。');
    }
    return result;
  });
}

export async function rewriteInputPaths(ctx, args, location, execution, config) {
  const imported = [];
  const rewrite = async inputPath => {
    const result = await importExternalFile(ctx, inputPath, location, execution, config);
    if (!result.local) {
      imported.push({
        from: inputPath,
        to: result.path,
        sha256: result.sha256,
        size: result.size,
        source_path: result.source_path,
        imported_at: result.imported_at,
        reused: result.reused,
      });
    }
    return result.path;
  };
  let prepared = args;
  if (isAbsolutePath(prepared.file_path)) prepared = { ...prepared, file_path: await rewrite(prepared.file_path) };
  if (Array.isArray(prepared.files) && prepared.files.some(item => isAbsolutePath(item?.file_path) || isAbsolutePath(item?.path))) {
    const files = [];
    for (const item of prepared.files) {
      if (isAbsolutePath(item?.file_path)) files.push({ ...item, file_path: await rewrite(item.file_path) });
      else if (isAbsolutePath(item?.path)) files.push({ ...item, path: await rewrite(item.path) });
      else files.push(item);
    }
    prepared = { ...prepared, files };
  }
  if (Array.isArray(prepared.sources) && prepared.sources.some(item => isAbsolutePath(item?.file_path))) {
    const sources = [];
    for (const item of prepared.sources) {
      sources.push(isAbsolutePath(item?.file_path) ? { ...item, file_path: await rewrite(item.file_path) } : item);
    }
    prepared = { ...prepared, sources };
  }
  return { args: prepared, imported };
}

export async function readWorkspaceFile(ctx, parts, location, limit) {
  const file = await openWorkspaceFile(ctx, parts, location);
  return { ...file, bytes: await readOpenedFile(ctx, file, location.signal, limit) };
}

export async function readAttachment(ctx, filePath, location) {
  return (await readWorkspaceFile(ctx, pathParts(filePath), location)).bytes;
}

export async function snapshotEvidence(ctx, file, location, limit = MAX_ATTACHMENT_BYTES, readLarge) {
  try {
    const snapshot = await openWorkspaceFile(ctx, file.split('/'), location);
    if (readLarge !== undefined && snapshot.size > limit && typeof ctx.fs.readByteRange === 'function') {
      return await readLarge(snapshot);
    }
    return { ...snapshot, bytes: await readOpenedFile(ctx, snapshot, location.signal, limit) };
  } catch (error) {
    location.signal?.throwIfAborted();
    if (error instanceof WorkspaceFileError || (error?.name === 'FsError' && error.code !== 'FS_ABORTED')) return null;
    throw error;
  }
}

export async function progressDocument(ctx, name, location) {
  const { cwd, root, signal } = location;
  const info = await ctx.fs.lstat(name, { cwd }, signal);
  if (info === undefined) {
    const target = await ctx.fs.resolve(name, { cwd, signal });
    if (!ctx.fs.contains(root, target)) throw new ToolError('path', '续接文档须位于当前题目工作区。');
    return { name, target, text: '', version: undefined };
  }
  const { bytes, target, version } = await readWorkspaceFile(ctx, pathParts(name), location);
  try {
    if (bytes.includes(0)) throw new ToolError('encoding', '非文本数据');
    return { name, target, version, text: new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes) };
  } catch {
    throw new ToolError('encoding', name + ' 须使用 UTF-8 文本格式。');
  }
}

export async function recordedResults(ctx, location) {
  try {
    return decodeEvidenceIndex((await progressDocument(ctx, EVIDENCE_INDEX, location)).text);
  } catch {
    location.signal?.throwIfAborted();
    return new Map();
  }
}

export async function persistResult(ctx, location, execution, id, result) {
  const entry = encodeEvidenceEntry(id, result);
  if (!entry) return undefined;
  const policy = ctx.sandboxPolicy.resolve({ session: execution.agent?.session });
  if (!policy || policy.mode === 'read-only') return 'session_only';
  try {
    await checkedOutput(ctx, location, '.ctf', true);
    for (let attempt = 0; attempt < 3; attempt++) {
      const document = await progressDocument(ctx, EVIDENCE_INDEX, location);
      const body = appendEvidenceIndex(document.text, id, entry);
      if (body === document.text) return 'recorded';
      const intent = document.version === undefined ? { kind: 'createIfAbsent' }
        : { kind: 'replaceIfVersion', version: document.version };
      try {
        await ctx.fs.writeText(document.target, body, intent, location.signal, policy);
        return 'recorded';
      } catch (error) {
        if (attempt === 2 || location.signal?.aborted) throw error;
      }
    }
  } catch {
    return 'session_only';
  }
}

export function parseExpectedHash(value) {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/iu.test(value)) {
    throw new ToolError('unsupported', 'expected_sha256 必须是 64 位十六进制字符串。');
  }
  return value.toLowerCase();
}
