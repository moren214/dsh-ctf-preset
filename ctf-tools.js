import { createHash, randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { constants, createReadStream } from 'node:fs';
import { copyFile, lstat, mkdir, realpath, unlink } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative } from 'node:path';
import { downloadAttachment, MAX_TRANSFER_BYTES, provenanceUrl, stageAttachment } from './attachment-transfer.js';
import { createNetworkBoundary, pinAddress, webUrl } from './network-boundary.js';
import { cleanHttpResponse, platformBase, platformCredential, platformRequest } from './platform-request.js';
import { describeToolError, ToolError } from './tool-errors.js';
import { readZipWithKnownPassword } from './archive-password.js';
import { MAX_ATTACHMENT_BYTES } from './attachment-layout.js';
import { inspectAttachment } from './attachment.js';
import { readTarOrGzipMember } from './archive.js';
import {
  checkAttachmentHash, createRangeInspector, inspectEvidenceLines, inspectLogWindow, MAX_LOG_WINDOW_BYTES,
  requireCurrentFile, WorkspaceFileError,
} from './attachment-ranges.js';
import { BYTE_WINDOW_PROPERTIES, describeByteWindow, MAX_WINDOW_BYTES, parseByteWindow, printableStrings, windowLength } from './byte-window.js';
import { inspectZipRanges, readZipMember } from './zip-directory.js';
import { inspectNativeArchive, nativeArchiveFormat, readNativeArchiveMember } from './archive-directory.js';
import { parsePcapngQuery, PCAPNG_QUERY_SCHEMA } from './pcapng-statistics.js';
import { inspectMedia, MEDIA_PROPERTIES, parseMediaRequest, parsePngRequest, PNG_PIXEL_PROPERTIES } from './media-reader.js';
import { inspectElf, verifyElf } from './elf.js';
import { PWN_PATTERN_PROPERTIES, cyclicPattern } from './pwn-pattern.js';
import { NET_SESSION_PROPERTIES, createNetSessionManager } from './net-session.js';
import { REV_QUERY_PROPERTIES, runRevQuery } from './rev-query.js';
import { HTTP_REQUEST_PROPERTIES, httpRequest } from './http-client.js';
import { PCAP_STREAM_PROPERTIES, pcapStream } from './pcap-stream.js';
import { MAX_EVIDENCE_SOURCES, MAX_EVIDENCE_TEXT, verifyEvidence } from './evidence.js';
import { HTTP_EVIDENCE_PROPERTIES, MAX_HTTP_BYTES, verifyHttpEvidence } from './http-evidence.js';
import { FLASK_ROUTE_PROPERTIES, MAX_FLASK_SOURCE_BYTES, traceFlaskRoute } from './flask-route.js';
import { FLASK_RESPONSE_PROPERTIES, verifyFlaskResponse } from './flask-response.js';
import { MAX_REV_TEXT_BYTES } from './rev-evidence.js';
import { REV_EXPORT_PROPERTIES, queryRevExport } from './rev-export.js';
import { REV_ADDRESS_PROPERTIES, mapRevAddress } from './rev-address.js';
import { REV_MACHINE_PROPERTIES, verifyRevMachine } from './rev-machine.js';
import { REV_TRACE_PROPERTIES, compareRevTrace } from './rev-trace.js';
import { BATCH_TEXT_PROPERTIES, MAX_BATCH_FILE_BYTES, readCtfFiles } from './batch-text.js';
import { CALCULATION_PROPERTIES } from './offline-calculation.js';
import { createCalculationRunner } from './offline-calculation-runner.js';
import { Base100Workbench, WORKBENCH_BASE100_PROPERTIES } from './workbench-base100.js';
import { CONFIG_LIST_FIELDS, CONFIG_PATH_FIELDS, CONFIG_TEXT_FIELDS, createWorkbenchEnvironment, WorkbenchDependencyError } from './workbench-config.js';
import { PROGRESS_ACTION_KEYS, PROGRESS_PARAMETERS, PROGRESS_PROPERTIES, manageProgress } from './ctf-progress.js';
import { appendStatus, readStatusHistory } from './ctf-status.js';
import { createToolResults, OFFLINE_RESULT_SCOPE, RESULT_HASH } from './ctf-result-values.js';
import { detectBrowser, detectGdb, findOnPathAsync, registerExtraTools } from './extra-tools.js';
import { handleSubmission } from './submission.js';
import { appendEvidenceIndex, decodeEvidenceIndex, encodeEvidenceEntry } from './evidence-index.js';

export const name = 'ctf-attachment-tools';
export const inject = ['tools', 'fs', 'workingDirectory', 'sandboxPolicy'];
export const Config = {
  '~standard': {
    version: 1,
    vendor: 'ctf-preset',
    validate(input) {
      const value = input ?? {};
      if (typeof value !== 'object' || Array.isArray(value)) return { issues: [{ message: 'CTF 配置须是对象。' }] };
      for (const field of CONFIG_PATH_FIELDS) {
        if (value[field] !== undefined && typeof value[field] !== 'string') {
          return { issues: [{ message: `${field} 须是本机路径。`, path: [field] }] };
        }
      }
      for (const field of CONFIG_TEXT_FIELDS) {
        if (value[field] !== undefined && typeof value[field] !== 'string') {
          return { issues: [{ message: `${field} 须是字符串。`, path: [field] }] };
        }
      }
      for (const field of CONFIG_LIST_FIELDS) {
        if (value[field] !== undefined && (!Array.isArray(value[field])
          || value[field].some(item => typeof item !== 'string' || item.length === 0))) {
          return { issues: [{ message: field + ' 须是字符串数组。', path: [field] }] };
        }
      }
      if (value.compact !== undefined && typeof value.compact !== 'boolean') {
        return { issues: [{ message: 'compact 须是布尔值。', path: ['compact'] }] };
      }
      return { value };
    },
  },
};

const AUTO_FILE_HASH_LIMIT = 128 * 1024 * 1024;
const OUTPUT_CONFIGS = new WeakMap();

const IMPORT_DIR = '.ctf-attachments';
const STATUS_FILE = '.ctf-status.json';
const INSTANCE_STATE_FILE = '.ctf-instances.json';
const instanceTransitions = new Set();
const SUBMISSION_LOG = '.ctf-submissions.jsonl';
const STATUS_PROPERTIES = {
  action: { type: 'string', enum: ['set', 'show', 'board'], description: 'set 追加一条时间盒心跳；show 查看最近状态并返回含 code、severity、action 的结构化 warnings；board 拉取平台榜单并写入一条状态记录。' },
  phase: { type: 'string', maxLength: 200, description: '当前阶段，例如 题面理解、入口定位、利用构造、复核。' },
  stuck: { type: 'string', maxLength: 400, description: '当前卡点，一句话说清卡在哪一步。' },
  ruled_out: { type: 'array', maxItems: 8, items: { type: 'string', maxLength: 200 }, description: '已排除的假设或路径。' },
  next_step: { type: 'string', maxLength: 400, description: '下一步计划，写可执行的一步。' },
  need: { type: 'string', maxLength: 200, description: '需要谁或什么帮助；没有就省略。' },
};
const SUBMIT_PROPERTIES = {
  flag: { type: 'string', maxLength: 512, description: '待提交的 flag 原文，不要带多余空格。' },
  pattern: { type: 'string', maxLength: 200, description: '可选的 flag 格式正则，例如 ^FLAG\\{[0-9a-f]{32}\\}$。' },
  source: { type: 'string', maxLength: 400, description: 'flag 来源：结果编号、命令或提示，写可核对的位置。' },
  dynamic: { type: 'boolean', description: '动态 flag 设为 true 时，会要求实例名和刷新时间。' },
  instance: { type: 'string', maxLength: 200, description: '动态 flag 所属实例或题目名。' },
  refreshed_at: { type: 'string', maxLength: 40, description: '实例刷新时间（ISO 8601），动态 flag 必填。' },
  record: { type: 'boolean', description: 'check_flag / submit_check 传 true 才写本地预检回执。正式提交始终记录回执。' },
};
const SUBMIT_FLAG_PROPERTIES = {
  ...SUBMIT_PROPERTIES,
  challenge: { type: 'string', maxLength: 200, description: '题目标识，平台需要时填写。' },
};
const INSTANCE_PROPERTIES = {
  action: { type: 'string', enum: ['status', 'list', 'create', 'rotate', 'delete'], description: 'status 查看配置；list 列出实例；create 新建；rotate 确认新实例已创建后删除传入 id；delete 删除传入 id。' },
  id: { type: 'string', maxLength: 200, description: '实例标识，rotate 与 delete 必填。' },
  body: { type: 'object', description: 'create 或 rotate 的请求体，按 JSON 原样提交。', additionalProperties: true },
};
const FETCH_PROPERTIES = {
  url: { type: 'string', maxLength: 2048, description: '赛题附件的 http(s) 下载地址，只用于比赛实例。' },
  name: { type: 'string', maxLength: 200, description: '保存文件名；省略时取 URL 最后一段。' },
  sha256: { type: 'string', description: '可选，下载内容的 64 位十六进制 SHA-256；不符会报 conflict。' },
  max_bytes: { type: 'integer', minimum: 1, maximum: MAX_TRANSFER_BYTES, default: MAX_ATTACHMENT_BYTES,
    description: '下载大小上限。默认 32 MiB，可为明确要分段处理的大文件指定更高上限。' },
};
const PATH_SCHEMA = {
  type: 'string',
  description: '题目附件相对于会话工作目录的路径。已在配置中授权的外部附件可在允许写入的会话里复制到 .ctf-attachments/ 并登记 SHA-256。',
};
const ZIP_FORMAT_HINT = { type: 'string', enum: ['zip'], description: '设为 zip 时检查文件内部嵌入的 ZIP。' };
const SHA256_SCHEMA = { type: 'string', description: '待核对的 64 位十六进制 SHA-256。翻页时可使用前一页返回的值。' };
const ATTACHMENT_PROPERTIES = {
  file_path: PATH_SCHEMA,
  format_hint: ZIP_FORMAT_HINT,
  offset: { type: 'integer', minimum: 0, maximum: MAX_ATTACHMENT_BYTES, description: '从 0 开始的结构记录索引。后续页使用 next_offset。' },
  limit: { type: 'integer', minimum: 1, maximum: 16, description: '每页记录数，默认 10。' },
  expected_sha256: SHA256_SCHEMA,
  pcapng: PCAPNG_QUERY_SCHEMA,
};
const LOG_RANGE_PROPERTIES = {
  file_path: PATH_SCHEMA,
  byte_offset: { type: 'integer', minimum: 0, description: '从 0 开始的原件字节偏移。后续片段使用 next_byte_offset。默认 0。' },
  byte_length: { type: 'integer', minimum: 1, maximum: MAX_LOG_WINDOW_BYTES, description: '所需字节数，默认 2048。结果向外对齐至完整 UTF-8 字符。' },
  expected_sha256: SHA256_SCHEMA,
};
const BINARY_RANGE_PROPERTIES = {
  file_path: PATH_SCHEMA,
  ...BYTE_WINDOW_PROPERTIES,
  strings: { type: 'boolean', description: '附带该片段内可打印 ASCII 字符串及原件偏移。默认 false。' },
  min_string_length: { type: 'integer', minimum: 1, maximum: 256, description: '字符串最短字节数，默认 4，仅在 strings 为 true 时使用。' },
  hash_scope: {
    type: 'string', enum: ['auto', 'file', 'range'],
    description: '默认 auto。超过 128 MiB 时默认只计算片段 SHA-256。file 计算原件和片段，range 只读和散列这段。',
  },
  expected_sha256: SHA256_SCHEMA,
};
const ARCHIVE_MEMBER_PROPERTIES = {
  file_path: PATH_SCHEMA,
  format_hint: ZIP_FORMAT_HINT,
  password: { type: 'string', maxLength: 512, description: '可选。用于读取单个 ZIP 成员的已知口令。' },
  member_index: { type: 'integer', minimum: 0, description: 'inspect_attachment 目录里的 member_index，零起始。单文件 gzip 使用 0。' },
  ...BYTE_WINDOW_PROPERTIES,
  expected_sha256: SHA256_SCHEMA,
};
const ADDRESS_SCHEMA = { type: 'string', description: 'ELF 文件中的十六进制地址，如 0x1000。' };
const VERIFY_PROPERTIES = {
  file_path: PATH_SCHEMA,
  expected_entry: ADDRESS_SCHEMA,
  expected_main: ADDRESS_SCHEMA,
  expected_sha256: { type: 'string', description: '待核对的 64 位十六进制 SHA-256 字符串。' },
  symbol_label: {
    type: 'object',
    description: '核对反汇编注释中的动态符号基址与有符号偏移。',
    additionalProperties: false,
    required: ['base', 'displacement', 'address'],
    properties: {
      base: ADDRESS_SCHEMA,
      displacement: { type: 'string', description: '有符号十六进制偏移，如 -0x20 或 0x20。' },
      address: ADDRESS_SCHEMA,
    },
  },
};
const SOURCE_PROPERTIES = {
  file_path: PATH_SCHEMA,
  line: { type: 'integer', minimum: 1, description: '可选的 1 起始行号。省略时，前缀须在文件内唯一。' },
  prefix: { type: 'string', minLength: 1, maxLength: MAX_EVIDENCE_TEXT, description: '目标值之前的原样文本。' },
  suffix: { type: 'string', minLength: 1, maxLength: MAX_EVIDENCE_TEXT, description: '目标值之后的原样文本。省略时取到行尾。' },
  result_id: { type: 'string', maxLength: 64, description: '引用 read_binary_range 或 read_log_range 返回的结果编号。可附完整字节范围，编号失效时用原件复算。' },
  byte_offset: { type: 'integer', minimum: 0, description: '字节范围起点，从 0 起算。与 file_path、byte_length 和原件 sha256 一同提供。' },
  byte_length: { type: 'integer', minimum: 1, maximum: MAX_WINDOW_BYTES, description: '要复算的精确字节长度。' },
  sha256: SHA256_SCHEMA,
  range_sha256: { ...SHA256_SCHEMA, description: '可选，同时核对该字节范围的 SHA-256。' },
};
const EVIDENCE_PROPERTIES = {
  sources: {
    type: 'array', minItems: 2, maxItems: MAX_EVIDENCE_SOURCES,
    items: { type: 'object', properties: SOURCE_PROPERTIES, additionalProperties: false },
  },
  expected_value: { type: 'string', maxLength: MAX_EVIDENCE_TEXT, description: '可选的期望值。按原样比较，包括空白及大小写。' },
};

function objectWithKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).every(key => keys.includes(key));
}

export function pathParts(path) {
  if (typeof path !== 'string' || path.length > 2048 || /^[\\/]/u.test(path)
    || /[:\u0000-\u001f\u007f]/u.test(path)) {
    throw new ToolError('path', 'file_path 必须是会话工作目录下的相对路径。');
  }
  const parts = path.split(/[\\/]/u).filter(part => part !== '.');
  if (parts.length === 0 || parts.length > 48
    || parts.some(part => part.trim() === '' || part === '..' || /[. ]$/u.test(part))) {
    throw new ToolError('path', 'file_path 必须指向工作目录下的普通附件文件。');
  }
  return parts;
}

async function workspaceLocation(ctx, execution) {
  const { agent, signal } = execution;
  const rootPath = agent?.session?.header?.cwd;
  if (typeof rootPath !== 'string') throw new Error('请先为 CTF 会话选择一个题目工作区。');
  const cwd = await ctx.workingDirectory.ensure(agent, signal);
  if (/^[\\/]{2}/u.test(rootPath) || /^[\\/]{2}/u.test(cwd)) {
    throw new Error('请从本地题目工作区选择附件。');
  }
  const root = await ctx.fs.resolve(rootPath, { signal });
  const current = await ctx.fs.resolve(cwd, { signal });
  if (!ctx.fs.contains(root, current)) throw new Error('当前目录超出了本会话的题目工作区。');
  return { cwd, root, directoryKey: current.targetKey, signal };
}

async function openWorkspaceFile(ctx, parts, { cwd, root, signal }) {
  let relative = '';
  for (const [index, part] of parts.entries()) {
    relative = relative ? `${relative}/${part}` : part;
    const info = await ctx.fs.lstat(relative, { cwd }, signal);
    const expectedType = index === parts.length - 1 ? 'file' : 'directory';
    if (info?.type !== expectedType) throw new WorkspaceFileError(`请选择普通文件路径。无法读取 ${relative}。`);
  }
  const target = await ctx.fs.resolve(relative, { cwd, signal });
  if (!ctx.fs.contains(root, target)) throw new WorkspaceFileError('附件超出了本会话的题目工作区。');
  const before = await ctx.fs.stat(target, signal);
  if (before?.type !== 'file') throw new WorkspaceFileError('请选择工作区内的普通附件文件。');
  return { target, targetKey: target.targetKey, size: before.size, version: before.version };
}

async function readOpenedFile(ctx, file, signal, limit = MAX_ATTACHMENT_BYTES) {
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

function isAbsolutePath(path) {
  return typeof path === 'string' && (/^[A-Za-z]:[\\/]/u.test(path) || /^[\\/]{1,2}/u.test(path));
}

function importFileName(path) {
  const raw = String(path).split(/[\\/]/u).filter(part => part !== '').pop() ?? '';
  let name = raw.replace(/[^\w.\-+()\u4e00-\u9fff]/gu, '_').replace(/^[\s.]+/u, '').replace(/[. ]+$/u, '');
  if (name.length === 0) name = 'attachment';
  if (name.length > 80) {
    const dot = name.lastIndexOf('.');
    const extension = dot > 0 && name.length - dot <= 16 ? name.slice(dot) : '';
    name = name.slice(0, 80 - extension.length) + extension;
  }
  return name;
}

function writablePolicy(ctx, execution) {
  const policy = ctx.sandboxPolicy.resolve({ session: execution.agent?.session });
  if (!policy || policy.mode === 'read-only') throw new Error('当前会话为只读权限，无法修改文件或比赛状态。');
  return policy;
}

async function checkedOutput(ctx, location, name, directory = false) {
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
  const path = relative(directory, file);
  return path !== '' && path !== '..' && !path.startsWith('../') && !path.startsWith('..\\') && !isAbsolute(path);
}

async function storeAttachment(ctx, location, execution, name, sourceFields, transfer) {
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
      const path = IMPORT_DIR + '/' + candidate;
      const target = await checkedOutput(ctx, location, path);
      try {
        await copyFile(temp, target, constants.COPYFILE_EXCL);
        copied = target;
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
        continue;
      }
      published = { path, name: candidate, size: received.size, sha256: received.sha256,
        ...sourceFields, ...(received.finalUrl === undefined ? {} : { final_url: received.finalUrl }),
        ...(received.contentType ? { content_type: received.contentType } : {}),
        imported_at: new Date().toISOString(), reused: false };
      break;
    }
    if (!published) throw new Error('找不到可用的附件文件名。');
    const manifest = IMPORT_DIR + '/manifest.jsonl';
    for (let attempt = 0; attempt < 3; attempt++) {
      const document = await progressDocument(ctx, manifest, location);
      const addition = (document.text && !document.text.endsWith('\n') ? '\n' : '') + JSON.stringify(published) + '\n';
      const intent = document.version === undefined ? { kind: 'createIfAbsent' }
        : { kind: 'replaceIfVersion', version: document.version };
      try {
        await ctx.fs.writeText(document.target, document.text + addition, intent, location.signal, policy);
        return { ...published, ...(received.head === undefined ? {} : {
          detected_type: detectAttachmentType(name, received.head),
        }), ...(received.status === undefined ? {} : { http_status: received.status }) };
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

async function importExternalFile(ctx, sourcePath, location, execution, config) {
  if (!isAbsolute(sourcePath) || /^[\\/]{2}/u.test(sourcePath)) throw new WorkspaceFileError('请使用本机已授权附件路径。');
  const source = await realpath(sourcePath);
  const current = await realpath(location.cwd);
  if (underDirectory(current, source) && underDirectory(location.cwd, sourcePath)) {
    const path = pathParts(relative(location.cwd, sourcePath)).join('/');
    await openWorkspaceFile(ctx, pathParts(path), location);
    return { path, reused: true, local: true };
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

async function rewriteInputPaths(ctx, args, location, execution, config) {
  const imported = [];
  const rewrite = async path => {
    const result = await importExternalFile(ctx, path, location, execution, config);
    if (!result.local) imported.push({ from: path, to: result.path, sha256: result.sha256, size: result.size,
      source_path: result.source_path, imported_at: result.imported_at, reused: result.reused });
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

async function readWorkspaceFile(ctx, parts, location, limit) {
  const file = await openWorkspaceFile(ctx, parts, location);
  return { ...file, bytes: await readOpenedFile(ctx, file, location.signal, limit) };
}

async function readAttachment(ctx, path, location) {
  return (await readWorkspaceFile(ctx, pathParts(path), location)).bytes;
}

async function readMediaAttachment(ctx, args, request, location, workbench) {
  const expectedHash = parseExpectedHash(args.expected_sha256);
  const file = await readWorkspaceFile(ctx, pathParts(args.file_path), location);
  const sha256 = createHash('sha256').update(file.bytes).digest('hex');
  checkAttachmentHash(expectedHash, sha256);
  const report = await inspectMedia(file.bytes, request, location.signal, workbench);
  await requireCurrentFile(ctx.fs, file, location.signal);
  return { ...report, size: file.size, sha256 };
}

async function snapshotEvidence(ctx, file, location, limit = MAX_ATTACHMENT_BYTES, readLarge) {
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

async function progressDocument(ctx, name, location) {
  const { cwd, root, signal } = location;
  const info = await ctx.fs.lstat(name, { cwd }, signal);
  if (info === undefined) {
    const target = await ctx.fs.resolve(name, { cwd, signal });
    if (!ctx.fs.contains(root, target)) throw new Error('续接文档须位于当前题目工作区。');
    return { name, target, text: '', version: undefined };
  }
  const { bytes, target, version } = await readWorkspaceFile(ctx, pathParts(name), location);
  try {
    if (bytes.includes(0)) throw new Error('非文本数据');
    return { name, target, version, text: new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes) };
  } catch {
    throw new Error(name + ' 须使用 UTF-8 文本格式。');
  }
}

const EVIDENCE_INDEX = '.ctf/results.json';

async function recordedResults(ctx, location) {
  try {
    return decodeEvidenceIndex((await progressDocument(ctx, EVIDENCE_INDEX, location)).text);
  } catch {
    location.signal?.throwIfAborted();
    return new Map();
  }
}

async function persistResult(ctx, location, execution, id, result) {
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

async function runProgress(ctx, args, execution, results, inspectRanges) {
  const policy = ctx.sandboxPolicy.resolve({ session: execution.agent?.session });
  if (['save', 'writeup', 'repair'].includes(args.action) && policy?.mode === 'read-only') {
    throw new Error('当前会话为只读权限，可读取续接记录并在对话中报告。');
  }
  const location = await workspaceLocation(ctx, execution);
  const recorded = await recordedResults(ctx, location);
  return manageProgress(args, {
    canWrite: policy?.mode !== 'read-only',
    normalizePath: path => pathParts(path).join('/'),
    cwd: location.cwd,
    readDocument: name => progressDocument(ctx, name, location),
    async readEvidence(path, references) {
      const snapshot = await snapshotEvidence(ctx, path, location, MAX_ATTACHMENT_BYTES, file => {
        if (references.some(reference => reference.line !== undefined)) {
          return inspectRanges(file, location.signal, undefined, reader => inspectEvidenceLines(reader, references), { hashFile: false });
        }
        return inspectRanges(file, location.signal, undefined, () => ({ report: {} }));
      });
      return snapshot?.bytes ?? snapshot;
    },
    readResult: id => results.get(execution.agent?.session, location.directoryKey, id) ?? recorded.get(id),
    listResults: () => {
      const live = results.list(execution.agent?.session, location.directoryKey);
      const ids = new Set(live.map(item => item.result_id));
      return [...live, ...[...recorded].filter(([id]) => !ids.has(id))
        .map(([result_id, entry]) => ({ result_id, tool: entry.tool, status: 'recorded' }))];
    },
    ...(typeof execution.agent?.session?.id === 'string' && execution.agent.session.id !== ''
      ? { sessionId: execution.agent.session.id }
      : {}),
    async writeDocument(document, content) {
      if (Buffer.byteLength(content, 'utf8') > MAX_ATTACHMENT_BYTES) {
        throw new Error('续接文档会超过 32 MiB。');
      }
      if (document.version === undefined && typeof document.name === 'string' && document.name.includes('/')) {
        await checkedOutput(ctx, location, dirname(document.name).replaceAll('\\', '/'), true);
      }
      const intent = document.version === undefined
        ? { kind: 'createIfAbsent' }
        : { kind: 'replaceIfVersion', version: document.version };
      const outcome = await ctx.fs.writeText(document.target, content, intent, location.signal, policy);
      ctx.emit('fs/observed', document.target, { kind: 'present', version: outcome.version }, execution);
    },
  });
}

function statusLine(value, field, maxLength = 400) {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value.length > maxLength || /[\r\n]/u.test(value)) {
    throw new Error(field + ' 须为单行文本（最多 ' + maxLength + ' 字符）。');
  }
  return value.trim();
}

function statusFiles(ctx, location, execution, config) {
  return {
    read: name => progressDocument(ctx, name, location),
    normalizeEntry: entry => entry?.phase === 'scoreboard'
      ? { ...entry, board: boardSummary(entry.board, config?.platformTeamId) ?? null }
      : entry,
    async write(document, body) {
      const policy = writablePolicy(ctx, execution);
      const intent = document.version === undefined
        ? { kind: 'createIfAbsent' }
        : { kind: 'replaceIfVersion', version: document.version };
      await ctx.fs.writeText(document.target, body, intent, location.signal, policy);
    },
  };
}

function boardScalars(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const board = {};
  if (Number.isSafeInteger(value.rank) && value.rank > 0) board.rank = value.rank;
  if (Number.isFinite(value.score)) board.score = value.score;
  const solved = value.solved_count ?? value.solved;
  if (Number.isSafeInteger(solved) && solved >= 0) board.solved = solved;
  return Object.keys(board).length > 0 ? board : undefined;
}

function boardSummary(body, teamId) {
  const root = body?.data ?? body;
  if (teamId !== undefined) {
    const rows = Array.isArray(root) ? root : root?.rows ?? root?.teams ?? root?.standings;
    if (Array.isArray(rows)) {
      const team = rows.find(row => String(row?.team_id ?? row?.id ?? '') === teamId);
      return boardScalars(team);
    }
  }
  return boardScalars(root?.me ?? root?.self ?? root?.team ?? root);
}

function statusWarnings(entries) {
  const warnings = [];
  const add = (code, severity, message, action, thresholdMinutes) =>
    warnings.push({ code, severity, message, action, ...(thresholdMinutes === undefined ? {} : { threshold_minutes: thresholdMinutes }) });
  const last = entries[entries.length - 1];
  if (last) {
    const minutes = Math.max(0, Math.round((Date.now() - Date.parse(last.at)) / 60000));
    if (minutes >= 60) add('timebox_60', 'urgent', '距上一条状态已 ' + minutes + ' 分钟：整理卡点并升级求助，给出三条候选路径和排除证据。', '升级求助并比较三条路径。', 60);
    else if (minutes >= 30) add('timebox_30', 'warning', '距上一条状态已 ' + minutes + ' 分钟：列出三条候选路径，写清各自的验证代价。', '列出三条候选路径并选择验证成本最低的一条。', 30);
    else if (minutes >= 15) add('timebox_15', 'info', '距上一条状态已 ' + minutes + ' 分钟：没有新假设就换方向，先排除一条已走路径。', '核对新假设或排除一条已走路径。', 15);
  }
  if (last && !last.next_step) add('next_step_missing', 'warning', '本条状态没有写 next_step：补一条具体可执行的下一步。', '保存一个可执行的下一步。');
  if (entries.length < 2) add('status_records_low', 'info', '本题状态记录不足 2 条，收尾前至少再记录一次。', '收尾前补一条状态记录。');
  return warnings;
}

function warningMessages(warnings) {
  return warnings.map(warning => warning.message);
}

async function runStatus(ctx, args, execution, config) {
  const location = await workspaceLocation(ctx, execution);
  const files = statusFiles(ctx, location, execution, config);
  const history = await readStatusHistory(files);
  const { entries, recovered } = history;
  const last = entries[entries.length - 1];
  const elapsed = entries.length ? Math.max(0, Math.round((Date.now() - Date.parse(entries[0].at)) / 60000)) : 0;
  if (args.action === 'show') {
    const warnings = statusWarnings(entries);
    if (recovered) warnings.push({ code: 'status_recovered', severity: 'warning', message: '主状态文件不可读，当前结果从恢复副本载入。' });
    return { status: 'status', file: STATUS_FILE, records: entries.length, elapsed_minutes: elapsed, last,
      warnings, warning_messages: warningMessages(warnings) };
  }
  if (args.action === 'board') {
    writablePolicy(ctx, execution);
    const boardPath = config?.platformLeaderboardPath ?? '/scoreboard';
    const response = await platformRequest(config, execution.signal, 'GET', boardPath);
    let board;
    if (platformOperationSucceeded(response)) {
      try { board = boardSummary(JSON.parse(response.body), config?.platformTeamId); }
      catch { /* The platform did not return a supported team summary. */ }
    }
    if (!board) return { status: 'board_unavailable', file: STATUS_FILE, records: entries.length, platform_status: response?.status ?? null,
      reason: '平台响应没有可辨认的本队名次、分数或解题数。' };
    await checkedOutput(ctx, location, '.ctf', true);
    const saved = await appendStatus(files, { phase: 'scoreboard', board });
    return { status: 'board', file: STATUS_FILE, records: saved.entries.length, platform_status: response?.status ?? null, board,
      ...(saved.warning ? { warning: saved.warning } : {}) };
  }
  const phase = statusLine(args.phase, 'phase', 200);
  const stuck = statusLine(args.stuck, 'stuck', 400);
  const nextStep = statusLine(args.next_step, 'next_step', 400);
  const need = statusLine(args.need, 'need', 200);
  if (!phase && !stuck && !nextStep) throw new Error('状态记录至少给出 phase、stuck 或 next_step 之一。');
  const ruledOut = args.ruled_out === undefined ? [] : args.ruled_out.map(item => statusLine(item, 'ruled_out', 200)).filter(Boolean);
  await checkedOutput(ctx, location, '.ctf', true);
  const saved = await appendStatus(files, { phase, stuck, ruled_out: ruledOut, next_step: nextStep, need });
  const warnings = statusWarnings(saved.entries);
  if (saved.recovered) warnings.push({ code: 'status_recovered', severity: 'warning', message: '主状态文件不可读，已在恢复副本基础上追加记录。' });
  return { status: 'recorded', file: STATUS_FILE, records: saved.entries.length, elapsed_minutes: elapsed,
    entry: saved.entry, warnings, warning_messages: warningMessages(warnings), ...(saved.warning ? { warning: saved.warning } : {}) };
}

const RECEIPT_FIELDS = ['id', 'at', 'kind', 'verdict', 'ready', 'flag_sha256', 'challenge', 'instance', 'platform', 'platform_status'];

function receiptForStorage(entry) {
  const safe = {};
  for (const key of RECEIPT_FIELDS) {
    const value = entry[key];
    if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) safe[key] = value;
  }
  if (typeof safe.platform === 'string') {
    try { webUrl(safe.platform); }
    catch { delete safe.platform; }
  }
  return safe;
}

function submissionFiles(ctx, location, execution) {
  return {
    async read() {
      const document = await progressDocument(ctx, SUBMISSION_LOG, location);
      const receipts = document.text.split('\n').filter(Boolean).map(line => JSON.parse(line));
      if (receipts.some(entry => entry === null || typeof entry !== 'object' || Array.isArray(entry))) {
        throw new Error('提交回执格式无效，请先核对记录。');
      }
      return { document, receipts };
    },
    async write(document, receipts) {
      const policy = ctx.sandboxPolicy.resolve({ session: execution.agent?.session });
      if (policy?.mode === 'read-only') throw new Error('当前会话为只读权限，无法记录正式提交。');
      const body = receipts.map(entry => JSON.stringify(receiptForStorage(entry))).join('\n') + '\n';
      if (Buffer.byteLength(body) > MAX_ATTACHMENT_BYTES) throw new Error('提交回执超过文件大小上限。');
      const intent = document.version === undefined ? { kind: 'createIfAbsent' }
        : { kind: 'replaceIfVersion', version: document.version };
      await ctx.fs.writeText(document.target, body, intent, location.signal, policy);
    },
  };
}

async function runSubmitCheck(ctx, args, execution, config) {
  const location = await workspaceLocation(ctx, execution);
  return { ...await handleSubmission(args, submissionFiles(ctx, location, execution), undefined, platformBase(config) || undefined, location.signal),
    file: SUBMISSION_LOG };
}

const PYTHON_MODULES = {
  z3: 'pip install z3-solver',
  fpylll: 'pip install fpylll',
  Crypto: 'pip install pycryptodome',
  sympy: 'pip install sympy',
  libarchive: 'pip install libarchive-c',
  capstone: 'pip install capstone',
  fitz: 'pip install pymupdf',
  PIL: 'pip install pillow',
  cv2: 'pip install opencv-python',
  numpy: 'pip install numpy',
};

function pythonModuleState(pythonPath, signal) {
  const names = JSON.stringify(Object.keys(PYTHON_MODULES));
  const script = 'import importlib.util, json, sys\n'
    + `names = ${names}\n`
    + 'print(json.dumps({"version": "%d.%d" % sys.version_info[:2], "modules": {name: importlib.util.find_spec(name) is not None for name in names}}))\n';
  return new Promise(resolve => execFile(pythonPath, ['-I', '-B', '-c', script], {
    encoding: 'utf8', cwd: dirname(pythonPath), timeout: 3500, maxBuffer: 8192, windowsHide: true, signal,
  }, (error, stdout) => {
    if (!error) {
      try { return resolve(JSON.parse(stdout)); } catch { /* invalid probe response */ }
    }
    resolve(undefined);
  }));
}

async function runDoctor(ctx, execution, config, workbench) {
  const location = await workspaceLocation(ctx, execution);
  const checks = [];
  const add = (check, ok, detail, required = true) => checks.push({ name: check, ok, detail, required });
  add('node', true, process.version);
  const promptService = ctx.get?.('systemPrompt');
  const hostCapabilities = {
    tools_register: typeof ctx.tools?.register === 'function',
    filesystem: typeof ctx.fs?.resolve === 'function' && typeof ctx.fs?.lstat === 'function'
      && typeof ctx.fs?.readBytes === 'function',
    system_prompt_context: typeof promptService?.context === 'function',
    supported_dsh_range: '>=0.2.2-rc.5 <0.3.0',
  };
  add('dsh:tools.register', hostCapabilities.tools_register, hostCapabilities.tools_register ? '可用' : '当前 DSH 缺少工具注册接口。');
  add('dsh:filesystem', hostCapabilities.filesystem, hostCapabilities.filesystem ? '可用' : '当前 DSH 缺少工作区文件接口。');
  add('dsh:systemPrompt.context', hostCapabilities.system_prompt_context,
    hostCapabilities.system_prompt_context ? '已注入续接提示。' : '不可用；改由包内 SKILL.md 提供相同规则。', false);
  const issue = workbench.configurationIssue();
  add('workbench_config', issue === undefined, issue ?? '已载入适用的 CTF 配置。', false);
  const deadline = AbortSignal.timeout(8500);
  const probeSignal = location.signal ? AbortSignal.any([deadline, location.signal]) : deadline;
  let python;
  let pythonIssue;
  try { python = await workbench.resolvePython(probeSignal); }
  catch (error) { pythonIssue = deadline.aborted ? 'Python 探测超时。' : error.message; }
  location.signal?.throwIfAborted();
  add('python', python !== undefined, python ?? pythonIssue, false);
  const state = python ? await pythonModuleState(python, probeSignal) : undefined;
  location.signal?.throwIfAborted();
  if (state) {
    const [major, minor] = String(state.version ?? '0.0').split('.').map(Number);
    const supported = major > 3 || (major === 3 && minor >= 11);
    add('python:version', supported, state.version + (supported ? '' : '：需要 3.11 以上。'), false);
    for (const name of Object.keys(PYTHON_MODULES)) {
      const present = state.modules?.[name] === true;
      add('python:' + name, present,
        present ? '已安装' : '未安装：' + PYTHON_MODULES[name] + ' 后可启用对应功能。', false);
    }
  } else if (python) {
    add('python:modules', false, 'Python 模块探测失败：检查 Python 是否可执行。', false);
  }
  const toolNames = ['jadx', 'apktool', 'apksigner', 'john', 'hashcat'];
  const [gdb, browser, ...paths] = await Promise.all([
    detectGdb(config), detectBrowser(config), ...toolNames.map(findOnPathAsync),
  ]);
  add('gdb', typeof gdb === 'string' && gdb !== '', gdb ?? '未找到 gdb：只影响本机对应能力。', false);
  add('browser', typeof browser === 'string' && browser !== '', browser ?? '未找到 Chrome/Edge：browser_session 不可用。', false);
  for (const [index, tool] of toolNames.entries()) {
    const found = paths[index];
    add(tool, Boolean(found), found ?? '未安装：对应功能会返回 dependency 提示。', false);
  }
  for (const [file, label] of [['notes.md', '续接记录'], ['handoff.md', '接替简报'], [STATUS_FILE, '时间盒心跳'], [SUBMISSION_LOG, '提交回执']]) {
    let present = false;
    try {
      present = (await ctx.fs.lstat(file, { cwd: location.cwd }, location.signal)) !== undefined;
    } catch {
      present = false;
    }
    add(file, present, present ? '已存在' : '尚未生成（' + label + '）', false);
  }
  const missing = checks.filter(item => item.required && !item.ok).map(item => item.name);
  const optionalMissing = checks.filter(item => !item.required && !item.ok).map(item => item.name);
  return { status: missing.length ? 'missing' : optionalMissing.length ? 'partial' : 'ok', cwd: location.cwd,
    host_capabilities: hostCapabilities, checks, missing, optional_missing: optionalMissing };
}

async function runCompetitionApi(ctx, args, execution, config) {
  if (args.action === 'submit') return runSubmitFlag(ctx, args, execution, config);
  return runInstance(ctx, { ...args, action: args.action === 'instances' ? 'list' : args.action }, execution, config);
}

function platformOperationSucceeded(response) {
  if (!response || response.status < 200 || response.status >= 300 || response.truncated || response.body_error) return false;
  if (typeof response.body !== 'string' || response.body === '') return true;
  try {
    const body = JSON.parse(response.body);
    return body?.success !== false && body?.ok !== false && !['error', 'failed', 'rejected'].includes(body?.status);
  } catch {
    return true;
  }
}

async function runSubmitFlag(ctx, args, execution, config) {
  const location = await workspaceLocation(ctx, execution);
  const base = platformBase(config);
  let validated = args;
  if (args.dynamic && base && typeof args.instance === 'string') {
    const instances = await instanceRecords(ctx, location);
    const record = instances.entries.findLast(entry => entry.platform === base && entry.id === args.instance);
    if (record?.state === 'deleted') return { status: 'rejected', verdict: 'rejected_local', reason: '该平台实例已删除。' };
    if (record?.observed_at) validated = { ...args, refreshed_at: record.observed_at };
  }
  return handleSubmission(validated, submissionFiles(ctx, location, execution),
    body => platformRequest(config, execution.signal, 'POST', config?.platformSubmitPath ?? '/submissions', body), base || undefined, location.signal);
}

async function instanceRecords(ctx, location) {
  const document = await progressDocument(ctx, INSTANCE_STATE_FILE, location);
  if (!document.text) return { document, entries: [] };
  const entries = JSON.parse(document.text);
  if (!Array.isArray(entries)) throw new Error('实例记录格式无效。');
  return { document, entries };
}

function createdInstance(response) {
  try {
    const body = JSON.parse(response.body);
    const record = body?.data?.instance ?? body?.data ?? body?.instance ?? body;
    const id = record?.id ?? record?.instance_id;
    if (typeof id === 'string' && id.trim() && id.length <= 200 && !['.', '..'].includes(id.trim())) return id.trim();
    if (Number.isSafeInteger(id)) return String(id);
  } catch { /* Unknown response format has no recorded instance identifier. */ }
  return undefined;
}

async function recordInstance(ctx, location, execution, platform, id, state) {
  if (id === undefined) return false;
  const policy = writablePolicy(ctx, execution);
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const { document, entries } = await instanceRecords(ctx, location);
      const next = [...entries.filter(entry => entry.platform !== platform || entry.id !== id),
        { platform, id, state, observed_at: new Date().toISOString() }].slice(-128);
      const intent = document.version === undefined ? { kind: 'createIfAbsent' }
        : { kind: 'replaceIfVersion', version: document.version };
      await ctx.fs.writeText(document.target, JSON.stringify(next, null, 2) + '\n', intent, location.signal, policy);
      return true;
    } catch {
      if (location.signal?.aborted) return false;
    }
  }
  return false;
}

async function runInstance(ctx, args, execution, config) {
  const location = await workspaceLocation(ctx, execution);
  const base = platformBase(config);
  const { tokenEnv, token } = platformCredential(config);
  const path = config?.platformInstancesPath ?? '/instances';
  if (args.action === 'status') {
    return { status: 'status', configured: base !== '', base: base ? provenanceUrl(webUrl(base)) : null, token_env: tokenEnv,
      token_present: token !== '', instances_path: path, cwd: location.cwd };
  }
  const call = (method, route, body) => platformRequest(config, execution.signal, method, route, body);
  if (args.action === 'list') {
    const request = await call('GET', path);
    return { status: platformOperationSucceeded(request) ? 'instances' : 'failed', request };
  }
  writablePolicy(ctx, execution);
  if (args.action === 'create') {
    const request = await call('POST', path, args.body ?? {});
    if (!platformOperationSucceeded(request)) return { status: 'failed', request };
    const id = createdInstance(request);
    return { status: 'created', request, id, instance_recorded: await recordInstance(ctx, location, execution, base, id, 'created') };
  }
  if (!['rotate', 'delete'].includes(args.action)) throw new Error('未知的实例操作。');
  const id = typeof args.id === 'string' ? args.id.trim() : '';
  if (!id || id === '.' || id === '..' || id.length > 200) throw new Error('rotate 与 delete 需要有效实例 id。');
  const transition = JSON.stringify([base, id]);
  if (instanceTransitions.has(transition)) return { status: 'busy', id };
  instanceTransitions.add(transition);
  try {
    const history = await instanceRecords(ctx, location);
    if (history.entries.some(entry => entry.platform === base && entry.id === id && entry.state === 'deleted')) {
      return { status: 'already_deleted', id };
    }
    let replacement;
    if (args.action === 'rotate') {
      let created;
      try {
        created = await call('POST', path, args.body ?? {});
      } catch {
        return { status: 'unconfirmed', step: 'create', id, old_preserved: true, reason: '请用 list 核对新实例是否已创建。' };
      }
      if (!platformOperationSucceeded(created)) return { status: 'failed', step: 'create', id, old_preserved: true, created };
      const newId = createdInstance(created);
      if (!newId || newId === id) {
        return { status: 'unconfirmed', step: 'create', id, old_preserved: true, created, reason: '平台未返回一个可确认的新实例标识。' };
      }
      const recorded = await recordInstance(ctx, location, execution, base, newId, 'created');
      replacement = { new_id: newId, created, instance_recorded: recorded };
      if (!recorded) return { status: 'partial', step: 'record', id, old_preserved: true, ...replacement };
    }
    let deleted;
    try {
      deleted = await call('DELETE', path + '/' + encodeURIComponent(id));
    } catch {
      return { status: replacement ? 'partial' : 'unconfirmed', step: 'delete', id, ...replacement,
        reason: '需要通过 list 核对旧实例是否已删除。' };
    }
    if (!platformOperationSucceeded(deleted)) {
      return { status: replacement ? 'partial' : 'failed', step: 'delete', id, request: deleted, ...replacement };
    }
    const previousRecorded = await recordInstance(ctx, location, execution, base, id, 'deleted');
    return replacement ? { status: 'rotated', id, deleted, previous_recorded: previousRecorded, ...replacement }
      : { status: 'deleted', id, request: deleted, instance_recorded: previousRecorded };
  } finally {
    instanceTransitions.delete(transition);
  }
}

function detectAttachmentType(name, bytes) {
  const path = String(name ?? '');
  const ext = path.includes('.') ? path.slice(path.lastIndexOf('.') + 1).toLowerCase() : '';
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

async function runFetchAttachment(ctx, args, execution) {
  const url = webUrl(args.url);
  const location = await workspaceLocation(ctx, execution);
  let fallback = url.pathname.split('/').filter(Boolean).at(-1) ?? 'attachment';
  try { fallback = decodeURIComponent(fallback); } catch { /* keep literal path segment */ }
  const wanted = typeof args.name === 'string' && args.name.trim() !== '' ? args.name.trim() : fallback;
  const expected = parseExpectedHash(args.sha256);
  const limit = args.max_bytes ?? MAX_ATTACHMENT_BYTES;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_TRANSFER_BYTES) throw new Error('max_bytes 须在 1 字节至 256 MiB 内。');
  const result = await storeAttachment(ctx, location, execution, wanted, { source_url: provenanceUrl(url) }, async temp => {
    const received = await downloadAttachment(url, temp, { signal: location.signal, limit });
    checkAttachmentHash(expected, received.sha256);
    return received;
  });
  return { status: 'imported', ...result, ...(result.size > MAX_ATTACHMENT_BYTES ? {
    inspection: { range_tool: 'read_binary_range', full_file_limit_bytes: MAX_ATTACHMENT_BYTES,
      ...(result.detected_type === 'zip' ? { zip_directory_tool: 'inspect_attachment', member_tool: 'read_archive_member' } : {}) },
  } : {}) };
}

function parseAddress(value, field, signed = false) {
  const pattern = signed ? /^[+-]?0x[0-9a-f]{1,16}$/iu : /^0x[0-9a-f]{1,16}$/iu;
  if (typeof value !== 'string' || !pattern.test(value)) {
    throw new Error(`${field} 必须是${signed ? '可带符号的' : ''}十六进制数。`);
  }
  if (value.startsWith('-')) return -BigInt(value.slice(1));
  return BigInt(value.startsWith('+') ? value.slice(1) : value);
}

function parseExpectedHash(value) {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/iu.test(value)) {
    throw new Error('expected_sha256 必须是 64 位十六进制字符串。');
  }
  return value.toLowerCase();
}

function parseClaims(args) {
  const claims = {};
  if (args.expected_entry !== undefined) claims.entry = parseAddress(args.expected_entry, 'expected_entry');
  if (args.expected_main !== undefined) claims.main = parseAddress(args.expected_main, 'expected_main');
  if (args.expected_sha256 !== undefined) claims.sha256 = parseExpectedHash(args.expected_sha256);
  if (args.symbol_label !== undefined) {
    const label = args.symbol_label;
    if (!objectWithKeys(label, ['base', 'displacement', 'address'])) throw new Error('symbol_label 必须是对象。');
    claims.symbol_label = {
      base: parseAddress(label.base, 'symbol_label.base'),
      displacement: parseAddress(label.displacement, 'symbol_label.displacement', true),
      address: parseAddress(label.address, 'symbol_label.address'),
    };
  }
  if (Object.keys(claims).length === 0) throw new Error('请提供至少一项待核验的地址、标注或 SHA-256。');
  return claims;
}

function singleLine(value, minLength) {
  return typeof value === 'string' && value.length >= minLength && value.length <= 2 * MAX_EVIDENCE_TEXT
    && [...value].length <= MAX_EVIDENCE_TEXT
    && !/[\r\n\0\p{Cs}]/u.test(value);
}

function parseEvidenceRange(source) {
  if (source.byte_offset === undefined && source.byte_length === undefined
    && source.sha256 === undefined && source.range_sha256 === undefined) return undefined;
  if (!singleLine(source.file_path, 1) || !Number.isSafeInteger(source.byte_offset) || source.byte_offset < 0
    || !Number.isSafeInteger(source.byte_length) || source.byte_length < 1 || source.byte_length > MAX_WINDOW_BYTES
    || typeof source.sha256 !== 'string' || !RESULT_HASH.test(source.sha256.toLowerCase())
    || (source.range_sha256 !== undefined && (typeof source.range_sha256 !== 'string'
      || !RESULT_HASH.test(source.range_sha256.toLowerCase())))) {
    throw new Error('字节范围须包含相对 file_path、非负 byte_offset、有效 byte_length 和原件 sha256。');
  }
  return {
    file_path: pathParts(source.file_path).join('/'),
    byte_offset: source.byte_offset,
    byte_length: source.byte_length,
    expected_file_sha256: source.sha256.toLowerCase(),
    expected_range_sha256: source.range_sha256?.toLowerCase(),
  };
}

function parseEvidenceSources(args, resolveResult) {
  if (!Array.isArray(args.sources) || args.sources.length < 2 || args.sources.length > MAX_EVIDENCE_SOURCES) {
    throw new Error('sources 须提供 2 至 8 条证据位置。');
  }
  if (args.expected_value !== undefined && !singleLine(args.expected_value, 0)) {
    throw new Error('expected_value 须是不超过 256 字符的单行文本。');
  }
  return args.sources.map(source => {
    if (source === null || typeof source !== 'object' || Array.isArray(source)
      || !objectWithKeys(source, Object.keys(SOURCE_PROPERTIES))) {
      throw new Error('每条证据只可包含文本定位、字节范围或结果编号字段。');
    }
    const range = parseEvidenceRange(source);
    if ((range || source.result_id !== undefined) && [source.line, source.prefix, source.suffix].some(value => value !== undefined)) {
      throw new Error('文本前缀、行号和后缀须作为单独的证据，不能与字节范围或结果编号混用。');
    }
    if (source.result_id !== undefined) {
      if (typeof source.result_id !== 'string' || !RESULT_HASH.test(source.result_id.toLowerCase())
        || (source.file_path !== undefined && range === undefined)) {
        throw new Error('result_id 须是 64 位结果编号，可单独使用或附完整字节范围。');
      }
      const id = source.result_id.toLowerCase();
      const output = resolveResult(id)?.report;
      if (output === undefined) {
        if (range) return { ...range, result_id: id, used_fallback: true };
        throw new Error('result_id 不存在或已过期，请附原件路径、字节范围和 SHA-256，或重新读取。');
      }
      if (typeof output.file !== 'string' || !Number.isSafeInteger(output.byte_offset)
        || !Number.isSafeInteger(output.byte_length)) {
        throw new Error('该 result_id 没有可复核的单个文件范围，请使用原件路径和前缀，或直接提供字节范围。');
      }
      const reference = {
        file_path: pathParts(output.file).join('/'),
        byte_offset: output.byte_offset,
        byte_length: output.byte_length,
        expected_range_sha256: typeof output.range_sha256 === 'string' ? output.range_sha256 : undefined,
        expected_file_sha256: typeof output.sha256 === 'string' ? output.sha256 : undefined,
      };
      if (range && Object.entries(range).some(([key, value]) => value !== undefined && reference[key] !== value)) {
        throw new Error('提供的字节范围或 SHA-256 与该 result_id 的原件引用不一致。');
      }
      return reference;
    }
    if (range) return range;
    if (!singleLine(source.file_path, 1) || !singleLine(source.prefix, 1)
      || (source.suffix !== undefined && !singleLine(source.suffix, 1))
      || (source.line !== undefined && (!Number.isSafeInteger(source.line) || source.line < 1))) {
      throw new Error('每条证据须提供相对文件路径和单行前缀，可附行号及单行后缀。');
    }
    return { file_path: pathParts(source.file_path).join('/'), line: source.line, prefix: source.prefix, suffix: source.suffix };
  });
}

function resultSources(tool, output, workspace) {
  if (!workspace) return [];
  if (tool === 'read_ctf_files') return output.sources.length ? output.sources : undefined;
  if (['trace_flask_route', 'verify_flask_response', 'query_rev_export', 'map_rev_address',
    'verify_rev_machine', 'compare_rev_trace'].includes(tool)) return output.sources;
  if (tool === 'verify_http_evidence') return output.observations.map(observation => observation.source);
  if (tool === 'verify_evidence') {
    if (!output.observations.every(source => typeof source.sha256 === 'string' && RESULT_HASH.test(source.sha256))) return undefined;
    return output.observations.map(source => ({
      file_path: source.file, sha256: source.sha256,
      ...(source.status === 'observed' ? { line: source.line, byte_offset: source.byte_offset, byte_length: source.byte_length || undefined } : {}),
    }));
  }
  if (typeof output.sha256 !== 'string' || !RESULT_HASH.test(output.sha256)) return undefined;
  return [{
    file_path: pathParts(output.file).join('/'), sha256: output.sha256,
    ...(['read_log_range', 'read_binary_range'].includes(tool)
      ? { byte_offset: output.byte_offset, byte_length: output.byte_length || undefined } : {}),
  }];
}

function describeArchiveMember(member, memberIndex, window) {
  const { bytes, format, variant, name, size = bytes?.length } = member;
  const length = windowLength(size, window);
  const chunk = member.chunk ?? bytes.subarray(window.offset, window.offset + length);
  return {
    format, variant, member_index: memberIndex, member_name: name, member_size: size,
    ...(member.name_encoding === undefined ? {} : { name_encoding: member.name_encoding }),
    ...(member.name_truncated ? { name_truncated: true } : {}),
    ...(member.encryption_flag_only ? { encryption_flag_only: true } : {}),
    member_sha256: member.sha256 ?? createHash('sha256').update(bytes).digest('hex'),
    ...describeByteWindow(chunk, size, window),
  };
}

async function readArchiveMember(ctx, args, location, inspectRanges, workbench) {
  const memberIndex = args.member_index;
  if (!Number.isSafeInteger(memberIndex) || memberIndex < 0) throw new Error('member_index 须是非负整数。');
  const window = parseByteWindow(args, 'auto', 1024);
  const expectedHash = parseExpectedHash(args.expected_sha256);
  const zipHint = args.format_hint === 'zip';
  if (args.format_hint !== undefined && !zipHint) throw new Error('format_hint 目前支持 zip。');
  const file = await openWorkspaceFile(ctx, pathParts(args.file_path), location);
  if (args.password !== undefined) {
    const bytes = await readOpenedFile(ctx, file, location.signal);
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    checkAttachmentHash(expectedHash, sha256);
    const member = await readZipWithKnownPassword(bytes, memberIndex, args.password, workbench, location.signal);
    await requireCurrentFile(ctx.fs, file, location.signal);
    if (member.status === 'dependency_missing') return { ...member, size: file.size, sha256 };
    return { ...describeArchiveMember(member, memberIndex, window), size: file.size, sha256 };
  }
  if (typeof ctx.fs.readByteRange === 'function') {
    const zip = await inspectRanges(file, location.signal, expectedHash, async (reader, index) => {
      const member = await readZipMember(reader, memberIndex, index, zipHint);
      return member && { report: describeArchiveMember(member, memberIndex, window), zipIndex: member.zipIndex };
    });
    if (zip !== undefined) return zip;
    if (zipHint) throw new Error('未在文件中找到可验证的 ZIP 目录。');
  }
  const bytes = await readOpenedFile(ctx, file, location.signal);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  checkAttachmentHash(expectedHash, sha256);
  const native = zipHint ? undefined : nativeArchiveFormat(bytes);
  const member = native
    ? await readNativeArchiveMember(bytes, native, memberIndex, window, location.signal, workbench)
    : (zipHint ? undefined : await readTarOrGzipMember(bytes, memberIndex, location.signal))
      ?? await readZipMember({ size: bytes.length, read: (offset, length) => bytes.subarray(offset, offset + length) },
        memberIndex, undefined, zipHint);
  if (member === undefined) throw new Error('可读取 ZIP/ZIP64、TAR、TAR.GZ、gzip、7z 和 RAR 的普通文件成员。');
  await requireCurrentFile(ctx.fs, file, location.signal);
  if (member.status === 'dependency_missing') return { ...member, member_index: memberIndex, size: bytes.length, sha256 };
  return { ...describeArchiveMember(member, memberIndex, window), size: bytes.length, sha256 };
}

function compactJson(value, config) {
  return JSON.stringify(value, null, config?.compact === false ? 2 : 0);
}

function registerTool(ctx, toolName, description, properties, run, required = ['file_path'], capture, parametersOverride) {
  ctx.tools.register({
    name: toolName,
    description,
    parameters: parametersOverride ?? {
      type: 'object',
      properties,
      additionalProperties: false,
      required,
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
    async execute(args, execution) {
      const askedFile = typeof args?.file_path === 'string' ? args.file_path : undefined;
      try {
        if (!objectWithKeys(args, Object.keys(properties))) throw new ToolError('unsupported', '提供了此工具不支持的参数。');
        const location = capture?.workspace ? await workspaceLocation(ctx, execution) : undefined;
        let prepared = args;
        let imported;
        if (location !== undefined) ({ args: prepared, imported } = await rewriteInputPaths(ctx, args, location, execution, capture.config));
        const report = await run(prepared, execution, location);
        const output = { file: prepared.file_path, ...(imported?.length ? { imported } : {}), ...report };
        const scope = capture?.workspace ? location.directoryKey : (capture?.scope ?? null);
        const resultId = capture && scope !== undefined ? capture.results.remember(execution.agent?.session, scope, toolName,
          output, resultSources(toolName, output, capture.workspace)) : undefined;
        const outputConfig = capture?.config ?? OUTPUT_CONFIGS.get(ctx);
        if (resultId === undefined) return compactJson(output, outputConfig);
        const result = capture.workspace ? capture.results.get(execution.agent?.session, scope, resultId) : undefined;
        const summary = result?.summary;
        const evidencePersistence = result === undefined ? undefined : await persistResult(ctx, location, execution, resultId, result);
        return compactJson({
          result_id: resultId, ...output,
          ...(evidencePersistence === undefined ? {} : { evidence_persistence: evidencePersistence }),
          ...(summary === undefined ? {} : {
            result_cache: { mode: 'fields', field_count: summary.fields.size, limited: summary.limited },
          }),
        }, outputConfig);
      } catch (error) {
        return compactJson({ ok: false, file: askedFile, error: describeToolError(error) }, capture?.config ?? OUTPUT_CONFIGS.get(ctx));
      }
    },
  });
}

export function apply(ctx, config) {
  const workbench = createWorkbenchEnvironment(config);
  config = workbench.presetConfig();
  OUTPUT_CONFIGS.set(ctx, config);
  const inspectRanges = createRangeInspector(ctx.fs);
  const results = createToolResults();
  const calculation = createCalculationRunner();
  ctx.effect(() => () => calculation.dispose(), 'CTF offline calculation workers');
  const fileResults = { results, workspace: true, config };
  const offlineResults = { results, workspace: false, scope: OFFLINE_RESULT_SCOPE };
  const sessionResults = { results, workspace: false };
  const network = createNetworkBoundary(config);
  const tcpSessions = new WeakMap();
  const managers = new Set();
  ctx.effect(() => () => {
    for (const manager of managers) manager.dispose();
    managers.clear();
  }, 'CTF TCP sessions');
  async function tcpManager(execution) {
    const location = await workspaceLocation(ctx, execution);
    const session = execution.agent.session;
    let inSession = tcpSessions.get(session);
    if (inSession === undefined) {
      inSession = new Map();
      tcpSessions.set(session, inSession);
    }
    let manager = inSession.get(location.directoryKey);
    if (!managers.has(manager)) {
      if (managers.size >= 32) {
        const idle = [...managers].find(entry => entry.idle());
        if (idle) { idle.dispose(); managers.delete(idle); }
        else throw new Error('TCP 会话工作区数量已达上限。');
      }
      manager = createNetSessionManager({ authorize: network.tcp });
      inSession.set(location.directoryKey, manager);
      managers.add(manager);
    }
    return manager;
  }
  registerTool(ctx, 'read_ctf_files',
    '边界：需要一次读取多个已知文本路径或行段时用本工具；单个文件用 read。批量读取题面已经列明的本地文本路径与行段，返回每个片段的文本、原件行号、字节偏移和 SHA-256。',
    BATCH_TEXT_PROPERTIES,
    (args, _execution, location) => readCtfFiles(args, {
      normalizePath: path => pathParts(path).join('/'),
      read: path => snapshotEvidence(ctx, path, location, MAX_BATCH_FILE_BYTES),
    }), ['files'], fileResults);
  registerTool(ctx, 'inspect_attachment',
    '只读检查本地 PNG、JPEG、ZIP/ZIP64、7z、RAR、TAR/TAR.GZ、gzip、PCAP/PCAPNG、ELF、PE 和 WebAssembly。返回原件 SHA-256 和分页结构。归档目录返回成员序号及大小。传 pcapng 查询接口和 UTC 窗口。',
    ATTACHMENT_PROPERTIES,
    async (args, _execution, location) => {
      const { offset = 0, limit = 10 } = args;
      if (!Number.isInteger(offset) || offset < 0 || offset > MAX_ATTACHMENT_BYTES
        || !Number.isInteger(limit) || limit < 1 || limit > 16) {
        throw new Error('offset 必须是范围内的非负整数，limit 必须是 1 至 16 的整数。');
      }
      const paging = { offset, limit };
      const expectedHash = parseExpectedHash(args.expected_sha256);
      const pcapngQuery = parsePcapngQuery(args.pcapng);
      const zipHint = args.format_hint === 'zip';
      if (args.format_hint !== undefined && !zipHint) throw new Error('format_hint 目前支持 zip。');
      if (zipHint && pcapngQuery !== undefined) throw new Error('一次只能查询 ZIP 或 PCAPNG。');
      const file = await openWorkspaceFile(ctx, pathParts(args.file_path), location);
      if (pcapngQuery === undefined && typeof ctx.fs.readByteRange === 'function') {
        const zip = await inspectRanges(file, location.signal, expectedHash,
          (reader, index) => inspectZipRanges(reader, paging, index, zipHint));
        if (zip !== undefined) return zip;
        if (zipHint) throw new Error('未在文件中找到可验证的 ZIP 目录。');
      }
      const bytes = await readOpenedFile(ctx, file, location.signal);
      if (zipHint) {
        const zip = await inspectZipRanges({ size: bytes.length, read: (offset, length) => bytes.subarray(offset, offset + length) },
          paging, undefined, true);
        if (zip === undefined) throw new Error('未在文件中找到可验证的 ZIP 目录。');
        const sha256 = createHash('sha256').update(bytes).digest('hex');
        checkAttachmentHash(expectedHash, sha256);
        return { ...zip.report, size: bytes.length, sha256 };
      }
      const archiveFormat = pcapngQuery === undefined ? nativeArchiveFormat(bytes) : undefined;
      if (archiveFormat !== undefined) {
        const sha256 = createHash('sha256').update(bytes).digest('hex');
        checkAttachmentHash(expectedHash, sha256);
        const archive = await inspectNativeArchive(bytes, archiveFormat, paging, location.signal, workbench);
        return { ...archive, size: bytes.length, sha256 };
      }
      const report = inspectAttachment(bytes, paging, pcapngQuery);
      checkAttachmentHash(expectedHash, report.sha256);
      return report;
    }, undefined, fileResults);
  registerTool(ctx, 'read_png_pixels',
    '读取 PNG 原始像素或 LSB 位平面，支持区域、分页、通道及 APNG 帧。返回样本位深和帧语义。',
    { file_path: PATH_SCHEMA, ...PNG_PIXEL_PROPERTIES, expected_sha256: SHA256_SCHEMA },
    (args, _execution, location) => readMediaAttachment(ctx, args, parsePngRequest(args), location, workbench),
    ['file_path'], fileResults);
  registerTool(ctx, 'inspect_media',
    '检查 PDF、常见图像及帧元数据、PNG/JPEG 二维码、WAV/FLAC/ID3 音频元数据。返回原件 SHA-256。',
    { file_path: PATH_SCHEMA, ...MEDIA_PROPERTIES, expected_sha256: SHA256_SCHEMA },
    (args, _execution, location) => readMediaAttachment(ctx, args, parseMediaRequest(args), location, workbench),
    ['file_path', 'kind'], fileResults);
  registerTool(ctx, 'read_archive_member',
    '按目录的 member_index 在内存中读取单个普通归档成员，成员解压后限 1 MiB。返回分页内容和原件、成员 SHA-256。支持未加密 ZIP/ZIP64、TAR/TAR.GZ、gzip、7z/RAR。',
    ARCHIVE_MEMBER_PROPERTIES,
    (args, _execution, location) => readArchiveMember(ctx, args, location, inspectRanges, workbench), ['file_path', 'member_index'], fileResults);
  registerTool(ctx, 'read_binary_range',
    '按精确偏移读取本地附件的一段字节，每次最多 4 KiB。默认输出十六进制、ASCII 和片段 SHA-256。strings 为 true 时附可打印字符串及绝对偏移。',
    BINARY_RANGE_PROPERTIES,
    async (args, _execution, location) => {
      const window = parseByteWindow(args, 'hexdump', 256);
      const { hash_scope: scope = 'auto', strings = false, min_string_length: minimum = 4 } = args;
      const expectedHash = parseExpectedHash(args.expected_sha256);
      if (!['auto', 'file', 'range'].includes(scope) || (scope === 'range' && expectedHash !== undefined)) {
        throw new Error('hash_scope 须为 auto、file 或 range。核对原件 SHA-256 时请选择 auto 或 file。');
      }
      if (typeof strings !== 'boolean' || !Number.isSafeInteger(minimum) || minimum < 1 || minimum > 256) {
        throw new Error('strings 须为布尔值，min_string_length 须是 1 至 256 的整数。');
      }
      if (typeof ctx.fs.readByteRange !== 'function') throw new Error('当前 DSH 文件服务不支持分段读取。');
      const file = await openWorkspaceFile(ctx, pathParts(args.file_path), location);
      const hashFile = scope === 'file' || (scope === 'auto' && (expectedHash !== undefined || file.size <= AUTO_FILE_HASH_LIMIT));
      return inspectRanges(file, location.signal, expectedHash, async ({ size, read }) => {
        const bytes = await read(window.offset, windowLength(size, window));
        const report = describeByteWindow(bytes, size, window);
        return { report: {
          ...report,
          hash_scope: hashFile ? 'file' : 'range',
          ...(strings ? printableStrings(bytes, window.offset, minimum) : {}),
        } };
      }, { hashFile });
    }, undefined, fileResults);
  registerTool(ctx, 'read_log_range',
    '按字节偏移只读题目目录里的 UTF-8 日志或文本片段。返回实际偏移、下一段偏移和原件 SHA-256。继续读取时可核对上一段的 SHA-256。',
    LOG_RANGE_PROPERTIES,
    async (args, _execution, location) => {
      const { byte_offset: offset = 0, byte_length: length = 2048 } = args;
      if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isInteger(length) || length < 1 || length > MAX_LOG_WINDOW_BYTES) {
        throw new Error('byte_offset 须是非负安全整数，byte_length 须在 1 至 4096 之间。');
      }
      if (typeof ctx.fs.readByteRange !== 'function') throw new Error('当前 DSH 文件服务不支持分段读取。');
      const expectedHash = parseExpectedHash(args.expected_sha256);
      const file = await openWorkspaceFile(ctx, pathParts(args.file_path), location);
      return inspectRanges(file, location.signal, expectedHash, reader => inspectLogWindow(reader, offset, length));
    }, undefined, fileResults);
  registerTool(ctx, 'inspect_elf',
    '检查本地 ELF 的文件头、静态与动态符号表状态、入口和 SHA-256。按 checksec 口径给出 NX、PIE、RELRO、canary、FORTIFY、动态导入、DT_NEEDED 和 x86-64 常见 gadget 字节扫描；x86-64 还返回 PLT/GOT 重定位、system 等 libc 导出偏移和 /bin/sh 位置。依赖节头，节头缺失时部分字段不可用。对匹配的 x86-64 glibc 启动形式给出可核验的 main 证据。',
    { file_path: PATH_SCHEMA },
    async (args, _execution, location) => inspectElf(await readAttachment(ctx, args.file_path, location)), undefined, fileResults);
  registerTool(ctx, 'pwn_cyclic',
    '生成或查找 pwntools 兼容的 De Bruijn 循环模式（阶 4、字母表 a–z）。create 返回指定长度前缀；find 按十六进制字节串或 0x 整数（默认小端）返回 0 起始偏移；用于栈溢出 offset 和泄露值定位。',
    PWN_PATTERN_PROPERTIES,
    async args => cyclicPattern(args), ['operation']);
  registerTool(ctx, 'net_session',
    '边界：需要保持连接多次收发、按分隔符读取或自定义 TCP 协议时用本工具；一次性管道用 shell。建立 TCP 会话并收发字节，支持 connect、send、recv、read_until、close 和 list。recv 在文本安全时返回 UTF-8，二进制返回十六进制和 hexdump；read_until 读到分隔符或 64 KiB 上限；单次发送限 1 MiB，最多同时保留 8 个会话。用于 pwn 远程交互和自定义 TCP 协议。',
    NET_SESSION_PROPERTIES,
    async (args, execution) => {
      if (args.operation === 'send') writablePolicy(ctx, execution);
      const manager = await tcpManager(execution);
      const report = await manager.execute(args, { signal: execution.signal });
      return Array.isArray(report) ? { sessions: report } : report;
    }, ['operation'], sessionResults);
  registerTool(ctx, 'http_request',
    '边界：需要指定方法、请求头、重定向策略或结构化观测时用本工具；单次简单 curl 用 shell。发起 HTTP/HTTPS 请求并返回状态、响应头和有限正文。自动重定向仅限同源且无请求体的 GET/HEAD，其他跳转保留 3xx 响应。正文支持 gzip/deflate/br，最多 1 MiB。',
    HTTP_REQUEST_PROPERTIES,
    async (args, execution) => {
      await workspaceLocation(ctx, execution);
      if (!['GET', 'HEAD', 'OPTIONS'].includes(String(args.method ?? 'GET').toUpperCase()) || args.body !== undefined) {
        writablePolicy(ctx, execution);
      }
      if (Object.keys(args.headers ?? {}).some(name => name.toLowerCase() === 'host')) {
        throw new Error('HTTP Host 随授权 URL 生成。');
      }
      return cleanHttpResponse(await httpRequest(args, { signal: execution.signal, authorize: network.http }));
    }, ['url'], sessionResults);
  registerTool(ctx, 'pcap_stream',
    '只读分析 PCAP/PCAPNG，支持 BSD 回环和 Linux cooked。重组 IPv4 分片及 TCP 流，列出捕获时间及 UDP DNS 的查询名、TXT 样本。未完成分片和截断包单列统计。',
    PCAP_STREAM_PROPERTIES,
    async (args, execution, location) => {
      await openWorkspaceFile(ctx, pathParts(args.file_path), location);
      return pcapStream(args, { cwd: location.cwd, signal: execution.signal });
    }, ['file_path'], fileResults);
  registerTool(ctx, 'verify_elf',
    '从原文件重新核验 ELF 入口、main、动态符号偏移标注或 SHA-256。逐项返回匹配状态与理由。',
    VERIFY_PROPERTIES,
    async (args, _execution, location) => {
      const claims = parseClaims(args);
      return verifyElf(await readAttachment(ctx, args.file_path, location), claims);
    }, undefined, fileResults);
  registerTool(ctx, 'verify_evidence',
    '对照 2 至 8 个本地证据位置。可提供文本前缀、文件字节范围及 SHA-256，或结果编号。编号过期时可按完整的原件范围复算。',
    EVIDENCE_PROPERTIES,
    async (args, execution, location) => {
      const recorded = await recordedResults(ctx, location);
      const sources = parseEvidenceSources(args, id => results.get(execution.agent?.session, location.directoryKey, id) ?? recorded.get(id));
      return verifyEvidence(sources, args.expected_value, file => snapshotEvidence(ctx, file, location));
    }, ['sources'], fileResults);
  registerTool(ctx, 'verify_http_evidence',
    '用已知方法、路径及可选的请求 ID，对照题目内的 HAR、JSONL 或 Common/Combined 日志及预期状态表。返回状态码、匹配情况、少量响应头元数据及原件位置。',
    HTTP_EVIDENCE_PROPERTIES,
    (args, _execution, location) => verifyHttpEvidence(args, {
      normalizePath: path => pathParts(path).join('/'),
      read: path => readWorkspaceFile(ctx, path.split('/'), location, MAX_HTTP_BYTES),
    }), ['request', 'sources'], fileResults);
  registerTool(ctx, 'trace_flask_route',
    '从本地 Python 源码定位 Flask 方法、路径、蓝图挂载、请求前钩子、响应钩子和处理函数。汇总可静态识别的状态码及源码行。',
    FLASK_ROUTE_PROPERTIES,
    (args, _execution, location) => traceFlaskRoute(args, {
      normalizePath: path => pathParts(path).join('/'),
      read: path => readWorkspaceFile(ctx, path.split('/'), location, MAX_FLASK_SOURCE_BYTES),
    }, location.signal, workbench), ['entry_file', 'request'], fileResults);
  registerTool(ctx, 'verify_flask_response',
    '将已有的 JSONL 应用返回事件与本会话的 HTTP 观测和 Flask 源码结果核对。按已知请求 ID、方法、路径、状态码与源码行关联，证据不足时保留候选。',
    FLASK_RESPONSE_PROPERTIES,
    (args, execution, location) => verifyFlaskResponse(args, {
      normalizePath: path => pathParts(path).join('/'),
      readEvent: path => readWorkspaceFile(ctx, path.split('/'), location, MAX_HTTP_BYTES),
      readSource: path => snapshotEvidence(ctx, path, location, MAX_HTTP_BYTES),
      async result(id) {
        const local = results.get(execution.agent?.session, location.directoryKey, id);
        if (local?.report !== undefined) return local;
        const recorded = (await recordedResults(ctx, location)).get(id);
        return recorded?.full === true ? recorded : undefined;
      },
    }), ['http_result_id', 'observation_index', 'trace_result_id', 'file_path'], fileResults);
  registerTool(ctx, 'query_rev_export',
    '按已知名称、地址或字符串查询现有的本地 JSONL 或 GNU 式导出。返回导出中记录的函数、直接调用与引用证据。',
    REV_EXPORT_PROPERTIES,
    async (args, _execution, location) => {
      const parts = pathParts(args.file_path);
      const { bytes } = await readWorkspaceFile(ctx, parts, location, MAX_REV_TEXT_BYTES);
      return queryRevExport(bytes, parts.join('/'), args.format, args.query);
    }, ['file_path', 'format', 'query'], fileResults);
  registerTool(ctx, 'map_rev_address',
    '在本地 ELF、PE 或 Wasm 原件上核对给定虚拟地址、相对地址、节内偏移或文件偏移。返回映射位置、字节范围与原件引用。',
    REV_ADDRESS_PROPERTIES,
    async (args, _execution, location) => {
      const parts = pathParts(args.file_path);
      const { bytes } = await readWorkspaceFile(ctx, parts, location);
      return mapRevAddress(bytes, parts.join('/'), args);
    }, ['file_path', 'queries'], fileResults);
  registerTool(ctx, 'verify_rev_machine',
    '按已给出的本地 JSONL 字节状态机规则处理短 Hex 样例。返回每一步的输入、状态、累加值、输出与规则行。',
    REV_MACHINE_PROPERTIES,
    async (args, _execution, location) => {
      const parts = pathParts(args.file_path);
      const { bytes } = await readWorkspaceFile(ctx, parts, location, MAX_REV_TEXT_BYTES);
      return verifyRevMachine(bytes, parts.join('/'), args);
    }, ['file_path', 'input_hex'], fileResults);
  registerTool(ctx, 'compare_rev_trace',
    '对照已有本地 JSONL 运行记录与参考记录或本会话的状态机结果。按 step 和指定字段返回第一个差异及两侧证据。',
    REV_TRACE_PROPERTIES,
    (args, execution, location) => compareRevTrace(args, {
      normalizePath: path => pathParts(path).join('/'),
      read: path => readWorkspaceFile(ctx, path.split('/'), location, MAX_REV_TEXT_BYTES),
      snapshot: path => snapshotEvidence(ctx, path, location, MAX_REV_TEXT_BYTES),
      async result(id) {
        const local = results.get(execution.agent?.session, location.directoryKey, id);
        if (local?.report !== undefined) return local;
        const recorded = (await recordedResults(ctx, location)).get(id);
        return recorded?.full === true ? recorded : undefined;
      },
    }), ['file_path', 'fields'], fileResults);
  registerTool(ctx, 'rev_query',
    '用本机 Python 与 capstone 对会话工作区内的 ELF 做线性反汇编（按符号、地址或节，20 至 400 条）或字符串扫描（最短 4 至 64 字节，最多 200 条）。返回地址、字节、助记符、操作数和文件偏移；反汇编需要 capstone，strings 只依赖 Python。',
    Object.fromEntries(Object.entries(REV_QUERY_PROPERTIES).filter(([key]) => key !== 'python_path')),
    async (args, execution, location) => {
      const file = await openWorkspaceFile(ctx, pathParts(args.file_path), location);
      const report = await runRevQuery(args, {
        cwd: location.cwd, signal: execution.signal, pythonPath: await workbench.resolvePython(execution.signal),
      });
      await requireCurrentFile(ctx.fs, file, location.signal);
      return report;
    }, ['file_path', 'operation'], fileResults);
  registerTool(ctx, 'calculate_offline',
    '执行大整数、定宽字、模运算、字节序、进制或编码转换，以及哈希/HMAC、base32/base58/base85/URL/HTML、XOR 与单字节爆破、凯撒/维吉尼亚/仿射/栅栏、AES、RSA 原始运算和 RSA 攻击（rsa_attack：factor/fermat/wiener/common_modulus/broadcast/small_e）。可引用前序结果并核对样例，返回首个不符的步骤。',
    CALCULATION_PROPERTIES,
    (args, execution) => calculation.run(args.steps, execution.signal),
    ['steps'], offlineResults);
  const base100 = new Base100Workbench(workbench);
  ctx.effect(() => () => base100.dispose(), 'CTF Base100 workbench process');
  registerTool(ctx, 'workbench_base100',
    '批量使用本机 CTF 工作台进行 Base100 编码和解码。编码输入为 UTF-8 或 Hex。解码返回 Hex 和有效的 UTF-8 文本。',
    WORKBENCH_BASE100_PROPERTIES,
    async (args, execution) => {
      try {
        return await base100.run(args.items, execution.signal);
      } catch (error) {
        if (!(error instanceof WorkbenchDependencyError)) throw error;
        return { status: 'dependency_missing', reason: error.message };
      }
    },
    ['items'], offlineResults);
  registerTool(ctx, 'ctf_progress',
    'load 恢复题目笔记并复核原件。check 核对 claims，纯工具值一致时返回 tool_match，只有笔记记录时返回 recorded。save 保存结果与附件路径。writeup 生成题解草稿。handoff 整理题目目录、附件和下一步。repair 可备份并修复托管区。',
    PROGRESS_PROPERTIES,
    (args, execution) => {
      const allowed = PROGRESS_ACTION_KEYS[args.action];
      if (!allowed || Object.keys(args).some(key => !allowed.includes(key))) {
        throw new ToolError('unsupported', 'ctf_progress 的字段须与 action 对应。');
      }
      return runProgress(ctx, args, execution, results, inspectRanges);
    }, ['action'], undefined, PROGRESS_PARAMETERS);
  registerTool(ctx, 'ctf_status',
    '记录或查看时间盒心跳：已用时间、卡点、已排除假设、下一步和需要谁。set 追加一条（每题建议至少 2 次），show 返回含 code、severity、action 的 warnings[] 以及兼容文本 warning_messages：15 分钟换方向、30 分钟列三条路径、60 分钟升级求助；board 从平台榜单接口拉取排名/分数/解题数并写一条记录。',
    STATUS_PROPERTIES,
    (args, execution) => runStatus(ctx, args, execution, config), ['action']);
  registerTool(ctx, 'check_flag',
    '提交前在本地校验 flag 的格式、长度、来源、重复记录和实例刷新时间。默认只读，传 record:true 时才写预检回执。',
    SUBMIT_FLAG_PROPERTIES,
    (args, execution) => runSubmitCheck(ctx, args, execution, config), ['flag']);
  registerTool(ctx, 'submit_flag',
    '本地校验通过后按插件配置的 platformUrl 提交 flag 到比赛平台，解析平台响应并返回 accepted / rejected / duplicate，同时把回执写入 .ctf-submissions.jsonl。未配置平台时返回 dependency；同一 flag 重复提交会先告警。',
    SUBMIT_FLAG_PROPERTIES,
    (args, execution) => runSubmitFlag(ctx, args, execution, config), ['flag']);
  registerTool(ctx, 'ctf_instance',
    '列出、创建和删除比赛实例。rotate 先确认新实例已创建，再删除传入 id。创建失败时保留旧实例。',
    INSTANCE_PROPERTIES,
    (args, execution) => runInstance(ctx, args, execution, config), ['action']);
  registerTool(ctx, 'fetch_attachment',
    '下载附件到工作区并登记来源和 SHA-256。默认 32 MiB，可显式放宽至 256 MiB。大文件返回分段读取提示。',
    FETCH_PROPERTIES,
    (args, execution) => runFetchAttachment(ctx, args, execution), ['url']);
  registerTool(ctx, 'submit_check',
    '已弃用兼容别名：请改用 check_flag。仍执行本地预检，不联网、不代替平台提交。',
    SUBMIT_FLAG_PROPERTIES,
    (args, execution) => runSubmitCheck(ctx, args, execution, config), ['flag']);
  registerTool(ctx, 'ctf_doctor',
    '自检宿主必需接口、本机依赖与续接文件。返回 status（ok/partial/missing）、必需缺项 missing、可选缺项 optional_missing 和宿主能力。尚未创建的题目记录与可选工具不会误报为必需故障；无提示注入接口时依赖包内 SKILL。只读不改文件。',
    { action: { type: 'string', enum: ['check'], description: '默认 check。' } },
    (_args, execution) => runDoctor(ctx, execution, config, workbench), ['action']);
  registerTool(ctx, 'competition_api',
    '按插件配置的 platformUrl 访问比赛平台：status 查看配置与 token 环境变量，instances 列出实例，create 新建实例（body 为请求体），delete 删除实例（需 id），submit 提交 flag 并追加本地回执。未配置平台时说明如何配置；不回显 token。',
    {
      action: { type: 'string', enum: ['status', 'instances', 'create', 'delete', 'submit'], description: '要执行的动作。' },
      ...SUBMIT_FLAG_PROPERTIES,
      id: { type: 'string', maxLength: 200, description: 'delete 时的实例标识。' },
      body: { type: 'object', description: 'create 时的请求体，按 JSON 原样提交。', additionalProperties: true },
    },
    (args, execution) => runCompetitionApi(ctx, args, execution, config), ['action']);
  registerExtraTools(ctx, config, {
    location: execution => workspaceLocation(ctx, execution),
    async input(location, path) {
      const parts = pathParts(path);
      await openWorkspaceFile(ctx, parts, location);
      return join(location.cwd, ...parts);
    },
    read: (location, path, limit) => readWorkspaceFile(ctx, pathParts(path), location, limit),
    output: (location, path, directory) => checkedOutput(ctx, location, path, directory),
    python: signal => workbench.resolvePython(signal),
    authorize: network.http,
    async observe(tool, args, execution, report) {
      if (tool === 'cloud_metadata' || (tool === 'archive_crack' && args.action !== 'info')
        || ['failed', 'timeout', 'closed'].includes(report.status)) return undefined;
      const location = await workspaceLocation(ctx, execution);
      const session = execution.agent?.session;
      const sources = typeof args.file_path === 'string' && RESULT_HASH.test(report.input_sha256 ?? '')
        ? [{ file_path: pathParts(args.file_path).join('/'), sha256: report.input_sha256 }] : [];
      const resultId = results.remember(session, location.directoryKey, tool, report, sources);
      if (!resultId) return undefined;
      const result = results.get(session, location.directoryKey, resultId);
      const persisted = sources.length && result ? await persistResult(ctx, location, execution, resultId, result) : undefined;
      return { result_id: resultId, ...(persisted === undefined ? {} : { evidence_persistence: persisted }) };
    },
  });
  const prompt = ctx.get?.('systemPrompt');
  if (prompt && typeof prompt.context === 'function') {
    try {
      prompt.context({
        name: 'ctf-resume-hint',
        order: 900,
        text: '本题工作区可能有 notes.md（续接记录）、handoff.md（接替简报）、.ctf-status.json（时间盒心跳）和 .ctf-submissions.jsonl（提交回执）：开始或接手时先读它们，再决定下一步。',
      });
    } catch {
      // Older hosts may not expose the system prompt service; SKILL.md carries the same rule.
    }
  }
}
