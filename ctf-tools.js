import { createHash, randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { constants, createReadStream } from 'node:fs';
import { copyFile, lstat, mkdir, readFile, realpath, unlink } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative } from 'node:path';
import { downloadAttachment, MAX_TRANSFER_BYTES, provenanceUrl, stageAttachment } from './attachment-transfer.js';
import { createNetworkBoundary, pinAddress, webUrl } from './network-boundary.js';
import { platformAuthHeaders, platformBase, platformCredential, platformRequest, redactPlatformToken } from './platform-request.js';
import { describeToolError, ToolError } from './tool-errors.js';
import { readZipWithKnownPassword } from './archive-password.js';
import { checkRange, MAX_ARCHIVE_MEMBER_BYTES, MAX_ATTACHMENT_BYTES } from './attachment-layout.js';
import { inspectAttachment } from './attachment.js';
import { inspectDecompressedStream, readDecompressedStreamMember, readTarOrCompressedMember } from './archive.js';
import { compressedStreamFormat, decompressCompressedStream } from './compressed-stream.js';
import {
  checkAttachmentHash, createRangeInspector, inspectEvidenceLines, inspectLogWindow, MAX_LOG_WINDOW_BYTES,
  requireCurrentFile, WorkspaceFileError,
} from './attachment-ranges.js';
import { BYTE_WINDOW_PROPERTIES, describeByteWindow, MAX_WINDOW_BYTES, parseByteWindow, printableStrings, windowLength } from './byte-window.js';
import { BINARY_SCAN_PROPERTIES, parseBinaryScan, scanBinary } from './binary-scan.js';
import { inspectZipRanges, readZipMember } from './zip-directory.js';
import { inspectZipCandidates } from './zip-candidates.js';
import { inspectNativeArchive, nativeArchiveFormat, readNativeArchiveMember } from './archive-directory.js';
import { parsePcapngQuery, PCAPNG_QUERY_SCHEMA } from './pcapng-statistics.js';
import { inspectMedia, MEDIA_PROPERTIES, parseMediaRequest, parsePngRequest, PNG_PIXEL_PROPERTIES } from './media-reader.js';
import { inspectElf, verifyElf } from './elf.js';
import { PWN_PATTERN_PROPERTIES, cyclicPattern } from './pwn-pattern.js';
import { PWN_PAYLOAD_PROPERTIES, buildPwnPayload } from './pwn-payload.js';
import { NET_SESSION_PROPERTIES, createNetSessionManager } from './net-session.js';
import { REV_QUERY_PROPERTIES, runRevQuery } from './rev-query.js';
import { createCookieJarStore, HTTP_REQUEST_PROPERTIES, httpRequest } from './http-client.js';
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
import { CALCULATION_PROPERTIES, hasAttachmentInputs, validateSteps } from './offline-calculation.js';
import { createCalculationRunner } from './offline-calculation-runner.js';
import { Base100Workbench, WORKBENCH_BASE100_PROPERTIES } from './workbench-base100.js';
import { CONFIG_BOOLEAN_FIELDS, CONFIG_LIST_FIELDS, CONFIG_PATH_FIELDS, CONFIG_TEXT_FIELDS, createWorkbenchEnvironment, dshHome, WorkbenchDependencyError } from './workbench-config.js';
import { PROGRESS_ACTION_KEYS, PROGRESS_PARAMETERS, PROGRESS_PROPERTIES, manageProgress } from './ctf-progress.js';
import { appendStatus, readStatusHistory, summarizeStatus } from './ctf-status.js';
import { cachedResultValue, createToolResults, OFFLINE_RESULT_SCOPE, RESULT_HASH } from './ctf-result-values.js';
import { experimentRequestHash } from './experiment-input.js';
import { detectBrowser, detectGdb, findOnPathAsync, registerExtraTools } from './extra-tools.js';
import { handleSubmission } from './submission.js';
import { appendEvidenceIndex, decodeEvidenceIndex, encodeEvidenceEntry } from './evidence-index.js';
import { detectSandbox, runSandbox, SANDBOX_PROPERTIES } from './sandbox-runner.js';
import { GRAPH_DIR, GRAPH_FILE, GRAPH_PROPERTIES, manageGraph } from './ctf-graph.js';
import { ARENA_PROPERTIES, runArena } from './ctf-arena.js';
import { resolveToolDomainSelection, shouldRegisterTool } from './ctf-router.js';

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
      for (const field of CONFIG_BOOLEAN_FIELDS) {
        if (value[field] !== undefined && typeof value[field] !== 'boolean') {
          return { issues: [{ message: `${field} 须是布尔值。`, path: [field] }] };
        }
      }
      return { value };
    },
  },
};

const AUTO_FILE_HASH_LIMIT = 128 * 1024 * 1024;
const OUTPUT_CONFIGS = new WeakMap();
const DOMAIN_SELECTIONS = new WeakMap();

const IMPORT_DIR = '.ctf-attachments';
const STATUS_FILE = '.ctf-status.json';
const INSTANCE_STATE_FILE = '.ctf-instances.json';
const instanceTransitions = new Set();
const SUBMISSION_LOG = '.ctf-submissions.jsonl';
const STATUS_PROPERTIES = {
  action: { type: 'string', enum: ['set', 'show', 'board'], description: 'set 追加时间盒心跳；show 查状态与 warnings；board 拉取榜单。' },
  phase: { type: 'string', maxLength: 200, description: '当前阶段。' },
  stuck: { type: 'string', maxLength: 400, description: '当前卡点。' },
  ruled_out: { type: 'array', maxItems: 8, items: { type: 'string', maxLength: 200 }, description: '已排除路径。' },
  next_step: { type: 'string', maxLength: 400, description: '可执行下一步。' },
  need: { type: 'string', maxLength: 200, description: '所需帮助。' },
};
const SUBMIT_PROPERTIES = {
  flag: { type: 'string', maxLength: 512, description: '待提交 flag 原文。' },
  pattern: { type: 'string', maxLength: 200, description: '可选 flag 格式正则。' },
  source: { type: 'string', maxLength: 400, description: 'flag 来源位置。' },
  dynamic: { type: 'boolean', description: '动态 flag 为 true 时需 instance 与 refreshed_at。' },
  instance: { type: 'string', maxLength: 200, description: '实例名。' },
  refreshed_at: { type: 'string', maxLength: 40, description: '实例刷新 ISO 时间。' },
  record: { type: 'boolean', description: 'check_flag 传 true 才写预检回执。' },
  retry_unknown: { type: 'boolean', description: '上次提交为 unknown/pending（如 429/超时）时允许重提。' },
};
const SUBMIT_FLAG_PROPERTIES = {
  ...SUBMIT_PROPERTIES,
  challenge: { type: 'string', maxLength: 200, description: '题目标识。' },
};
const INSTANCE_PROPERTIES = {
  action: { type: 'string', enum: ['status', 'list', 'create', 'rotate', 'delete'], description: '实例操作。' },
  id: { type: 'string', maxLength: 200, description: '实例 ID（rotate/delete 必填）。' },
  body: { type: 'object', description: 'create/rotate JSON 请求体。', additionalProperties: true },
};
const FETCH_PROPERTIES = {
  url: { type: 'string', maxLength: 2048, description: '赛题附件 http(s) 地址。' },
  name: { type: 'string', maxLength: 200, description: '保存文件名。' },
  sha256: { type: 'string', description: '可选 64 位 SHA-256 校验。' },
  max_bytes: { type: 'integer', minimum: 1, maximum: MAX_TRANSFER_BYTES, default: MAX_ATTACHMENT_BYTES, description: '下载上限（默认 32 MiB）。' },
};
const PATH_SCHEMA = { type: 'string', description: '相对工作区附件路径（已授权外部路径可自动导入）。' };
const RESULT_SOURCE_PROPERTIES = {
  source_result_id: { type: 'string', pattern: '^[a-f0-9]{64}$', description: '引用前序派生字节结果编号。' },
  source_result_ids: { type: 'array', minItems: 1, maxItems: 64, uniqueItems: true,
    items: { type: 'string', pattern: '^[a-f0-9]{64}$' }, description: '按顺序拼接连续 PNG bitstream 结果编号。' },
};
const ARCHIVE_FORMAT_HINT = { type: 'string', enum: ['zip', 'zlib', 'deflate_raw'], description: '内嵌 zip/zlib/deflate_raw 提示。' };
const SHA256_SCHEMA = { type: 'string', description: '待核对的 64 位 SHA-256。' };
const ZIP_RANGE_PROPERTIES = {
  archive_offset: { type: 'integer', minimum: 0 },
  archive_length: { type: 'integer', minimum: 1 },
};
const ATTACHMENT_PROPERTIES = {
  file_path: PATH_SCHEMA,
  ...RESULT_SOURCE_PROPERTIES,
  format_hint: ARCHIVE_FORMAT_HINT,
  ...ZIP_RANGE_PROPERTIES,
  scan_result_id: { type: 'string', pattern: '^[a-f0-9]{64}$', description: 'scan_binary 结果编号（核对 ZIP 候选）。' },
  offset: { type: 'integer', minimum: 0, maximum: MAX_ATTACHMENT_BYTES },
  limit: { type: 'integer', minimum: 1, maximum: 16 },
  expected_sha256: SHA256_SCHEMA,
  pcapng: PCAPNG_QUERY_SCHEMA,
};
const LOG_RANGE_PROPERTIES = {
  file_path: PATH_SCHEMA,
  byte_offset: { type: 'integer', minimum: 0 },
  byte_length: { type: 'integer', minimum: 1, maximum: MAX_LOG_WINDOW_BYTES },
  expected_sha256: SHA256_SCHEMA,
};
const BINARY_RANGE_PROPERTIES = {
  file_path: PATH_SCHEMA,
  ...BYTE_WINDOW_PROPERTIES,
  strings: { type: 'boolean', description: '附带可打印 ASCII 字符串。' },
  min_string_length: { type: 'integer', minimum: 1, maximum: 256 },
  hash_scope: { type: 'string', enum: ['auto', 'file', 'range'] },
  expected_sha256: SHA256_SCHEMA,
};
const ARCHIVE_MEMBER_PROPERTIES = {
  file_path: PATH_SCHEMA,
  format_hint: ARCHIVE_FORMAT_HINT,
  ...ZIP_RANGE_PROPERTIES,
  password: { type: 'string', maxLength: 512, description: '可选已知 ZIP 口令。' },
  member_index: { type: 'integer', minimum: 0, description: '归档成员索引（从 0 起）。' },
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

function networkScopeFor(execution, location, leaseId) {
  const session = execution.agent?.session;
  if (!session || typeof session !== 'object' || typeof location?.directoryKey !== 'string') return undefined;
  return { session, workspaceKey: location.directoryKey, ...(leaseId ? { leaseId } : {}) };
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

function attachmentSnapshot(file) {
  return createHash('sha256').update(JSON.stringify([file.size, file.version])).digest('hex');
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
  if (!policy || policy.mode === 'read-only') throw new ToolError('permission', '当前会话为只读权限，无法修改文件或比赛状态。');
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

function resultField(result, pointer) {
  if (result.summary !== undefined) return cachedResultValue(result, pointer);
  return cachedResultValue(result, pointer);
}

async function resolveResultRecord(ctx, id, execution, location, results) {
  let result = results.get(execution.agent?.session, location.directoryKey, id);
  if (result === undefined) result = (await recordedResults(ctx, location)).get(id);
  if (result === undefined) throw new ToolError('conflict', '结果编号不存在或已过期，请重新读取来源。');
  return result;
}

async function resolveResultBytes(ctx, id, execution, location, results, inspectRanges, workbench) {
  const result = await resolveResultRecord(ctx, id, execution, location, results);
  const artifact = results.getArtifact(execution.agent?.session, id);
  if (artifact !== undefined) {
    const digest = createHash('sha256').update(artifact.bytes).digest('hex');
    const expected = resultField(result, '/artifact_sha256') ?? resultField(result, '/packed_sha256');
    if (typeof expected === 'string' && digest !== expected) throw new ToolError('conflict', '缓存派生字节与结果编号中的 SHA-256 不同。');
    const report = result.summary === undefined ? result.report : undefined;
    const source = artifact.evidence[0] ?? result.sources?.[0];
    return { bytes: artifact.bytes, result, source, data_sha256: digest,
      source_evidence: report?.source_evidence ?? (source === undefined ? undefined
        : { ...source, source_result_id: id, source_tool: result.tool, derived_sha256: digest }) };
  }
  if (['read_binary_range', 'read_archive_member'].includes(result.tool)) {
    const recovered = await recoverCalculationInput(ctx, result, location, inspectRanges, workbench);
    return { ...recovered, result, source: recovered.source,
      source_evidence: { ...recovered.source, source_result_id: id,
        ...(recovered.member_index === undefined ? {} : { member_index: recovered.member_index, member_sha256: recovered.member_sha256 }),
        ...(recovered.member_page === undefined ? {} : { member_page: recovered.member_page }),
        ...(recovered.archive_range === undefined ? {} : { archive_range: recovered.archive_range }),
        ...(recovered.byte_offset === undefined ? {} : { byte_offset: recovered.byte_offset, byte_length: recovered.byte_length }),
        derived_sha256: recovered.data_sha256 } };
  }
  throw new ToolError('conflict', '该结果没有可复读的二进制内容。请在当前会话重新生成它，再传入 source_result_id。');
}

async function resolveMediaInput(ctx, args, execution, location, workbench, results, inspectRanges) {
  const id = args.source_result_id;
  const ids = args.source_result_ids;
  if ((typeof args.file_path === 'string') === (id !== undefined || ids !== undefined)
    || (id !== undefined && ids !== undefined)) {
    throw new ToolError('unsupported', 'file_path、source_result_id 和 source_result_ids 只能选一种输入。');
  }
  if (args.file_path !== undefined) {
    const file = await readWorkspaceFile(ctx, pathParts(args.file_path), location);
    const sha256 = createHash('sha256').update(file.bytes).digest('hex');
    checkAttachmentHash(parseExpectedHash(args.expected_sha256), sha256);
    return { bytes: file.bytes, file: args.file_path, sha256, data_sha256: sha256, size: file.size,
      source_evidence: { file_path: pathParts(args.file_path).join('/'), sha256 } , fileSnapshot: file };
  }
  const sourceIds = ids ?? [id];
  if (!Array.isArray(sourceIds) || sourceIds.length < 1 || sourceIds.length > 64) {
    throw new ToolError('unsupported', '请提供一个来源结果编号，或 1 至 64 个连续位流结果编号。');
  }
  const parts = [];
  const reports = [];
  let source;
  let sourceEvidence;
  let previous;
  let bitstreamSignature;
  let total = 0;
  for (const sourceId of sourceIds) {
    if (typeof sourceId !== 'string' || !RESULT_HASH.test(sourceId)) throw new ToolError('unsupported', '来源编号须为 64 位十六进制 SHA-256。');
    const item = await resolveResultBytes(ctx, sourceId, execution, location, results, inspectRanges, workbench);
    total += item.bytes.length;
    if (total > 16 * 1024 * 1024) throw new ToolError('size', '连续派生字节最多拼接 16 MiB。');
    const report = item.result.summary === undefined ? item.result.report : undefined;
    if (sourceIds.length > 1) {
      const operation = resultField(item.result, '/operation');
      const offset = resultField(item.result, '/bit_offset');
      const count = resultField(item.result, '/bit_count');
      const next = resultField(item.result, '/next_bit_offset');
      const fileHash = resultField(item.result, '/sha256');
      const frame = resultField(item.result, '/frame_index');
      const signature = report === undefined ? undefined : JSON.stringify([fileHash, frame, report.region, report.channels,
        report.bit_index, report.bit_order, report.total_bit_count]);
      if (item.result.tool !== 'read_png_pixels' || operation !== 'bitstream'
        || !Number.isSafeInteger(offset) || !Number.isSafeInteger(count)
        || signature === undefined || (bitstreamSignature !== undefined && signature !== bitstreamSignature)
        || (previous !== undefined && (previous.next !== offset || previous.fileHash !== fileHash || previous.frame !== frame))) {
        throw new ToolError('unsupported', '多结果拼接只接受同一 PNG、同一帧且 bit_offset 连续的 bitstream 分页。');
      }
      bitstreamSignature = signature;
      previous = { next, fileHash, frame };
      const packedHash = resultField(item.result, '/packed_sha256');
      if (typeof packedHash !== 'string' || createHash('sha256').update(item.bytes).digest('hex') !== packedHash) {
        throw new ToolError('conflict', '位流分页数据与记录的 SHA-256 不同。');
      }
    }
    parts.push(item.bytes);
    reports.push(item);
    source ??= item.source;
    sourceEvidence ??= item.source_evidence ?? (item.source === undefined ? undefined : { ...item.source, source_result_id: sourceId, derived_sha256: item.data_sha256 });
  }
  const bytes = parts.length === 1 ? parts[0] : Buffer.concat(parts, total);
  const dataSha = createHash('sha256').update(bytes).digest('hex');
  checkAttachmentHash(parseExpectedHash(args.expected_sha256), dataSha);
  const file = source?.file_path;
  const sha256 = source?.sha256;
  return { bytes, file, sha256, data_sha256: dataSha, size: bytes.length,
    source_evidence: sourceEvidence ?? source, source_result_ids: sourceIds };
}

async function readMediaAttachment(ctx, args, request, location, workbench, execution, results, inspectRanges) {
  const input = await resolveMediaInput(ctx, args, execution, location, workbench, results, inspectRanges);
  if (input.bytes.length > MAX_ATTACHMENT_BYTES) throw new ToolError('size', '派生媒体输入最多 32 MiB。');
  const report = await inspectMedia(input.bytes, request, location.signal, workbench);
  if (input.fileSnapshot !== undefined) await requireCurrentFile(ctx.fs, input.fileSnapshot, location.signal);
  let artifact = report.__artifact_bytes;
  if (request.kind === 'png' && ['bitstream', 'lsb'].includes(request.operation) && typeof report.hex === 'string') {
    artifact = Buffer.from(report.hex, 'hex');
  }
  if (request.kind === 'qr' && Array.isArray(report.codes)) {
    const code = report.codes.find(value => value.byte_exact && typeof value.hex === 'string' && !value.hex_truncated);
    if (code) artifact = Buffer.from(code.hex, 'hex');
  }
  const { __artifact_bytes: _privateArtifact, ...visible } = report;
  if (artifact !== undefined && visible.artifact_sha256 === undefined) {
    visible.artifact_sha256 = createHash('sha256').update(artifact).digest('hex');
  }
  return { ...visible, file: input.file, size: input.size, sha256: input.sha256,
    data_sha256: input.data_sha256, source_evidence: input.source_evidence,
    ...(input.source_result_ids === undefined ? {} : { source_result_ids: input.source_result_ids }),
    ...(artifact === undefined ? {} : { __artifact_bytes: artifact }) };
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
    throw new ToolError('permission', '当前会话为只读权限，可读取续接记录并在对话中报告。');
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
    throw new ToolError('unsupported', field + ' 须为单行文本（最多 ' + maxLength + ' 字符）。');
  }
  return value.trim();
}

function graphFiles(ctx, location, execution) {
  const policy = ctx.sandboxPolicy.resolve({ session: execution.agent?.session });
  return {
    canWrite: Boolean(policy && policy.mode !== 'read-only'),
    read: name => progressDocument(ctx, name, location),
    async write(document, body) {
      const activePolicy = writablePolicy(ctx, execution);
      if (document.version === undefined && typeof document.name === 'string' && document.name.includes('/')) {
        await checkedOutput(ctx, location, GRAPH_DIR, true);
      }
      const intent = document.version === undefined
        ? { kind: 'createIfAbsent' }
        : { kind: 'replaceIfVersion', version: document.version };
      const outcome = await ctx.fs.writeText(document.target, body, intent, location.signal, activePolicy);
      ctx.emit?.('fs/observed', document.target, { kind: 'present', version: outcome?.version }, execution);
    },
  };
}

async function runGraphTool(ctx, args, execution) {
  const location = await workspaceLocation(ctx, execution);
  return manageGraph(args, graphFiles(ctx, location, execution), {
    defaultOwner: typeof execution.agent?.session?.id === 'string' && execution.agent.session.id !== ''
      ? execution.agent.session.id : 'agent',
  });
}

async function runSandboxTool(ctx, args, execution, config) {
  const location = await workspaceLocation(ctx, execution);
  const policy = ctx.sandboxPolicy.resolve({ session: execution.agent?.session });
  const writable = Boolean(policy && policy.mode !== 'read-only');
  return runSandbox(args, {
    cwd: location.cwd,
    config,
    signal: execution.signal,
    writable,
    async checkWorkspaceFile(rel) {
      const parts = pathParts(rel);
      await openWorkspaceFile(ctx, parts, location);
      return parts.join('/');
    },
  });
}

async function runArenaTool(ctx, args, execution, config, network) {
  const location = await workspaceLocation(ctx, execution);
  const networkScope = networkScopeFor(execution, location);
  const policy = ctx.sandboxPolicy.resolve({ session: execution.agent?.session });
  const writable = Boolean(policy && policy.mode !== 'read-only');
  const gFiles = graphFiles(ctx, location, execution);
  const owner = typeof execution.agent?.session?.id === 'string' && execution.agent.session.id !== ''
    ? execution.agent.session.id : 'commander';
  return runArena(args, {
    config,
    signal: execution.signal,
    writable,
    network,
    networkScope,
    authorizeResponse: (res, leaseId) => authorizeInstanceTargets(res, network,
      leaseId ? { ...networkScope, leaseId } : networkScope),
    revokeTargets: leaseId => network?.revoke(networkScope, leaseId),
    recordInstance: (id, state) => recordInstance(ctx, location, execution, platformBase(config), id, state),
    lookupInstance: async id => {
      const { entries } = await instanceRecords(ctx, location);
      return entries.findLast(entry => entry.platform === platformBase(config) && entry.id === id);
    },
    syncGraphFact: factArgs => manageGraph(factArgs, gFiles, { defaultOwner: owner }),
    fetchFile: (url, platformConfig) => runFetchAttachment(ctx, { url }, execution, platformConfig ?? config, network),
    submissionFiles: submissionFiles(ctx, location, execution),
  });
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
      const outcome = await ctx.fs.writeText(document.target, body, intent, location.signal, policy);
      ctx.emit?.('fs/observed', document.target, { kind: 'present', version: outcome?.version }, execution);
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

function warningMessages(warnings) {
  return warnings.map(warning => warning.message);
}

async function runStatus(ctx, args, execution, config) {
  const location = await workspaceLocation(ctx, execution);
  const files = statusFiles(ctx, location, execution, config);
  const history = await readStatusHistory(files);
  const { entries, recovered } = history;
  if (args.action === 'show') {
    const summary = summarizeStatus(entries);
    const warnings = [...summary.warnings];
    if (recovered) warnings.push({ code: 'status_recovered', severity: 'warning', message: '主状态文件不可读，当前结果从恢复副本载入。' });
    return { status: 'status', file: STATUS_FILE, records: summary.records, elapsed_minutes: summary.elapsed_minutes, last: summary.last,
      warnings, warning_messages: warningMessages(warnings) };
  }
  if (args.action === 'board') {
    const policy = ctx.sandboxPolicy.resolve({ session: execution.agent?.session });
    if (!policy) throw new ToolError('permission', '当前会话没有可用的文件权限策略。');
    const readOnly = policy.mode === 'read-only';
    const boardPath = config?.platformLeaderboardPath ?? '/scoreboard';
    const response = await platformRequest(config, execution.signal, 'GET', boardPath);
    let board;
    if (platformOperationSucceeded(response)) {
      try { board = boardSummary(JSON.parse(response.body), config?.platformTeamId); }
      catch { /* The platform did not return a supported team summary. */ }
    }
    if (!board) return { status: 'board_unavailable', file: STATUS_FILE, records: entries.length, platform_status: response?.status ?? null,
      reason: '平台响应没有可辨认的本队名次、分数或解题数。' };
    if (readOnly) return { status: 'board', file: STATUS_FILE, records: entries.length, platform_status: response?.status ?? null,
      board, recorded: false, note: '只读会话未写入本地状态记录。' };
    await checkedOutput(ctx, location, '.ctf', true);
    const saved = await appendStatus(files, { phase: 'scoreboard', board });
    return { status: 'board', file: STATUS_FILE, records: saved.entries.length, platform_status: response?.status ?? null, board,
      ...(saved.warning ? { warning: saved.warning } : {}) };
  }
  const phase = statusLine(args.phase, 'phase', 200);
  const stuck = statusLine(args.stuck, 'stuck', 400);
  const nextStep = statusLine(args.next_step, 'next_step', 400);
  const need = statusLine(args.need, 'need', 200);
  if (!phase && !stuck && !nextStep) throw new ToolError('unsupported', '状态记录至少给出 phase、stuck 或 next_step 之一。');
  const ruledOut = args.ruled_out === undefined ? [] : args.ruled_out.map(item => statusLine(item, 'ruled_out', 200)).filter(Boolean);
  await checkedOutput(ctx, location, '.ctf', true);
  const saved = await appendStatus(files, { phase, stuck, ruled_out: ruledOut, next_step: nextStep, need });
  const summary = summarizeStatus(saved.entries);
  const warnings = [...summary.warnings];
  if (saved.recovered) warnings.push({ code: 'status_recovered', severity: 'warning', message: '主状态文件不可读，已在恢复副本基础上追加记录。' });
  return { status: 'recorded', file: STATUS_FILE, records: summary.records, elapsed_minutes: summary.elapsed_minutes,
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
      const receipts = [];
      let corruptedLines = 0;
      for (const rawLine of document.text.split('\n')) {
        const line = rawLine.trim();
        if (!line) continue;
        try {
          const entry = JSON.parse(line);
          if (entry !== null && typeof entry === 'object' && !Array.isArray(entry)) {
            receipts.push(entry);
          } else {
            corruptedLines += 1;
          }
        } catch {
          corruptedLines += 1;
        }
      }
      return { document, receipts, corruptedLines };
    },
    async write(document, receipts) {
      const policy = ctx.sandboxPolicy.resolve({ session: execution.agent?.session });
      if (policy?.mode === 'read-only') throw new ToolError('permission', '当前会话为只读权限，无法记录正式提交。');
      const body = receipts.map(entry => JSON.stringify(receiptForStorage(entry))).join('\n') + '\n';
      if (Buffer.byteLength(body) > MAX_ATTACHMENT_BYTES) throw new ToolError('size', '提交回执超过文件大小上限。');
      const intent = document.version === undefined ? { kind: 'createIfAbsent' }
        : { kind: 'replaceIfVersion', version: document.version };
      const outcome = await ctx.fs.writeText(document.target, body, intent, location.signal, policy);
      ctx.emit?.('fs/observed', document.target, { kind: 'present', version: outcome?.version }, execution);
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
  capstone: 'pip install capstone',
  fitz: 'pip install pymupdf',
  PIL: 'pip install pillow',
  cv2: 'pip install opencv-python',
  numpy: 'pip install numpy',
};

function pythonModuleState(pythonPath, libarchivePath, signal) {
  const names = JSON.stringify(Object.keys(PYTHON_MODULES));
  const libPath = JSON.stringify(libarchivePath ?? '');
  const script = 'import ctypes as c, importlib.util, json, sys\n'
    + `names = ${names}\n`
    + `lib_path = ${libPath}\n`
    + 'def has_libarchive(path):\n'
    + '  try:\n'
    + '    if sys.platform == "win32":\n'
    + '      c.CDLL(path, winmode=0x1100) if path else c.CDLL("archiveint.dll", winmode=0x800)\n'
    + '      return True\n'
    + '    candidates = [path] if path else (["/usr/lib/libarchive.2.dylib", "/usr/lib/libarchive.dylib"] if sys.platform == "darwin" else ["libarchive.so.13", "libarchive.so"])\n'
    + '    for candidate in candidates:\n'
    + '      try:\n'
    + '        c.CDLL(candidate)\n'
    + '        return True\n'
    + '      except OSError:\n'
    + '        continue\n'
    + '    return False\n'
    + '  except (OSError, TypeError):\n'
    + '    return False\n'
    + 'print(json.dumps({"version": "%d.%d" % sys.version_info[:2], "modules": {name: importlib.util.find_spec(name) is not None for name in names}, "libarchive": has_libarchive(lib_path)}))\n';
  return new Promise(resolve => execFile(pythonPath, ['-E', '-P', '-B', '-c', script], {
    encoding: 'utf8', cwd: dirname(pythonPath), timeout: 3500, maxBuffer: 8192, windowsHide: true, signal,
  }, (error, stdout) => {
    if (!error) {
      try { return resolve(JSON.parse(stdout)); } catch { /* invalid probe response */ }
    }
    resolve(undefined);
  }));
}

const BUNDLED_SKILL_URL = new URL('./SKILL.md', import.meta.url);

function normalizedTextHash(text) {
  return createHash('sha256').update(String(text).replace(/\r\n/gu, '\n'), 'utf8').digest('hex');
}

async function checkSkillSync(cwd) {
  let bundledHash;
  try {
    bundledHash = normalizedTextHash(await readFile(BUNDLED_SKILL_URL, 'utf8'));
  } catch {
    return { ok: false, detail: '无法读取包内 SKILL.md。' };
  }
  const workspaceSkill = join(cwd, '.dsh', 'skills', 'ctf', 'SKILL.md');
  const globalSkill = join(dshHome(), 'skills', 'ctf', 'SKILL.md');
  for (const [scope, candidate] of [['工作区', workspaceSkill], ['全局', globalSkill]]) {
    let text;
    try {
      text = await readFile(candidate, 'utf8');
    } catch {
      continue;
    }
    if (normalizedTextHash(text) === bundledHash) {
      return { ok: true, detail: `已同步（${scope}：${candidate}）` };
    }
    return {
      ok: false,
      detail: `${scope} SKILL.md 与包内版本不一致（${candidate}）；请重新复制包内 SKILL.md 覆盖。`,
    };
  }
  return {
    ok: false,
    detail: `未检测到已安装的 CTF 技能文件（${globalSkill} 或工作区 .dsh/skills/ctf/SKILL.md）；请复制包内 SKILL.md。`,
  };
}

async function runDoctor(ctx, execution, config, workbench, registeredToolTier) {
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
  const configuredToolTier = config?.enableExtendedAudit === true ? 'full' : 'core';
  const activeToolTier = registeredToolTier ?? configuredToolTier;
  const tierSynced = activeToolTier === configuredToolTier;
  add('tool_tier_sync', tierSynced, tierSynced
    ? `已同步（${activeToolTier}，${activeToolTier === 'full' ? 45 : 27} 个工具）`
    : `配置 enableExtendedAudit 为 ${configuredToolTier}，但当前进程已注册为 ${activeToolTier}；重启或重载 DSH 后生效。`, false);
  const activeDomain = DOMAIN_SELECTIONS.get(ctx)?.label ?? 'all';
  let configuredDomain = 'all';
  let domainConfigError;
  try { configuredDomain = resolveToolDomainSelection(config).label; }
  catch (error) { domainConfigError = error.message; }
  const domainSynced = domainConfigError === undefined && activeDomain === configuredDomain;
  add('tool_domain_sync', domainSynced, domainConfigError
    ? domainConfigError
    : domainSynced
      ? `已同步（toolDomain: ${activeDomain}）`
      : `配置 toolDomain 为 ${configuredDomain}，但当前进程已注册为 ${activeDomain}；重启或重载 DSH 后生效。`, false);
  const skillState = await checkSkillSync(location.cwd);
  add('skill_sync', skillState.ok, skillState.detail, false);
  const deadline = AbortSignal.timeout(8500);
  const probeSignal = location.signal ? AbortSignal.any([deadline, location.signal]) : deadline;
  let python;
  let pythonIssue;
  try { python = await workbench.resolvePython(probeSignal); }
  catch (error) { pythonIssue = deadline.aborted ? 'Python 探测超时。' : error.message; }
  location.signal?.throwIfAborted();
  add('python', python !== undefined, python ?? pythonIssue, false);
  let libarchivePath = '';
  let libarchiveIssue;
  try { libarchivePath = workbench.library(); }
  catch (error) { libarchiveIssue = error.message; }
  const state = python ? await pythonModuleState(python, libarchiveIssue ? '' : libarchivePath, probeSignal) : undefined;
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
    if (libarchiveIssue) {
      add('libarchive', false, libarchiveIssue, false);
    } else {
      const hasLibarchive = state.libarchive === true;
      add('libarchive', hasLibarchive,
        hasLibarchive ? (libarchivePath || '系统原生归档库可用') : '未找到本机 libarchive 动态库：安装系统 libarchive 或在 ctf-workbench.json 配置 libarchivePath。', false);
    }
  } else if (python) {
    add('python:modules', false, 'Python 模块探测失败：检查 Python 是否可执行。', false);
    if (libarchiveIssue) add('libarchive', false, libarchiveIssue, false);
  } else if (libarchiveIssue) {
    add('libarchive', false, libarchiveIssue, false);
  }
  const toolNames = ['jadx', 'apktool', 'apksigner', 'john', 'hashcat'];
  const [gdb, browser, sandbox, ...paths] = await Promise.all([
    detectGdb(config), detectBrowser(config), detectSandbox(config, probeSignal), ...toolNames.map(findOnPathAsync),
  ]);
  const baseProfile = sandbox.profiles?.base;
  const heavyProfile = sandbox.profiles?.heavy;
  const dockerDaemonDown = !sandbox.docker?.available && !sandbox.docker?.daemon_version;
  add('sandbox', sandbox.available,
    sandbox.available ? `${sandbox.backend}:${sandbox.image ?? sandbox.distro}`
      : `不可用（Docker: ${sandbox.docker.reason}；WSL2: ${sandbox.wsl.reason}）`, false);
  if (baseProfile?.image) {
    add('sandbox:docker_base', Boolean(baseProfile.available),
      baseProfile.available
        ? `已就绪（${baseProfile.image}）`
        : dockerDaemonDown
          ? `未就绪（${sandbox.docker.reason}）`
          : `未构建（${baseProfile.image}）：可执行 docker build -t ${baseProfile.image} docker/`, false);
  }
  if (heavyProfile?.image && heavyProfile.image !== baseProfile?.image) {
    add('sandbox:docker_heavy', Boolean(heavyProfile.available),
      heavyProfile.available
        ? `已就绪（${heavyProfile.image}，自动按需升级）`
        : dockerDaemonDown
          ? `未就绪（${sandbox.docker.reason}）`
          : `未构建（${heavyProfile.image}，可选重器档位）：可执行 docker build -f docker/Dockerfile.heavy -t ${heavyProfile.image} docker/`, false);
  }
  const sandboxSummary = {
    available: sandbox.available,
    active_backend: sandbox.backend,
    active_target: sandbox.image ?? sandbox.distro ?? null,
    docker_base: { image: baseProfile?.image ?? null, available: Boolean(baseProfile?.available) },
    docker_heavy: { image: heavyProfile?.image ?? null, available: Boolean(heavyProfile?.available) },
    wsl: { distro: sandbox.wsl?.distro ?? null, available: Boolean(sandbox.wsl?.available) },
    next_steps: [
      ...(!baseProfile?.available && baseProfile?.image ? [`docker build -t ${baseProfile.image} docker/`] : []),
      ...(!heavyProfile?.available && heavyProfile?.image && heavyProfile.image !== baseProfile?.image
        ? [`docker build -f docker/Dockerfile.heavy -t ${heavyProfile.image} docker/`] : []),
    ],
  };
  add('gdb', typeof gdb === 'string' && gdb !== '', gdb ?? '未找到 gdb：只影响本机对应能力。', false);
  add('browser', typeof browser === 'string' && browser !== '', browser ?? '未找到 Chrome/Edge：browser_session 不可用。', false);
  for (const [index, tool] of toolNames.entries()) {
    const found = paths[index];
    add(tool, Boolean(found), found ?? '未安装：对应功能会返回 dependency 提示。', false);
  }
  for (const [file, label] of [['notes.md', '续接记录'], ['handoff.md', '接替简报'], [GRAPH_FILE, '事实意图图谱'], [STATUS_FILE, '时间盒心跳'], [SUBMISSION_LOG, '提交回执']]) {
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
    tool_tier: activeToolTier, configured_tool_tier: configuredToolTier, sandbox, sandbox_summary: sandboxSummary, host_capabilities: hostCapabilities, checks, missing, optional_missing: optionalMissing };
}

async function runCompetitionApi(ctx, args, execution, config, network) {
  if (args.action === 'submit') return runSubmitFlag(ctx, args, execution, config);
  return runInstance(ctx, { ...args, action: args.action === 'instances' ? 'list' : args.action }, execution, config, network);
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
  if (args.dynamic && base) {
    const instances = await instanceRecords(ctx, location);
    const instanceId = typeof args.instance === 'string' ? args.instance.trim() : '';
    const record = instanceId ? instances.entries.findLast(entry => entry.platform === base && entry.id === instanceId) : undefined;
    const age = record?.state === 'created' ? Date.now() - Date.parse(record.observed_at ?? '') : Infinity;
    if (!Number.isFinite(age) || age < -5 * 60000 || age > 30 * 60000) {
      return { status: 'rejected', verdict: 'rejected_local', reason: '动态 flag 需要 30 分钟内由 ctf_instance、ctf_arena 容器操作写入的实例记录；调用方提供的 refreshed_at 不作为可信刷新时间。' };
    }
    validated = { ...args, refreshed_at: record.observed_at };
  }
  return handleSubmission(validated, submissionFiles(ctx, location, execution),
    body => platformRequest(config, execution.signal, 'POST', config?.platformSubmitPath ?? '/submissions', body), base || undefined, location.signal);
}

async function instanceRecords(ctx, location) {
  const document = await progressDocument(ctx, INSTANCE_STATE_FILE, location);
  if (!document.text) return { document, entries: [] };
  let parsed;
  try {
    parsed = JSON.parse(document.text);
  } catch {
    // 实例账本由本插件独占写入；单行损坏不应连带让 ctf_instance/ctf_arena/submit_flag 一起瘫痪。
    return { document, entries: [] };
  }
  if (!Array.isArray(parsed)) return { document, entries: [] };
  return { document, entries: parsed.filter(entry => entry !== null && typeof entry === 'object' && !Array.isArray(entry)) };
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

const INSTANCE_TCP_KEYS = new Set(['addr', 'address', 'connect', 'nc', 'tcp', 'endpoint', 'target', 'entry', 'access', 'connection', 'host_port']);

function validPortNumber(value) {
  const port = typeof value === 'string' && /^\d{1,5}$/u.test(value.trim()) ? Number(value.trim()) : value;
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : undefined;
}

export function extractInstanceTargets(response) {
  const httpTargets = [];
  const tcpTargets = [];
  if (typeof response?.body !== 'string' || response.body.trim() === '') return { http: httpTargets, tcp: tcpTargets };
  let parsed;
  try { parsed = JSON.parse(response.body); }
  catch { return { http: httpTargets, tcp: tcpTargets }; }
  let visited = 0;
  function inspectString(value, key) {
    const text = value.trim();
    if (!text || text.length > 512) return;
    if (/^https?:\/\//iu.test(text)) {
      httpTargets.push(text);
      return;
    }
    if (!INSTANCE_TCP_KEYS.has(key)) return;
    const nc = /^(?:nc|ncat|netcat)\s+(?:-[A-Za-z0-9]+\s+)*(\[[^\]]+\]|[^\s:]+)\s+(\d{1,5})(?:\s|$)/iu.exec(text);
    if (nc) {
      const port = validPortNumber(nc[2]);
      if (port !== undefined) tcpTargets.push({ host: nc[1], port });
      return;
    }
    const hostPort = /^(\[[^\]]+\]|[A-Za-z0-9.-]+):(\d{1,5})$/u.exec(text);
    if (hostPort) {
      const port = validPortNumber(hostPort[2]);
      if (port !== undefined) tcpTargets.push({ host: hostPort[1], port });
    }
  }
  function walk(node, depth, key = '') {
    if (depth > 5 || visited >= 128 || node === null || node === undefined) return;
    visited += 1;
    if (typeof node === 'string') {
      inspectString(node, key);
      return;
    }
    if (Array.isArray(node)) {
      for (const item of node.slice(0, 32)) walk(item, depth + 1, key);
      return;
    }
    if (typeof node !== 'object') return;
    const rawHost = node.host ?? node.ip ?? node.hostname;
    if (typeof rawHost === 'string' && rawHost.trim() && !/[\s/\\:?#]/u.test(rawHost.trim())) {
      const host = rawHost.trim();
      const proto = typeof (node.protocol ?? node.scheme) === 'string' ? String(node.protocol ?? node.scheme).trim().toLowerCase() : '';
      const singlePort = validPortNumber(node.port);
      const portEntries = [];
      if (singlePort !== undefined) portEntries.push({ port: singlePort, proto });
      if (Array.isArray(node.ports)) {
        for (const item of node.ports.slice(0, 16)) {
          const numeric = validPortNumber(item);
          if (numeric !== undefined) portEntries.push({ port: numeric, proto });
          else if (item && typeof item === 'object') {
            const p = validPortNumber(item.port ?? item.external ?? item.host_port ?? item.public_port);
            const itemProto = typeof (item.protocol ?? item.scheme) === 'string' ? String(item.protocol ?? item.scheme).trim().toLowerCase() : proto;
            if (p !== undefined) portEntries.push({ port: p, proto: itemProto });
          }
        }
      }
      for (const entry of portEntries) {
        tcpTargets.push({ host, port: entry.port });
        if (entry.proto === 'http' || entry.proto === 'https') {
          httpTargets.push(`${entry.proto}://${host.includes(':') && !host.startsWith('[') ? `[${host}]` : host}:${entry.port}`);
        }
      }
    }
    for (const [childKey, childValue] of Object.entries(node)) {
      walk(childValue, depth + 1, childKey.toLowerCase());
    }
  }
  walk(parsed, 0);
  return { http: httpTargets, tcp: tcpTargets };
}

function authorizeInstanceTargets(response, network, scope) {
  if (!network || !scope) return undefined;
  const extracted = extractInstanceTargets(response);
  const http = [...new Set(extracted.http.map(url => network.grantHttp(url, scope)).filter(Boolean))];
  const tcp = [...new Set(extracted.tcp.map(({ host, port }) => network.grantTcp(host, port, scope)).filter(Boolean))];
  return http.length || tcp.length ? { http, tcp } : undefined;
}

async function runInstance(ctx, args, execution, config, network) {
  const location = await workspaceLocation(ctx, execution);
  const networkScope = networkScopeFor(execution, location);
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
    const ok = platformOperationSucceeded(request);
    const authorized = ok ? authorizeInstanceTargets(request, network, networkScope) : undefined;
    return { status: ok ? 'instances' : 'failed', request, ...(authorized ? { authorized_targets: authorized } : {}) };
  }
  writablePolicy(ctx, execution);
  if (args.action === 'create') {
    const request = await call('POST', path, args.body ?? {});
    if (!platformOperationSucceeded(request)) return { status: 'failed', request };
    const id = createdInstance(request);
    const authorized = id ? authorizeInstanceTargets(request, network, { ...networkScope, leaseId: `instance:${id}` }) : undefined;
    return { status: 'created', request, id, instance_recorded: await recordInstance(ctx, location, execution, base, id, 'created'),
      ...(authorized ? { authorized_targets: authorized } : {}) };
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
      const authorized = authorizeInstanceTargets(created, network, { ...networkScope, leaseId: `instance:${newId}` });
      const recorded = await recordInstance(ctx, location, execution, base, newId, 'created');
      replacement = { new_id: newId, created, instance_recorded: recorded, ...(authorized ? { authorized_targets: authorized } : {}) };
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
    network?.revoke(networkScope, `instance:${id}`);
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

async function runFetchAttachment(ctx, args, execution, config, network) {
  const url = webUrl(args.url);
  const location = await workspaceLocation(ctx, execution);
  const networkScope = networkScopeFor(execution, location);
  let fallback = url.pathname.split('/').filter(Boolean).at(-1) ?? 'attachment';
  try { fallback = decodeURIComponent(fallback); } catch { /* keep literal path segment */ }
  const wanted = typeof args.name === 'string' && args.name.trim() !== '' ? args.name.trim() : fallback;
  const expected = parseExpectedHash(args.sha256);
  const limit = args.max_bytes ?? MAX_ATTACHMENT_BYTES;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_TRANSFER_BYTES) throw new Error('max_bytes 须在 1 字节至 256 MiB 内。');
  let platformOrigin;
  const base = platformBase(config);
  if (base) {
    try { platformOrigin = webUrl(base).origin; } catch { /* invalid platformUrl grants nothing */ }
  }
  const authorizeHop = (hopUrl, signal) => {
    const trusted = (platformOrigin !== undefined && hopUrl.origin === platformOrigin)
      || Boolean(network?.isHttpAuthorized(hopUrl, networkScope));
    return pinAddress(hopUrl.hostname, { publicOnly: !trusted, signal });
  };
  const headersFor = hopUrl => {
    if (platformOrigin === undefined || hopUrl.origin !== platformOrigin) return {};
    if (hopUrl.protocol !== 'https:' && config?.allowInsecurePlatformHttp !== true) return {};
    return platformAuthHeaders(config);
  };
  const result = await storeAttachment(ctx, location, execution, wanted, { source_url: provenanceUrl(url) }, async temp => {
    const received = await downloadAttachment(url, temp, { signal: location.signal, limit, authorizeHop, headersFor });
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
  if (tool === 'calculate_offline') {
    return [...new Map(output.input_evidence.map(item => [JSON.stringify(item.source), item.source])).values()];
  }
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
  if (typeof output.sha256 !== 'string' || !RESULT_HASH.test(output.sha256)) {
    return tool === 'scan_binary' ? [] : undefined;
  }
  return [{
    file_path: pathParts(output.file).join('/'), sha256: output.sha256,
    ...(['read_log_range', 'read_binary_range'].includes(tool)
      ? { byte_offset: output.byte_offset, byte_length: output.byte_length || undefined } : {}),
  }];
}

function parseZipRange(args, size) {
  const { archive_offset: offset, archive_length: length } = args;
  if (offset === undefined && length === undefined) return undefined;
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(length) || length < 1) {
    throw new ToolError('unsupported', 'ZIP 区间须同时提供非负安全整数 archive_offset 和正安全整数 archive_length。');
  }
  if (length > size - offset) throw new ToolError('size', '指定的 ZIP 区间超出了原件大小。');
  return { byte_offset: offset, byte_length: length };
}

async function inspectSelectedZip(ctx, inspectRanges, file, { signal, expectedHash, range }, inspect) {
  if (typeof ctx.fs.readByteRange !== 'function') throw new ToolError('dependency', '当前 DSH 文件服务不支持 ZIP 区间读取。');
  const { byte_offset: start, byte_length: size } = range;
  return inspectRanges(file, signal, expectedHash, async reader => {
    const report = await inspect({
      size,
      read(offset, length) {
        checkRange(size, offset, length, 'ZIP 区间读取');
        return reader.read(start + offset, length);
      },
    });
    if (report === undefined) {
      throw new ToolError('unsupported', '所选区间内没有可验证的 ZIP。请核对起点和长度。');
    }
    // Directory indexes use offsets in their own view. Only cache the whole-file index.
    return { report: {
      ...report,
      archive_range: range,
      ...(report.archive_offset === undefined ? {} : { archive_offset: start + report.archive_offset }),
      ...(report.trailing_offset === undefined ? {} : { trailing_offset: start + report.trailing_offset }),
    } };
  });
}

function describeArchiveMember(member, memberIndex, window) {
  const { bytes, format, variant, name, size = bytes?.length } = member;
  const length = windowLength(size, window);
  const chunk = member.chunk ?? bytes.subarray(window.offset, window.offset + length);
  return {
    format, variant, member_index: memberIndex, member_name: name, member_size: size,
    ...(member.pageOnly ? { result_scope: 'page' } : {}),
    ...(member.name_encoding === undefined ? {} : { name_encoding: member.name_encoding }),
    ...(member.name_truncated ? { name_truncated: true } : {}),
    ...(member.encryption_flag_only ? { encryption_flag_only: true } : {}),
    member_sha256: member.sha256 ?? createHash('sha256').update(bytes).digest('hex'),
    ...describeByteWindow(chunk, size, window),
  };
}

function archiveFormatHint(format) {
  if (format === 'ZIP') return 'zip';
  if (format === 'zlib' || format === 'TAR.ZLIB') return 'zlib';
  if (format === 'deflate_raw' || format === 'TAR.DEFLATE') return 'deflate_raw';
  return undefined;
}

async function inspectAttachmentWithCompression(bytes, paging, pcapngQuery, formatHint, signal, workbench) {
  const format = pcapngQuery === undefined && formatHint === undefined ? compressedStreamFormat(bytes) : undefined;
  if (format === undefined) return inspectAttachment(bytes, paging, pcapngQuery, formatHint);
  const decompressed = await decompressCompressedStream(bytes, format, signal, workbench);
  if (decompressed.status !== 'ok') return { format, ...decompressed };
  return inspectDecompressedStream(decompressed.bytes, paging, format);
}

async function readArchiveMember(ctx, args, location, inspectRanges, workbench, full = false) {
  const memberIndex = args.member_index;
  if (!Number.isSafeInteger(memberIndex) || memberIndex < 0) throw new Error('member_index 须是非负整数。');
  const window = full ? { offset: 0, length: MAX_ARCHIVE_MEMBER_BYTES, encoding: 'base64' } : parseByteWindow(args, 'auto', 1024);
  const expectedHash = parseExpectedHash(args.expected_sha256);
  const zipHint = args.format_hint === 'zip';
  const compressionHint = ['zlib', 'deflate_raw'].includes(args.format_hint) ? args.format_hint : undefined;
  if (compressionHint !== undefined && (args.archive_offset !== undefined || args.archive_length !== undefined
    || args.password !== undefined)) {
    throw new ToolError('unsupported', '压缩流格式提示不能与 ZIP 区间或 ZIP 口令合用。');
  }
  const file = await openWorkspaceFile(ctx, pathParts(args.file_path), location);
  const range = parseZipRange(args, file.size);
  const zipOptions = { window: full ? undefined : window, signal: location.signal };
  if (range !== undefined) {
    const { signal } = location;
    return inspectSelectedZip(ctx, inspectRanges, file, { signal, expectedHash, range }, async reader => {
      if (args.password !== undefined && reader.size > MAX_ATTACHMENT_BYTES) {
        throw new ToolError('size', '使用已知口令时，所选 ZIP 区间最多 32 MiB。');
      }
      const member = args.password === undefined
        ? await readZipMember(reader, memberIndex, undefined, true, zipOptions)
        : await readZipWithKnownPassword(await reader.read(0, reader.size), memberIndex, args.password, workbench, signal);
      if (member === undefined || member.status === 'dependency_missing') return member;
      return describeArchiveMember(member, memberIndex, window);
    });
  }
  if (args.password !== undefined) {
    const bytes = await readOpenedFile(ctx, file, location.signal);
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    checkAttachmentHash(expectedHash, sha256);
    const member = await readZipWithKnownPassword(bytes, memberIndex, args.password, workbench, location.signal);
    await requireCurrentFile(ctx.fs, file, location.signal);
    if (member.status === 'dependency_missing') return { ...member, size: file.size, sha256 };
    return { ...describeArchiveMember(member, memberIndex, window), size: file.size, sha256 };
  }
  if (compressionHint === undefined && typeof ctx.fs.readByteRange === 'function') {
    const zip = await inspectRanges(file, location.signal, expectedHash, async (reader, index) => {
      const member = await readZipMember(reader, memberIndex, index, zipHint, zipOptions);
      return member && { report: describeArchiveMember(member, memberIndex, window), zipIndex: member.zipIndex };
    });
    if (zip !== undefined) return zip;
    if (zipHint) throw new Error('未在文件中找到可验证的 ZIP 目录。');
  }
  const bytes = await readOpenedFile(ctx, file, location.signal);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  checkAttachmentHash(expectedHash, sha256);
  const compressedFormat = compressionHint === undefined && !zipHint ? compressedStreamFormat(bytes) : undefined;
  if (compressedFormat !== undefined) {
    const decompressed = await decompressCompressedStream(bytes, compressedFormat, location.signal, workbench);
    if (decompressed.status !== 'ok') {
      await requireCurrentFile(ctx.fs, file, location.signal);
      return { format: compressedFormat, ...decompressed, member_index: memberIndex, size: bytes.length, sha256 };
    }
    const member = await readDecompressedStreamMember(decompressed.bytes, memberIndex, location.signal, compressedFormat);
    if (member === undefined) throw new Error('压缩流内容不是可读取的 TAR 或单文件成员。');
    await requireCurrentFile(ctx.fs, file, location.signal);
    return { ...describeArchiveMember(member, memberIndex, window), size: bytes.length, sha256 };
  }
  const native = zipHint || compressionHint !== undefined ? undefined : nativeArchiveFormat(bytes);
  const member = native
    ? await readNativeArchiveMember(bytes, native, memberIndex, window, location.signal, workbench)
    : (zipHint ? undefined : await readTarOrCompressedMember(bytes, memberIndex, location.signal, compressionHint))
      ?? await readZipMember({ size: bytes.length, read: (offset, length) => bytes.subarray(offset, offset + length) },
        memberIndex, undefined, zipHint, zipOptions);
  if (member === undefined) throw new Error('可读取 ZIP/ZIP64、TAR、TAR.GZ、gzip、zlib、bzip2、xz、指定格式的 raw Deflate、7z 和 RAR 的普通文件成员。');
  await requireCurrentFile(ctx.fs, file, location.signal);
  if (member.status === 'dependency_missing') return { ...member, member_index: memberIndex, size: bytes.length, sha256 };
  return { ...describeArchiveMember(member, memberIndex, window), size: bytes.length, sha256 };
}

async function recoverCalculationInput(ctx, result, location, inspectRanges, workbench) {
  const get = field => cachedResultValue(result, field);
  const fileName = get('/file');
  const fileHash = get('/sha256');
  if (typeof fileName !== 'string' || typeof fileHash !== 'string' || !RESULT_HASH.test(fileHash)) {
    throw new ToolError('conflict', '该结果缺少可复核的原件引用。请带原件 SHA-256 重新读取。');
  }
  const source = { file_path: pathParts(fileName).join('/'), sha256: fileHash };
  if (!result.sources.some(reference => reference.file_path === source.file_path && reference.sha256 === fileHash)) {
    throw new ToolError('conflict', '结果的原件路径或 SHA-256 与记录不一致。');
  }
  if (result.tool === 'read_binary_range') {
    const offset = get('/byte_offset');
    const length = get('/byte_length');
    const rangeHash = get('/range_sha256');
    if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(length) || length < 0 || length > MAX_WINDOW_BYTES
      || typeof rangeHash !== 'string' || !RESULT_HASH.test(rangeHash)) {
      throw new ToolError('unsupported', '该结果没有完整的原件字节范围。');
    }
    if (typeof ctx.fs.readByteRange !== 'function') throw new ToolError('dependency', '当前文件服务不支持分段复读。');
    const file = await openWorkspaceFile(ctx, pathParts(fileName), location);
    const { bytes } = await inspectRanges(file, location.signal, fileHash, async reader => {
      checkRange(reader.size, offset, length, '计算输入');
      const bytes = await reader.read(offset, length);
      if (createHash('sha256').update(bytes).digest('hex') !== rangeHash) {
        throw new ToolError('conflict', '片段字节与记录的 SHA-256 不同。');
      }
      return { report: { bytes } };
    });
    return { bytes, source: { ...source, byte_offset: offset, ...(length === 0 ? {} : { byte_length: length }) }, data_sha256: rangeHash };
  }

  const memberIndex = get('/member_index');
  const memberHash = get('/member_sha256');
  const memberSize = get('/member_size');
  const pageOnly = get('/result_scope') === 'page';
  if (!Number.isSafeInteger(memberIndex) || memberIndex < 0 || !Number.isSafeInteger(memberSize)
    || memberSize < 0 || typeof memberHash !== 'string' || !RESULT_HASH.test(memberHash)) {
    throw new ToolError('unsupported', '该结果缺少成员编号、完整大小或成员哈希。');
  }
  if (!pageOnly && memberSize > MAX_ARCHIVE_MEMBER_BYTES) {
    throw new ToolError('size', '请重新读取该大成员的所需页，再引用对应的结果编号。');
  }
  const offset = pageOnly ? get('/byte_offset') : 0;
  const length = pageOnly ? get('/byte_length') : memberSize;
  const dataHash = pageOnly ? get('/range_sha256') : memberHash;
  if (pageOnly && (!Number.isSafeInteger(offset) || offset < 0 || offset > memberSize
    || !Number.isSafeInteger(length) || length < 0 || length > Math.min(MAX_WINDOW_BYTES, memberSize - offset)
    || !RESULT_HASH.test(dataHash ?? ''))) {
    throw new ToolError('unsupported', '该结果缺少可复核的成员页坐标或 SHA-256。');
  }
  const archiveOffset = get('/archive_range/byte_offset');
  const archiveLength = get('/archive_range/byte_length');
  const member = await readArchiveMember(ctx, {
    file_path: fileName, expected_sha256: fileHash, member_index: memberIndex,
    ...(pageOnly ? { byte_offset: offset, byte_length: Math.max(1, length), encoding: 'base64' } : {}),
    ...(archiveFormatHint(get('/format')) === undefined ? {} : { format_hint: archiveFormatHint(get('/format')) }),
    ...(archiveOffset === undefined && archiveLength === undefined ? {} : { archive_offset: archiveOffset, archive_length: archiveLength }),
  }, location, inspectRanges, workbench, !pageOnly);
  if (member.status === 'dependency_missing') throw new ToolError('dependency', member.reason);
  const bytes = Buffer.from(member.data, 'base64');
  if (member.member_size !== memberSize || member.member_sha256 !== memberHash || bytes.length !== length
    || createHash('sha256').update(bytes).digest('hex') !== dataHash) {
    throw new ToolError('conflict', '当前解压得到的成员或页与记录不一致。');
  }
  return { bytes, source, data_sha256: dataHash, member_index: memberIndex, member_sha256: memberHash,
    ...(pageOnly ? { member_page: { byte_offset: offset, byte_length: length } } : {}),
    ...(member.archive_range === undefined ? {} : { archive_range: member.archive_range }) };
}

async function runReferencedCalculation(ctx, args, execution, location, results, inspectRanges, workbench, calculation) {
  const references = validateSteps(args.steps);
  const origin = new Map();
  const resolved = [];
  const inputEvidence = [];
  let saved;
  let inputBytes = 0;
  for (const reference of references) {
    const { result_id: id, encoding = 'utf8', step, input } = reference;
    let data = origin.get(id);
    if (data === undefined) {
      let result = results.get(execution.agent?.session, location.directoryKey, id);
      if (result === undefined) {
        saved ??= await recordedResults(ctx, location);
        result = saved.get(id);
      }
      if (result === undefined || !['read_binary_range', 'read_archive_member'].includes(result.tool)) {
        throw new ToolError('unsupported', '引用须来自本题目录的分段读取或归档成员结果。');
      }
      data = await recoverCalculationInput(ctx, result, location, inspectRanges, workbench);
      origin.set(id, data);
    }
    const { bytes, ...proof } = data;
    inputBytes += bytes.length;
    if (inputBytes > 2 * MAX_ARCHIVE_MEMBER_BYTES) throw new ToolError('size', '每批引用的原始数据合计最多 2 MiB。');
    const value = bytes.toString(encoding);
    if (encoding === 'utf8' && !Buffer.from(value, 'utf8').equals(bytes)) {
      throw new ToolError('encoding', '引用的字节不是完整 UTF-8，请选择 hex 或 base64。');
    }
    resolved.push(value);
    inputEvidence.push({ step, input_index: input, result_id: id, encoding, data_bytes: bytes.length, ...proof });
  }
  const report = await calculation.run(args.steps, location.signal, resolved, {
    candidates: args.candidates, resumeId: args.resume_id, session: execution.agent?.session, directoryKey: location.directoryKey,
  });
  return { ...report, input_evidence: inputEvidence };
}

function resolveConfig(configSource) {
  return typeof configSource === 'function' ? configSource() : configSource;
}

function compactJson(value, configSource) {
  const config = resolveConfig(configSource);
  return JSON.stringify(value, null, config?.compact === false ? 2 : 0);
}

function registerTool(ctx, toolName, description, properties, run, required = ['file_path'], capture, parametersOverride) {
  if (!shouldRegisterTool(toolName, DOMAIN_SELECTIONS.get(ctx))) return;
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
      const binding = typeof capture === 'function' ? capture(args) : capture;
      try {
        if (!objectWithKeys(args, Object.keys(properties))) throw new ToolError('unsupported', '提供了此工具不支持的参数。');
        const location = binding?.workspace ? await workspaceLocation(ctx, execution) : undefined;
        let prepared = args;
        let imported;
        if (location !== undefined) ({ args: prepared, imported } = await rewriteInputPaths(ctx, args, location, execution, resolveConfig(binding.config)));
        const report = await run(prepared, execution, location);
        const artifactBytes = Buffer.isBuffer(report?.__artifact_bytes) ? report.__artifact_bytes : undefined;
        if (artifactBytes !== undefined) delete report.__artifact_bytes;
        const requestHash = binding?.workspace ? experimentRequestHash(toolName, typeof prepared.file_path === 'string'
          ? { ...prepared, file_path: pathParts(prepared.file_path).join('/') } : prepared) : undefined;
        const output = { file: prepared.file_path, ...(imported?.length ? { imported } : {}), ...report,
          ...(requestHash === undefined ? {} : { request_sha256: requestHash }) };
        const scope = binding?.workspace ? location.directoryKey : (binding?.scope ?? null);
        const resultId = binding && scope !== undefined ? binding.results.remember(execution.agent?.session, scope, toolName,
          output, resultSources(toolName, output, binding.workspace)) : undefined;
        const outputConfig = binding?.config ?? OUTPUT_CONFIGS.get(ctx);
        if (resultId === undefined) return compactJson(output, outputConfig);
        if (artifactBytes !== undefined) binding.results.rememberArtifact(execution.agent?.session, resultId, artifactBytes,
          resultSources(toolName, output, binding.workspace));
        const result = binding.workspace ? binding.results.get(execution.agent?.session, scope, resultId) : undefined;
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
        return compactJson({ ok: false, file: askedFile, error: describeToolError(error) }, binding?.config ?? OUTPUT_CONFIGS.get(ctx));
      }
    },
  });
}

export function apply(ctx, config) {
  const workbench = createWorkbenchEnvironment(config);
  const currentConfig = () => workbench.presetConfig();
  OUTPUT_CONFIGS.set(ctx, currentConfig);
  const domainSelection = resolveToolDomainSelection(currentConfig());
  DOMAIN_SELECTIONS.set(ctx, domainSelection);
  const inspectRanges = createRangeInspector(ctx.fs);
  const results = createToolResults();
  const calculation = createCalculationRunner();
  ctx.effect(() => () => calculation.dispose(), 'CTF offline calculation workers');
  const fileResults = { results, workspace: true, config: currentConfig };
  const offlineResults = { results, workspace: false, scope: OFFLINE_RESULT_SCOPE };
  const sessionResults = { results, workspace: false };
  const network = createNetworkBoundary(currentConfig);
  const cookieJars = new WeakMap();
  function cookieJarFor(execution, directoryKey, name) {
    if (name === undefined) return undefined;
    const session = execution.agent.session;
    let byWorkspace = cookieJars.get(session);
    if (byWorkspace === undefined) {
      byWorkspace = new Map();
      cookieJars.set(session, byWorkspace);
    }
    let store = byWorkspace.get(directoryKey);
    if (store === undefined) {
      store = createCookieJarStore();
      byWorkspace.set(directoryKey, store);
    }
    return store.forJar(name);
  }
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
      const scope = networkScopeFor(execution, location);
      manager = createNetSessionManager({ authorize: (host, port, signal) => network.tcp(host, port, signal, scope) });
      inSession.set(location.directoryKey, manager);
      managers.add(manager);
    }
    return manager;
  }
  const extendedAudit = currentConfig().enableExtendedAudit === true;
  if (extendedAudit) {
    registerTool(ctx, 'read_ctf_files',
      '批量读取多个已知本地文本路径与行段，返回行号、字节偏移与 SHA-256。',
      BATCH_TEXT_PROPERTIES,
      (args, _execution, location) => readCtfFiles(args, {
        normalizePath: path => pathParts(path).join('/'),
        read: path => snapshotEvidence(ctx, path, location, MAX_BATCH_FILE_BYTES),
      }), ['files'], fileResults);
  }
  registerTool(ctx, 'inspect_attachment',
    '只读检查附件格式、归档目录或抓包结构；支持 format_hint、scan_result_id 与 pcapng 统计。',
    ATTACHMENT_PROPERTIES,
    async (args, execution, location) => {
      const { offset = 0, limit = 10 } = args;
      if (!Number.isInteger(offset) || offset < 0 || offset > MAX_ATTACHMENT_BYTES
        || !Number.isInteger(limit) || limit < 1 || limit > 16) {
        throw new Error('offset 必须是范围内的非负整数，limit 必须是 1 至 16 的整数。');
      }
      const paging = { offset, limit };
      const expectedHash = parseExpectedHash(args.expected_sha256);
      const pcapngQuery = parsePcapngQuery(args.pcapng);
      const zipHint = args.format_hint === 'zip';
      const compressionHint = ['zlib', 'deflate_raw'].includes(args.format_hint) ? args.format_hint : undefined;
      if (args.source_result_id !== undefined || args.source_result_ids !== undefined) {
        if (args.scan_result_id !== undefined || args.archive_offset !== undefined || args.archive_length !== undefined || args.pcapng !== undefined) {
          throw new ToolError('unsupported', '派生字节输入不能同时使用扫描编号、ZIP 区间或 PCAPNG 查询范围。');
        }
        const input = await resolveMediaInput(ctx, args, execution, location, workbench, results, inspectRanges);
        if (input.bytes.length > MAX_ATTACHMENT_BYTES) throw new ToolError('size', '派生附件最多 32 MiB。');
        const report = await inspectAttachmentWithCompression(input.bytes, paging, undefined, compressionHint, location.signal, workbench);
        checkAttachmentHash(expectedHash, input.data_sha256);
        return { ...report, file: input.file, sha256: input.sha256, data_sha256: input.data_sha256,
          source_evidence: input.source_evidence,
          ...(input.source_result_ids === undefined ? {} : { source_result_ids: input.source_result_ids }) };
      }
      if (typeof args.file_path !== 'string') throw new ToolError('path', '请提供 file_path 或 source_result_id。');
      const file = await openWorkspaceFile(ctx, pathParts(args.file_path), location);
      const range = parseZipRange(args, file.size);
      if (args.scan_result_id !== undefined) {
        if (typeof args.scan_result_id !== 'string' || !RESULT_HASH.test(args.scan_result_id) || range || pcapngQuery !== undefined
          || compressionHint !== undefined) {
          throw new ToolError('unsupported', 'scan_result_id 只用于 ZIP 候选核对，不能与指定区间或 PCAPNG 查询合用。');
        }
        const markerResult = results.get(execution.agent?.session, location.directoryKey, args.scan_result_id);
        const scan = markerResult?.report;
        if (markerResult?.tool !== 'scan_binary' || scan?.mode !== 'signatures' || typeof scan.file !== 'string'
          || pathParts(scan.file).join('/') !== pathParts(args.file_path).join('/') || !Array.isArray(scan.matches)) {
          throw new ToolError('unsupported', '请引用本题同一原件的签名扫描结果。');
        }
        if (typeof ctx.fs.readByteRange !== 'function') throw new ToolError('dependency', '当前文件服务不支持 ZIP 候选核对。');
        if (file.size !== scan.size || scan.snapshot_id !== attachmentSnapshot(file)) {
          throw new ToolError('conflict', '扫描之后附件发生变化，请重新扫描。');
        }
        return inspectRanges(file, location.signal, expectedHash ?? scan.sha256, async reader => ({
          report: { ...await inspectZipCandidates(reader, scan, paging), scan_result_id: args.scan_result_id },
        }));
      }
      if ((zipHint || compressionHint !== undefined || range !== undefined) && pcapngQuery !== undefined) {
        throw new ToolError('unsupported', '一次只能查询压缩/ZIP 附件或 PCAPNG。');
      }
      if (compressionHint !== undefined && range !== undefined) {
        throw new ToolError('unsupported', 'zlib 和 raw Deflate 格式提示不能与 ZIP 区间合用。');
      }
      if (range !== undefined) {
        return inspectSelectedZip(ctx, inspectRanges, file, { signal: location.signal, expectedHash, range },
          async reader => (await inspectZipRanges(reader, paging, undefined, true))?.report);
      }
      if (pcapngQuery === undefined && compressionHint === undefined && typeof ctx.fs.readByteRange === 'function') {
        const zip = await inspectRanges(file, location.signal, expectedHash,
          (reader, index) => inspectZipRanges(reader, paging, index, zipHint));
        if (zip !== undefined) return zip;
        if (zipHint) throw new Error('未在文件中找到可验证的 ZIP 目录。');
      }
      const bytes = await readOpenedFile(ctx, file, location.signal);
      const sha256 = createHash('sha256').update(bytes).digest('hex');
      if (zipHint) {
        const zip = await inspectZipRanges({ size: bytes.length, read: (offset, length) => bytes.subarray(offset, offset + length) },
          paging, undefined, true);
        if (zip === undefined) throw new Error('未在文件中找到可验证的 ZIP 目录。');
        const sha256 = createHash('sha256').update(bytes).digest('hex');
        checkAttachmentHash(expectedHash, sha256);
        return { ...zip.report, size: bytes.length, sha256 };
      }
      const archiveFormat = pcapngQuery === undefined && compressionHint === undefined ? nativeArchiveFormat(bytes) : undefined;
      if (archiveFormat !== undefined) {
        const sha256 = createHash('sha256').update(bytes).digest('hex');
        checkAttachmentHash(expectedHash, sha256);
        const archive = await inspectNativeArchive(bytes, archiveFormat, paging, location.signal, workbench);
        return { ...archive, size: bytes.length, sha256 };
      }
      const report = await inspectAttachmentWithCompression(bytes, paging, pcapngQuery, compressionHint, location.signal, workbench);
      checkAttachmentHash(expectedHash, report.sha256 ?? sha256);
      return { ...report, size: bytes.length, sha256: report.sha256 ?? sha256 };
    }, [], fileResults);
  registerTool(ctx, 'read_png_pixels',
    '读取 PNG 像素、单页 LSB 或连续位流（支持区域、通道、APNG 帧及 source_result_id）。',
    { file_path: PATH_SCHEMA, ...RESULT_SOURCE_PROPERTIES, ...PNG_PIXEL_PROPERTIES, expected_sha256: SHA256_SCHEMA },
    (args, execution, location) => readMediaAttachment(ctx, args, parsePngRequest(args), location, workbench, execution, results, inspectRanges),
    [], fileResults);
  registerTool(ctx, 'inspect_media',
    '检查 PDF（含渲染与嵌入附件）、图像、二维码、音频、只读 SQLite、Office 与 AI 模型/Pickle 静态安全体检。',
    { file_path: PATH_SCHEMA, ...RESULT_SOURCE_PROPERTIES, ...MEDIA_PROPERTIES, expected_sha256: SHA256_SCHEMA },
    (args, execution, location) => readMediaAttachment(ctx, args, parseMediaRequest(args), location, workbench, execution, results, inspectRanges),
    ['kind'], fileResults);
  registerTool(ctx, 'read_archive_member',
    '按 member_index 分页读取归档/压缩流成员并返回原件、成员与页的 SHA-256。',
    ARCHIVE_MEMBER_PROPERTIES,
    (args, _execution, location) => readArchiveMember(ctx, args, location, inspectRanges, workbench), ['file_path', 'member_index'], fileResults);
  registerTool(ctx, 'scan_binary',
    '分块扫描附件中的格式签名、十六进制或 UTF-8 字节并返回偏移与片段 SHA-256。',
    { file_path: PATH_SCHEMA, ...BINARY_SCAN_PROPERTIES, expected_sha256: SHA256_SCHEMA },
    async (args, _execution, location) => {
      const request = parseBinaryScan(args);
      const expectedHash = parseExpectedHash(args.expected_sha256);
      if (request.hashScope === 'range' && expectedHash !== undefined) {
        throw new ToolError('unsupported', '核对原件 SHA-256 时请省略 hash_scope 或选择 file。');
      }
      if (typeof ctx.fs.readByteRange !== 'function') throw new ToolError('dependency', '当前 DSH 文件服务不支持分段扫描。');
      const file = await openWorkspaceFile(ctx, pathParts(args.file_path), location);
      const hashFile = expectedHash !== undefined || request.hashScope === 'file';
      return inspectRanges(file, location.signal, expectedHash, async reader => ({
        report: { ...await scanBinary(reader, request, location.signal), hash_scope: hashFile ? 'file' : 'range',
          snapshot_id: attachmentSnapshot(file) },
      }), { hashFile });
    }, undefined, fileResults);
  registerTool(ctx, 'read_binary_range',
    '按精确偏移读取附件片段（每次最多 4 KiB），返回 hexdump/ASCII/可选字符串与 SHA-256。',
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
  if (extendedAudit) {
    registerTool(ctx, 'read_log_range',
      '按字节偏移只读 UTF-8 日志片段，返回对齐偏移与原件 SHA-256。',
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
  }
  registerTool(ctx, 'inspect_elf',
    '静态检查本地 ELF：头信息、checksec（NX/PIE/RELRO/canary/FORTIFY）、导入、PLT/GOT、gadget 与 libc 导出。',
    { file_path: PATH_SCHEMA },
    async (args, _execution, location) => inspectElf(await readAttachment(ctx, args.file_path, location)), undefined, fileResults);
  if (extendedAudit || domainSelection.allowedTools?.has('pwn_cyclic')) {
    registerTool(ctx, 'pwn_cyclic',
      '生成或查找 pwntools 兼容 De Bruijn 循环模式（阶 4）。',
      PWN_PATTERN_PROPERTIES,
      async args => cyclicPattern(args), ['operation']);
    registerTool(ctx, 'pwn_payload',
      '复核 Pwn 基址并组装有界 x86-64 小端 ROP 数据。',
      PWN_PAYLOAD_PROPERTIES,
      async args => buildPwnPayload(args), ['operation']);
  }
  registerTool(ctx, 'net_session',
    '管理长连接 TCP 会话（connect/send/recv/read_until/close/list），用于 Pwn 交互与自定义协议。',
    NET_SESSION_PROPERTIES,
    async (args, execution) => {
      if (args.operation === 'send') writablePolicy(ctx, execution);
      const manager = await tcpManager(execution);
      const report = await manager.execute(args, { signal: execution.signal });
      return Array.isArray(report) ? { sessions: report } : report;
    }, ['operation'], sessionResults);
  registerTool(ctx, 'http_request',
    '发起 HTTP(S) 请求，支持自定义 Host、cookie_jar、multipart 上传与重定向控制，保留赛题响应头（仅脱敏平台令牌）。',
    HTTP_REQUEST_PROPERTIES,
    async (args, execution) => {
      const location = await workspaceLocation(ctx, execution);
      if (!['GET', 'HEAD', 'OPTIONS'].includes(String(args.method ?? 'GET').toUpperCase())
        || args.body !== undefined || args.multipart !== undefined) {
        writablePolicy(ctx, execution);
      }
      const jar = cookieJarFor(execution, location.directoryKey, args.cookie_jar);
      const response = await httpRequest(args, {
        signal: execution.signal,
        authorize: (target, signal) => network.http(target, signal, networkScopeFor(execution, location)),
        ...(jar ? { cookieJar: jar } : {}),
        readFile: async (filePath, limit) => (await readWorkspaceFile(ctx, pathParts(filePath), location, limit)).bytes,
      });
      return redactPlatformToken(response, platformCredential(currentConfig()).token);
    }, ['url'], sessionResults);
  registerTool(ctx, 'pcap_stream',
    '只读分析 PCAP/PCAPNG：重组 IPv4 分片与 TCP 流，提取 DNS 查询与 TXT 样本。',
    PCAP_STREAM_PROPERTIES,
    async (args, execution, location) => {
      await openWorkspaceFile(ctx, pathParts(args.file_path), location);
      return pcapStream(args, { cwd: location.cwd, signal: execution.signal });
    }, ['file_path'], fileResults);
  registerTool(ctx, 'ctf_sandbox',
    'Linux 安全工具沙箱（Docker 优先，自动回退 WSL2）：status 探测兵器库；exec 运行命令/脚本；decompile 列出函数或反编译；pwn_triage 采集 checksec/libc/gadget/seccomp。',
    SANDBOX_PROPERTIES,
    (args, execution) => runSandboxTool(ctx, args, execution, currentConfig()),
    ['action'], sessionResults);
  if (extendedAudit) {
    registerTool(ctx, 'verify_elf',
      '从原文件复核 ELF 入口、main、动态符号偏移标注或 SHA-256。',
      VERIFY_PROPERTIES,
      async (args, _execution, location) => {
        const claims = parseClaims(args);
        return verifyElf(await readAttachment(ctx, args.file_path, location), claims);
      }, undefined, fileResults);
    registerTool(ctx, 'verify_evidence',
      '对照 2 至 8 个本地证据位置并核验一致性。',
      EVIDENCE_PROPERTIES,
      async (args, execution, location) => {
        const recorded = await recordedResults(ctx, location);
        const sources = parseEvidenceSources(args, id => results.get(execution.agent?.session, location.directoryKey, id) ?? recorded.get(id));
        return verifyEvidence(sources, args.expected_value, file => snapshotEvidence(ctx, file, location));
      }, ['sources'], fileResults);
    registerTool(ctx, 'verify_http_evidence',
      '对照题目 HAR/JSONL/访问日志中的 HTTP 请求观测。',
      HTTP_EVIDENCE_PROPERTIES,
      (args, _execution, location) => verifyHttpEvidence(args, {
        normalizePath: path => pathParts(path).join('/'),
        read: path => readWorkspaceFile(ctx, path.split('/'), location, MAX_HTTP_BYTES),
      }), ['request', 'sources'], fileResults);
    registerTool(ctx, 'trace_flask_route',
      '静态定位 Flask 路由、蓝图、钩子与处理函数状态码。',
      FLASK_ROUTE_PROPERTIES,
      (args, _execution, location) => traceFlaskRoute(args, {
        normalizePath: path => pathParts(path).join('/'),
        read: path => readWorkspaceFile(ctx, path.split('/'), location, MAX_FLASK_SOURCE_BYTES),
      }, location.signal, workbench), ['entry_file', 'request'], fileResults);
    registerTool(ctx, 'verify_flask_response',
      '核对 JSONL 应用返回事件、HTTP 观测与 Flask 路由追踪结果。',
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
      '查询本地 JSONL 或 GNU 式逆向导出中的函数与引用。',
      REV_EXPORT_PROPERTIES,
      async (args, _execution, location) => {
        const parts = pathParts(args.file_path);
        const { bytes } = await readWorkspaceFile(ctx, parts, location, MAX_REV_TEXT_BYTES);
        return queryRevExport(bytes, parts.join('/'), args.format, args.query);
      }, ['file_path', 'format', 'query'], fileResults);
    registerTool(ctx, 'map_rev_address',
      '在本地 ELF、PE 或 Wasm 原件上核对虚拟地址、RVA 与文件偏移映射。',
      REV_ADDRESS_PROPERTIES,
      async (args, _execution, location) => {
        const parts = pathParts(args.file_path);
        const { bytes } = await readWorkspaceFile(ctx, parts, location);
        return mapRevAddress(bytes, parts.join('/'), args);
      }, ['file_path', 'queries'], fileResults);
    registerTool(ctx, 'verify_rev_machine',
      '按本地 JSONL 字节状态机规则复算短 Hex 样例。',
      REV_MACHINE_PROPERTIES,
      async (args, _execution, location) => {
        const parts = pathParts(args.file_path);
        const { bytes } = await readWorkspaceFile(ctx, parts, location, MAX_REV_TEXT_BYTES);
        return verifyRevMachine(bytes, parts.join('/'), args);
      }, ['file_path', 'input_hex'], fileResults);
    registerTool(ctx, 'compare_rev_trace',
      '对照本地 JSONL 运行轨迹与参考记录或状态机结果。',
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
  }
  registerTool(ctx, 'rev_query',
    '多架构二进制查询（ELF32/64、PE32/32+）：disassemble 反汇编、cfg 控制流、strings 扫串、triage 快检加壳/密码常量（无需 capstone）。',
    Object.fromEntries(Object.entries(REV_QUERY_PROPERTIES).filter(([key]) => key !== 'python_path')),
    async (args, execution, location) => {
      const file = await openWorkspaceFile(ctx, pathParts(args.file_path), location);
      let report;
      try {
        report = await runRevQuery(args, {
          cwd: location.cwd, signal: execution.signal, pythonPath: await workbench.resolvePython(execution.signal),
        });
      } catch (error) {
        if (typeof error?.message === 'string' && /capstone/iu.test(error.message)) {
          const sb = await detectSandbox(currentConfig(), execution.signal);
          const hint = sb.available
            ? `宿主机缺少 capstone，可改用 rev_query(operation: "triage"/"strings")，或直接切换 ctf_sandbox(action: "decompile" / "exec") 使用 ${sb.backend} 沙箱内的反汇编/反编译工具。`
            : '宿主机缺少 capstone，可改用 rev_query(operation: "triage"/"strings")，或安装 capstone / 构建 dsh-ctf-sandbox:latest。';
          throw new ToolError('dependency', error.message, hint);
        }
        throw error;
      }
      await requireCurrentFile(ctx.fs, file, location.signal);
      return report;
    }, ['file_path', 'operation'], fileResults);
  registerTool(ctx, 'calculate_offline',
    '离线多步确定性计算：大整数/模运算、编解码、哈希/HMAC、古典密码、XOR、AES、RSA/ECDSA/LCG 复算，支持 result_id 引用与超时续算。',
    CALCULATION_PROPERTIES,
    (args, execution, location) => location === undefined
      ? calculation.run(args.steps, execution.signal, undefined, {
        candidates: args.candidates, resumeId: args.resume_id, session: execution.agent?.session,
      })
      : runReferencedCalculation(ctx, args, execution, location, results, inspectRanges, workbench, calculation),
    ['steps'], args => hasAttachmentInputs(args?.steps) ? fileResults : offlineResults);
  if (extendedAudit) {
    const base100 = new Base100Workbench(workbench);
    ctx.effect(() => () => base100.dispose(), 'CTF Base100 workbench process');
    registerTool(ctx, 'workbench_base100',
      '批量使用本机 CTF 工作台进行 Base100 编解码。',
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
  }
  registerTool(ctx, 'ctf_graph',
    '工作区共享分层 Fact-Intent 图谱（.ctf-graph/）：board 查极简索引、expand 按需展开、add_fact/add_intent 记事实与任务、claim_intent 并发互斥认领、finish_intent 原子结案。',
    GRAPH_PROPERTIES,
    (args, execution) => runGraphTool(ctx, args, execution),
    ['action']);
  registerTool(ctx, 'ctf_progress',
    '题目续接笔记（load/check/save/writeup/handoff/results/experiments/repair）。',
    PROGRESS_PROPERTIES,
    (args, execution) => {
      const allowed = PROGRESS_ACTION_KEYS[args.action];
      if (!allowed || Object.keys(args).some(key => !allowed.includes(key))) {
        throw new ToolError('unsupported', 'ctf_progress 的字段须与 action 对应。');
      }
      return runProgress(ctx, args, execution, results, inspectRanges);
    }, ['action'], undefined, PROGRESS_PARAMETERS);
  registerTool(ctx, 'ctf_status',
    '时间盒心跳与榜单（set/show/board），自动产出 15/30/60 分钟预警。',
    STATUS_PROPERTIES,
    (args, execution) => runStatus(ctx, args, execution, currentConfig()), ['action']);
  registerTool(ctx, 'check_flag',
    '本地预检 flag 格式、来源、重复与实例刷新时间；传 record:true 写预检回执。',
    SUBMIT_FLAG_PROPERTIES,
    (args, execution) => runSubmitCheck(ctx, args, execution, currentConfig()), ['flag']);
  registerTool(ctx, 'submit_flag',
    '本地校验通过后向平台提交 flag 并写入 .ctf-submissions.jsonl 回执。',
    SUBMIT_FLAG_PROPERTIES,
    (args, execution) => runSubmitFlag(ctx, args, execution, currentConfig()), ['flag']);
  registerTool(ctx, 'ctf_instance',
    '管理赛题实例（status/list/create/rotate/delete），并自动为本会话授权返回的 HTTP/TCP 靶机。',
    INSTANCE_PROPERTIES,
    (args, execution) => runInstance(ctx, args, execution, currentConfig(), network), ['action']);
  registerTool(ctx, 'ctf_arena',
    'CTFd/GZCTF/通用赛题平台适配器：拉题单、查题情、一键同步到 ctf_graph、下载附件、启删容器与提交 flag。',
    ARENA_PROPERTIES,
    (args, execution) => runArenaTool(ctx, args, execution, currentConfig(), network), ['action']);
  registerTool(ctx, 'fetch_attachment',
    '下载赛题附件到 .ctf-attachments/ 并校验 SHA-256（已授权与平台同源支持内网/认证头）。',
    FETCH_PROPERTIES,
    (args, execution) => runFetchAttachment(ctx, args, execution, currentConfig(), network), ['url']);
  if (extendedAudit) {
    registerTool(ctx, 'submit_check',
      '已弃用兼容别名：请改用 check_flag。',
      SUBMIT_FLAG_PROPERTIES,
      (args, execution) => runSubmitCheck(ctx, args, execution, currentConfig()), ['flag']);
  }
  const registeredToolTier = extendedAudit ? 'full' : 'core';
  registerTool(ctx, 'ctf_doctor',
    '只读自检宿主能力、工具分层、SKILL 同步、Linux 沙箱、本机依赖与工作区续接文件。',
    { action: { type: 'string', enum: ['check'], description: '默认 check。' } },
    (_args, execution) => runDoctor(ctx, execution, currentConfig(), workbench, registeredToolTier), ['action']);
  if (extendedAudit) {
    registerTool(ctx, 'competition_api',
      '兼容旧入口：访问比赛平台（status/instances/create/delete/submit）。',
      {
        action: { type: 'string', enum: ['status', 'instances', 'create', 'delete', 'submit'], description: '要执行的动作。' },
        ...SUBMIT_FLAG_PROPERTIES,
        id: { type: 'string', maxLength: 200, description: 'delete 时的实例标识。' },
        body: { type: 'object', description: 'create 时的请求体，按 JSON 原样提交。', additionalProperties: true },
      },
      (args, execution) => runCompetitionApi(ctx, args, execution, currentConfig(), network), ['action']);
  }
  registerExtraTools(ctx, currentConfig, {
    extendedAudit,
    domainSelection,
    shouldRegister: toolName => shouldRegisterTool(toolName, domainSelection),
    location: execution => workspaceLocation(ctx, execution),
    async input(location, path) {
      const parts = pathParts(path);
      await openWorkspaceFile(ctx, parts, location);
      return join(location.cwd, ...parts);
    },
    read: (location, path, limit) => readWorkspaceFile(ctx, pathParts(path), location, limit),
    output: (location, path, directory) => checkedOutput(ctx, location, path, directory),
    python: signal => workbench.resolvePython(signal),
    authorize: (url, signal, execution, location) => network.http(url, signal,
      networkScopeFor(execution, location ?? { directoryKey: undefined })),
    platformToken: () => platformCredential(currentConfig()).token,
    async observe(tool, args, execution, report, artifactBytes) {
      if (tool === 'cloud_metadata' || (tool === 'archive_crack' && args.action !== 'info')
        || ['failed', 'timeout', 'closed'].includes(report.status)) return undefined;
      const location = await workspaceLocation(ctx, execution);
      const session = execution.agent?.session;
      const sources = typeof args.file_path === 'string' && RESULT_HASH.test(report.input_sha256 ?? '')
        ? [{ file_path: pathParts(args.file_path).join('/'), sha256: report.input_sha256 }] : [];
      const resultId = results.remember(session, location.directoryKey, tool, report, sources);
      if (!resultId) return undefined;
      if (Buffer.isBuffer(artifactBytes)) results.rememberArtifact(session, resultId, artifactBytes, sources);
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
        text: '本题工作区可能有 .ctf-graph/（优先用 ctf_graph board 查共享事实与待办任务）、notes.md（续接记录）、handoff.md（接替简报）、.ctf-status.json（时间盒心跳）和 .ctf-submissions.jsonl（提交回执）：开始或接手时先读它们，再决定下一步。',
      });
    } catch {
      // Older hosts may not expose the system prompt service; SKILL.md carries the same rule.
    }
  }
}
