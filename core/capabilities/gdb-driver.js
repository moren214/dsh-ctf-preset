import { closeSync, openSync, readSync } from 'node:fs';
import path from 'node:path';
import { ToolError } from '../contracts/errors.js';

const GDB_ATOM = '(?:\\$[A-Za-z][A-Za-z0-9_]*|0x[0-9a-f]{1,16}|[0-9]{1,16}|&?[A-Za-z_][A-Za-z0-9_.@$]*)';
const GDB_EXPR = `${GDB_ATOM}(?:\\s*[+-]\\s*${GDB_ATOM}){0,3}`;
const GDB_CAST = '(?:\\((?:void|char|int|long|unsigned\\s+long|uint64_t|uint32_t|int64_t|int32_t)\\s*\\*{1,2}\\))';
const GDB_VALUE = `(?:\\*(?:${GDB_CAST})?\\s*)?(?:${GDB_EXPR}|\\(${GDB_EXPR}\\))`;

export const GDB_COMMAND_PATTERNS = [
  new RegExp(`^(?:break|b)\\s+\\*?${GDB_EXPR}$`, 'iu'),
  /^(?:run|start|starti|continue|c|step|s|stepi|si|next|n|nexti|ni|finish|fin|kill)$/iu,
  /^(?:bt|backtrace)(?:\s+[0-9]{1,3})?$/iu,
  /^(?:info|i)\s+(?:registers|reg|r)(?:\s+[A-Za-z0-9_]+){0,8}$/iu,
  /^(?:info|i)\s+(?:all-registers|frame|files|proc\s+mappings|sharedlibrary|args|locals|functions|variables|breakpoints|b)$/iu,
  new RegExp(`^(?:info|i)\\s+symbol\\s+${GDB_EXPR}$`, 'iu'),
  /^frame(?:\s+[0-9]{1,4})?$/iu,
  new RegExp(`^x\\/(?:[1-9][0-9]{0,2})?(?:[bghw][xduoctafis]?|[xduoctafis][bghw]?)?\\s+${GDB_VALUE}$`, 'iu'),
  new RegExp(`^(?:disassemble|disas)(?:\\s+${GDB_EXPR}(?:\\s*,\\s*${GDB_EXPR})?)?$`, 'iu'),
  new RegExp(`^(?:p|print)(?:\\/[xduoctafs]|\\s+\\/[xduoctafs])?\\s+${GDB_VALUE}$`, 'iu'),
  /^set\s+follow-fork-mode\s+(?:child|parent)$/iu,
  /^set\s+disassembly-flavor\s+(?:intel|att)$/iu,
  /^handle\s+SIG(?:ALRM|PIPE|USR1|USR2)(?:\s+(?:nostop|stop|noprint|print|pass|nopass)){1,3}$/iu,
];

export function validatedGdbCommands(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 24) {
    throw new ToolError('unsupported', 'debug 需要 1 至 24 条 GDB 命令。');
  }
  return value.map(command => {
    if (typeof command !== 'string' || command.length > 256 || /[\0\r\n;]/u.test(command)) {
      throw new ToolError('unsupported', 'GDB 命令须为单行文本且不超过 256 字符。');
    }
    const normalized = command.trim();
    if (!GDB_COMMAND_PATTERNS.some(pattern => pattern.test(normalized))) {
      throw new ToolError('unsupported', `GDB 命令不在只读调试白名单内：${normalized.slice(0, 80)}。`);
    }
    return normalized;
  });
}

export function validatedGdbArgs(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 16) {
    throw new ToolError('unsupported', 'args 须为最多 16 项的字符串数组。');
  }
  return value.map((item, idx) => {
    if (typeof item !== 'string' || item.length > 256 || /[\0\r\n]/u.test(item)) {
      throw new ToolError('unsupported', `args[${idx}] 须为不超过 256 字符的单行字符串。`);
    }
    return item;
  });
}

export function quoteGdbPath(value) {
  return '"' + value.replaceAll('\\', '/').replaceAll('"', '\\"') + '"';
}

export function quoteGdbInputPath(value, posix = process.platform !== 'win32') {
  return posix ? "'" + value.replaceAll("'", "'\\''") + "'" : quoteGdbPath(value);
}

export function quoteGdbArg(value, posix) {
  return posix ? "'" + value.replaceAll("'", "'\\''") + "'" : quoteGdbPath(value);
}

export function isElfBinary(filePath) {
  let fd;
  try {
    fd = openSync(filePath, 'r');
    const head = Buffer.alloc(4);
    const n = readSync(fd, head, 0, 4, 0);
    return n === 4 && head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* ignore */ }
    }
  }
}

export function sandboxRelativePath(cwd, absPath) {
  return './' + path.relative(cwd, absPath).replaceAll('\\', '/');
}
