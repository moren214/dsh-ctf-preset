const HINTS = {
  path: '使用题目目录内的相对路径。外部附件需位于用户授权的导入目录。',
  missing: '核对文件名、目录和下载状态。',
  size: '缩小输入范围，或在支持时用 read_binary_range 分段读取。',
  encoding: '核对文本编码。二进制数据可用 read_binary_range。',
  dependency: '用 ctf_doctor 查看缺少的配置或运行时能力。',
  network: '核对已授权的来源、端口和连接状态。',
  timeout: '缩小本次操作范围或调整该工具的等待时间。',
  conflict: '重新读取原件或当前 revision 后再提交。',
  abort: '调用已取消。',
  permission: '检查当前会话的文件权限或目标授权。',
  unsupported: '检查工具参数及支持的格式。',
  other: '检查返回消息和输入，确认故障位置。',
};

const CODE_KINDS = new Map(Object.entries({
  ENOENT: 'missing', ENOTDIR: 'path', ELOOP: 'path', EACCES: 'permission', EPERM: 'permission',
  FS_NOT_FOUND: 'missing', FS_PERMISSION_DENIED: 'permission', FS_ABORTED: 'abort',
  FS_CONFLICT: 'conflict', FS_VERSION_MISMATCH: 'conflict', FS_TOO_LARGE: 'size',
  ABORT_ERR: 'abort', ERR_BUFFER_TOO_LARGE: 'size', ETIMEDOUT: 'timeout',
  ENOTFOUND: 'network', EAI_AGAIN: 'network', ECONNREFUSED: 'network', ECONNRESET: 'network',
  EPIPE: 'network', EHOSTUNREACH: 'network', ENETUNREACH: 'network',
}));

export class ToolError extends Error {
  constructor(kind, message, detail) {
    super(message);
    this.kind = kind;
    if (detail !== undefined) this.detail = detail;
  }
}

export function describeToolError(error) {
  const { name, code } = error ?? {};
  const kind = typeof error?.kind === 'string' && Object.hasOwn(HINTS, error.kind) ? error.kind
    : name === 'AbortError' ? 'abort' : name === 'TimeoutError' ? 'timeout' : CODE_KINDS.get(code) ?? 'other';
  const message = typeof error?.message === 'string' ? error.message : String(error);
  return { kind, message, hint: HINTS[kind], ...(error instanceof ToolError && error.detail ? { detail: error.detail } : {}) };
}
