export const MAX_ATTACHMENT_BYTES = 32 * 1024 * 1024;
export const MAX_ARCHIVE_MEMBER_BYTES = 1024 * 1024;
export const MAX_MEMBER_NAME = 1024;

export function label(value, maximum = 96) {
  return value.replace(/[\p{Cc}\p{Cf}]/gu, '?').slice(0, maximum).replace(/[\uD800-\uDBFF]$/u, '');
}

export function checkRange(end, start, size, field) {
  if (start < 0 || size < 0 || size > end - start) throw new Error('附件结构无效：' + field + ' 超出文件范围。');
}

export function page(table, total, rows, offset) {
  const next = offset + rows.length;
  return { table, total, offset, rows, next_offset: next < total ? next : null };
}

export function inPage(index, { offset, limit }) {
  return index >= offset && index < offset + limit;
}
