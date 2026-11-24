import { inspectZipFooter } from './zip-directory.js';
import { ToolError } from './tool-errors.js';

const SCAN_VALIDATION_BYTES = 32 * 1024 * 1024;

export async function inspectZipCandidates(reader, scan, { offset, limit }) {
  const footers = scan.matches.filter(hit => hit.signature === 'zip_end');
  const headers = scan.matches.filter(hit => hit.signature === 'zip').map(hit => hit.byte_offset);
  let remaining = SCAN_VALIDATION_BYTES;
  const bounded = {
    size: reader.size,
    read(at, length) {
      if (length > remaining) throw new ToolError('size', '本页 ZIP 结构校验的读入预算已用完。');
      remaining -= length;
      return reader.read(at, length);
    },
  };
  const candidates = [];
  for (const hit of footers.slice(offset, offset + limit)) {
    let inspected;
    try {
      inspected = await inspectZipFooter(bounded, hit.byte_offset, { offset: 0, limit: 4 });
    } catch (error) {
      if (!(error instanceof ToolError) || error.kind !== 'size') throw error;
      inspected = { status: 'insufficient', reason: error.message };
    }
    candidates.push({ footer_offset: hit.byte_offset, ...inspected });
  }
  const next = offset + candidates.length;
  return {
    format: 'ZIP', status: candidates.some(item => item.status === 'confirmed') ? 'ok' : 'insufficient',
    candidates, candidate_count: footers.length, header_offsets: headers,
    next_offset: next < footers.length ? next : null,
    next_scan_offset: scan.next_byte_offset,
    ...(footers.length === 0 ? { reason: '本页扫描没有 ZIP 结束签名。可续扫或指定已知 ZIP 区间。' } : {}),
  };
}
