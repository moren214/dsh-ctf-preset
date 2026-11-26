import { createHash, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { ToolError } from '../contracts/errors.js';
import { createStateStore } from '../state/state-store.js';

export const MAX_ARTIFACT_ITEM_BYTES = 16 * 1024 * 1024;
export const MAX_ARTIFACT_STORE_BYTES = 128 * 1024 * 1024;
const HASH_RE = /^[a-f0-9]{64}$/u;

export function createArtifactStore(cwd, { readOnly = false, stateStore } = {}) {
  const store = stateStore ?? createStateStore(cwd, { readOnly });
  const artifactDir = path.join(cwd, '.ctf', 'artifacts');

  function blobPath(sha256) {
    return path.join(artifactDir, `${sha256}.bin`);
  }

  function writeBlobAtomic(sha256, bytes) {
    mkdirSync(artifactDir, { recursive: true });
    const target = blobPath(sha256);
    if (existsSync(target)) return target;
    const tmp = path.join(artifactDir, `.tmp-${sha256.slice(0, 12)}-${randomUUID().slice(0, 8)}`);
    try {
      writeFileSync(tmp, bytes);
      try {
        renameSync(tmp, target);
      } catch {
        if (!existsSync(target)) throw new ToolError('conflict', 'Artifact 写入重命名失败。');
      }
      return target;
    } finally {
      if (existsSync(tmp)) {
        try { unlinkSync(tmp); } catch { /* ignore */ }
      }
    }
  }

  function evictIfNeeded(db) {
    const rows = db.prepare('SELECT result_id, artifact_sha256, byte_length FROM artifacts WHERE byte_length > 0 ORDER BY last_accessed_at ASC').all();
    let total = rows.reduce((sum, r) => sum + Number(r.byte_length ?? 0), 0);
    for (const row of rows) {
      if (total <= MAX_ARTIFACT_STORE_BYTES) break;
      db.prepare('DELETE FROM artifacts WHERE result_id = ?').run(row.result_id);
      total -= Number(row.byte_length ?? 0);
      if (row.artifact_sha256) {
        const stillUsed = db.prepare('SELECT 1 FROM artifacts WHERE artifact_sha256 = ? LIMIT 1').get(row.artifact_sha256);
        if (!stillUsed) {
          const p = blobPath(row.artifact_sha256);
          if (existsSync(p)) {
            try { unlinkSync(p); } catch { /* ignore */ }
          }
        }
      }
    }
  }

  function putArtifact({ resultId, tool, bytes, mediaType, sources = [], report }) {
    if (readOnly) return { persisted: false, reason: 'read_only' };
    if (typeof resultId !== 'string' || !HASH_RE.test(resultId)) {
      throw new ToolError('unsupported', 'Artifact result_id 须为 64 位十六进制 SHA-256。');
    }
    let artifactSha = null;
    let byteLength = 0;
    if (bytes !== undefined && bytes !== null) {
      const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
      if (buf.length > MAX_ARTIFACT_ITEM_BYTES) {
        throw new ToolError('size', `单个 Artifact 不能超过 ${MAX_ARTIFACT_ITEM_BYTES / (1024 * 1024)} MiB。`);
      }
      artifactSha = createHash('sha256').update(buf).digest('hex');
      byteLength = buf.length;
      writeBlobAtomic(artifactSha, buf);
    }
    const now = Date.now();
    const sourcesJson = JSON.stringify(Array.isArray(sources) ? sources : []);
    const reportJson = report === undefined ? null : JSON.stringify(report);
    store.runImmediate(db => {
      db.prepare(`
        INSERT INTO artifacts(result_id, tool, artifact_sha256, byte_length, media_type, sources_json, report_json, created_at, last_accessed_at)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(result_id) DO UPDATE SET
          artifact_sha256 = COALESCE(excluded.artifact_sha256, artifacts.artifact_sha256),
          byte_length = CASE WHEN excluded.byte_length > 0 THEN excluded.byte_length ELSE artifacts.byte_length END,
          media_type = COALESCE(excluded.media_type, artifacts.media_type),
          last_accessed_at = excluded.last_accessed_at
      `).run(resultId, tool, artifactSha, byteLength, mediaType ?? null, sourcesJson, reportJson, now, now);
      evictIfNeeded(db);
    });
    return { persisted: true, result_id: resultId, artifact_sha256: artifactSha, byte_length: byteLength };
  }

  function getArtifactRecord(resultId) {
    if (typeof resultId !== 'string' || !HASH_RE.test(resultId)) return undefined;
    return store.runRead(db => {
      const row = db.prepare('SELECT * FROM artifacts WHERE result_id = ?').get(resultId);
      if (!row) return undefined;
      return {
        result_id: row.result_id,
        tool: row.tool,
        artifact_sha256: row.artifact_sha256 ?? undefined,
        byte_length: row.byte_length,
        media_type: row.media_type ?? undefined,
        sources: JSON.parse(row.sources_json || '[]'),
        report: row.report_json ? JSON.parse(row.report_json) : undefined,
        created_at: row.created_at,
      };
    }, undefined);
  }

  function getArtifactBytes(resultId) {
    const rec = getArtifactRecord(resultId);
    if (!rec?.artifact_sha256) return undefined;
    const p = blobPath(rec.artifact_sha256);
    if (!existsSync(p)) return undefined;
    const bytes = readFileSync(p);
    const actualSha = createHash('sha256').update(bytes).digest('hex');
    if (actualSha !== rec.artifact_sha256) {
      throw new ToolError('conflict', '磁盘 Artifact 内容与记录的 SHA-256 不一致。');
    }
    return { bytes, evidence: rec.sources, record: rec };
  }

  function listArtifacts(limit = 64) {
    return store.runRead(db => db.prepare(
      'SELECT result_id, tool, artifact_sha256, byte_length, media_type, created_at FROM artifacts ORDER BY last_accessed_at DESC LIMIT ?',
    ).all(limit), () => []);
  }

  function materializeToTemp(resultId, suffix = '.bin') {
    const data = getArtifactBytes(resultId);
    if (!data) return undefined;
    const matDir = path.join(cwd, '.ctf', 'artifacts', 'materialized');
    mkdirSync(matDir, { recursive: true });
    const safeSuffix = /^[.A-Za-z0-9_-]{1,16}$/u.test(suffix) ? suffix : '.bin';
    const rel = `.ctf/artifacts/materialized/${resultId.slice(0, 16)}${safeSuffix}`;
    const abs = path.join(cwd, rel);
    if (!existsSync(abs)) writeFileSync(abs, data.bytes);
    return { relPath: rel, absPath: abs, sha256: data.record.artifact_sha256, bytes: data.bytes };
  }

  return {
    artifactDir,
    putArtifact,
    getArtifactRecord,
    getArtifactBytes,
    listArtifacts,
    materializeToTemp,
  };
}
