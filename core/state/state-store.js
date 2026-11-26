import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { ToolError } from '../contracts/errors.js';

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS graph_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  schema_version INTEGER NOT NULL,
  revision INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS graph_facts (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  challenge TEXT NOT NULL,
  kind TEXT NOT NULL,
  title TEXT NOT NULL,
  summary TEXT,
  evidence TEXT,
  source TEXT,
  created_by TEXT,
  dedupe_key TEXT,
  created_at TEXT NOT NULL,
  race_id TEXT,
  branch_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_facts_challenge ON graph_facts(challenge);
CREATE UNIQUE INDEX IF NOT EXISTS idx_facts_dedupe ON graph_facts(challenge, dedupe_key) WHERE dedupe_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS graph_intents (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  challenge TEXT NOT NULL,
  title TEXT NOT NULL,
  parent_fact_ids_json TEXT NOT NULL,
  hypothesis TEXT,
  priority INTEGER NOT NULL,
  budget_minutes INTEGER NOT NULL,
  status TEXT NOT NULL,
  owner TEXT,
  claim_lease TEXT,
  claimed_at TEXT,
  finished_at TEXT,
  outcome TEXT,
  produced_fact_ids_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  race_id TEXT,
  branch_id TEXT,
  superseded_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_intents_challenge_status ON graph_intents(challenge, status);
CREATE INDEX IF NOT EXISTS idx_intents_race ON graph_intents(race_id);

CREATE TABLE IF NOT EXISTS network_grants (
  scope_workspace TEXT NOT NULL,
  kind TEXT NOT NULL,
  target_key TEXT NOT NULL,
  lease_id TEXT,
  granted_by TEXT,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (scope_workspace, kind, target_key)
);

CREATE TABLE IF NOT EXISTS instance_records (
  platform TEXT NOT NULL,
  instance_id TEXT NOT NULL,
  state TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  PRIMARY KEY (platform, instance_id)
);

CREATE TABLE IF NOT EXISTS instance_locks (
  lock_key TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS submission_receipts (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  at TEXT NOT NULL,
  kind TEXT NOT NULL,
  verdict TEXT NOT NULL,
  ready INTEGER NOT NULL,
  flag_sha256 TEXT NOT NULL,
  challenge TEXT,
  instance TEXT,
  platform TEXT,
  platform_status INTEGER
);

CREATE TABLE IF NOT EXISTS artifacts (
  result_id TEXT PRIMARY KEY,
  tool TEXT NOT NULL,
  artifact_sha256 TEXT,
  byte_length INTEGER NOT NULL DEFAULT 0,
  media_type TEXT,
  sources_json TEXT NOT NULL,
  report_json TEXT,
  created_at INTEGER NOT NULL,
  last_accessed_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_artifacts_lru ON artifacts(last_accessed_at);
`;

const BUSY_RETRIES = 24;

function isBusyError(error) {
  const msg = String(error?.message ?? '');
  return error?.code === 'ERR_SQLITE_ERROR' && /locked|busy/iu.test(msg)
    || /SQLITE_BUSY|SQLITE_LOCKED|database is locked/iu.test(msg);
}

function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function openDb(dbPath, { readOnly = false } = {}) {
  const db = readOnly ? new DatabaseSync(dbPath, { readOnly: true }) : new DatabaseSync(dbPath);
  db.exec('PRAGMA busy_timeout = 5000;');
  if (!readOnly) {
    db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;');
  }
  return db;
}

export function dbPathForWorkspace(cwd) {
  return path.join(cwd, '.ctf', 'runtime.db');
}

export function createStateStore(cwd, { readOnly = false } = {}) {
  const dbPath = dbPathForWorkspace(cwd);

  function ensureInitialized(db) {
    db.exec(SCHEMA_SQL);
    const meta = db.prepare('SELECT revision FROM graph_meta WHERE id = 1').get();
    if (!meta) {
      db.prepare('INSERT INTO graph_meta(id, schema_version, revision, updated_at) VALUES(1, 1, 0, ?)')
        .run(new Date().toISOString());
    }
  }

  function runImmediate(fn) {
    if (readOnly) {
      throw new ToolError('permission', '当前会话为只读权限，无法写入状态数据库。');
    }
    mkdirSync(path.dirname(dbPath), { recursive: true });
    for (let attempt = 0; attempt < BUSY_RETRIES; attempt += 1) {
      const db = openDb(dbPath, { readOnly: false });
      try {
        ensureInitialized(db);
        db.exec('BEGIN IMMEDIATE;');
        try {
          const result = fn(db);
          db.exec('COMMIT;');
          return result;
        } catch (inner) {
          try { db.exec('ROLLBACK;'); } catch { /* ignore rollback error */ }
          throw inner;
        }
      } catch (error) {
        if (isBusyError(error) && attempt + 1 < BUSY_RETRIES) {
          sleepSync(Math.min(120, 8 + attempt * 5));
          continue;
        }
        throw error;
      } finally {
        try { db.close(); } catch { /* ignore */ }
      }
    }
    throw new ToolError('conflict', '状态数据库并发忙，请重试。');
  }

  function runRead(fn, emptyValue) {
    if (!existsSync(dbPath)) {
      return typeof emptyValue === 'function' ? emptyValue() : emptyValue;
    }
    for (let attempt = 0; attempt < BUSY_RETRIES; attempt += 1) {
      let db;
      try {
        db = openDb(dbPath, { readOnly: true });
        return fn(db);
      } catch (error) {
        if (isBusyError(error) && attempt + 1 < BUSY_RETRIES) {
          sleepSync(Math.min(80, 5 + attempt * 4));
          continue;
        }
        if (/no such table/iu.test(String(error?.message ?? ''))) {
          return typeof emptyValue === 'function' ? emptyValue() : emptyValue;
        }
        throw error;
      } finally {
        try { db?.close(); } catch { /* ignore */ }
      }
    }
    throw new ToolError('conflict', '状态数据库读取忙，请重试。');
  }

  // ── Network Grants ──────────────────────────────────────────────────────────

  function grantNetworkTarget(workspaceKey, kind, targetKey, { leaseId, grantedBy, expiresAt }) {
    if (typeof workspaceKey !== 'string' || !workspaceKey) return false;
    return runImmediate(db => {
      db.prepare('DELETE FROM network_grants WHERE expires_at <= ?').run(Date.now());
      const existingCount = db.prepare('SELECT COUNT(*) AS cnt FROM network_grants WHERE scope_workspace = ? AND kind = ?')
        .get(workspaceKey, kind).cnt;
      const exists = db.prepare('SELECT 1 FROM network_grants WHERE scope_workspace = ? AND kind = ? AND target_key = ?')
        .get(workspaceKey, kind, targetKey);
      if (!exists && existingCount >= 64) return false;
      db.prepare(`
        INSERT INTO network_grants(scope_workspace, kind, target_key, lease_id, granted_by, expires_at)
        VALUES(?, ?, ?, ?, ?, ?)
        ON CONFLICT(scope_workspace, kind, target_key) DO UPDATE SET
          lease_id = excluded.lease_id,
          granted_by = excluded.granted_by,
          expires_at = excluded.expires_at
      `).run(workspaceKey, kind, targetKey, leaseId ?? null, grantedBy ?? null, expiresAt);
      return true;
    });
  }

  function hasNetworkGrant(workspaceKey, kind, targetKey, { excludeGrantedBy } = {}) {
    if (typeof workspaceKey !== 'string' || !workspaceKey) return false;
    return runRead(db => {
      const row = db.prepare('SELECT granted_by, expires_at FROM network_grants WHERE scope_workspace = ? AND kind = ? AND target_key = ?')
        .get(workspaceKey, kind, targetKey);
      if (!row || row.expires_at <= Date.now()) return false;
      if (excludeGrantedBy && row.granted_by === excludeGrantedBy) return false;
      return true;
    }, false);
  }

  function listNetworkGrants(workspaceKey, { excludeGrantedBy } = {}) {
    if (typeof workspaceKey !== 'string' || !workspaceKey) return [];
    const now = Date.now();
    return runRead(db => {
      const rows = db.prepare(
        'SELECT kind, target_key, lease_id, granted_by, expires_at FROM network_grants WHERE scope_workspace = ? AND expires_at > ?',
      ).all(workspaceKey, now);
      return excludeGrantedBy ? rows.filter(r => r.granted_by !== excludeGrantedBy) : rows;
    }, () => []);
  }

  function revokeNetworkGrants(workspaceKey, leaseId) {
    if (typeof workspaceKey !== 'string' || !workspaceKey) return 0;
    return runImmediate(db => {
      const info = leaseId === undefined
        ? db.prepare('DELETE FROM network_grants WHERE scope_workspace = ?').run(workspaceKey)
        : db.prepare('DELETE FROM network_grants WHERE scope_workspace = ? AND lease_id = ?').run(workspaceKey, leaseId);
      return Number(info.changes ?? 0);
    });
  }

  // ── Instance Records & Locks ────────────────────────────────────────────────

  function listInstances() {
    return runRead(db => db.prepare(
      'SELECT platform, instance_id AS id, state, observed_at FROM instance_records ORDER BY observed_at ASC',
    ).all(), () => []);
  }

  function importLegacyInstances(entries) {
    if (!Array.isArray(entries) || entries.length === 0) return;
    runImmediate(db => {
      const stmt = db.prepare(`
        INSERT OR IGNORE INTO instance_records(platform, instance_id, state, observed_at)
        VALUES(?, ?, ?, ?)
      `);
      for (const e of entries) {
        if (typeof e?.platform === 'string' && typeof e?.id === 'string' && typeof e?.state === 'string') {
          stmt.run(e.platform, e.id, e.state, String(e.observed_at ?? new Date().toISOString()));
        }
      }
    });
  }

  function recordInstance(platform, id, state, observedAt = new Date().toISOString()) {
    return runImmediate(db => {
      db.prepare(`
        INSERT INTO instance_records(platform, instance_id, state, observed_at)
        VALUES(?, ?, ?, ?)
        ON CONFLICT(platform, instance_id) DO UPDATE SET
          state = excluded.state,
          observed_at = excluded.observed_at
      `).run(platform, id, state, observedAt);
      return true;
    });
  }

  function acquireInstanceLock(lockKey, owner, ttlMs = 30000) {
    const now = Date.now();
    return runImmediate(db => {
      db.prepare('DELETE FROM instance_locks WHERE expires_at <= ?').run(now);
      const existing = db.prepare('SELECT owner, expires_at FROM instance_locks WHERE lock_key = ?').get(lockKey);
      if (existing && existing.expires_at > now) return false;
      db.prepare('INSERT OR REPLACE INTO instance_locks(lock_key, owner, expires_at) VALUES(?, ?, ?)')
        .run(lockKey, owner, now + ttlMs);
      return true;
    });
  }

  function releaseInstanceLock(lockKey, owner) {
    if (readOnly || !existsSync(dbPath)) return;
    runImmediate(db => {
      if (owner) db.prepare('DELETE FROM instance_locks WHERE lock_key = ? AND owner = ?').run(lockKey, owner);
      else db.prepare('DELETE FROM instance_locks WHERE lock_key = ?').run(lockKey);
    });
  }

  // ── Submission Receipts ─────────────────────────────────────────────────────

  function listSubmissionReceipts() {
    return runRead(db => db.prepare(
      'SELECT id, at, kind, verdict, ready, flag_sha256, challenge, instance, platform, platform_status FROM submission_receipts ORDER BY seq ASC',
    ).all().map(row => ({ ...row, ready: Boolean(row.ready) })), () => []);
  }

  function recordSubmissionReceipt(receipt) {
    return runImmediate(db => {
      db.prepare(`
        INSERT OR REPLACE INTO submission_receipts(id, at, kind, verdict, ready, flag_sha256, challenge, instance, platform, platform_status)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        receipt.id ?? randomUUID(),
        receipt.at ?? new Date().toISOString(),
        receipt.kind ?? 'check',
        receipt.verdict ?? 'checked',
        receipt.ready ? 1 : 0,
        receipt.flag_sha256,
        receipt.challenge ?? null,
        receipt.instance ?? null,
        receipt.platform ?? null,
        receipt.platform_status ?? null,
      );
      return true;
    });
  }

  function importLegacySubmissions(receipts = []) {
    if (!Array.isArray(receipts) || receipts.length === 0) return false;
    return runImmediate(db => {
      const count = db.prepare('SELECT COUNT(*) AS cnt FROM submission_receipts').get().cnt;
      if (count > 0) return false;
      const insert = db.prepare(`
        INSERT OR IGNORE INTO submission_receipts(id, at, kind, verdict, ready, flag_sha256, challenge, instance, platform, platform_status)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const r of receipts) {
        if (!r || typeof r !== 'object' || typeof r.flag_sha256 !== 'string') continue;
        insert.run(
          r.id ?? randomUUID(),
          r.at ?? new Date().toISOString(),
          r.kind ?? 'submit',
          r.verdict ?? 'unknown',
          r.ready ? 1 : 0,
          r.flag_sha256,
          r.challenge ?? null,
          r.instance ?? null,
          r.platform ?? null,
          r.platform_status ?? null,
        );
      }
      return true;
    });
  }

  function claimSubmissionAttempt({
    id = randomUUID(),
    flag_sha256,
    platform,
    challenge,
    instance,
    at = new Date().toISOString(),
    retry_unknown = false,
  }) {
    return runImmediate(db => {
      const rows = db.prepare(
        'SELECT id, kind, verdict, flag_sha256, platform, challenge, instance, platform_status FROM submission_receipts ORDER BY seq ASC',
      ).all();
      const scope = { platform, challenge, instance };
      const duplicate = rows.filter(row => {
        if (row.flag_sha256 !== flag_sha256) return false;
        const isSub = row.kind === 'submit' || (row.kind == null && row.verdict !== 'checked'
          && (row.platform_status != null || ['accepted', 'duplicate', 'unknown', 'pending'].includes(row.verdict)));
        if (!isSub) return false;
        if (row.verdict === 'rejected') return false;
        if (retry_unknown && (row.verdict === 'unknown' || row.verdict === 'pending')) return false;
        return ['platform', 'challenge', 'instance'].every(k =>
          row[k] == null || scope[k] === undefined || row[k] === scope[k]);
      }).length;
      if (duplicate > 0) {
        return { claimed: false, duplicate, receipts_count: rows.length };
      }
      db.prepare(`
        INSERT INTO submission_receipts(id, at, kind, verdict, ready, flag_sha256, challenge, instance, platform, platform_status)
        VALUES(?, ?, 'submit', 'pending', 0, ?, ?, ?, ?, NULL)
      `).run(id, at, flag_sha256, challenge ?? null, instance ?? null, platform ?? null);
      return { claimed: true, id, duplicate: 0, receipts_count: rows.length + 1 };
    });
  }

  function finalizeSubmissionAttempt(id, { verdict = 'unknown', platform_status = null } = {}) {
    return runImmediate(db => {
      const ready = verdict === 'accepted' ? 1 : 0;
      const info = db.prepare(
        'UPDATE submission_receipts SET verdict = ?, ready = ?, platform_status = ? WHERE id = ?',
      ).run(verdict, ready, platform_status ?? null, id);
      return { updated: info.changes > 0, verdict, ready: Boolean(ready) };
    });
  }

  function recordCheckReceipt(entry) {
    return recordSubmissionReceipt({
      id: entry.id ?? randomUUID(),
      at: entry.at ?? new Date().toISOString(),
      kind: 'check',
      verdict: 'checked',
      ready: Boolean(entry.ready),
      flag_sha256: entry.flag_sha256,
      challenge: entry.challenge,
      instance: entry.instance,
      platform: entry.platform,
    });
  }

  // ── Graph Atomic Store (Fact/Intent + Best-of-N Race) ───────────────────────

  function readGraphRow(db) {
    const meta = db.prepare('SELECT schema_version, revision, updated_at FROM graph_meta WHERE id = 1').get()
      ?? { schema_version: 1, revision: 0, updated_at: new Date().toISOString() };
    const facts = db.prepare('SELECT * FROM graph_facts ORDER BY seq ASC').all().map(row => ({
      id: row.id,
      challenge: row.challenge,
      kind: row.kind,
      title: row.title,
      ...(row.summary ? { summary: row.summary } : {}),
      ...(row.evidence ? { evidence: row.evidence } : {}),
      ...(row.source ? { source: row.source } : {}),
      ...(row.created_by ? { created_by: row.created_by } : {}),
      ...(row.dedupe_key ? { dedupe_key: row.dedupe_key } : {}),
      ...(row.race_id ? { race_id: row.race_id } : {}),
      ...(row.branch_id ? { branch_id: row.branch_id } : {}),
      created_at: row.created_at,
    }));
    const intents = db.prepare('SELECT * FROM graph_intents ORDER BY seq ASC').all().map(row => ({
      id: row.id,
      challenge: row.challenge,
      title: row.title,
      parent_fact_ids: JSON.parse(row.parent_fact_ids_json || '[]'),
      ...(row.hypothesis ? { hypothesis: row.hypothesis } : {}),
      priority: row.priority,
      budget_minutes: row.budget_minutes,
      status: row.status,
      owner: row.owner,
      claim_lease: row.claim_lease,
      claimed_at: row.claimed_at,
      finished_at: row.finished_at,
      outcome: row.outcome,
      produced_fact_ids: JSON.parse(row.produced_fact_ids_json || '[]'),
      created_at: row.created_at,
      ...(row.race_id ? { race_id: row.race_id } : {}),
      ...(row.branch_id ? { branch_id: row.branch_id } : {}),
      ...(row.superseded_by ? { superseded_by: row.superseded_by } : {}),
    }));
    return { schema_version: meta.schema_version, revision: meta.revision, updated_at: meta.updated_at, facts, intents };
  }

  function readGraphSnapshot() {
    return runRead(readGraphRow, () => ({
      schema_version: 1,
      revision: 0,
      updated_at: new Date().toISOString(),
      facts: [],
      intents: [],
    }));
  }

  function mutateGraph(mutator, nowIso = new Date().toISOString()) {
    return runImmediate(db => {
      const graph = readGraphRow(db);
      const beforeFactIds = new Set(graph.facts.map(f => f.id));
      const beforeIntentMap = new Map(graph.intents.map(i => [i.id, JSON.stringify(i)]));
      const outcome = mutator(graph, nowIso);
      if (outcome?.skipWrite) {
        return { ...outcome.response, revision: graph.revision, recovered: false, graph };
      }
      const nextRevision = graph.revision + 1;
      db.prepare('UPDATE graph_meta SET revision = ?, updated_at = ? WHERE id = 1').run(nextRevision, nowIso);
      const insertFact = db.prepare(`
        INSERT INTO graph_facts(id, challenge, kind, title, summary, evidence, source, created_by, dedupe_key, created_at, race_id, branch_id)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const f of graph.facts) {
        if (!beforeFactIds.has(f.id)) {
          insertFact.run(
            f.id, f.challenge, f.kind, f.title, f.summary ?? null, f.evidence ?? null,
            f.source ?? null, f.created_by ?? null, f.dedupe_key ?? null, f.created_at,
            f.race_id ?? null, f.branch_id ?? null,
          );
        }
      }
      const upsertIntent = db.prepare(`
        INSERT INTO graph_intents(id, challenge, title, parent_fact_ids_json, hypothesis, priority, budget_minutes,
          status, owner, claim_lease, claimed_at, finished_at, outcome, produced_fact_ids_json, created_at, race_id, branch_id, superseded_by)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          status = excluded.status,
          owner = excluded.owner,
          claim_lease = excluded.claim_lease,
          claimed_at = excluded.claimed_at,
          finished_at = excluded.finished_at,
          outcome = excluded.outcome,
          produced_fact_ids_json = excluded.produced_fact_ids_json,
          budget_minutes = excluded.budget_minutes,
          superseded_by = excluded.superseded_by
      `);
      for (const intent of graph.intents) {
        const serialized = JSON.stringify(intent);
        if (beforeIntentMap.get(intent.id) !== serialized) {
          upsertIntent.run(
            intent.id, intent.challenge, intent.title, JSON.stringify(intent.parent_fact_ids ?? []),
            intent.hypothesis ?? null, intent.priority, intent.budget_minutes, intent.status,
            intent.owner ?? null, intent.claim_lease ?? null, intent.claimed_at ?? null,
            intent.finished_at ?? null, intent.outcome ?? null, JSON.stringify(intent.produced_fact_ids ?? []),
            intent.created_at, intent.race_id ?? null, intent.branch_id ?? null, intent.superseded_by ?? null,
          );
        }
      }
      graph.revision = nextRevision;
      graph.updated_at = nowIso;
      return { ...outcome.response, revision: nextRevision, recovered: false, graph };
    });
  }

  function importLegacyGraph(legacyGraph) {
    if (!legacyGraph || (!legacyGraph.facts?.length && !legacyGraph.intents?.length)) return;
    runImmediate(db => {
      const existing = db.prepare('SELECT COUNT(*) AS cnt FROM graph_facts').get().cnt
        + db.prepare('SELECT COUNT(*) AS cnt FROM graph_intents').get().cnt;
      if (existing > 0) return;
      db.prepare('UPDATE graph_meta SET revision = ?, updated_at = ? WHERE id = 1')
        .run(legacyGraph.revision ?? 0, legacyGraph.updated_at ?? new Date().toISOString());
      const insertFact = db.prepare(`
        INSERT OR IGNORE INTO graph_facts(id, challenge, kind, title, summary, evidence, source, created_by, dedupe_key, created_at, race_id, branch_id)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const f of legacyGraph.facts ?? []) {
        insertFact.run(
          f.id, f.challenge, f.kind, f.title, f.summary ?? null, f.evidence ?? null,
          f.source ?? null, f.created_by ?? null, f.dedupe_key ?? null, f.created_at ?? new Date().toISOString(),
          f.race_id ?? null, f.branch_id ?? null,
        );
      }
      const insertIntent = db.prepare(`
        INSERT OR IGNORE INTO graph_intents(id, challenge, title, parent_fact_ids_json, hypothesis, priority, budget_minutes,
          status, owner, claim_lease, claimed_at, finished_at, outcome, produced_fact_ids_json, created_at, race_id, branch_id, superseded_by)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const i of legacyGraph.intents ?? []) {
        insertIntent.run(
          i.id, i.challenge, i.title, JSON.stringify(i.parent_fact_ids ?? []),
          i.hypothesis ?? null, i.priority ?? 3, i.budget_minutes ?? 15, i.status ?? 'open',
          i.owner ?? null, i.claim_lease ?? null, i.claimed_at ?? null,
          i.finished_at ?? null, i.outcome ?? null, JSON.stringify(i.produced_fact_ids ?? []),
          i.created_at ?? new Date().toISOString(), i.race_id ?? null, i.branch_id ?? null, i.superseded_by ?? null,
        );
      }
    });
  }

  return {
    dbPath,
    readOnly,
    runImmediate,
    runRead,
    grantNetworkTarget,
    hasNetworkGrant,
    listNetworkGrants,
    revokeNetworkGrants,
    listInstances,
    importLegacyInstances,
    recordInstance,
    acquireInstanceLock,
    releaseInstanceLock,
    listSubmissionReceipts,
    recordSubmissionReceipt,
    importLegacySubmissions,
    claimSubmissionAttempt,
    finalizeSubmissionAttempt,
    recordCheckReceipt,
    readGraphSnapshot,
    mutateGraph,
    importLegacyGraph,
  };
}
