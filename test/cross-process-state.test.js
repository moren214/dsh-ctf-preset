import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createArtifactStore } from '../core/artifacts/artifact-store.js';
import { createStateStore } from '../core/state/state-store.js';
import { manageGraphInStore } from '../ctf-graph.js';
import { createNetworkBoundary } from '../network-boundary.js';
import { handleSubmission } from '../submission.js';

const ROOT_URL = new URL('..', import.meta.url);
const RESULT_HASH = /^[a-f0-9]{64}$/u;

function runWorker(cwd, workerId, scriptPath, artifactId, expectedHash) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [scriptPath, cwd, String(workerId), artifactId, expectedHash], {
      cwd: fileURLToPath(ROOT_URL),
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk.toString('utf8'); });
    child.stderr.on('data', chunk => { stderr += chunk.toString('utf8'); });
    child.once('error', reject);
    child.once('close', code => {
      if (code !== 0) {
        return reject(new Error(`worker ${workerId} exited ${code}: ${stderr || stdout}`));
      }
      try {
        resolve(JSON.parse(stdout.trim()));
      } catch (err) {
        reject(new Error(`worker ${workerId} bad JSON (${stdout}): ${err.message}`));
      }
    });
  });
}

test('8 OS processes contend safely on SQLite StateStore (graph, locks, network_grants, ArtifactStore)', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'ctf-xproc-8-'));
  const scriptPath = join(cwd, 'worker.mjs');
  try {
    const store = createStateStore(cwd);
    const artifacts = createArtifactStore(cwd, { stateStore: store });
    const boundary = createNetworkBoundary({ allowLoopbackDynamic: false }, { stateStoreForWorkspace: dir => createStateStore(dir) });

    // Parent grants one HTTP origin and one TCP target in shared workspace.
    const parentSession = { id: 'parent-coordinator' };
    const parentScope = { session: parentSession, workspaceKey: cwd, leaseId: 'lease-shared' };
    assert.equal(boundary.grantHttp('http://10.99.88.77:31337/chal', parentScope), 'http://10.99.88.77:31337');
    assert.equal(boundary.grantTcp('10.99.88.77', 1337, parentScope), '10.99.88.77:1337');

    // Verify in-process isolation for another session in the SAME runtime still holds!
    const otherLocalScope = { session: { id: 'other-local-session' }, workspaceKey: cwd };
    assert.equal(boundary.isHttpAuthorized('http://10.99.88.77:31337/chal', otherLocalScope), false);

    // Parent creates 4 shared intents in StateStore and 1 shared artifact.
    for (let i = 1; i <= 4; i++) {
      await manageGraphInStore({ action: 'add_intent', challenge: 'shared-chall', title: `intent-${i}`, priority: 5 - i }, store);
    }
    const payload = Buffer.from('CROSS_PROCESS_SHARED_ARTIFACT_PAYLOAD_2026');
    const expectedHash = createHash('sha256').update(payload).digest('hex');
    const artifactId = createHash('sha256').update('shared-result-id').digest('hex');
    artifacts.putArtifact({ resultId: artifactId, tool: 'xproc_fixture', bytes: payload });

    const workerScript = `
import { createHash } from 'node:crypto';
import { createStateStore } from ${JSON.stringify(new URL('../core/state/state-store.js', import.meta.url).href)};
import { createArtifactStore } from ${JSON.stringify(new URL('../core/artifacts/artifact-store.js', import.meta.url).href)};
import { manageGraphInStore } from ${JSON.stringify(new URL('../ctf-graph.js', import.meta.url).href)};
import { createNetworkBoundary } from ${JSON.stringify(new URL('../network-boundary.js', import.meta.url).href)};

const [cwd, workerId, artifactId, expectedHash] = process.argv.slice(2);
const store = createStateStore(cwd);
const artifacts = createArtifactStore(cwd, { stateStore: store });
const boundary = createNetworkBoundary({}, { stateStoreForWorkspace: dir => createStateStore(dir) });
const scope = { session: { id: 'child-' + workerId }, workspaceKey: cwd };

const httpOk = boundary.isHttpAuthorized('http://10.99.88.77:31337/api', scope);
const tcpOk = boundary.isTcpAuthorized('10.99.88.77', 1337, scope);

const addedFacts = [];
for (let j = 0; j < 3; j++) {
  const res = await manageGraphInStore({
    action: 'add_fact',
    challenge: 'xproc-chall',
    kind: 'recon',
    title: 'fact-w' + workerId + '-' + j,
    dedupe_key: 'w' + workerId + '-' + j,
  }, store, { defaultOwner: 'worker-' + workerId });
  addedFacts.push(res.fact.id);
}

const claimedIds = [];
for (let k = 0; k < 4; k++) {
  const res = await manageGraphInStore({
    action: 'claim_intent',
    challenge: 'shared-chall',
    next: true,
    owner: 'worker-' + workerId,
  }, store);
  if (res.status === 'claimed') claimedIds.push(res.intent.id);
}

const lockAcquired = store.acquireInstanceLock('plat:shared-inst', 'worker-' + workerId, 15000);
const blob = artifacts.getArtifactBytes(artifactId);
const actualHash = blob ? createHash('sha256').update(blob.bytes).digest('hex') : null;

const { handleSubmission } = await import(${JSON.stringify(new URL('../submission.js', import.meta.url).href)});
let httpSent = 0;
const subRes = await handleSubmission(
  { flag: 'flag{xproc_atomic_submit_2026}', source: 'xproc-worker-' + workerId, challenge: 'xproc-chall' },
  {
    async read() { return { receipts: store.listSubmissionReceipts(), document: { text: '' }, corruptedLines: 0 }; },
    claimSubmissionAttempt: attempt => store.claimSubmissionAttempt(attempt),
    finalizeSubmissionAttempt: (id, outcome) => store.finalizeSubmissionAttempt(id, outcome),
  },
  async () => {
    httpSent += 1;
    return { status: 200, body: JSON.stringify({ verdict: 'accepted', correct: true }) };
  },
  'https://ctf.local',
);

console.log(JSON.stringify({
  workerId,
  httpOk,
  tcpOk,
  addedCount: addedFacts.length,
  claimedIds,
  lockAcquired,
  artifactHashOk: actualHash === expectedHash,
  subVerdict: subRes.verdict,
  httpSent,
}));
`;
    await writeFile(scriptPath, workerScript, 'utf8');

    const results = await Promise.all(
      Array.from({ length: 8 }, (_, idx) => runWorker(cwd, idx + 1, scriptPath, artifactId, expectedHash)),
    );

    // Every child process saw cross-process HTTP/TCP grants & verified shared artifact hash.
    for (const r of results) {
      assert.equal(r.httpOk, true, `worker ${r.workerId} missed HTTP grant`);
      assert.equal(r.tcpOk, true, `worker ${r.workerId} missed TCP grant`);
      assert.equal(r.addedCount, 3);
      assert.equal(r.artifactHashOk, true);
    }

    // Instance lock acquired by strictly 1 of 8 processes.
    const lockWinners = results.filter(r => r.lockAcquired);
    assert.equal(lockWinners.length, 1, `expected 1 lock winner, got ${lockWinners.length}`);

    // Authoritative SQLite submission ledger: strictly 1 of 8 processes calls submit(), 7 get rejected_local.
    assert.equal(results.reduce((sum, r) => sum + r.httpSent, 0), 1);
    assert.equal(results.filter(r => r.subVerdict === 'accepted').length, 1);
    assert.equal(results.filter(r => r.subVerdict === 'rejected_local').length, 7);
    const receipts = store.listSubmissionReceipts();
    assert.equal(receipts.length, 1);
    assert.equal(receipts[0].verdict, 'accepted');

    // All 4 shared intents claimed by strictly 1 owner each, no duplicates across 8 processes.
    const allClaimed = results.flatMap(r => r.claimedIds);
    assert.equal(allClaimed.length, 4, `expected 4 total claims, got ${allClaimed.length}`);
    assert.equal(new Set(allClaimed).size, 4);

    // All 24 facts persisted cleanly without loss.
    const snap = store.readGraphSnapshot();
    const xprocFacts = snap.facts.filter(f => f.challenge === 'xproc-chall');
    assert.equal(xprocFacts.length, 24);

    // Best-of-N race creation and winner-takes-all sibling cancellation.
    const race = await manageGraphInStore({
      action: 'start_race',
      challenge: 'pwn-race',
      race_id: 'race-bof-1',
      branches: [
        { branch_id: 'ret2libc', title: 'Try ret2libc', priority: 5 },
        { branch_id: 'one-gadget', title: 'Try one_gadget', priority: 4 },
        { branch_id: 'dlresolve', title: 'Try ret2dlresolve', priority: 3 },
      ],
    }, store);
    assert.equal(race.status, 'ok');
    assert.equal(race.intents.length, 3);
    const winnerId = race.intents[0].id;
    const cancelRes = await manageGraphInStore({
      action: 'cancel_race_siblings',
      race_id: 'race-bof-1',
      winner_intent_id: winnerId,
    }, store);
    assert.equal(cancelRes.cancelled_ids.length, 2);
    assert.ok(!cancelRes.cancelled_ids.includes(winnerId));
    const afterRace = store.readGraphSnapshot().intents.filter(i => i.race_id === 'race-bof-1');
    assert.equal(afterRace.filter(i => i.status === 'dead' && i.superseded_by === winnerId).length, 2);
  } finally {
    await rm(cwd, { recursive: true, force: true, maxRetries: 10, retryDelay: 60 });
  }
});
