import assert from 'node:assert/strict';
import test from 'node:test';
import { appendStatus, readStatusHistory, summarizeStatus } from '../ctf-status.js';

function memoryFiles() {
  const documents = new Map();
  return {
    documents,
    normalizeEntry: entry => entry,
    async read(name) {
      return documents.get(name) ?? { name, text: '', version: undefined };
    },
    async write(document, text) {
      const current = documents.get(document.name);
      if (document.version !== current?.version) {
        throw Object.assign(new Error('stale version'), { code: 'FS_VERSION_MISMATCH' });
      }
      documents.set(document.name, { name: document.name, text, version: (current?.version ?? 0) + 1 });
    },
  };
}

test('status append retries concurrent version conflicts without losing either entry', async () => {
  const files = memoryFiles();
  const [left, right] = await Promise.all([
    appendStatus(files, { phase: 'analysis', next_step: 'inspect binary' }),
    appendStatus(files, { phase: 'web', next_step: 'review request log' }),
  ]);
  const saved = JSON.parse(files.documents.get('.ctf-status.json').text);
  assert.equal(saved.entries.length, 2);
  assert.equal(new Set(saved.entries.map(entry => entry.record_id)).size, 2);
  assert.ok(left.entries.length >= 1);
  assert.ok(right.entries.length >= 1);
});

test('status latest copy restores history and exposes structured warnings', async () => {
  const files = memoryFiles();
  await appendStatus(files, { phase: 'analysis' });
  const current = files.documents.get('.ctf-status.json');
  assert.equal(files.documents.get('.ctf/status.saved.json').text, current.text);
  files.documents.delete('.ctf-status.json');
  const recovered = await readStatusHistory(files);
  assert.equal(recovered.recovered, true);
  assert.equal(recovered.entries.length, 1);
  assert.ok(summarizeStatus(recovered.entries).warnings.some(warning => warning.code === 'next_step_missing'));
});
