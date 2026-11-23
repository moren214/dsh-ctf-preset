import test from 'node:test';
import assert from 'node:assert/strict';
import { manageProgress } from '../ctf-progress.js';

function workspace() {
  const documents = new Map();
  return {
    cwd: '/work/challenge',
    sessionId: 'session-alpha',
    normalizePath: path => path.split(/[\\/]/u).filter(Boolean).join('/'),
    async readDocument(name) {
      const stored = documents.get(name);
      if (!stored) return { name, target: { targetKey: name, displayPath: name }, text: '', version: undefined };
      return { ...stored };
    },
    async writeDocument(document, content) {
      const version = (documents.get(document.name)?.version ?? 0) + 1;
      documents.set(document.name, { name: document.name, target: document.target, text: content, version });
      return { version };
    },
    async readEvidence() { return null; },
    readResult() { return undefined; },
    listResults() { return []; },
  };
}

const emptyProgress = { confirmed: [], ruled_out: [], pending: [] };

test('save 同时写 .ctf/state.json 与 notes.md 托管块', async () => {
  const files = workspace();
  const saved = await manageProgress({ action: 'save', revision: 'absent', progress: emptyProgress }, files);
  assert.equal(saved.status, 'saved');
  assert.equal(saved.state_file, '.ctf/state.json');
  assert.match(saved.state_sha256, /^[a-f0-9]{64}$/u);
  const state = await files.readDocument('.ctf/state.json');
  assert.equal(state.version, 1);
  assert.match(state.text, /"version": 2/u);
  const notes = await files.readDocument('notes.md');
  assert.match(notes.text, /machine: \.ctf\/state\.json sha256:[a-f0-9]{64}/u);
  assert.match(notes.text, /## CTF 续接记录/u);
});

test('load 能读回结论并在换会话时提示', async () => {
  const files = workspace();
  await manageProgress({
    action: 'save', revision: 'absent',
    progress: { confirmed: [], ruled_out: ['排除静态链接'], pending: ['待验证 sandbox'] },
  }, files);
  const loaded = await manageProgress({ action: 'load' }, files);
  assert.equal(loaded.status, 'loaded');
  assert.deepEqual(loaded.progress.pending, ['待验证 sandbox']);
  assert.equal(loaded.progress.ruled_out[0], '排除静态链接');
  files.sessionId = 'session-beta';
  const warned = await manageProgress({ action: 'load' }, files);
  assert.match(warned.warning, /另一个会话/u);
});

test('repair 在内容未变时不改写文件', async () => {
  const files = workspace();
  await manageProgress({ action: 'save', revision: 'absent', progress: emptyProgress }, files);
  const loaded = await manageProgress({ action: 'load' }, files);
  const repaired = await manageProgress({ action: 'repair', revision: loaded.revision }, files);
  assert.equal(repaired.status, 'unchanged');
});

test('save 的 revision 过期时拒绝写入', async () => {
  const files = workspace();
  await manageProgress({ action: 'save', revision: 'absent', progress: emptyProgress }, files);
  await assert.rejects(
    manageProgress({ action: 'save', revision: 'f'.repeat(64), progress: emptyProgress }, files),
    /已被更新/u,
  );
});
