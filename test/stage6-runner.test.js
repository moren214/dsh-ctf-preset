import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { startRunnerHttpServer } from '../runner/http-server.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CLI_PATH = join(ROOT, 'runner', 'cli.js');

function runCli(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI_PATH, ...args], {
      cwd: ROOT,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', c => { stdout += c.toString('utf8'); });
    child.stderr.on('data', c => { stderr += c.toString('utf8'); });
    child.once('error', reject);
    child.once('close', code => resolve({ code, stdout, stderr }));
  });
}

test('Stage 6 headless runner CLI solves offline challenge via --mock-plan and writes trace + output', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'ctf-runner-cli-'));
  try {
    await writeFile(join(cwd, 'notes.txt'), 'secret=flag{runner_cli_solved_2026}\n', 'utf8');
    const planPath = join(cwd, 'plan.json');
    const tracePath = join(cwd, 'trace.jsonl');
    const outPath = join(cwd, 'result.json');
    await writeFile(planPath, JSON.stringify([
      { tool: 'read_binary_range', args: { file_path: 'notes.txt', encoding: 'utf8' } },
      { tool: 'ctf_domain', args: { action: 'enable', domain: 'crypto' } },
      { tool: 'crypto_solver', args: { operation: 'lcg_recover', outputs: ['17', '65', '257', '1025'], modulus: '10007', predict_count: 1 } },
      { finish: { flag: 'flag{runner_cli_solved_2026}', source: 'notes.txt' } },
    ]), 'utf8');

    const res = await runCli([
      '--challenge', cwd,
      '--mock-plan', planPath,
      '--trace', tracePath,
      '--output', outPath,
    ]);
    assert.equal(res.code, 0, res.stderr || res.stdout);
    const parsed = JSON.parse(res.stdout.trim());
    assert.equal(parsed.status, 'solved');
    assert.equal(parsed.flag, 'flag{runner_cli_solved_2026}');
    assert.equal(parsed.verified, true);
    assert.ok(parsed.active_domains.includes('crypto'));

    const savedOut = JSON.parse(await readFile(outPath, 'utf8'));
    assert.equal(savedOut.flag, 'flag{runner_cli_solved_2026}');
    const traceLines = (await readFile(tracePath, 'utf8')).trim().split('\n');
    assert.equal(traceLines.length, 4);

    // Unverified flag exits with non-zero code (2)
    const badPlanPath = join(cwd, 'bad-plan.json');
    await writeFile(badPlanPath, JSON.stringify([
      { finish: { flag: 'not_a_flag', source: '' } },
    ]), 'utf8');
    const badRes = await runCli(['--challenge', cwd, '--mock-plan', badPlanPath]);
    assert.equal(badRes.code, 2);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('Stage 6 runner HTTP API exposes GET /health, POST /solve, and GET /status/:id', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'ctf-runner-http-'));
  const srv = await startRunnerHttpServer({ host: '127.0.0.1', port: 0 });
  try {
    const h = await fetch(`${srv.url}/health`);
    assert.equal(h.status, 200);
    const health = await h.json();
    assert.equal(health.ok, true);

    const s = await fetch(`${srv.url}/solve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        challenge_dir: cwd,
        mock_plan: [
          { tool: 'ctf_verify_exit', args: { flag: 'flag{http_runner_ok_2026}', source: 'solver.py' } },
        ],
      }),
    });
    assert.equal(s.status, 200);
    const solved = await s.json();
    assert.equal(solved.status, 'solved');
    assert.ok(solved.job_id);

    const st = await fetch(`${srv.url}/status/${solved.job_id}`);
    assert.equal(st.status, 200);
    const statusBody = await st.json();
    assert.equal(statusBody.status, 'solved');
  } finally {
    await srv.close();
    await rm(cwd, { recursive: true, force: true });
  }
});

test('Stage 6 Docker supply chain lockfiles and Dockerfile.agent hardenings are complete', async () => {
  const baseDf = await readFile(new URL('../docker/Dockerfile', import.meta.url), 'utf8');
  const heavyDf = await readFile(new URL('../docker/Dockerfile.heavy', import.meta.url), 'utf8');
  const agentDf = await readFile(new URL('../docker/Dockerfile.agent', import.meta.url), 'utf8');
  const reqBase = await readFile(new URL('../docker/requirements-base.txt', import.meta.url), 'utf8');
  const reqHeavy = await readFile(new URL('../docker/requirements-heavy.txt', import.meta.url), 'utf8');
  const gemLock = await readFile(new URL('../docker/Gemfile.lock', import.meta.url), 'utf8');

  assert.match(baseDf, /ARG FFUF_SHA256_ARM64=/u);
  assert.match(baseDf, /COPY requirements-base\.txt/u);
  assert.match(baseDf, /seccomp-tools:1\.7\.1\s+one_gadget:1\.10\.0\s+zsteg:0\.2\.14/u);
  assert.match(heavyDf, /COPY requirements-heavy\.txt/u);
  assert.match(agentDf, /NODE_SHA256_AMD64=/u);
  assert.match(agentDf, /NODE_SHA256_ARM64=/u);
  assert.match(agentDf, /CTF_SANDBOX_BACKEND=local/u);
  assert.match(agentDf, /USER 10001:10001/u);
  assert.match(reqBase, /pwntools==4\.15\.1/u);
  assert.match(reqHeavy, /angr==10\.0\.7/u);
  assert.match(gemLock, /seccomp-tools \(1\.7\.1\)/u);
});
