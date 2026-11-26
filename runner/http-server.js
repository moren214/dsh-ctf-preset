import { randomUUID } from 'node:crypto';
import http from 'node:http';
import { runAutonomousSolver } from './solver-loop.js';

const MAX_BODY_BYTES = 1024 * 1024;

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', c => {
      total += c.length;
      if (total > MAX_BODY_BYTES) {
        req.destroy();
        reject({ statusCode: 413, message: 'Body too large' });
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      } catch {
        reject({ statusCode: 400, message: 'Invalid JSON' });
      }
    });
    req.on('error', reject);
  });
}

/**
 * Lightweight HTTP API wrapper around runAutonomousSolver for competition containers.
 */
export function startRunnerHttpServer({ host = '127.0.0.1', port = 0, maxConcurrent = 4, verifyFlag } = {}) {
  const jobs = new Map();
  let activeJobs = 0;

  const server = http.createServer(async (req, res) => {
    const urlPath = (req.url ?? '/').split('?')[0];
    const send = (status, body) => {
      res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(body));
    };

    if (req.method === 'GET' && urlPath === '/health') {
      return send(200, { ok: true, service: 'ctf-agent-runner', version: '1.0.0', active_jobs: activeJobs });
    }

    if (req.method === 'GET' && urlPath.startsWith('/status/')) {
      const jobId = urlPath.slice('/status/'.length);
      const job = jobs.get(jobId);
      if (!job) return send(404, { ok: false, error: 'job_not_found' });
      return send(200, job);
    }

    if (req.method === 'POST' && urlPath === '/solve') {
      if (activeJobs >= maxConcurrent) {
        return send(429, { ok: false, error: 'too_many_concurrent_jobs' });
      }
      let payload;
      try {
        payload = await readJsonBody(req);
      } catch (err) {
        return send(err.statusCode ?? 400, { ok: false, error: err.message });
      }
      const jobId = randomUUID();
      activeJobs += 1;
      const jobState = { job_id: jobId, status: 'running', started_at: new Date().toISOString() };
      jobs.set(jobId, jobState);
      try {
        const result = await runAutonomousSolver({
          challengeDir: payload.challenge_dir ?? payload.challengeDir ?? process.env.CTF_CHALLENGE_DIR ?? '/work',
          prompt: payload.prompt,
          model: payload.model,
          baseUrl: payload.base_url ?? payload.baseUrl,
          apiKey: payload.api_key ?? payload.apiKey,
          maxSteps: payload.max_steps,
          timeoutMs: payload.timeout_ms,
          mockPlan: payload.mock_plan,
          verifyFlag,
        });
        jobs.set(jobId, { job_id: jobId, ...result });
        return send(result.exit_code === 0 ? 200 : 422, { job_id: jobId, ...result });
      } finally {
        activeJobs = Math.max(0, activeJobs - 1);
      }
    }

    return send(404, { ok: false, error: 'not_found' });
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      const addr = server.address();
      resolve({
        server,
        host: addr.address,
        port: addr.port,
        url: `http://${addr.address}:${addr.port}`,
        close: () => new Promise(done => server.close(() => done())),
      });
    });
  });
}
