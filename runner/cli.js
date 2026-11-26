#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startRunnerHttpServer } from './http-server.js';
import { runAutonomousSolver } from './solver-loop.js';

export function parseCliArgs(argv) {
  const opts = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') opts.help = true;
    else if (arg === '--server') opts.server = true;
    else if (arg === '--challenge' && argv[i + 1]) opts.challenge = argv[++i];
    else if (arg === '--prompt' && argv[i + 1]) opts.prompt = argv[++i];
    else if (arg === '--output' && argv[i + 1]) opts.output = argv[++i];
    else if (arg === '--model' && argv[i + 1]) opts.model = argv[++i];
    else if (arg === '--base-url' && argv[i + 1]) opts.baseUrl = argv[++i];
    else if (arg === '--budget-steps' && argv[i + 1]) opts.maxSteps = Number(argv[++i]);
    else if (arg === '--timeout-ms' && argv[i + 1]) opts.timeoutMs = Number(argv[++i]);
    else if (arg === '--mock-plan' && argv[i + 1]) opts.mockPlanPath = argv[++i];
    else if (arg === '--trace' && argv[i + 1]) opts.tracePath = argv[++i];
    else if (arg === '--port' && argv[i + 1]) opts.port = Number(argv[++i]);
    else if (arg === '--host' && argv[i + 1]) opts.host = argv[++i];
  }
  return opts;
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseCliArgs(argv);
  if (opts.help) {
    process.stdout.write('Usage: ctf-agent [--challenge DIR] [--prompt TEXT] [--output FILE] [--mock-plan FILE] [--server --port 8080]\n');
    return 0;
  }
  if (opts.server) {
    const srv = await startRunnerHttpServer({ host: opts.host ?? '0.0.0.0', port: opts.port ?? 8080 });
    process.stdout.write(JSON.stringify({ status: 'listening', url: srv.url }) + '\n');
    return 0;
  }
  const mockPlan = opts.mockPlanPath
    ? JSON.parse(await readFile(resolve(opts.mockPlanPath), 'utf8'))
    : undefined;
  const result = await runAutonomousSolver({
    challengeDir: opts.challenge ?? process.env.CTF_CHALLENGE_DIR ?? process.cwd(),
    prompt: opts.prompt,
    model: opts.model,
    baseUrl: opts.baseUrl,
    maxSteps: Number.isFinite(opts.maxSteps) ? opts.maxSteps : 24,
    timeoutMs: Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : 180_000,
    mockPlan,
    tracePath: opts.tracePath,
    outputPath: opts.output,
  });
  process.stdout.write(JSON.stringify(result) + '\n');
  return result.exit_code ?? (result.status === 'solved' ? 0 : 2);
}

const isEntrypoint = (() => {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1]);
  } catch {
    return false;
  }
})();

if (isEntrypoint) {
  const code = await main();
  if (code !== 0) process.exitCode = code;
}
