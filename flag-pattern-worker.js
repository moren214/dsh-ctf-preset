import { parentPort, workerData } from 'node:worker_threads';

try {
  parentPort.postMessage({ matches: new RegExp(workerData.pattern, 'u').test(workerData.flag) });
} catch {
  parentPort.postMessage({ invalid: true });
}
