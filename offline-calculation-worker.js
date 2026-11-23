import { parentPort, workerData } from 'node:worker_threads';
import { calculateSteps } from './offline-calculation.js';

try {
  parentPort.postMessage({ report: calculateSteps(workerData) });
} catch (error) {
  parentPort.postMessage({ error: error.message });
}
