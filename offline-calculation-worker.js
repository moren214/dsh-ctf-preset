import { parentPort, workerData } from 'node:worker_threads';
import { calculateSteps } from './offline-calculation.js';

try {
  const { steps, resolvedInputs, candidates, completed, trackProgress } = workerData;
  const onStep = trackProgress ? step => parentPort.postMessage({ step }) : undefined;
  parentPort.postMessage({ report: calculateSteps(steps, resolvedInputs, { completed, onStep, candidates }) });
} catch (error) {
  parentPort.postMessage({ error: error.message });
}
