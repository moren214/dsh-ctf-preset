import { existsSync } from 'node:fs';
import path from 'node:path';
import { createToolResults } from '../../ctf-result-values.js';
import { createNetworkBoundary } from '../../network-boundary.js';
import { createCalculationRunner } from '../../offline-calculation-runner.js';
import { createWorkbenchEnvironment } from '../../workbench-config.js';
import { createArtifactStore } from '../artifacts/artifact-store.js';
import { createGdbSessionManager } from '../sandbox/gdb-session.js';
import { createSandboxPool } from '../sandbox/sandbox-pool.js';
import { createStateStore } from '../state/state-store.js';

/**
 * Create an isolated CTF Core Runtime instance holding all runtime state
 * (StateStore, ArtifactStore, NetworkBoundary, SandboxPool, GDB sessions, etc.)
 * without any Cordis coupling or module-level singletons.
 */
export function createCtfRuntime({ config = {}, readOnly = false } = {}) {
  const workbench = createWorkbenchEnvironment(typeof config === 'function' ? {} : (config ?? {}));
  const getConfig = typeof config === 'function' ? config : () => workbench.presetConfig();
  const stateStores = new Map();
  const artifactStores = new Map();
  const detectCache = new Map();
  const calculationRunner = createCalculationRunner();
  const results = createToolResults();
  const sandboxPool = createSandboxPool();
  const gdbSessions = createGdbSessionManager();
  const patternWorkers = new Set();
  const cookieJars = new WeakMap();
  const tcpSessions = new WeakMap();
  const tcpManagers = new Set();
  const browserSessions = new WeakMap();
  const browsers = new Set();
  const instanceTransitions = new Set();

  function getStateStore(cwd, { readOnly: ro = readOnly } = {}) {
    if (typeof cwd !== 'string' || !cwd) return undefined;
    if (!path.isAbsolute(cwd) || !existsSync(cwd)) return undefined;
    const key = `${cwd}:${ro ? 'ro' : 'rw'}`;
    let store = stateStores.get(key);
    if (!store) {
      store = createStateStore(cwd, { readOnly: ro });
      stateStores.set(key, store);
    }
    return store;
  }

  function getArtifactStore(cwd, { readOnly: ro = readOnly } = {}) {
    if (typeof cwd !== 'string' || !cwd) return undefined;
    if (!path.isAbsolute(cwd) || !existsSync(cwd)) return undefined;
    const key = `${cwd}:${ro ? 'ro' : 'rw'}`;
    let store = artifactStores.get(key);
    if (!store) {
      const stateStore = getStateStore(cwd, { readOnly: ro });
      store = createArtifactStore(cwd, { readOnly: ro, stateStore });
      artifactStores.set(key, store);
    }
    return store;
  }

  const networkBoundary = createNetworkBoundary(getConfig, {
    stateStoreForWorkspace: (workspaceKey, ro) => getStateStore(workspaceKey, { readOnly: Boolean(ro) }),
  });

  async function dispose() {
    calculationRunner.dispose?.();
    await Promise.allSettled([...patternWorkers].map(w => w.terminate?.()));
    patternWorkers.clear();
    await gdbSessions.disposeAll?.().catch(() => {});
    await sandboxPool.disposeAll?.().catch(() => {});
    await Promise.allSettled([...browsers].map(browser => (browser.close ? browser.close() : browser.dispose?.())));
    browsers.clear();
    for (const manager of tcpManagers) (manager.dispose ? manager.dispose() : manager.clear?.());
    tcpManagers.clear();
    detectCache.clear();
    stateStores.clear();
    artifactStores.clear();
  }

  return {
    getConfig,
    readOnly,
    workbench,
    getStateStore,
    getArtifactStore,
    networkBoundary,
    sandboxPool,
    gdbSessions,
    patternWorkers,
    detectCache,
    calculationRunner,
    results,
    cookieJars,
    tcpSessions,
    tcpManagers,
    browserSessions,
    browsers,
    instanceTransitions,
    dispose,
  };
}
