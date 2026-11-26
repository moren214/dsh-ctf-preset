// Compatibility facade: Cordis host entrypoints moved to dsh-adapter/* and runtime to core/*.
export { apply, Config, inject, name } from './dsh-adapter/apply.js';
export { pathParts } from './dsh-adapter/filesystem.js';
export { extractInstanceTargets } from './dsh-adapter/register-tools.js';
