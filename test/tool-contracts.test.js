import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { apply } from '../ctf-tools.js';

function collectTools(config) {
  const tools = new Map();
  const context = {
    tools: { register(definition) { tools.set(definition.name, definition); } },
    fs: {},
    effect() {},
  };
  apply(context, config);
  return tools;
}

const coreTools = collectTools({ compact: true });
const fullTools = collectTools({ compact: true, enableExtendedAudit: true });

test('default Core Tier registers 28 slimmed tools and reduces schema size significantly', () => {
  assert.equal(coreTools.size, 28);
  assert.ok(coreTools.has('ctf_sandbox'));
  assert.ok(coreTools.has('ctf_graph'));
  assert.ok(coreTools.has('ctf_arena'));
  assert.ok(coreTools.has('ctf_domain'));
  assert.equal(coreTools.has('pwn_cyclic'), false);
  assert.equal(coreTools.has('cloud_metadata'), false);
  assert.equal(coreTools.has('verify_evidence'), false);
  assert.equal(coreTools.has('mobile_apk'), false);

  const schemaChars = JSON.stringify(
    [...coreTools.values()].map(({ name, description, parameters }) => ({ name, description, parameters })),
  ).length;
  assert.ok(schemaChars < 40000, `expected core schema < 40000 chars, got ${schemaChars}`);
});

test('enableExtendedAudit: true restores all 46 tools with full backward compatibility', () => {
  assert.equal(fullTools.size, 46);
  for (const name of ['pwn_cyclic', 'pwn_payload', 'verify_evidence', 'mobile_apk', 'cloud_metadata', 'competition_api', 'submit_check']) {
    assert.ok(fullTools.has(name), `expected ${name} in full tier`);
  }
});

for (const [name, tool] of fullTools) {
  test(`${name}: schema is declared and invalid fields return a structured error`, async () => {
    assert.equal(tool.parameters.type, 'object');
    assert.equal(typeof tool.description, 'string');
    assert.ok(tool.parameters.properties && typeof tool.parameters.properties === 'object');
    const text = await tool.execute({ __unexpected_contract_field: true }, {
      signal: new AbortController().signal,
      agent: { session: {} },
    });
    const result = JSON.parse(text);
    assert.equal(result.ok, false);
    assert.equal(typeof result.error.kind, 'string');
    assert.equal(typeof result.error.hint, 'string');
    assert.equal(text.includes('\n'), false, 'default tool results use compact JSON');
  });
}

test('ctf_progress schema stays compact while runtime still separates fields by action', async () => {
  const tool = coreTools.get('ctf_progress');
  const schema = tool.parameters;
  assert.equal(schema.oneOf, undefined, 'avoid verbose oneOf/not schema bloat');
  assert.ok(JSON.stringify(schema).length < 3600, 'ctf_progress schema should stay compact');
  const invalid = JSON.parse(await tool.execute({ action: 'load', revision: 'abc' }, {
    signal: new AbortController().signal,
    agent: { session: {} },
  }));
  assert.equal(invalid.ok, false);
  assert.equal(invalid.error.kind, 'unsupported');
});

test('package.json version, files manifest, CHANGELOG.md, and README.md stay consistent', async () => {
  const rootUrl = new URL('../', import.meta.url);
  const pkg = JSON.parse(await readFile(new URL('package.json', rootUrl), 'utf8'));
  const changelog = await readFile(new URL('CHANGELOG.md', rootUrl), 'utf8');
  const readme = await readFile(new URL('README.md', rootUrl), 'utf8');

  const topChangelogVersion = /^##\s+(\d+\.\d+\.\d+)\b/mu.exec(changelog)?.[1];
  assert.equal(topChangelogVersion, pkg.version, 'CHANGELOG.md latest heading must match package.json version');

  const minorPrefix = pkg.version.split('.').slice(0, 2).join('.') + '.x';
  assert.ok(changelog.includes(`| ${minorPrefix} |`), `CHANGELOG.md compat matrix should list ${minorPrefix}`);
  assert.ok(readme.includes(`（当前 \`${pkg.version}\`）`), `README.md should reference current version ${pkg.version}`);
  assert.ok(readme.includes(`- ${pkg.version} `), `README.md recent summary should list ${pkg.version}`);
  assert.ok(readme.includes(`${coreTools.size} 个核心实战工具`), `README.md should match core tool count (${coreTools.size})`);
  assert.ok(readme.includes(`共 ${fullTools.size} 个`), `README.md should match full tool count (${fullTools.size})`);

  const rootEntries = await readdir(rootUrl);
  const runtimeFiles = rootEntries.filter(name => /\.(?:js|py)$/u.test(name));
  for (const name of runtimeFiles) {
    assert.ok(pkg.files.includes(name), `package.json files should include ${name}`);
  }
  assert.ok(pkg.files.includes('docker/Dockerfile'));
  assert.ok(pkg.files.includes('docker/Dockerfile.heavy'));
});
