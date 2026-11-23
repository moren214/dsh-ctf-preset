import assert from 'node:assert/strict';
import { test } from 'node:test';
import { apply } from '../ctf-tools.js';

const tools = new Map();
const context = {
  tools: { register(definition) { tools.set(definition.name, definition); } },
  fs: {},
  effect() {},
};
apply(context, { compact: true });

for (const [name, tool] of tools) {
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

test('ctf_progress schema separates fields by action', () => {
  const schema = tools.get('ctf_progress').parameters;
  assert.equal(schema.oneOf.length, 7);
  assert.ok(schema.oneOf.some(variant => variant.properties.action.const === 'save'));
  assert.ok(schema.oneOf.some(variant => variant.properties.action.const === 'repair'));
});
