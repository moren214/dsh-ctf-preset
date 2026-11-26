import assert from 'node:assert/strict';
import { test } from 'node:test';
import { apply } from '../ctf-tools.js';
import { classifyChallengeDomain, resolveToolDomainSelection, ROUTER_DOMAINS } from '../ctf-router.js';
import { manageGraph } from '../ctf-graph.js';

function collect(config) {
  const tools = new Map();
  apply({
    tools: { register(def) { tools.set(def.name, def); } },
    fs: {},
    effect() {},
  }, config);
  const schemaChars = JSON.stringify(
    [...tools.values()].map(({ name, description, parameters }) => ({ name, description, parameters })),
  ).length;
  return { tools, schemaChars };
}

test('ctf-router: 按方向动态路由显著裁剪工具数量与 Schema 体积，且自动提升方向专精扩展工具', () => {
  const core = collect({ compact: true });
  assert.equal(core.tools.size, 27);

  const web = collect({ compact: true, toolDomain: 'web' });
  assert.ok(web.tools.has('http_request'));
  assert.ok(web.tools.has('browser_session'));
  assert.equal(web.tools.has('gdb_driver'), false);
  assert.equal(web.tools.has('read_png_pixels'), false);
  assert.equal(web.tools.has('calculate_offline'), false);
  assert.ok(web.schemaChars < core.schemaChars * 0.55, `web schema (${web.schemaChars}) should be <55% of core (${core.schemaChars})`);

  // pwn 方向自动提升 pwn_cyclic / pwn_payload，无需开启 enableExtendedAudit
  const pwn = collect({ compact: true, toolDomain: 'pwn' });
  assert.ok(pwn.tools.has('inspect_elf'));
  assert.ok(pwn.tools.has('gdb_driver'));
  assert.ok(pwn.tools.has('pwn_cyclic'));
  assert.ok(pwn.tools.has('pwn_payload'));
  assert.equal(pwn.tools.has('browser_session'), false);
  assert.equal(pwn.tools.has('stego_audio'), false);

  // mobile 方向自动提升 mobile_apk
  const mobile = collect({ compact: true, toolDomain: 'mobile' });
  assert.ok(mobile.tools.has('mobile_apk'));
  assert.ok(mobile.tools.has('rev_query'));
  assert.equal(mobile.tools.has('pcap_stream'), false);

  // 支持多方向逗号组合与别名归一化
  const combo = collect({ compact: true, toolDomain: 'reverse,cryptography' });
  assert.ok(combo.tools.has('rev_query'));
  assert.ok(combo.tools.has('crypto_solver'));
  assert.ok(combo.tools.has('calculate_offline'));
  assert.equal(combo.tools.has('browser_session'), false);

  // triage 极简起手集
  const triage = collect({ compact: true, toolDomain: 'triage' });
  assert.ok(triage.tools.size <= 10);
  assert.ok(triage.schemaChars < core.schemaChars * 0.45);

  // 非法 toolDomain 抛结构化 ToolError
  assert.throws(() => resolveToolDomainSelection({ toolDomain: 'unknown_xyz' }), err => err.kind === 'unsupported');
  assert.ok(ROUTER_DOMAINS.includes('web') && ROUTER_DOMAINS.includes('ai'));
});

test('ctf-router: 启发式方向分类覆盖 Web/Pwn/Rev/Crypto/Misc/Mobile/AI 及多标签组合', () => {
  const rWeb = classifyChallengeDomain({ category: 'Web', title: 'Flask SSTI', connection_info: 'http://10.0.0.5:8080' });
  assert.equal(rWeb.primary, 'web');
  assert.equal(rWeb.confidence, 'high');

  const rPwn = classifyChallengeDomain({ title: 'heap_note', files: ['vuln', 'libc.so.6'], connection_info: 'nc 10.0.0.5 9999' });
  assert.equal(rPwn.primary, 'pwn');
  assert.ok(rPwn.recommended_tools.includes('pwn_cyclic'));

  const rMobile = classifyChallengeDomain({ title: 'CrackMe', files: ['app-release.apk'] });
  assert.equal(rMobile.primary, 'mobile');
  assert.ok(rMobile.recommended_tools.includes('mobile_apk'));

  const rAi = classifyChallengeDomain({ title: 'Evil Model', files: ['chat.gguf'], description: 'check chat_template' });
  assert.equal(rAi.primary, 'ai');
  assert.ok(rAi.recommended_tools.includes('inspect_media'));

  const rCrypto = classifyChallengeDomain({ category: 'Crypto', title: 'RSA Wiener', files: ['task.sage'] });
  assert.equal(rCrypto.primary, 'crypto');

  const rUnknown = classifyChallengeDomain({ title: 'mystery' });
  assert.equal(rUnknown.primary, 'triage');
  assert.equal(rUnknown.confidence, 'low');
});

test('ctf_graph dispatch_plan 自动为每个子代理任务附带 recommended_domain', async () => {
  const store = {};
  const files = {
    canWrite: true,
    async read(name) { return store[name] ? { target: name, version: '1', text: store[name] } : { target: name, version: undefined, text: '' }; },
    async write(doc, body) { store[doc.target] = body; },
  };
  await manageGraph({
    action: 'add_fact',
    challenge: 'pwn-ezheap',
    title: '检测到 libc.so.6 与 nc 靶机',
    spawn_intents: [{ title: '分析堆溢出与 ret2libc', priority: 5 }],
  }, files);
  await manageGraph({
    action: 'add_fact',
    challenge: 'web-sqli',
    title: '登录接口存在 SQLi 注入点',
    spawn_intents: [{ title: '盲注提取 admin cookie', priority: 4 }],
  }, files);
  const plan = await manageGraph({ action: 'dispatch_plan', max_workers: 2 }, files);
  assert.equal(plan.assignments.length, 2);
  assert.equal(plan.assignments[0].recommended_domain, 'pwn');
  assert.equal(plan.assignments[1].recommended_domain, 'web');
});
