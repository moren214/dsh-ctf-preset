import assert from 'node:assert/strict';
import { test } from 'node:test';
import { apply } from '../ctf-tools.js';
import { classifyChallengeDomain, createDomainRouter, resolveToolDomainSelection, ROUTER_DOMAINS } from '../ctf-router.js';
import { loadSkillForDomains } from '../core/routing/skill-loader.js';
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
  assert.equal(core.tools.size, 28);

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

test('ctf-router: 双语与对抗样本分类准确率 >= 90%，支持热扩展与按域懒加载技能', async () => {
  const adversarialSuite = [
    { input: { title: 'BabySQL', description: '登录接口存在 SQL注入 与 任意文件读取，非 pwn 题目', connection_info: 'http://web.ctf.local:8080' }, expected: 'web' },
    { input: { title: 'EzStack', description: '经典栈溢出，提供 libc.so.6，没有源码', files: ['vuln.zip'], connection_info: 'nc 10.10.0.2 31337' }, expected: 'pwn' },
    { input: { title: 'TCP Note', description: '堆溢出与格式化字符串漏洞', connection_info: 'pwn.ctf.local:1337' }, expected: 'pwn' },
    { input: { title: 'VMProtect', description: '自定义虚拟机保护，请反编译并去混淆恢复算法，not web', files: ['vm.zip'] }, expected: 'rev' },
    { input: { title: 'Cloud Ops', description: 'Deploy service in Linux VM on Debian', category: 'Web', connection_info: 'https://ops.ctf.local' }, expected: 'web' },
    { input: { title: 'Lattice Break', description: '格密码 LLL / BKZ 还原私钥，打包在附件里', files: ['challenge.tar.gz'] }, expected: 'crypto' },
    { input: { title: '古典迷宫', description: '已知非对称加密模数和密文，求明文', files: ['pub.pem', 'cipher.enc'] }, expected: 'crypto' },
    { input: { title: 'Traffic Hunt', description: 'Wireshark 流量分析与频谱隐写', files: ['cap.pcapng', 'secret.wav'] }, expected: 'misc' },
    { input: { title: 'BadWeights', description: '大模型智能体越狱与提示词注入挑战，不是web题', connection_info: 'http://llm.ctf.local:9000' }, expected: 'ai' },
    { input: { title: 'RagBot', description: 'Chatbot with RAG knowledge base and prompt leak', descriptionExtra: '' }, expected: 'ai' },
    { input: { title: 'DroidSign', description: '安卓逆向，需要检查 APK 签名校验与原生层 so', files: ['target.apk'] }, expected: 'mobile' },
    { input: { title: 'HeaderElf', file_headers: [{ name: 'mystery', header_hex: '7f454c4602010100' }], description: '逆向分析程序逻辑' }, expected: 'rev' },
    { input: { title: 'HeaderModel', file_headers: [{ name: 'blob', header_hex: '4747554603000000' }], description: 'inspect metadata' }, expected: 'ai' },
    { input: { title: 'HeaderDex', file_headers: [{ name: 'classes', header_hex: '6465780a30333500' }] }, expected: 'mobile' },
    { input: { title: 'NotWebCrypto', description: '这不是 web 题，是 RSA 同余签名伪造' }, expected: 'crypto' },
    { input: { title: 'MemForensics', description: '内存取证与磁盘取证找 flag' }, expected: 'misc' },
  ];

  let hits = 0;
  for (const tc of adversarialSuite) {
    const res = classifyChallengeDomain(tc.input);
    if (res.primary === tc.expected) hits += 1;
  }
  const accuracy = hits / adversarialSuite.length;
  assert.ok(accuracy >= 0.9, `expected >= 90% accuracy on bilingual+adversarial suite, got ${(accuracy * 100).toFixed(1)}% (${hits}/${adversarialSuite.length})`);

  // Runtime domain router hot-expansion
  const router = createDomainRouter({ initialDomain: 'triage' });
  assert.deepEqual(router.activeDomains(), ['triage']);
  assert.equal(router.isToolAllowed('inspect_elf'), false);
  const expanded = router.enableDomain('rev');
  assert.ok(expanded.added_domains.includes('rev'));
  assert.ok(expanded.added_tools.includes('inspect_elf'));
  assert.equal(router.isToolAllowed('inspect_elf'), true);
  assert.equal(router.isToolAllowed('browser_session'), false);

  // Lazy per-domain skill loading (< 8 KB per single domain + core)
  const aiSkill = loadSkillForDomains(['ai']);
  assert.ok(aiSkill.byte_length > 500 && aiSkill.byte_length < 8192, `expected AI+core skill < 8192 bytes, got ${aiSkill.byte_length}`);
  assert.match(aiSkill.text, /CTF Core Runtime Rules/u);
  assert.match(aiSkill.text, /inspect_media/u);

  // Live Cordis ctf_domain hot-expansion starting from triage
  const regTools = new Map();
  const { execution: _e } = (() => ({ execution: { signal: new AbortController().signal, agent: { session: { id: 'rtest' } } } }))();
  apply({
    tools: { register(def) { regTools.set(def.name, def); } },
    effect() {},
    emit() {},
    workingDirectory: { async ensure() { return process.cwd(); } },
    sandboxPolicy: { resolve() { return { mode: 'read-only' }; } },
    fs: {
      async resolve(name) { return { targetKey: name, displayPath: name }; },
      contains() { return true; },
      async lstat() { return undefined; },
      async stat() { return null; },
      async readBytes() { return Buffer.alloc(0); },
    },
  }, { toolDomain: 'triage' });
  assert.equal(regTools.has('ctf_domain'), true);
  assert.equal(regTools.has('pwn_cyclic'), false);
  const expandOut = JSON.parse(await regTools.get('ctf_domain').execute({ action: 'enable', domain: 'pwn' }, _e));
  assert.equal(expandOut.status, 'ok');
  assert.ok(expandOut.registered_tools.includes('pwn_cyclic'));
  assert.equal(regTools.has('pwn_cyclic'), true);
  assert.equal(regTools.has('gdb_driver'), true);
});
