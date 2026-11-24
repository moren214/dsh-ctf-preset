import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import { experimentRequestHash } from '../experiment-input.js';
import { calculateSteps } from '../offline-calculation.js';
import { createCalculationRunner } from '../offline-calculation-runner.js';

test('真实计算线程核对已知种子、候选分支和固定 SHA-256 向量', async t => {
  const runner = createCalculationRunner();
  t.after(() => runner.dispose());
  const lcg = { operation: 'lcg_replay', start_index: 0, count: 5, expected: '["5","0","1","4","13"]' };
  const report = await runner.run([
    { ...lcg, inputs: ['5', '3', '1', '8'] },
    { ...lcg, inputs: ['5', '3', '1', '16'] },
    { operation: 'hash', inputs: ['abc'], algorithm: 'sha256',
      expected: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' },
    { ...lcg, inputs: ['5', '3', '1', '1'] },
  ], undefined, undefined, { candidates: [
    { label: 'A', checkpoints: [2, 3] },
    { label: 'B', checkpoints: [1, 3] },
    { label: 'C', checkpoints: [4] },
  ] });
  assert.deepEqual(report.steps.map(step => step.status === 'computed' ? step.result : step.status), [
    '["5","0","1","4","5"]', '["5","0","1","4","13"]',
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'error',
  ]);
  assert.deepEqual(report.candidates, [
    { label: 'A', status: 'match' },
    { label: 'B', status: 'mismatch', first_mismatch: 1 },
    { label: 'C', status: 'incomplete', first_unverified: 4 },
  ]);
});

test('LCG 使用大整数、支持已知负增量，并验证参数与候选检查点', () => {
  const lcg = { operation: 'lcg_replay', inputs: ['9007199254740993', '1', '-1', '9007199254740999'], start_index: 2, count: 2 };
  assert.equal(calculateSteps([lcg]).steps[0].result, '["9007199254740991","9007199254740990"]');
  assert.throws(() => calculateSteps([{ ...lcg, count: 33 }]), /起始下标/u);
  assert.throws(() => calculateSteps([lcg], [], { candidates: [{ label: 'A', checkpoints: [1] }] }), /expected/u);
});

test('长字节串按端序往返并检查零、溢出和长度上限', () => {
  const bytes = Buffer.from('8100' + 'a5'.repeat(1021) + '00', 'hex');
  const report = calculateSteps([
    { operation: 'bytes_to_integer', inputs: [bytes.toString('base64url')], from_encoding: 'base64url', byte_order: 'little' },
    { operation: 'integer_to_bytes', inputs: [{ step: 1 }], byte_order: 'little', byte_length: 1024 },
    { operation: 'integer_to_bytes', inputs: ['0'], byte_order: 'big' },
    { operation: 'integer_to_bytes', inputs: ['256'], byte_order: 'little', byte_length: 1 },
    { operation: 'integer_to_bytes', inputs: ['-1'], byte_order: 'big' },
    { operation: 'bytes_to_integer', inputs: ['ff'.repeat(1025)], byte_order: 'big' },
  ]);
  assert.equal(report.steps[0].byte_length, 1024);
  assert.equal(report.steps[1].result, bytes.toString('hex'));
  assert.equal(report.steps[2].result, '00');
  assert.match(report.steps[3].reason, /至少需要 2 字节/u);
  assert.match(report.steps[4].reason, /非负/u);
  assert.match(report.steps[5].reason, /1024 字节/u);
});

test('模逆不存在时给出公因数，同余核对返回非负余数', () => {
  const report = calculateSteps([
    { operation: 'modular_inverse', inputs: ['14', '21'] },
    { operation: 'modular_inverse', inputs: ['-3', '11'], expected: '7' },
    { operation: 'check_congruence', inputs: ['-3', '19', '11'], expected: 'true' },
  ]);
  assert.equal(report.steps[0].status, 'error');
  assert.equal(report.steps[0].gcd, '7');
  assert.equal(report.steps[0].result, undefined);
  assert.equal(report.steps[1].result, '7');
  assert.equal(report.steps[1].product_remainder, '1');
  assert.equal(report.steps[2].left_remainder, '8');
  assert.equal(report.steps[2].right_remainder, '8');
  const source = { result_id: 'a'.repeat(64), encoding: 'base64' };
  assert.throws(() => calculateSteps([
    { operation: 'bytes_to_integer', inputs: [source], byte_order: 'big', from_encoding: 'hex' },
  ]), /encoding 须与 from_encoding 一致/u);
  assert.throws(() => calculateSteps([
    { operation: 'modular_inverse', inputs: [source, '17'] },
  ]), /须使用前序结果/u);
});

test('超时后仅从下一步续算，并核对会话、参数和完整附件内容', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const payload = '界'.repeat(1800);
  const steps = [
    { operation: 'encode', inputs: [{ result_id: 'a'.repeat(64) }], scheme: 'url' },
    { operation: 'decode', inputs: [{ step: 1 }], scheme: 'url', expected: payload },
  ];
  const candidates = [{ label: '往返', checkpoints: [2] }];
  const executed = [];
  const session = {};
  const simulatedInterrupt = new Error('synthetic worker interruption');
  const runner = createCalculationRunner({
    budgetMs: 30,
    createWorker({ steps: plan, resolvedInputs, ...options }) {
      const worker = new EventEmitter();
      worker.terminate = async () => {};
      queueMicrotask(() => {
        const interrupt = options.completed.length === 0;
        try {
          const report = calculateSteps(plan, resolvedInputs, {
            ...options,
            onStep(step) {
              executed.push(step.step);
              worker.emit('message', { step });
              if (interrupt) throw simulatedInterrupt;
            },
          });
          worker.emit('message', { report });
        } catch (error) {
          if (error !== simulatedInterrupt) worker.emit('error', error);
        }
      });
      return worker;
    },
  });
  t.after(() => runner.dispose());
  const scope = { session, directoryKey: 'challenge-1', candidates };
  const pending = runner.run(steps, undefined, [payload], scope);
  await Promise.resolve();
  t.mock.timers.tick(30);
  const partial = await pending;
  assert.equal(partial.status, 'timeout');
  assert.equal(partial.completed_steps, 1);
  assert.equal(partial.next_step, 2);
  assert.equal(partial.steps[0].result.length, 4096);
  assert.deepEqual(partial.candidates, [{ label: '往返', status: 'incomplete', first_unverified: 2 }]);
  assert.match(partial.resume_id, /^[a-f0-9]{32}$/u);

  const resume = { ...scope, resumeId: partial.resume_id };
  await assert.rejects(runner.run(steps, undefined, [payload], { ...resume, session: {} }), /失效/u);
  await assert.rejects(runner.run(steps, undefined, [payload], { ...resume, directoryKey: 'challenge-2' }), /失效/u);
  await assert.rejects(runner.run(steps, undefined, [payload + '!'], resume), /失效/u);
  await assert.rejects(runner.run(steps, undefined, [payload], { ...resume, candidates: [] }), /失效/u);
  const reorderedSteps = steps.map(step => Object.fromEntries(Object.entries(step).reverse()));
  const final = await runner.run(reorderedSteps, undefined, [payload], resume);
  assert.deepEqual(executed, [1, 2]);
  assert.equal(final.steps[1].result, payload);
  assert.deepEqual(final.candidates, [{ label: '往返', status: 'match' }]);
  await assert.rejects(runner.run(steps, undefined, [payload], resume), /失效/u);
  assert.equal(experimentRequestHash('calculate_offline', { steps, candidates, resume_id: partial.resume_id }),
    experimentRequestHash('calculate_offline', { steps, candidates }));
});
