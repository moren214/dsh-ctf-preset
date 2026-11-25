#!/usr/bin/env node
// 把 CI 里的测试输出转成 GitHub 注解：失败用例名与末尾上下文都能在公开的
// annotations API 上看到，不必登录才能读 job 日志。
//
// 注意 Node 的两种报告格式：TTY 下是 spec（失败行以 "✖ " 开头），管道里是
// TAP（失败行是 "not ok 71 - name"）。CI 把输出 tee 到文件，拿到的是 TAP，
// 所以两种前缀都要认，否则会误报「没有失败用例行」。
import { readFileSync, existsSync } from 'node:fs';

const file = process.argv[2] ?? 'test-output.txt';
const text = existsSync(file) ? readFileSync(file, 'utf8') : '(没有捕获到 test-output.txt)';
const lines = text.split(/\r?\n/u);

const escape = value => String(value)
  .replaceAll('%', '%25')
  .replaceAll('\r', '%0D')
  .replaceAll('\n', '%0A');

const emit = (title, message) => {
  process.stdout.write(`::error title=${escape(title)}::${escape(message)}\n`);
};

const failureName = (line) => {
  if (line.startsWith('✖ ')) return line.slice(2).trim();
  const tap = /^not ok\s+\d+\s+-\s+(.*)$/u.exec(line);
  if (tap) return tap[1].trim();
  return null;
};

const failing = [...new Set(lines.map(failureName).filter(Boolean))];

if (failing.length > 0) {
  for (const name of failing.slice(0, 20)) emit('failing test', name);
  // 失败用例的诊断通常在其后若干行，单独抓一段，免得只知道名字不知道原因。
  const details = [];
  lines.forEach((line, index) => {
    if (!failureName(line)) return;
    const block = [];
    for (let cursor = index + 1; cursor < lines.length && block.length < 30; cursor += 1) {
      const next = lines[cursor];
      if (/^(?:ok|not ok)\s+\d+/u.test(next)) break;
      block.push(next);
    }
    const joined = block.join(' / ').trim();
    if (joined) details.push(`${failureName(line)} => ${joined}`);
  });
  if (details.length > 0) emit('failing detail', details.join(' /// ').slice(-3500));
} else {
  emit('failure without a ✖ line', '测试输出里没有失败用例行，可能是覆盖率门槛或运行期错误。');
}

// 覆盖率门槛的失败文案在输出最末尾，必须保留尾部而不是头部。
const floors = lines
  .map(line => line.replace(/^#\s?/u, '').trimEnd())
  .filter(line => /floors failed|coverage report row missing|< \d+(?:\.\d+)?%|Core module coverage/u.test(line))
  .join(' / ');

if (floors.length > 0) emit('coverage floors', floors.slice(-3500));

const tail = lines
  .map(line => line.replace(/^#\s?/u, '').trimEnd())
  .filter(line => line.trim().length > 0 && !/^-{20,}$/u.test(line))
  .join(' / ');

emit('suite tail', tail.slice(-3500));
