#!/usr/bin/env node
// 把 CI 里的测试输出转成 GitHub 注解：失败用例名与末尾上下文都能在公开的
// annotations API 上看到，不必登录才能读 job 日志。
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

const failing = [...new Set(lines
  .filter(line => line.startsWith('✖ '))
  .map(line => line.slice(2).trim())
  .filter(Boolean))];

if (failing.length > 0) {
  for (const name of failing.slice(0, 20)) emit('failing test', name);
} else {
  emit('failure without a ✖ line', '测试输出里没有失败用例行，可能是覆盖率门槛或运行期错误。');
}

const tail = lines
  .map(line => line.replace(/^#\s?/u, '').trimEnd())
  .filter(line => line.trim().length > 0 && !/^-{20,}$/u.test(line))
  .slice(-14)
  .join(' / ');

emit('suite tail', tail.slice(0, 3500));
