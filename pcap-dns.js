const MAX_QUESTIONS = 4;
const MAX_ANSWERS = 64;
const MAX_TXT_RECORDS = 4;
const MAX_TXT_STRINGS = 4;

class InvalidDnsMessage extends Error {}

function requireBytes(end, offset, length) {
  if (offset + length > end) throw new InvalidDnsMessage();
}

function visible(bytes, label = false) {
  let text = '';
  for (const byte of bytes) {
    if (byte >= 32 && byte <= 126 && byte !== 92 && (!label || byte !== 46)) {
      text += String.fromCharCode(byte);
    } else {
      text += '\\x' + byte.toString(16).padStart(2, '0');
    }
  }
  return text;
}

function readName(bytes, offset) {
  const labels = [];
  let cursor = offset;
  let resume;
  let pointerLimit = offset;
  let expanded = 1;
  for (let steps = 0; steps < 128; steps++) {
    requireBytes(bytes.length, cursor, 1);
    const length = bytes[cursor];
    if (length === 0) return { name: labels.join('.') || '.', next: resume ?? cursor + 1 };
    if ((length & 0xc0) === 0xc0) {
      requireBytes(bytes.length, cursor, 2);
      const target = ((length & 0x3f) << 8) | bytes[cursor + 1];
      if (target < 12 || target >= pointerLimit) throw new InvalidDnsMessage();
      resume ??= cursor + 2;
      pointerLimit = target;
      cursor = target;
      continue;
    }
    if (length > 63 || expanded + length + 1 > 255) throw new InvalidDnsMessage();
    requireBytes(bytes.length, cursor + 1, length);
    labels.push(visible(bytes.subarray(cursor + 1, cursor + 1 + length), true));
    expanded += length + 1;
    cursor += length + 1;
  }
  throw new InvalidDnsMessage();
}

function readTxt(bytes, start, end) {
  const strings = [];
  let cursor = start;
  while (cursor < end) {
    const length = bytes[cursor++];
    requireBytes(end, cursor, length);
    if (strings.length < MAX_TXT_STRINGS) strings.push(visible(bytes.subarray(cursor, cursor + length)));
    else return { strings, strings_truncated: true };
    cursor += length;
  }
  return { strings };
}

// Only question names and answer TXT data are exported. Other DNS counts use the header.
export function dnsDetails(bytes) {
  const report = { id: bytes.readUInt16BE(0), questions: [], txt_answers: [] };
  const questions = bytes.readUInt16BE(4);
  const answers = bytes.readUInt16BE(6);
  let cursor = 12;
  try {
    for (let index = 0; index < Math.min(questions, MAX_QUESTIONS); index++) {
      const { name, next } = readName(bytes, cursor);
      requireBytes(bytes.length, next, 4);
      report.questions.push({ qname: name, qtype: bytes.readUInt16BE(next), qclass: bytes.readUInt16BE(next + 2) });
      cursor = next + 4;
    }
    if (questions > MAX_QUESTIONS) return { ...report, details_truncated: true };
    for (let index = 0; index < Math.min(answers, MAX_ANSWERS); index++) {
      const { name, next } = readName(bytes, cursor);
      requireBytes(bytes.length, next, 10);
      const start = next + 10;
      const length = bytes.readUInt16BE(next + 8);
      requireBytes(bytes.length, start, length);
      cursor = start + length;
      if (bytes.readUInt16BE(next) !== 16) continue;
      if (report.txt_answers.length === MAX_TXT_RECORDS) return { ...report, details_truncated: true };
      report.txt_answers.push({ name, ttl: bytes.readUInt32BE(next + 4), ...readTxt(bytes, start, cursor) });
    }
    if (answers > MAX_ANSWERS) report.details_truncated = true;
    return report;
  } catch (error) {
    if (!(error instanceof InvalidDnsMessage)) throw error;
    return { ...report, malformed: true };
  }
}
