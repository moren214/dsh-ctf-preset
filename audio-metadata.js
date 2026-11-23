const MAX_TAGS = 32;
const MAX_TAG_BYTES = 1024;
const MAX_BLOCKS = 4096;

class AudioMetadataError extends Error {}

function requireBytes(end, offset, length) {
  if (offset > end || length > end - offset) throw new AudioMetadataError('音频元数据块超出原件范围。');
}

function readLabel(bytes, offset) {
  return bytes.toString('latin1', offset, offset + 4);
}

function tagText(bytes, encoding = 'utf-8') {
  const prefix = bytes.subarray(0, MAX_TAG_BYTES);
  const text = encoding === 'latin1' ? prefix.toString('latin1') : new TextDecoder(encoding).decode(prefix);
  return { text: text.replace(/\x00+$/u, ''), ...(bytes.length > prefix.length ? { truncated: true } : {}) };
}

function* riffChunks(bytes, cursor, end, uint32) {
  let count = 0;
  while (cursor < end) {
    if (++count > MAX_BLOCKS) throw new AudioMetadataError('音频元数据块数超过上限。');
    requireBytes(end, cursor, 8);
    const length = uint32(cursor + 4);
    const start = cursor + 8;
    requireBytes(end, start, length);
    const stop = start + length;
    yield { id: readLabel(bytes, cursor), start, stop, length };
    cursor = stop < end ? stop + (length & 1) : stop;
  }
}

function inspectWave(bytes) {
  const signature = readLabel(bytes, 0);
  const bigEndian = signature === 'RIFX';
  const uint16 = offset => bigEndian ? bytes.readUInt16BE(offset) : bytes.readUInt16LE(offset);
  const uint32 = offset => bigEndian ? bytes.readUInt32BE(offset) : bytes.readUInt32LE(offset);
  const end = uint32(4) + 8;
  if (end < 12) throw new AudioMetadataError('WAV 容器长度无效。');
  requireBytes(bytes.length, 0, end);
  let audio;
  let data;
  const tags = [];
  let tagCount = 0;
  for (const { id, start, stop, length } of riffChunks(bytes, 12, end, uint32)) {
    if (id === 'fmt ' && audio === undefined) {
      requireBytes(stop, start, 16);
      const formatTag = uint16(start);
      audio = {
        format_tag: formatTag, channels: uint16(start + 2), sample_rate: uint32(start + 4),
        bytes_per_second: uint32(start + 8), block_align: uint16(start + 12), bits_per_sample: uint16(start + 14),
      };
      if (formatTag === 0xfffe) {
        requireBytes(stop, start, 40);
        const extension = uint16(start + 16);
        if (extension < 22) throw new AudioMetadataError('WAV 扩展格式描述长度无效。');
        requireBytes(stop, start + 18, extension);
        audio.valid_bits_per_sample = uint16(start + 18);
        audio.channel_mask = uint32(start + 20);
        audio.subformat_guid_hex = bytes.toString('hex', start + 24, start + 40);
        if (!bigEndian && bytes.toString('hex', start + 26, start + 40) === '000000001000800000aa00389b71') {
          audio.subformat_tag = uint16(start + 24);
        }
      }
    } else if (id === 'data' && data === undefined) {
      data = { byte_offset: start, byte_length: length };
    } else if (id === 'LIST' && length >= 4 && readLabel(bytes, start) === 'INFO') {
      for (const field of riffChunks(bytes, start + 4, stop, uint32)) {
        if (++tagCount <= MAX_TAGS) tags.push({
          name: field.id, byte_offset: field.start, byte_length: field.length,
          ...tagText(bytes.subarray(field.start, field.stop)),
        });
      }
    }
  }
  if (audio === undefined) throw new AudioMetadataError('WAV 缺少 fmt 描述块。');
  if (data !== undefined && [1, 3].includes(audio.subformat_tag ?? audio.format_tag)
    && audio.block_align > 0 && audio.sample_rate > 0 && data.byte_length % audio.block_align === 0) {
    audio.sample_count = data.byte_length / audio.block_align;
    audio.duration_seconds = audio.sample_count / audio.sample_rate;
  }
  return {
    status: 'ok', format: 'WAV', variant: signature, ...audio, data: data ?? null, tags,
    tags_truncated: tagCount > tags.length, trailing_size: bytes.length - end,
    ...(end < bytes.length ? { trailing_offset: end } : {}),
  };
}

function flacComments(bytes, start, end) {
  let cursor = start;
  const nextLength = () => {
    requireBytes(end, cursor, 4);
    const length = bytes.readUInt32LE(cursor);
    cursor += 4;
    return length;
  };
  const vendorLength = nextLength();
  requireBytes(end, cursor, vendorLength);
  const vendor = tagText(bytes.subarray(cursor, cursor + vendorLength));
  cursor += vendorLength;
  const count = nextLength();
  if (count > Math.floor((end - cursor) / 4)) throw new AudioMetadataError('FLAC 注释数量无效。');
  const tags = [];
  for (let index = 0; index < Math.min(count, MAX_TAGS); index++) {
    const length = nextLength();
    requireBytes(end, cursor, length);
    const text = tagText(bytes.subarray(cursor, cursor + length));
    const separator = text.text.indexOf('=');
    tags.push({
      byte_offset: cursor, byte_length: length,
      ...(separator > 0 ? { name: text.text.slice(0, separator), text: text.text.slice(separator + 1) } : { text: text.text }),
      ...(text.truncated ? { truncated: true } : {}),
    });
    cursor += length;
  }
  return { vendor, tags, tags_truncated: count > tags.length };
}

function inspectFlac(bytes) {
  let cursor = 4;
  let audio;
  let comments;
  for (let index = 0; index < MAX_BLOCKS; index++) {
    requireBytes(bytes.length, cursor, 4);
    const header = bytes[cursor];
    const type = header & 0x7f;
    const length = bytes.readUIntBE(cursor + 1, 3);
    const start = cursor + 4;
    requireBytes(bytes.length, start, length);
    cursor = start + length;
    if ((index === 0 && type !== 0) || type === 127) throw new AudioMetadataError('FLAC 元数据块类型无效。');
    if (type === 0) {
      if (index !== 0 || length !== 34) throw new AudioMetadataError('FLAC STREAMINFO 长度或位置无效。');
      const packed = bytes.readBigUInt64BE(start + 10);
      const sampleRate = Number(packed >> 44n);
      const sampleCount = Number(packed & 0xfffffffffn);
      audio = {
        sample_rate: sampleRate, channels: Number(packed >> 41n & 7n) + 1,
        bits_per_sample: Number(packed >> 36n & 31n) + 1, sample_count: sampleCount || null,
        duration_seconds: sampleRate && sampleCount ? sampleCount / sampleRate : null,
        pcm_md5: bytes.toString('hex', start + 18, cursor),
      };
    } else if (type === 4 && comments === undefined) {
      comments = flacComments(bytes, start, cursor);
    }
    if ((header & 0x80) !== 0) {
      return { status: 'ok', format: 'FLAC', ...audio, audio_offset: cursor, ...(comments ?? { tags: [], tags_truncated: false }) };
    }
  }
  throw new AudioMetadataError('FLAC 元数据块数超过上限。');
}

function syncSafe(bytes, offset) {
  let size = 0;
  for (let index = offset; index < offset + 4; index++) {
    if (bytes[index] >= 128) throw new AudioMetadataError('ID3 标签长度无效。');
    size = size * 128 + bytes[index];
  }
  return size;
}

function id3Text(bytes) {
  const encoding = bytes[0];
  const content = bytes.subarray(1);
  if (encoding === 0) return tagText(content, 'latin1');
  if (encoding === 2) return tagText(content, 'utf-16be');
  if (encoding === 3) return tagText(content);
  if (encoding === 1) {
    if (content[0] === 0xfe && content[1] === 0xff) return tagText(content, 'utf-16be');
    if (content[0] === 0xff && content[1] === 0xfe) return tagText(content, 'utf-16le');
  }
  return undefined;
}

function id3v2(bytes) {
  requireBytes(bytes.length, 0, 10);
  const version = bytes[3];
  const flags = bytes[5];
  const tagEnd = 10 + syncSafe(bytes, 6);
  requireBytes(bytes.length, 0, tagEnd);
  const report = { version: '2.' + version + '.' + bytes[4], byte_offset: 0, byte_length: tagEnd, tags: [] };
  if ((version !== 3 && version !== 4) || (flags & 0xe0) !== 0) {
    return { ...report, status: 'partial', reason: '文字帧读取支持常规 ID3v2.3/2.4 标签。' };
  }
  let cursor = 10;
  let frameCount = 0;
  let skippedTextFrames = 0;
  while (cursor < tagEnd && bytes[cursor] !== 0) {
    if (++frameCount > MAX_BLOCKS) throw new AudioMetadataError('ID3 帧数超过上限。');
    requireBytes(tagEnd, cursor, 10);
    const id = readLabel(bytes, cursor);
    if (!/^[A-Z0-9]{4}$/u.test(id)) throw new AudioMetadataError('ID3 帧名称无效。');
    const length = version === 4 ? syncSafe(bytes, cursor + 4) : bytes.readUInt32BE(cursor + 4);
    const start = cursor + 10;
    requireBytes(tagEnd, start, length);
    if (id.startsWith('T') && length > 0) {
      if (report.tags.length === MAX_TAGS) return { ...report, status: 'ok', tags_truncated: true, skipped_text_frames: skippedTextFrames };
      const value = bytes[cursor + 9] === 0 ? id3Text(bytes.subarray(start, start + length)) : undefined;
      if (value === undefined) skippedTextFrames++;
      else report.tags.push({ name: id, byte_offset: start + 1, byte_length: length - 1, ...value });
    }
    cursor = start + length;
  }
  return { ...report, status: 'ok', tags_truncated: false, skipped_text_frames: skippedTextFrames };
}

function id3v1(bytes) {
  const start = bytes.length - 128;
  const v11 = bytes[start + 125] === 0 && bytes[start + 126] !== 0;
  const fields = [['title', 3, 30], ['artist', 33, 30], ['album', 63, 30], ['year', 93, 4], ['comment', 97, v11 ? 28 : 30]];
  const tags = fields.map(([name, offset, length]) => ({
    name, byte_offset: start + offset, byte_length: length,
    ...tagText(bytes.subarray(start + offset, start + offset + length), 'latin1'),
  }));
  return {
    version: v11 ? '1.1' : '1.0', byte_offset: start, byte_length: 128, tags,
    genre_index: bytes[start + 127], ...(v11 ? { track: bytes[start + 126] } : {}),
  };
}

export function inspectAudioMetadata(bytes) {
  try {
    const signature = readLabel(bytes, 0);
    if (bytes.length >= 12 && ['RIFF', 'RIFX'].includes(signature) && readLabel(bytes, 8) === 'WAVE') {
      return inspectWave(bytes);
    }
    if (signature === 'fLaC') return inspectFlac(bytes);
    const hasV2 = bytes.toString('latin1', 0, 3) === 'ID3';
    const hasV1 = bytes.length >= 128 && bytes.toString('latin1', bytes.length - 128, bytes.length - 125) === 'TAG';
    if (hasV2 || hasV1) {
      const v2 = hasV2 ? id3v2(bytes) : undefined;
      return { format: 'ID3', status: v2?.status ?? 'ok', id3v2: v2, id3v1: hasV1 ? id3v1(bytes) : undefined };
    }
    return { status: 'unsupported', reason: '音频元数据当前支持 RIFF/RIFX WAV、原生 FLAC 与 ID3 标签。' };
  } catch (error) {
    if (!(error instanceof AudioMetadataError)) throw error;
    return { status: 'invalid', reason: error.message };
  }
}
