import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { ToolError } from '../contracts/errors.js';
import { crc32 } from './zip-crack.js';

function pngChunk(type, data) {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(data.length, 0);
  head.write(type, 4, 'ascii');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), data])), 0);
  return Buffer.concat([head, data, crc]);
}

export function encodePng(width, height, rgb) {
  const stride = width * 3;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let row = 0; row < height; row += 1) {
    raw[row * (stride + 1)] = 0;
    rgb.copy(raw, row * (stride + 1) + 1, row * stride, row * stride + stride);
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 2;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', header),
    pngChunk('IDAT', deflateSync(raw, { level: 9 })),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

export function parseWav(buffer) {
  if (buffer.length < 12 || buffer.toString('ascii', 0, 4) !== 'RIFF' || buffer.toString('ascii', 8, 12) !== 'WAVE') {
    throw new ToolError('unsupported', '只支持 WAV（RIFF/WAVE）；FLAC、MP3 元数据请用 inspect_media 或 shell。');
  }
  const chunks = [];
  let cursor = 12;
  while (cursor + 8 <= buffer.length) {
    const id = buffer.toString('ascii', cursor, cursor + 4);
    const size = buffer.readUInt32LE(cursor + 4);
    const dataOffset = cursor + 8;
    chunks.push({ id, size, dataOffset });
    cursor += 8 + size + (size & 1);
    if (cursor <= dataOffset) break;
  }
  const fmt = chunks.find(chunk => chunk.id === 'fmt ');
  const data = chunks.find(chunk => chunk.id === 'data');
  if (!fmt || !data) throw new ToolError('unsupported', 'WAV 缺少 fmt 或 data 块。');
  if (fmt.size < 16 || fmt.dataOffset + fmt.size > buffer.length || data.dataOffset + data.size > buffer.length) {
    throw new ToolError('unsupported', 'WAV 的 fmt 或 data 块被截断。');
  }
  let format = buffer.readUInt16LE(fmt.dataOffset);
  if (format === 0xfffe) {
    const pcmGuid = Buffer.from('0100000000001000800000aa00389b71', 'hex');
    if (fmt.size < 40 || !buffer.subarray(fmt.dataOffset + 24, fmt.dataOffset + 40).equals(pcmGuid)) {
      throw new ToolError('unsupported', 'WAVEFORMATEXTENSIBLE 只支持标准 PCM 子格式。');
    }
    format = buffer.readUInt16LE(fmt.dataOffset + 24);
  }
  const channels = buffer.readUInt16LE(fmt.dataOffset + 2);
  const sampleRate = buffer.readUInt32LE(fmt.dataOffset + 4);
  const blockAlign = buffer.readUInt16LE(fmt.dataOffset + 12);
  const bitsPerSample = buffer.readUInt16LE(fmt.dataOffset + 14);
  if (channels < 1 || channels > 32 || sampleRate < 1) throw new ToolError('unsupported', 'WAV 声道数或采样率无效。');
  if (![8, 16, 24].includes(bitsPerSample)) {
    throw new ToolError('unsupported', `暂不支持 ${bitsPerSample} 位 PCM，支持 8/16/24 位。`);
  }
  if (format !== 1) throw new ToolError('unsupported', '只支持 PCM（format=1）的 WAV。');
  const frameSize = channels * (bitsPerSample / 8);
  if (blockAlign !== frameSize) throw new ToolError('unsupported', 'WAV block_align 与声道数及位深不匹配。');
  const frames = Math.floor(data.size / frameSize);
  const tags = {};
  for (const chunk of chunks) {
    if (chunk.id !== 'LIST' || chunk.size < 12) continue;
    const listType = buffer.toString('ascii', chunk.dataOffset, chunk.dataOffset + 4);
    if (listType !== 'INFO') continue;
    let position = chunk.dataOffset + 4;
    while (position + 8 <= chunk.dataOffset + chunk.size) {
      const tag = buffer.toString('ascii', position, position + 4);
      const length = buffer.readUInt32LE(position + 4);
      tags[tag] = buffer.toString('utf8', position + 8, Math.min(position + 8 + length, chunk.dataOffset + chunk.size))
        .replace(/\0+$/u, '');
      position += 8 + length + (length & 1);
    }
  }
  return { chunks, fmt: { format, channels, sampleRate, bitsPerSample }, data, frames, tags };
}

function sampleAt(buffer, wav, frame, channel) {
  const bytes = wav.fmt.bitsPerSample / 8;
  const offset = wav.data.dataOffset + (frame * wav.fmt.channels + channel) * bytes;
  if (wav.fmt.bitsPerSample === 8) return (buffer[offset] - 128) / 128;
  if (wav.fmt.bitsPerSample === 16) return buffer.readInt16LE(offset) / 32768;
  let value = buffer[offset] | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 16);
  if (value & 0x800000) value -= 0x1000000;
  return value / 8388608;
}

function rawSampleAt(buffer, wav, frame, channel) {
  const bytes = wav.fmt.bitsPerSample / 8;
  const offset = wav.data.dataOffset + (frame * wav.fmt.channels + channel) * bytes;
  if (wav.fmt.bitsPerSample === 8) return buffer[offset];
  if (wav.fmt.bitsPerSample === 16) return buffer.readUInt16LE(offset);
  return buffer[offset] | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 16);
}

function audioSelection(wav, args) {
  if (args.start_frame !== undefined && args.start_seconds !== undefined) throw new ToolError('unsupported', 'start_frame 和 start_seconds 只能选一个。');
  if (args.frame_count !== undefined && args.duration_seconds !== undefined) throw new ToolError('unsupported', 'frame_count 和 duration_seconds 只能选一个。');
  const start = args.start_frame ?? Math.floor((args.start_seconds ?? 0) * wav.fmt.sampleRate);
  const count = args.frame_count ?? (args.duration_seconds === undefined
    ? wav.frames - start : Math.ceil(args.duration_seconds * wav.fmt.sampleRate));
  if (!Number.isSafeInteger(start) || start < 0 || !Number.isSafeInteger(count) || count < 1 || start + count > wav.frames) {
    throw new ToolError('unsupported', '音频选段必须落在完整 PCM 帧范围内。');
  }
  const channels = args.channels ?? Array.from({ length: wav.fmt.channels }, (_, index) => index);
  if (!Array.isArray(channels) || channels.length < 1 || channels.length > wav.fmt.channels
    || new Set(channels).size !== channels.length || channels.some(channel => !Number.isInteger(channel) || channel < 0 || channel >= wav.fmt.channels)) {
    throw new ToolError('unsupported', 'channels 须是 WAV 中有效且不重复的声道编号。');
  }
  const sampleOffset = args.sample_offset ?? 0;
  if (!Number.isSafeInteger(sampleOffset) || sampleOffset < 0 || sampleOffset % 8 !== 0
    || sampleOffset > count * channels.length) throw new ToolError('unsupported', 'sample_offset 须按字节对齐并位于所选音频段内。');
  return { start, count, end: start + count, channels, sampleOffset };
}

function fftMagnitudes(samples) {
  const size = samples.length;
  const real = Float64Array.from(samples);
  const imag = new Float64Array(size);
  for (let index = 1, position = 0; index < size; index += 1) {
    let bit = size >> 1;
    for (; position & bit; bit >>= 1) position &= ~bit;
    position |= bit;
    if (index < position) {
      [real[index], real[position]] = [real[position], real[index]];
      [imag[index], imag[position]] = [imag[position], imag[index]];
    }
  }
  for (let length = 2; length <= size; length <<= 1) {
    const angle = (-2 * Math.PI) / length;
    const half = length >> 1;
    const stepCos = Math.cos(angle);
    const stepSin = Math.sin(angle);
    for (let start = 0; start < size; start += length) {
      let cos = 1;
      let sin = 0;
      for (let offset = 0; offset < half; offset += 1) {
        const even = start + offset;
        const odd = even + half;
        const oddReal = real[odd] * cos - imag[odd] * sin;
        const oddImag = real[odd] * sin + imag[odd] * cos;
        const evenReal = real[even];
        const evenImag = imag[even];
        real[even] = evenReal + oddReal;
        imag[even] = evenImag + oddImag;
        real[odd] = evenReal - oddReal;
        imag[odd] = evenImag - oddImag;
        const nextCos = cos * stepCos - sin * stepSin;
        sin = cos * stepSin + sin * stepCos;
        cos = nextCos;
      }
    }
  }
  const magnitudes = new Float64Array(size >> 1);
  for (let index = 0; index < magnitudes.length; index += 1) {
    magnitudes[index] = Math.hypot(real[index], imag[index]);
  }
  return magnitudes;
}

function colorFor(value) {
  const clamped = Math.min(1, Math.max(0, value));
  const red = Math.round(255 * Math.min(1, clamped * 2));
  const green = Math.round(255 * Math.min(1, Math.max(0, clamped * 2 - 0.5)));
  const blue = Math.round(255 * (1 - clamped));
  return [red, green, blue];
}

function renderSpectrumPng(windows, sampleRate, fftSize, hopSize) {
  const width = windows.length;
  const height = Math.min(fftSize / 2, 256);
  const rgb = Buffer.alloc(width * height * 3);
  let peak = 1e-9;
  for (const bins of windows) peak = Math.max(peak, ...bins);
  const peaks = new Float64Array(fftSize / 2);
  for (let column = 0; column < width; column += 1) {
    const bins = windows[column];
    for (const [index, value] of bins.entries()) peaks[index] = Math.max(peaks[index], value);
    for (let row = 0; row < height; row += 1) {
      const start = Math.floor((height - 1 - row) * bins.length / height);
      const end = Math.floor((height - row) * bins.length / height);
      let amplitude = 0;
      for (let bin = start; bin < end; bin += 1) amplitude = Math.max(amplitude, bins[bin]);
      const decibels = 20 * Math.log10(Math.max(1e-6, amplitude / peak));
      const [red, green, blue] = colorFor((decibels + 72) / 72);
      const position = (row * width + column) * 3;
      rgb[position] = red;
      rgb[position + 1] = green;
      rgb[position + 2] = blue;
    }
  }
  const pngBuffer = encodePng(width, height, rgb);
  const dominant = Array.from(peaks, (value, index) => ({ value, index }))
    .sort((left, right) => right.value - left.value).slice(0, 8)
    .map(item => ({ hz: Math.round(item.index * sampleRate / fftSize), magnitude: Number(item.value.toFixed(3)) }));
  return {
    pngBuffer,
    meta: {
      width, height, bytes: pngBuffer.length, fft_size: fftSize, hop_size: hopSize,
      bin_hz: sampleRate / fftSize, time_step_s: hopSize / sampleRate,
      frequency_axis: 'low_to_high_bottom_to_top', peaks: dominant,
    },
  };
}

export async function runStegoAudio(buffer, args, { signal, writeOutput } = {}) {
  const wav = parseWav(buffer);
  const inputHash = createHash('sha256').update(buffer).digest('hex');
  const selection = args.action === 'info' && wav.frames === 0
    ? { start: 0, count: 0, end: 0, channels: Array.from({ length: wav.fmt.channels }, (_, index) => index), sampleOffset: 0 }
    : audioSelection(wav, args);
  const base = {
    input_sha256: inputHash, format: 'wav', channels: wav.fmt.channels, sample_rate: wav.fmt.sampleRate,
    bits_per_sample: wav.fmt.bitsPerSample, frames: wav.frames,
    duration_s: Number((wav.frames / wav.fmt.sampleRate).toFixed(3)),
    selected_channels: selection.channels, start_frame: selection.start, end_frame: selection.end,
    selected_duration_s: Number((selection.count / wav.fmt.sampleRate).toFixed(3)),
    tags: wav.tags, chunks: wav.chunks.map(chunk => ({ id: chunk.id, size: chunk.size, offset: chunk.dataOffset })),
  };
  if (args.action === 'info') return { status: 'ok', ...base };
  if (args.action === 'lsb') {
    const bitIndex = args.bit_index ?? 0;
    const bitOrder = args.bit_order ?? 'lsb_first';
    if (!['lsb_first', 'msb_first'].includes(bitOrder)) throw new ToolError('unsupported', 'bit_order 须为 lsb_first 或 msb_first。');
    const maxBytes = Math.min(Math.max(args.max_bytes ?? 4096, 1), 65536);
    if (bitIndex >= wav.fmt.bitsPerSample) throw new ToolError('unsupported', `bit_index 超出 ${wav.fmt.bitsPerSample} 位采样范围。`);
    const bits = [];
    const totalSamples = selection.count * selection.channels.length;
    const sampleEnd = Math.min(totalSamples, selection.sampleOffset + maxBytes * 8);
    for (let logical = selection.sampleOffset; logical < sampleEnd; logical += 1) {
      const frame = selection.start + Math.floor(logical / selection.channels.length);
      const channel = selection.channels[logical % selection.channels.length];
      bits.push((rawSampleAt(buffer, wav, frame, channel) >> bitIndex) & 1);
    }
    const bytes = [];
    for (let index = 0; index + 8 <= bits.length; index += 8) {
      let value = 0;
      if (bitOrder === 'lsb_first') {
        for (let offset = 0; offset < 8; offset += 1) value |= bits[index + offset] << offset;
      } else {
        for (let offset = 0; offset < 8; offset += 1) value = (value << 1) | bits[index + offset];
      }
      bytes.push(value);
    }
    const data = Buffer.from(bytes);
    const printable = data.toString('utf8').replace(/[^\x20-\x7e\u4e00-\u9fff]/gu, '.');
    const text = printable.length <= 65536 ? printable : `${printable.slice(0, 65536)}\n…（输出已截断，共 ${printable.length} 字符）`;
    const dataHash = createHash('sha256').update(data).digest('hex');
    return {
      status: 'ok', ...base, input_sha256: inputHash, bit_index: bitIndex, bits_read: bits.length, bytes: data.length,
      sample_offset: selection.sampleOffset, next_sample_offset: sampleEnd < totalSamples ? sampleEnd - (sampleEnd % 8) : null,
      padding_bits: bits.length % 8,
      total_samples: totalSamples, artifact_sha256: dataHash,
      hex: data.toString('hex'), text: text.slice(0, 4096),
      sha256: dataHash, __artifact_bytes: data,
    };
  }
  if (args.action === 'spectrum') {
    const fftSize = args.fft_size ?? 2048;
    if (!Number.isInteger(fftSize) || fftSize < 256 || fftSize > 8192 || (fftSize & (fftSize - 1)) !== 0) {
      throw new ToolError('unsupported', 'fft_size 须为 256 至 8192 内的 2 的幂。');
    }
    if (selection.count === 0) throw new ToolError('unsupported', '所选 WAV 范围没有完整 PCM 帧。');
    const maxWindows = 192;
    const hopSize = Math.max(fftSize / 4, Math.ceil(Math.max(0, selection.count - fftSize) / (maxWindows - 1)));
    const windowCount = 1 + Math.ceil(Math.max(0, selection.count - fftSize) / hopSize);
    const coefficients = Float64Array.from({ length: fftSize }, (_, index) =>
      0.5 - 0.5 * Math.cos((2 * Math.PI * index) / (fftSize - 1)));
    const windows = [];
    for (let column = 0; column < windowCount; column += 1) {
      signal?.throwIfAborted();
      const mono = new Float64Array(fftSize);
      const localStart = column * hopSize;
      for (let index = 0; index < fftSize && localStart + index < selection.count; index += 1) {
        let sum = 0;
        for (const channel of selection.channels) sum += sampleAt(buffer, wav, selection.start + localStart + index, channel);
        mono[index] = sum / selection.channels.length * coefficients[index];
      }
      windows.push(fftMagnitudes(mono));
      if (column % 8 === 7) await new Promise(resolve => setImmediate(resolve));
    }
    const { pngBuffer, meta } = renderSpectrumPng(windows, wav.fmt.sampleRate, fftSize, hopSize);
    const relPath = args.path ?? ('spectrum-' + Date.now() + '.png');
    const savedPath = await writeOutput(relPath, pngBuffer);
    const pngSha = createHash('sha256').update(pngBuffer).digest('hex');
    return {
      status: 'ok', file: savedPath, ...meta, input_sha256: inputHash, sha256: pngSha,
      start_frame: selection.start, end_frame: selection.end, selected_channels: selection.channels,
      selected_duration_s: Number((selection.count / wav.fmt.sampleRate).toFixed(3)),
    };
  }
  throw new ToolError('unsupported', `未知操作：${args.action}。`);
}
