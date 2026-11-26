import { ToolError } from './tool-errors.js';
const ENTRY_BYTES = 12;
const ORIENTATION = 0x0112;
const EXIF_IFD = 0x8769;
const GPS_IFD = 0x8825;
const DATE_TIME_ORIGINAL = 0x9003;
const USER_COMMENT = 0x9286;
const MAX_USER_COMMENT_BYTES = 2048;
const ROOT_TEXT = new Map([[0x010e, 'description'], [0x010f, 'make'], [0x0110, 'model'],
  [0x0131, 'software'], [0x0132, 'date_time'], [0x013b, 'artist'], [0x8298, 'copyright']]);
const DETAIL_TEXT = new Map([[0x9004, 'date_time_digitized'], [0x9011, 'offset_time_original'],
  [0xa430, 'camera_owner'], [0xa434, 'lens_model']]);
const RATIONAL_FIELDS = new Map([[0x829a, 'exposure_time'], [0x829d, 'f_number'], [0x920a, 'focal_length']]);

function directoryEntries(bytes, offset, read16, visit) {
  if (offset < 8 || offset + 2 > bytes.length) throw new ToolError('size', '目录偏移超出 EXIF 数据范围。');
  const count = read16(offset);
  const first = offset + 2;
  if (first + count * ENTRY_BYTES + 4 > bytes.length) throw new ToolError('unsupported', 'EXIF 目录条目不完整。');
  for (let index = 0; index < count; index++) {
    const entry = first + index * ENTRY_BYTES;
    visit(read16(entry), entry);
  }
}

export function inspectExif(bytes, fileOffset) {
  try {
    const byteOrder = bytes.toString('latin1', 0, 2);
    if (bytes.length < 8 || (byteOrder !== 'II' && byteOrder !== 'MM')) throw new ToolError('unsupported', 'EXIF TIFF 文件头无效。');
    const read16 = (byteOrder === 'II' ? bytes.readUInt16LE : bytes.readUInt16BE).bind(bytes);
    const read32 = (byteOrder === 'II' ? bytes.readUInt32LE : bytes.readUInt32BE).bind(bytes);
    if (read16(2) !== 42) throw new ToolError('unsupported', 'EXIF TIFF 标记无效。');
    let orientation;
    let exifDirectory;
    let gpsDirectory;
    let dateTimeOriginal;
    let userComment;
    const fields = {};
    const warnings = [];
    const valueAt = (entry, type, width, count, maximum = count) => {
      const length = width * count;
      const offset = length <= 4 ? entry + 8 : read32(entry + 8);
      if (read16(entry + 2) !== type || count < 1 || count > maximum || offset < 8 || offset + length > bytes.length) return undefined;
      return { offset, length, file_offset: fileOffset + offset };
    };
    const ascii = entry => {
      const part = valueAt(entry, 2, 1, read32(entry + 4), 1024);
      if (part === undefined) return undefined;
      const text = bytes.toString('latin1', part.offset, part.offset + part.length).split('\0', 1)[0]
        .replace(/[\p{Cc}\p{Cf}]/gu, '?').trim();
      return text ? { value: text, file_offset: part.file_offset } : undefined;
    };
    const rational = (entry, count) => {
      if (read32(entry + 4) !== count) return undefined;
      const part = valueAt(entry, 5, 8, count);
      if (part === undefined) return undefined;
      const values = [];
      for (let cursor = part.offset; cursor < part.offset + part.length; cursor += 8) {
        const denominator = read32(cursor + 4);
        if (denominator === 0) return undefined;
        values.push(read32(cursor) / denominator);
      }
      return { value: count === 1 ? values[0] : values, file_offset: part.file_offset };
    };
    const add = (key, value) => {
      if (value !== undefined) fields[key] = value;
    };
    directoryEntries(bytes, read32(4), read16, (tag, entry) => {
      if (tag === ORIENTATION) {
        const value = read16(entry + 8);
        if (read16(entry + 2) !== 3 || read32(entry + 4) !== 1 || value < 1 || value > 8) {
          warnings.push('EXIF Orientation 字段无效，已忽略并继续解析其余字段。');
        } else {
          orientation = { value, file_offset: fileOffset + entry + 8 };
        }
      } else if (tag === EXIF_IFD || tag === GPS_IFD) {
        const pointer = valueAt(entry, 4, 4, read32(entry + 4), 1);
        if (!pointer) warnings.push('EXIF 子目录指针无效。');
        else if (tag === EXIF_IFD) exifDirectory = read32(pointer.offset);
        else gpsDirectory = read32(pointer.offset);
      } else if (ROOT_TEXT.has(tag)) add(ROOT_TEXT.get(tag), ascii(entry));
    });
    if (exifDirectory !== undefined) {
      directoryEntries(bytes, exifDirectory, read16, (tag, entry) => {
        if (DETAIL_TEXT.has(tag)) add(DETAIL_TEXT.get(tag), ascii(entry));
        if (RATIONAL_FIELDS.has(tag)) add(RATIONAL_FIELDS.get(tag), rational(entry, 1));
        if (tag === USER_COMMENT) {
          const count = read32(entry + 4);
          const part = valueAt(entry, 7, 1, count, MAX_USER_COMMENT_BYTES);
          if (!part) {
            warnings.push('EXIF UserComment 类型、长度或偏移无效。');
          } else {
            const prefix = bytes.toString('latin1', part.offset, Math.min(part.offset + 8, part.offset + part.length));
            let encoding = 'ASCII';
            let start = part.offset;
            if (prefix.startsWith('ASCII\0\0\0')) start += 8;
            else if (prefix.startsWith('UNICODE\0')) {
              encoding = byteOrder === 'II' ? 'UTF-16LE' : 'UTF-16BE';
              start += 8;
            } else {
              encoding = 'raw';
              warnings.push('EXIF UserComment 使用未识别的字符集标记。');
            }
            let valueBytes = bytes.subarray(start, part.offset + part.length);
            if (encoding === 'UTF-16BE') {
              if (valueBytes.length % 2 !== 0) {
                warnings.push('EXIF UserComment 的 UTF-16 字节数为奇数。');
                valueBytes = valueBytes.subarray(0, valueBytes.length - 1);
              }
              const swapped = Buffer.alloc(valueBytes.length);
              for (let index = 0; index < valueBytes.length; index += 2) {
                swapped[index] = valueBytes[index + 1];
                swapped[index + 1] = valueBytes[index];
              }
              valueBytes = swapped;
            }
            const value = valueBytes.toString(encoding === 'UTF-16LE' || encoding === 'UTF-16BE' ? 'utf16le' : 'latin1')
              .replace(/\0+$/u, '').replace(/[\p{Cc}\p{Cf}]/gu, '?').trim();
            if (value) userComment = { value, encoding, file_offset: fileOffset + start };
          }
        }
        if (tag === 0x8827 && read32(entry + 4) === 1) {
          const part = valueAt(entry, 3, 2, 1);
          if (part) add('iso', { value: read16(part.offset), file_offset: part.file_offset });
        }
        if (tag !== DATE_TIME_ORIGINAL) return;
        const length = read32(entry + 4);
        const offset = read32(entry + 8);
        if (read16(entry + 2) !== 2 || length !== 20 || offset < 8 || offset + length > bytes.length || bytes[offset + 19] !== 0) {
          throw new ToolError('unsupported', 'EXIF DateTimeOriginal 字段无效。');
        }
        const value = bytes.toString('latin1', offset, offset + 19);
        // An all-blank timestamp with its separators retained represents an unknown time.
        if (value.replace(/[: ]/gu, '') === '') return;
        if (!/^\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}$/u.test(value)) throw new ToolError('unsupported', 'EXIF DateTimeOriginal 格式无效。');
        dateTimeOriginal = { value, file_offset: fileOffset + offset };
      });
    }
    if (gpsDirectory !== undefined) {
      const gps = {};
      try {
        directoryEntries(bytes, gpsDirectory, read16, (tag, entry) => {
          if (tag === 1) gps.latitude_ref = ascii(entry);
          else if (tag === 2) gps.latitude_dms = rational(entry, 3);
          else if (tag === 3) gps.longitude_ref = ascii(entry);
          else if (tag === 4) gps.longitude_dms = rational(entry, 3);
          else if (tag === 6) gps.altitude = rational(entry, 1);
          else if (tag === 29) gps.date_stamp = ascii(entry);
        });
        for (const [axis, positive, negative, maximum] of [['latitude', 'N', 'S', 90], ['longitude', 'E', 'W', 180]]) {
          const direction = gps[axis + '_ref']?.value;
          const degrees = gps[axis + '_dms']?.value;
          if (!degrees || (direction !== positive && direction !== negative)) continue;
          const [whole, minutes, seconds] = degrees;
          const decimal = whole + minutes / 60 + seconds / 3600;
          if (minutes < 60 && seconds < 60 && decimal <= maximum) gps[axis] = direction === negative ? -decimal : decimal;
        }
        if (Object.values(gps).some(value => value !== undefined)) fields.gps = gps;
      } catch {
        warnings.push('EXIF GPS 目录不完整。');
      }
    }
    return { status: 'ok', file_offset: fileOffset, orientation, date_time_original: dateTimeOriginal,
      ...(userComment ? { user_comment: userComment } : {}), ...fields,
      ...(warnings.length > 0 ? { warnings } : {}) };
  } catch (error) {
    return { status: 'invalid', file_offset: fileOffset, reason: error.message };
  }
}
