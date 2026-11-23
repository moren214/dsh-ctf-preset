const MAX_DATAGRAMS = 128;
const MAX_PIECES = 128;
const MAX_AGE_PACKETS = 2048;

export function ipv4Fragments() {
  const pending = new Map();
  let seen = 0;
  let resolved = 0;
  let reassembled = 0;
  return {
    add(key, fragment, packet) {
      seen++;
      while (pending.size > 0) {
        const [oldest, item] = pending.entries().next().value;
        if (packet - item.packet <= MAX_AGE_PACKETS) break;
        pending.delete(oldest);
      }
      let record = pending.get(key);
      if (record === undefined) {
        if (pending.size >= MAX_DATAGRAMS) pending.delete(pending.keys().next().value);
        record = { pieces: [], end: undefined, frames: 0, bad: false };
      }
      pending.delete(key);
      pending.set(key, record);
      record.packet = packet;
      record.frames++;
      if (record.bad) return null;
      const { offset, more, bytes } = fragment;
      const end = offset + bytes.length;
      const invalid = () => {
        record.bad = true;
        record.pieces = [];
        return null;
      };
      if (bytes.length === 0 || end > 65515 || (more && bytes.length % 8 !== 0)) return invalid();
      if (record.end !== undefined && (end > record.end || (more ? end >= record.end : end !== record.end))) return invalid();
      for (const piece of record.pieces) {
        if (piece.offset === offset && piece.end === end && piece.more === more && piece.bytes.equals(bytes)) return null;
        if (offset < piece.end && piece.offset < end) return invalid();
        if (!more && piece.end >= end) return invalid();
      }
      if (record.pieces.length >= MAX_PIECES) return invalid();
      if (!more) record.end = end;
      record.pieces.push({ offset, end, bytes, more });
      if (record.end === undefined) return null;
      record.pieces.sort((left, right) => left.offset - right.offset);
      let cursor = 0;
      for (const piece of record.pieces) {
        if (piece.offset !== cursor) return null;
        cursor = piece.end;
      }
      if (cursor !== record.end) return null;
      pending.delete(key);
      resolved += record.frames;
      reassembled++;
      return Buffer.concat(record.pieces.map(piece => piece.bytes), cursor);
    },
    stats() { return { seen, reassembled, unresolved: seen - resolved }; },
  };
}
