"""Bounded bzip2 and XZ decompression for the CTF attachment tools."""

import sys

try:
    import bz2
    import lzma
except ImportError:
    print("Python 标准库缺少 bz2 或 lzma。", file=sys.stderr)
    raise SystemExit(4)

MAX_INPUT = 32 * 1024 * 1024
MAX_OUTPUT = 32 * 1024 * 1024


def decoder_for(kind):
    if kind == "bzip2":
        return bz2.BZ2Decompressor()
    if kind == "xz":
        return lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    raise ValueError("unsupported format")


def main():
    kind = sys.argv[1] if len(sys.argv) > 1 else ""
    data = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        print("input limit", file=sys.stderr)
        return 2
    output = bytearray()
    remaining = data
    try:
        while True:
            decoder = decoder_for(kind)
            while True:
                chunk = decoder.decompress(remaining, max_length=MAX_OUTPUT + 1 - len(output))
                output.extend(chunk)
                if len(output) > MAX_OUTPUT:
                    print("output limit", file=sys.stderr)
                    return 2
                if decoder.eof:
                    remaining = decoder.unused_data
                    if not remaining:
                        sys.stdout.buffer.write(output)
                        return 0
                    break
                if decoder.needs_input:
                    raise ValueError("incomplete stream")
                remaining = b""
    except (EOFError, OSError, ValueError, lzma.LZMAError) as error:
        print(str(error)[:256] or "invalid stream", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
