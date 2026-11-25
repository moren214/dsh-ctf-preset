"""Read one immutable archive in memory using the system libarchive API."""

import ctypes as c
import base64
import hashlib
import json
import stat
import sys
from zlib import crc32


ARCHIVE_OK = 0
ARCHIVE_EOF = 1
ARCHIVE_WARN = -20
MAX_INPUT = 32 * 1024 * 1024
MAX_MEMBER = 1024 * 1024
MAX_NAME = 1024
MAX_SAFE_INTEGER = (1 << 53) - 1
SYSTEM_LIBRARY_SEARCH = 0x800


def vint(data, offset, end):
    value = 0
    for shift in range(0, 70, 7):
        if offset >= end:
            break
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if byte < 0x80:
            return value, offset
    raise ValueError("Incomplete RAR5 header integer")


SEVEN_Z_SIGNATURE = b"7z\xbc\xaf\x27\x1c"


def seven_zip_volume(data):
    """Reject anything that is not a 7z container before libarchive sees it.

    libarchive 3.7 (Ubuntu 24.04) segfaults inside its 7z reader when the
    buffer has no 7z signature, so the signature and the minimum header
    length must be checked in this process instead of probing the library.
    """
    return len(data) >= 32 and data[:6] == SEVEN_Z_SIGNATURE


def rar_volume(data, variant):
    if variant == "RAR4":
        if len(data) < 14 or data[9] != 0x73:
            return False
        header_end = 7 + int.from_bytes(data[12:14], "little")
        return (14 <= header_end <= len(data)
                and crc32(data[9:header_end]) & 0xffff == int.from_bytes(data[7:9], "little")
                and bool(data[10] & 1))
    if variant != "RAR5" or len(data) < 13:
        return False
    try:
        size, offset = vint(data, 12, len(data))
        end = offset + size
        if end > len(data) or crc32(data[12:end]) != int.from_bytes(data[8:12], "little"):
            return False
        header, offset = vint(data, offset, end)
        if header != 1:
            return False
        flags, offset = vint(data, offset, end)
        if flags & 1:
            _, offset = vint(data, offset, end)
        if flags & 2:
            _, offset = vint(data, offset, end)
        archive_flags, _ = vint(data, offset, end)
        return bool(archive_flags & 1)
    except ValueError:
        return False


def read_member(archive, read_data, size, offset, length):
    if size is not None and (size < 0 or size > MAX_MEMBER):
        return {"status": "unsupported", "reason": "归档成员解压后须在 1 MiB 内。"}
    if size is not None and offset > size:
        return {"status": "out_of_range", "reason": "byte_offset 超出归档成员大小。"}
    digest = hashlib.sha256()
    preview = bytearray()
    buffer = c.create_string_buffer(64 * 1024)
    total = 0
    while True:
        count = read_data(archive, buffer, len(buffer))
        if count < 0:
            return {"status": "invalid", "reason": "归档成员无法解压或内容校验失败。"}
        if count == 0:
            break
        next_offset = total + count
        if next_offset > MAX_MEMBER:
            return {"status": "unsupported", "reason": "归档成员解压后须在 1 MiB 内。"}
        if size is not None and next_offset > size:
            return {"status": "invalid", "reason": "归档成员解压后超出声明的大小。"}
        chunk = buffer[:count]
        digest.update(chunk)
        start = max(offset, total)
        end = min(offset + length, next_offset)
        if end > start:
            preview.extend(chunk[start - total:end - total])
        total = next_offset
    if size is not None and total != size:
        return {"status": "invalid", "reason": "归档成员解压后的大小与声明不一致。"}
    if offset > total:
        return {"status": "out_of_range", "reason": "byte_offset 超出归档成员大小。"}
    return {"status": "ok", "member_size": total, "member_sha256": digest.hexdigest(),
            "preview": base64.b64encode(preview).decode("ascii")}


def load_libarchive(path):
    if sys.platform == "win32":
        return c.CDLL(path, winmode=0x1100) if path else c.CDLL("archiveint.dll", winmode=SYSTEM_LIBRARY_SEARCH)
    candidates = [path] if path else (
        ["/usr/lib/libarchive.2.dylib", "/usr/lib/libarchive.dylib"] if sys.platform == "darwin"
        else ["libarchive.so.13", "libarchive.so"]
    )
    for candidate in candidates:
        try:
            return c.CDLL(candidate)
        except OSError:
            continue
    raise OSError("libarchive unavailable")


def read_directory(data, variant, offset, limit, member_index=None, library_path=None):
    if rar_volume(data, variant):
        return {"status": "unsupported", "volume": True, "reason": "当前目录检查覆盖单卷 RAR。"}
    if variant == "7z" and not seven_zip_volume(data):
        return {"status": "invalid", "reason": "归档目录不完整或结构无效。", "detail": "缺少 7z 文件签名。"}

    try:
        lib = load_libarchive(library_path)
    except (OSError, TypeError):
        return {"status": "dependency_missing", "reason": "本机归档库 libarchive 不可用。可在 ctf-workbench.json 配置 libarchivePath。"}

    pointer = c.c_void_p

    def bind(name, result, *parameters):
        method = getattr(lib, name)
        method.restype = result
        method.argtypes = parameters
        return method

    formats = {"7z": "7zip", "RAR4": "rar", "RAR5": "rar5"}
    new_archive = bind("archive_read_new", pointer)
    free_archive = bind("archive_read_free", c.c_int, pointer)
    enable_format = bind("archive_read_support_format_" + formats[variant], c.c_int, pointer)
    open_memory = bind("archive_read_open_memory", c.c_int, pointer, pointer, c.c_size_t)
    next_header = bind("archive_read_next_header", c.c_int, pointer, c.POINTER(pointer))
    last_error = bind("archive_error_string", c.c_char_p, pointer)
    archive_encryption = bind("archive_read_has_encrypted_entries", c.c_int, pointer)
    entry_encryption = bind("archive_entry_is_encrypted", c.c_int, pointer)
    entry_name = bind("archive_entry_pathname_w", c.c_wchar_p, pointer)
    entry_size = bind("archive_entry_size", c.c_int64, pointer)
    size_is_set = bind("archive_entry_size_is_set", c.c_int, pointer)
    entry_type = bind("archive_entry_filetype", c.c_uint, pointer)
    if member_index is not None:
        entry_hardlink = bind("archive_entry_hardlink", c.c_char_p, pointer)
        read_data = bind("archive_read_data", c.c_ssize_t, pointer, pointer, c.c_size_t)
    archive = new_archive()
    if not archive:
        raise MemoryError("Unable to initialize libarchive")

    def failure(count):
        raw = last_error(archive)
        detail = raw.decode("utf-8", "replace") if raw else ""
        if count == 0 and archive_encryption(archive) > 0 and "encrypt" in detail.lower():
            return {"status": "encrypted_headers", "headers_encrypted": True, "reason": "归档目录头已加密。"}
        return {"status": "invalid", "reason": "归档目录不完整或结构无效。", "detail": detail[:160]}

    try:
        # The input bytes must outlive the memory-backed archive reader.
        backing = c.c_char_p(data)
        if enable_format(archive) != ARCHIVE_OK or open_memory(archive, c.cast(backing, pointer), len(data)) != ARCHIVE_OK:
            return failure(0)
        rows = []
        total = 0
        encrypted_members = 0
        kinds = {stat.S_IFREG: "file", stat.S_IFDIR: "directory", stat.S_IFLNK: "symbolic_link"}
        while True:
            entry = pointer()
            status = next_header(archive, c.byref(entry))
            if status == ARCHIVE_EOF:
                break
            if status not in (ARCHIVE_OK, ARCHIVE_WARN) or not entry.value:
                return failure(total)
            encrypted = bool(entry_encryption(entry))
            if member_index == total:
                if encrypted:
                    return {"status": "encrypted", "reason": "归档成员已加密。当前可以读取未加密成员。"}
                if entry_type(entry) != stat.S_IFREG or entry_hardlink(entry) is not None:
                    return {"status": "unsupported", "reason": "请选择归档中的普通文件成员。"}
                size = entry_size(entry) if size_is_set(entry) else None
                name = entry_name(entry)
                result = read_member(archive, read_data, size, offset, limit)
                return {**result, "name": name[:MAX_NAME] if name is not None else None}
            if member_index is None and offset <= total < offset + limit:
                size = entry_size(entry) if size_is_set(entry) else None
                name = entry_name(entry)
                rows.append({
                    "name": name[:MAX_NAME] if name is not None else None,
                    "kind": kinds.get(entry_type(entry), "other"),
                    "uncompressed_size": str(size) if size is not None and size > MAX_SAFE_INTEGER else size,
                    "encrypted": encrypted,
                })
            encrypted_members += encrypted
            total += 1
        if member_index is not None:
            return {"status": "out_of_range", "reason": "member_index 超出归档目录范围。"}
        if archive_encryption(archive) < 0:
            for row in rows:
                if not row["encrypted"]:
                    row["encrypted"] = None
            encrypted_members = None
        return {"status": "ok", "headers_encrypted": False, "encrypted_members": encrypted_members, "rows": rows, "total": total}
    finally:
        free_archive(archive)


def main():
    variant, offset, limit, library_path, *selection = sys.argv[1:]
    offset, limit = int(offset), int(limit)
    member_index = int(selection[0]) if selection else None
    if member_index is not None and (member_index < 0 or offset < 0 or not 1 <= limit <= MAX_MEMBER):
        raise ValueError("Invalid member read parameters")
    data = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise ValueError("Archive exceeds the attachment size limit")
    try:
        result = read_directory(data, variant, offset, limit, member_index, library_path or None)
    except AttributeError:
        result = {"status": "dependency_missing", "reason": "本机 libarchive 缺少所需接口。请检查已安装的归档库版本。"}
    print(json.dumps(result, ensure_ascii=True))


if __name__ == "__main__":
    main()
