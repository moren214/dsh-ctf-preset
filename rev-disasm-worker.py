#!/usr/bin/env python3
"""rev-disasm-worker.py: x86-64 ELF 反汇编与字符串查询 worker。

协议：stdin 每行一个 JSON 请求，stdout 每行一个 JSON 响应。
请求：{"file": "...", "operation": "disassemble"|"strings", ...}
响应：{"ok": true, ...} 或 {"ok": false, "error": "..."}

只依赖 Python 标准库；disassemble 额外需要 capstone。ELF 结构自行解析，
不依赖 pyelftools，便于在精简环境里运行。
"""

import json
import os
import re
import struct
import sys

ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
EM_X86_64 = 62
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_NOBITS = 8
SHT_DYNSYM = 11
SHF_EXECINSTR = 0x4
PT_LOAD = 1
PF_X = 1
STT_FUNC = 2
STT_GNU_IFUNC = 10
MAX_FILE_SIZE = 64 * 1024 * 1024
MAX_STRINGS = 200
MAX_STRING_TEXT = 256
DEFAULT_COUNT = 100
MIN_COUNT = 20
MAX_COUNT = 400
DEFAULT_MIN_LENGTH = 6
MIN_STRING_LENGTH = 4
MAX_STRING_LENGTH = 64


class QueryError(Exception):
    """可以直接返回给调用方的查询错误。"""


def _cstring(blob, offset):
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\0", offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode("utf-8", "replace")


def _integer(value, default, minimum, maximum, label):
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise QueryError(f"{label} 必须是整数。")
    if value < minimum or value > maximum:
        raise QueryError(f"{label} 必须在 {minimum} 到 {maximum} 之间。")
    return value


def _parse_address(value):
    if isinstance(value, bool):
        raise QueryError("address 必须是十六进制（0x...）或十进制整数。")
    if isinstance(value, int):
        address = value
    elif isinstance(value, str):
        text = value.strip().lower()
        if not text:
            raise QueryError("address 不能为空。")
        try:
            address = int(text, 16) if text.startswith("0x") else int(text, 10)
        except ValueError:
            raise QueryError("address 必须是十六进制（0x...）或十进制整数。")
    else:
        raise QueryError("address 必须是十六进制（0x...）或十进制整数。")
    if address < 0 or address > 0xFFFFFFFFFFFFFFFF:
        raise QueryError("address 超出 64 位地址范围。")
    return address


def _optional_name(value, label):
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise QueryError(f"{label} 必须是非空字符串。")
    if len(value) > 256 or "\0" in value:
        raise QueryError(f"{label} 包含非法字符或过长。")
    return value


class ElfFile:
    """最小化的 ELF64 小端 x86-64 解析器。"""

    def __init__(self, data):
        self.data = data
        self.sections = []
        self.programs = []
        self._symbols = None
        self._section_names = b""
        self._parse_header()
        self._parse_sections()
        self._parse_programs()

    def _parse_header(self):
        data = self.data
        if len(data) < 4 or data[:4] != ELF_MAGIC:
            raise QueryError("此文件不是 ELF 文件。")
        if len(data) < 64:
            raise QueryError("ELF 文件头不完整，文件可能已损坏。")
        if data[4] != ELFCLASS64:
            raise QueryError("仅支持 64 位 ELF 文件（当前为 32 位 ELF）。")
        if data[5] != ELFDATA2LSB:
            raise QueryError("仅支持小端 ELF 文件。")
        if data[6] != 1:
            raise QueryError("ELF 文件头版本无效。")

        self.e_type, self.e_machine, version = struct.unpack_from("<HHI", data, 16)
        if version != 1:
            raise QueryError("ELF 文件头版本无效。")
        if self.e_machine != EM_X86_64:
            raise QueryError(
                f"仅支持 x86-64 ELF 文件（当前机器类型为 {self.e_machine}）。"
            )

        self.entry, self.phoff, self.shoff = struct.unpack_from("<QQQ", data, 24)
        (ehsize, self.phentsize, phnum, self.shentsize, shnum, shstrndx) = (
            struct.unpack_from("<HHHHHH", data, 52)
        )
        if ehsize < 64 or ehsize > len(data):
            raise QueryError("ELF 文件头长度无效。")

        self.program_count = phnum
        self.section_count = shnum
        self.section_names_index = shstrndx

        first_section = None
        if self.shoff != 0:
            if self.shentsize < 64:
                raise QueryError("ELF 节头大小无效。")
            if self.shoff + self.shentsize > len(data):
                raise QueryError("ELF 节头表超出文件范围，文件可能已损坏。")
            first_section = struct.unpack_from("<IIQQQQIIQQ", data, self.shoff)

        if self.shoff != 0 and shnum == 0 and first_section is not None:
            self.section_count = first_section[5]
        if shstrndx == 0xFFFF and first_section is not None:
            self.section_names_index = first_section[6]
        if phnum == 0xFFFF and first_section is not None:
            self.program_count = first_section[7]

    def _parse_sections(self):
        data = self.data
        count = self.section_count
        if self.shoff == 0 or count == 0:
            return
        if self.shentsize < 64:
            raise QueryError("ELF 节头大小无效。")
        if count > len(data) // self.shentsize:
            raise QueryError("ELF 节头表超出文件范围，文件可能已损坏。")
        if self.shoff + count * self.shentsize > len(data):
            raise QueryError("ELF 节头表超出文件范围，文件可能已损坏。")

        for index in range(count):
            offset = self.shoff + index * self.shentsize
            (name_offset, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
             sh_link, sh_info, sh_addralign, sh_entsize) = struct.unpack_from(
                "<IIQQQQIIQQ", data, offset
            )
            if sh_type != SHT_NOBITS and sh_size > 0:
                if sh_offset + sh_size > len(data):
                    raise QueryError("ELF 节内容超出文件范围，文件可能已损坏。")
            self.sections.append({
                "index": index,
                "name": "",
                "name_offset": name_offset,
                "type": sh_type,
                "flags": sh_flags,
                "addr": sh_addr,
                "offset": sh_offset,
                "size": sh_size,
                "link": sh_link,
                "info": sh_info,
                "align": sh_addralign,
                "entsize": sh_entsize,
            })

        if 0 <= self.section_names_index < len(self.sections):
            name_section = self.sections[self.section_names_index]
            if name_section["type"] == SHT_STRTAB and name_section["offset"] <= len(data):
                end = min(name_section["offset"] + name_section["size"], len(data))
                self._section_names = data[name_section["offset"]:end]

        for section in self.sections:
            section["name"] = _cstring(self._section_names, section["name_offset"])

    def _parse_programs(self):
        data = self.data
        count = self.program_count
        if self.phoff == 0 or count == 0:
            return
        if self.phentsize < 56:
            raise QueryError("ELF 程序头大小无效。")
        if count > len(data) // self.phentsize:
            raise QueryError("ELF 程序头表超出文件范围，文件可能已损坏。")
        if self.phoff + count * self.phentsize > len(data):
            raise QueryError("ELF 程序头表超出文件范围，文件可能已损坏。")

        for index in range(count):
            offset = self.phoff + index * self.phentsize
            (p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz,
             p_memsz, p_align) = struct.unpack_from("<IIQQQQQQ", data, offset)
            if p_type == PT_LOAD and p_filesz > 0:
                if p_offset + p_filesz > len(data) or p_filesz > p_memsz:
                    raise QueryError("ELF 加载段超出文件范围，文件可能已损坏。")
            self.programs.append({
                "type": p_type,
                "flags": p_flags,
                "offset": p_offset,
                "vaddr": p_vaddr,
                "filesz": p_filesz,
                "memsz": p_memsz,
            })

    def symbols(self):
        if self._symbols is not None:
            return self._symbols
        result = []
        data = self.data
        for section in self.sections:
            if section["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
                continue
            if section["entsize"] != 24 or section["size"] == 0:
                continue
            if section["size"] % 24 != 0:
                continue
            if not 0 <= section["link"] < len(self.sections):
                continue
            string_section = self.sections[section["link"]]
            if string_section["type"] != SHT_STRTAB:
                continue
            table = data[string_section["offset"]:
                         string_section["offset"] + string_section["size"]]
            for index in range(section["size"] // 24):
                offset = section["offset"] + index * 24
                (name_offset, info, other, shndx, value,
                 size) = struct.unpack_from("<IBBHQQ", data, offset)
                if name_offset == 0:
                    continue
                name = _cstring(table, name_offset)
                if not name:
                    continue
                result.append({
                    "name": name,
                    "type": info & 0xF,
                    "bind": info >> 4,
                    "shndx": shndx,
                    "value": value,
                    "size": size,
                })
        self._symbols = result
        return result

    def section_by_name(self, name):
        for section in self.sections:
            if section["name"] == name:
                return section
        raise QueryError(f'未找到名为 "{name}" 的节。')

    def section_for_offset(self, offset):
        for section in self.sections:
            if section["type"] == SHT_NOBITS or section["size"] == 0:
                continue
            if section["offset"] <= offset < section["offset"] + section["size"]:
                return section["name"] or None
        return None

    def address_for_offset(self, offset):
        for program in self.programs:
            if program["type"] != PT_LOAD or program["filesz"] == 0:
                continue
            if program["offset"] <= offset < program["offset"] + program["filesz"]:
                return program["vaddr"] + offset - program["offset"]
        return None

    def segment_for_address(self, address):
        hits = [
            program for program in self.programs
            if program["type"] == PT_LOAD
            and program["vaddr"] <= address < program["vaddr"] + program["memsz"]
        ]
        if not hits:
            raise QueryError(f"地址 0x{address:x} 不在 ELF 的加载段（PT_LOAD）内。")
        executable = [program for program in hits if program["flags"] & PF_X]
        program = (executable or hits)[0]
        delta = address - program["vaddr"]
        if delta >= program["filesz"]:
            raise QueryError(
                f"地址 0x{address:x} 位于仅内存区域（BSS 或未初始化段），没有可读取的字节。"
            )
        if not program["flags"] & PF_X:
            raise QueryError(f"地址 0x{address:x} 不在可执行段内。")
        return program, program["offset"] + delta

    def resolve_symbol(self, name):
        named = [symbol for symbol in self.symbols() if symbol["name"] == name]
        if not named:
            raise QueryError(f'未找到符号 "{name}"。')
        functions = [
            symbol for symbol in named
            if symbol["type"] in (STT_FUNC, STT_GNU_IFUNC)
            and symbol["shndx"] != 0 and symbol["value"] != 0
        ]
        if not functions:
            defined = [symbol for symbol in named if symbol["shndx"] != 0]
            if defined:
                raise QueryError(
                    f'符号 "{name}" 不是函数符号（STT_FUNC），请改用 address 指定地址。'
                )
            raise QueryError(
                f'符号 "{name}" 是未定义符号（导入符号），没有可反汇编的地址。'
            )
        values = sorted({symbol["value"] for symbol in functions})
        if len(values) > 1:
            raise QueryError(f'符号 "{name}" 对应多个函数地址，请改用 address 指定。')
        return values[0]

    def disassemble(self, request):
        try:
            import capstone
        except ImportError:
            raise QueryError(
                "当前 Python 环境缺少 capstone，无法反汇编；strings 查询仍可使用。"
            )

        count = _integer(request.get("count"), DEFAULT_COUNT, MIN_COUNT, MAX_COUNT, "count")
        address_arg = request.get("address")
        symbol_arg = _optional_name(request.get("symbol"), "symbol")
        section_arg = _optional_name(request.get("section"), "section")
        address = None

        if address_arg is not None:
            start = _parse_address(address_arg)
            program, offset = self.segment_for_address(start)
            available = program["filesz"] - (offset - program["offset"])
        elif symbol_arg is not None:
            start = self.resolve_symbol(symbol_arg)
            program, offset = self.segment_for_address(start)
            available = program["filesz"] - (offset - program["offset"])
        elif section_arg is not None:
            section = self.section_by_name(section_arg)
            if section["type"] == SHT_NOBITS or section["size"] == 0:
                raise QueryError(f'节 "{section_arg}" 没有可反汇编的文件内容。')
            start = section["addr"]
            offset = section["offset"]
            available = section["size"]
        else:
            start = self.entry
            if start == 0:
                raise QueryError(
                    "ELF 入口地址为 0，无法确定反汇编起点；请指定 symbol、address 或 section。"
                )
            program, offset = self.segment_for_address(start)
            available = program["filesz"] - (offset - program["offset"])

        window = min(available, count * 15)
        code = self.data[offset:offset + window]
        if not code:
            raise QueryError(f"起始地址 0x{start:x} 处没有可读取的代码字节。")

        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = False
        instructions = []
        next_address = start
        for instruction in decoder.disasm(code, start):
            instructions.append({
                "address": hex(instruction.address),
                "bytes": instruction.bytes.hex(),
                "mnemonic": instruction.mnemonic,
                "op_str": instruction.op_str,
            })
            next_address = instruction.address + instruction.size
            if len(instructions) >= count:
                break
        if not instructions:
            raise QueryError(f"起始地址 0x{start:x} 处没有可反汇编的 x86-64 指令。")

        result = {
            "architecture": "x86-64",
            "entry": hex(self.entry),
            "start_address": hex(start),
            "instructions": instructions,
            "next_address": hex(next_address),
        }
        if symbol_arg is not None:
            result["symbol"] = symbol_arg
        if section_arg is not None and address_arg is None and symbol_arg is None:
            result["section"] = section_arg
        return result

    def strings(self, request):
        minimum = _integer(
            request.get("min_length"), DEFAULT_MIN_LENGTH,
            MIN_STRING_LENGTH, MAX_STRING_LENGTH, "min_length",
        )
        section_arg = _optional_name(request.get("section"), "section")

        if section_arg is not None:
            section = self.section_by_name(section_arg)
            if section["type"] == SHT_NOBITS or section["size"] == 0:
                raise QueryError(f'节 "{section_arg}" 没有可扫描的文件内容。')
            ranges = [section]
        else:
            ranges = sorted(
                (
                    section for section in self.sections
                    if section["type"] != SHT_NOBITS
                    and section["size"] > 0
                    and not section["flags"] & SHF_EXECINSTR
                ),
                key=lambda section: section["offset"],
            )
            if not ranges:
                ranges = None

        pattern = re.compile(b"[\x20-\x7e]{%d,}" % minimum)
        results = []
        truncated = False

        def add(offset, text, section_name):
            nonlocal truncated
            if len(results) >= MAX_STRINGS:
                truncated = True
                return False
            address = self.address_for_offset(offset)
            if len(text) > MAX_STRING_TEXT:
                text = text[:MAX_STRING_TEXT] + "..."
            results.append({
                "address": hex(address) if address is not None else None,
                "file_offset": offset,
                "section": section_name or None,
                "text": text,
            })
            return True

        if ranges is None:
            for match in pattern.finditer(self.data):
                if not add(match.start(), match.group().decode("ascii"),
                           self.section_for_offset(match.start())):
                    break
        else:
            for section in ranges:
                chunk = self.data[section["offset"]:section["offset"] + section["size"]]
                for match in pattern.finditer(chunk):
                    if not add(section["offset"] + match.start(),
                               match.group().decode("ascii"), section["name"]):
                        break
                if truncated:
                    break

        result = {
            "min_length": minimum,
            "strings": results,
            "truncated": truncated,
        }
        if section_arg is not None:
            result["section"] = section_arg
        return result


def read_file(path):
    if not isinstance(path, str) or not path:
        raise QueryError("请求缺少 file 路径。")
    if "\0" in path:
        raise QueryError("file 路径包含非法字符。")
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_FILE_SIZE + 1)
    except OSError as error:
        reason = error.strerror or str(error)
        raise QueryError(f"无法读取文件 {path}：{reason}")
    if len(data) > MAX_FILE_SIZE:
        raise QueryError("文件超过 64 MiB，无法处理。")
    return data


def handle_request(request):
    if not isinstance(request, dict):
        raise QueryError("请求必须是 JSON 对象。")
    operation = request.get("operation")
    if operation not in ("disassemble", "strings"):
        raise QueryError("operation 必须是 disassemble 或 strings。")
    data = read_file(request.get("file"))
    elf = ElfFile(data)
    if operation == "disassemble":
        return elf.disassemble(request)
    return elf.strings(request)


def main():
    try:
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except Exception:
            reply = {"ok": False, "error": "请求不是合法的 JSON。"}
        else:
            try:
                reply = {"ok": True, **handle_request(request)}
            except QueryError as error:
                reply = {"ok": False, "error": str(error)}
            except Exception as error:  # 兜底：worker 不能因坏输入崩溃
                reply = {"ok": False, "error": f"反汇编工作台内部错误：{error}"}
        sys.stdout.write(
            json.dumps(reply, ensure_ascii=True, separators=(",", ":")) + "\n"
        )
        sys.stdout.flush()


if __name__ == "__main__":
    main()
