#!/usr/bin/env python3
"""rev-disasm-worker.py: 多架构 ELF32/64、PE32/32+ 反汇编、控制流、字符串与特征快检 worker。

协议：stdin 每行一个 JSON 请求，stdout 每行一个 JSON 响应。
请求：{"file": "...", "operation": "disassemble"|"cfg"|"strings"|"triage", ...}
响应：{"ok": true, ...} 或 {"ok": false, "error": "..."}

仅依赖 Python 标准库；disassemble 与 cfg 额外需要 capstone；strings 与 triage 无需 capstone。
"""

import json
import re
import struct
import sys

ELF_MAGIC = b"\x7fELF"
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFDATA2MSB = 2

EM_386 = 3
EM_ARM = 40
EM_X86_64 = 62
EM_AARCH64 = 183
EM_RISCV = 243

SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_NOBITS = 8
SHT_DYNSYM = 11
SHF_EXECINSTR = 0x4
PT_LOAD = 1
PF_X = 1
STT_FUNC = 2
STT_GNU_IFUNC = 10

IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64
IMAGE_SCN_MEM_EXECUTE = 0x20000000

MAX_FILE_SIZE = 64 * 1024 * 1024
MAX_STRINGS = 200
MAX_STRING_TEXT = 256
DEFAULT_COUNT = 100
MIN_COUNT = 20
MAX_COUNT = 400
DEFAULT_MAX_BLOCKS = 64
MIN_MAX_BLOCKS = 1
MAX_MAX_BLOCKS = 256
DEFAULT_MAX_INSTRUCTIONS = 512
MIN_MAX_INSTRUCTIONS = 32
MAX_MAX_INSTRUCTIONS = 2048
DEFAULT_MIN_LENGTH = 6
MIN_STRING_LENGTH = 4
MAX_STRING_LENGTH = 64

STANDARD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

CRYPTO_SIGNATURES = [
    ("AES_SBOX", bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76])),
    ("AES_INV_SBOX", bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB])),
    ("SHA256_K_LE", struct.pack("<IIII", 0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5)),
    ("SHA256_K_BE", struct.pack(">IIII", 0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5)),
    ("SHA256_IV_LE", struct.pack("<IIII", 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A)),
    ("SHA256_IV_BE", struct.pack(">IIII", 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A)),
    ("MD5_IV_LE", struct.pack("<IIII", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)),
    ("CHACHA20_SIGMA", b"expand 32-byte k"),
    ("CHACHA20_TAU", b"expand 16-byte k"),
    ("TEA_DELTA_LE", struct.pack("<I", 0x9E3779B9)),
    ("TEA_DELTA_BE", struct.pack(">I", 0x9E3779B9)),
    ("TEA_NEG_DELTA_LE", struct.pack("<I", 0x61C88647)),
    ("CRC32_POLY_LE", struct.pack("<I", 0xEDB88320)),
]


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


def _capstone_for(architecture, big_endian=False, thumb=False):
    try:
        import capstone
    except ImportError:
        raise QueryError(
            "当前 Python 环境缺少 capstone，无法反汇编；strings 与 triage 查询仍可使用。"
        )
    endian = capstone.CS_MODE_BIG_ENDIAN if big_endian else capstone.CS_MODE_LITTLE_ENDIAN
    if architecture == "x86-64":
        return capstone, capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64), 15
    if architecture == "x86":
        return capstone, capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32), 15
    if architecture == "aarch64":
        return capstone, capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM | endian), 4
    if architecture == "arm":
        mode = (capstone.CS_MODE_THUMB if thumb else capstone.CS_MODE_ARM) | endian
        return capstone, capstone.Cs(capstone.CS_ARCH_ARM, mode), 4
    if architecture in ("riscv64", "riscv32"):
        if not hasattr(capstone, "CS_ARCH_RISCV"):
            raise QueryError("当前安装的 capstone 版本不支持 RISC-V。")
        base = capstone.CS_MODE_RISCV64 if architecture == "riscv64" else capstone.CS_MODE_RISCV32
        extra = getattr(capstone, "CS_MODE_RISCVC", 0)
        return capstone, capstone.Cs(capstone.CS_ARCH_RISCV, base | extra | endian), 4
    raise QueryError(f"暂不支持架构 {architecture} 的反汇编。")


class ElfFile:
    """支持 ELF32 / ELF64、x86 / x86-64 / ARM / AArch64 / RISC-V 的轻量解析器。"""

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
        if len(data) < 52:
            raise QueryError("ELF 文件头不完整，文件可能已损坏。")

        ei_class = data[4]
        if ei_class == ELFCLASS64:
            self.is_64 = True
            self.format = "elf64"
            min_ehdr = 64
        elif ei_class == ELFCLASS32:
            self.is_64 = False
            self.format = "elf32"
            min_ehdr = 52
        else:
            raise QueryError(f"不支持的 ELF 位宽标识：{ei_class}。")

        if len(data) < min_ehdr:
            raise QueryError("ELF 文件头不完整，文件可能已损坏。")

        ei_data = data[5]
        if ei_data == ELFDATA2LSB:
            self.endian_prefix = "<"
            self.big_endian = False
            self.endian = "little"
        elif ei_data == ELFDATA2MSB:
            self.endian_prefix = ">"
            self.big_endian = True
            self.endian = "big"
        else:
            raise QueryError(f"无效的 ELF 字节序标识：{ei_data}。")

        if data[6] != 1:
            raise QueryError("ELF 文件头版本无效。")

        ep = self.endian_prefix
        self.e_type, self.e_machine, version = struct.unpack_from(ep + "HHI", data, 16)
        if version != 1:
            raise QueryError("ELF 文件头版本无效。")

        arch_map = {
            EM_386: "x86",
            EM_ARM: "arm",
            EM_X86_64: "x86-64",
            EM_AARCH64: "aarch64",
            EM_RISCV: "riscv64" if self.is_64 else "riscv32",
        }
        self.architecture = arch_map.get(self.e_machine, f"unknown({self.e_machine})")

        if self.is_64:
            self.entry, self.phoff, self.shoff = struct.unpack_from(ep + "QQQ", data, 24)
            (ehsize, self.phentsize, phnum, self.shentsize, shnum, shstrndx) = (
                struct.unpack_from(ep + "HHHHHH", data, 52)
            )
            min_shdr = 64
        else:
            self.entry, self.phoff, self.shoff = struct.unpack_from(ep + "III", data, 24)
            (ehsize, self.phentsize, phnum, self.shentsize, shnum, shstrndx) = (
                struct.unpack_from(ep + "HHHHHH", data, 40)
            )
            min_shdr = 40

        if ehsize < min_ehdr or ehsize > len(data):
            raise QueryError("ELF 文件头长度无效。")

        self.program_count = phnum
        self.section_count = shnum
        self.section_names_index = shstrndx

        first_section = None
        if self.shoff != 0:
            if self.shentsize < min_shdr:
                raise QueryError("ELF 节头大小无效。")
            if self.shoff + self.shentsize > len(data):
                raise QueryError("ELF 节头表超出文件范围，文件可能已损坏。")
            sh_fmt = ep + ("IIQQQQIIQQ" if self.is_64 else "IIIIIIIIII")
            first_section = struct.unpack_from(sh_fmt, data, self.shoff)

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
        min_shdr = 64 if self.is_64 else 40
        if self.shentsize < min_shdr:
            raise QueryError("ELF 节头大小无效。")
        if count > len(data) // self.shentsize:
            raise QueryError("ELF 节头表超出文件范围，文件可能已损坏。")
        if self.shoff + count * self.shentsize > len(data):
            raise QueryError("ELF 节头表超出文件范围，文件可能已损坏。")

        sh_fmt = self.endian_prefix + ("IIQQQQIIQQ" if self.is_64 else "IIIIIIIIII")
        for index in range(count):
            offset = self.shoff + index * self.shentsize
            (name_offset, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
             sh_link, sh_info, sh_addralign, sh_entsize) = struct.unpack_from(sh_fmt, data, offset)
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
        min_phdr = 56 if self.is_64 else 32
        if self.phentsize < min_phdr:
            raise QueryError("ELF 程序头大小无效。")
        if count > len(data) // self.phentsize:
            raise QueryError("ELF 程序头表超出文件范围，文件可能已损坏。")
        if self.phoff + count * self.phentsize > len(data):
            raise QueryError("ELF 程序头表超出文件范围，文件可能已损坏。")

        ep = self.endian_prefix
        for index in range(count):
            offset = self.phoff + index * self.phentsize
            if self.is_64:
                (p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz,
                 p_memsz, _p_align) = struct.unpack_from(ep + "IIQQQQQQ", data, offset)
            else:
                (p_type, p_offset, p_vaddr, _p_paddr, p_filesz,
                 p_memsz, p_flags, _p_align) = struct.unpack_from(ep + "IIIIIIII", data, offset)
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
        sym_size = 24 if self.is_64 else 16
        ep = self.endian_prefix
        for section in self.sections:
            if section["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
                continue
            if section["entsize"] != sym_size or section["size"] == 0:
                continue
            if section["size"] % sym_size != 0:
                continue
            if not 0 <= section["link"] < len(self.sections):
                continue
            string_section = self.sections[section["link"]]
            if string_section["type"] != SHT_STRTAB:
                continue
            table = data[string_section["offset"]:
                         string_section["offset"] + string_section["size"]]
            for index in range(section["size"] // sym_size):
                offset = section["offset"] + index * sym_size
                if self.is_64:
                    (name_offset, info, _other, shndx, value,
                     size) = struct.unpack_from(ep + "IBBHQQ", data, offset)
                else:
                    (name_offset, value, size, info, _other,
                     shndx) = struct.unpack_from(ep + "IIIBBH", data, offset)
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

    def offset_for_address(self, address):
        for program in self.programs:
            if program["type"] != PT_LOAD or program["filesz"] == 0:
                continue
            if program["vaddr"] <= address < program["vaddr"] + program["filesz"]:
                return program["offset"] + address - program["vaddr"]
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

    def summary(self):
        section_names = [s["name"] for s in self.sections if s["name"]]
        return {
            "format": self.format,
            "architecture": self.architecture,
            "endian": self.endian,
            "entry": hex(self.entry),
            "section_count": len(self.sections),
            "stripped": not any(s["type"] == SHT_SYMTAB for s in self.sections),
            "has_debug_info": any(name.startswith(".debug") for name in section_names),
            "sections": [
                {
                    "name": s["name"],
                    "addr": hex(s["addr"]),
                    "offset": s["offset"],
                    "size": s["size"],
                    "executable": bool(s["flags"] & SHF_EXECINSTR),
                }
                for s in self.sections[:48]
                if s["name"]
            ],
        }

    def disassemble(self, request):
        count = _integer(request.get("count"), DEFAULT_COUNT, MIN_COUNT, MAX_COUNT, "count")
        address_arg = request.get("address")
        symbol_arg = _optional_name(request.get("symbol"), "symbol")
        section_arg = _optional_name(request.get("section"), "section")

        if address_arg is not None:
            raw_start = _parse_address(address_arg)
            thumb = self.architecture == "arm" and bool(raw_start & 1)
            start = raw_start & ~1 if thumb else raw_start
            program, offset = self.segment_for_address(start)
            available = program["filesz"] - (offset - program["offset"])
        elif symbol_arg is not None:
            raw_start = self.resolve_symbol(symbol_arg)
            thumb = self.architecture == "arm" and bool(raw_start & 1)
            start = raw_start & ~1 if thumb else raw_start
            program, offset = self.segment_for_address(start)
            available = program["filesz"] - (offset - program["offset"])
        elif section_arg is not None:
            section = self.section_by_name(section_arg)
            if section["type"] == SHT_NOBITS or section["size"] == 0:
                raise QueryError(f'节 "{section_arg}" 没有可反汇编的文件内容。')
            thumb = False
            start = section["addr"]
            offset = section["offset"]
            available = section["size"]
        else:
            raw_start = self.entry
            if raw_start == 0:
                raise QueryError(
                    "ELF 入口地址为 0，无法确定反汇编起点；请指定 symbol、address 或 section。"
                )
            thumb = self.architecture == "arm" and bool(raw_start & 1)
            start = raw_start & ~1 if thumb else raw_start
            program, offset = self.segment_for_address(start)
            available = program["filesz"] - (offset - program["offset"])

        _capstone, decoder, max_insn = _capstone_for(self.architecture, self.big_endian, thumb=thumb)
        decoder.detail = False
        window = min(available, count * max_insn)
        code = self.data[offset:offset + window]
        if not code:
            raise QueryError(f"起始地址 0x{start:x} 处没有可读取的代码字节。")

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
            raise QueryError(f"起始地址 0x{start:x} 处没有可反汇编的 {self.architecture} 指令。")

        result = {
            "format": self.format,
            "architecture": self.architecture,
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

    def control_flow(self, request):
        if self.architecture not in ("x86-64", "x86", "aarch64"):
            raise QueryError(f"cfg 目前支持 x86-64、x86 与 aarch64，当前为 {self.architecture}；请改用 disassemble 或 triage。")
        capstone, decoder, max_insn = _capstone_for(self.architecture, self.big_endian)
        decoder.detail = True
        is_x86 = self.architecture in ("x86-64", "x86")
        x86_const = getattr(capstone, "x86_const", None) if is_x86 else None
        arm64_const = getattr(capstone, "arm64_const", None) if self.architecture == "aarch64" else None

        max_blocks = _integer(
            request.get("max_blocks"), DEFAULT_MAX_BLOCKS,
            MIN_MAX_BLOCKS, MAX_MAX_BLOCKS, "max_blocks",
        )
        max_instructions = _integer(
            request.get("max_instructions"), DEFAULT_MAX_INSTRUCTIONS,
            MIN_MAX_INSTRUCTIONS, MAX_MAX_INSTRUCTIONS, "max_instructions",
        )
        symbol_arg = _optional_name(request.get("symbol"), "symbol")
        address_arg = request.get("address")
        if (symbol_arg is None) == (address_arg is None):
            raise QueryError("cfg 必须且只能指定 symbol 或 address。")

        symbol_size = 0
        function_name = symbol_arg
        if symbol_arg is not None:
            start = self.resolve_symbol(symbol_arg)
            matching = [
                symbol for symbol in self.symbols()
                if symbol["name"] == symbol_arg
                and symbol["value"] == start
                and symbol["type"] in (STT_FUNC, STT_GNU_IFUNC)
                and symbol["shndx"] != 0
            ]
            symbol_size = max((symbol["size"] for symbol in matching), default=0)
        else:
            start = _parse_address(address_arg)
            exact = [
                symbol for symbol in self.symbols()
                if symbol["value"] == start
                and symbol["type"] in (STT_FUNC, STT_GNU_IFUNC)
                and symbol["shndx"] != 0
            ]
            if exact:
                function_name = sorted(symbol["name"] for symbol in exact)[0]
                symbol_size = max(symbol["size"] for symbol in exact)

        program, code_offset = self.segment_for_address(start)
        segment_end = program["vaddr"] + min(program["filesz"], program["memsz"])
        boundary_source = "load_segment"
        if symbol_size > 0:
            natural_end = min(start + symbol_size, segment_end)
            boundary_source = "symbol_size"
        else:
            later_functions = [
                symbol["value"] for symbol in self.symbols()
                if symbol["type"] in (STT_FUNC, STT_GNU_IFUNC)
                and symbol["shndx"] != 0
                and start < symbol["value"] < segment_end
            ]
            if later_functions:
                natural_end = min(segment_end, min(later_functions))
                boundary_source = "next_function_symbol"
            else:
                natural_end = segment_end
        instruction_window_end = start + max_instructions * max_insn
        limit = min(natural_end, instruction_window_end)
        if limit == instruction_window_end and natural_end > instruction_window_end:
            boundary_source = "instruction_window"
        if limit <= start:
            raise QueryError(f"地址 0x{start:x} 没有可分析的函数内容。")
        limit_offset = code_offset + limit - start

        pending = [start]
        pending_index = 0
        queued = {start}
        leaders = {start}
        blocked_starts = set()
        decoded = {}
        edges = []
        calls = []
        data_references = []
        undecodable = []
        truncation_reasons = set()

        def in_function(address):
            return start <= address < limit

        def enqueue(address, leader=False):
            if not in_function(address) or address in blocked_starts:
                return False
            if leader and address not in leaders:
                if len(leaders) >= max_blocks:
                    blocked_starts.add(address)
                    truncation_reasons.add("max_blocks")
                    return False
                leaders.add(address)
            if address not in decoded and address not in queued:
                pending.append(address)
                queued.add(address)
            return True

        while pending_index < len(pending):
            current = pending[pending_index]
            pending_index += 1
            if current in decoded or current in blocked_starts:
                continue
            if len(decoded) >= max_instructions:
                truncation_reasons.add("max_instructions")
                break
            byte_offset = code_offset + current - start
            byte_end = min(byte_offset + max_insn, limit_offset)
            instruction = next(
                decoder.disasm(self.data[byte_offset:byte_end], current, count=1),
                None,
            )
            if instruction is None:
                if current == start:
                    raise QueryError(
                        f"地址 0x{start:x} 处没有可反汇编的 {self.architecture} 指令。"
                    )
                undecodable.append(hex(current))
                truncation_reasons.add("undecodable_bytes")
                continue

            next_address = instruction.address + instruction.size
            item = {
                "address": hex(instruction.address),
                "bytes": instruction.bytes.hex(),
                "mnemonic": instruction.mnemonic,
                "op_str": instruction.op_str,
            }
            decoded[current] = {
                "instruction": item,
                "next": next_address,
                "terminator": None,
            }

            mnem = instruction.mnemonic.lower()
            if self.architecture == "x86-64" and x86_const is not None:
                for operand in instruction.operands:
                    if (operand.type == x86_const.X86_OP_MEM
                            and operand.mem.base == x86_const.X86_REG_RIP):
                        target = next_address + operand.mem.disp
                        target_offset = self.offset_for_address(target)
                        data_references.append({
                            "source": hex(instruction.address),
                            "target": hex(target),
                            "kind": "rip_relative",
                            "size": operand.size,
                            "file_offset": target_offset,
                            "section": self.section_for_offset(target_offset)
                            if target_offset is not None else None,
                        })

            if is_x86:
                is_call = instruction.group(capstone.CS_GRP_CALL)
                is_jump = instruction.group(capstone.CS_GRP_JUMP)
                is_return = (
                    instruction.group(capstone.CS_GRP_RET)
                    or instruction.group(capstone.CS_GRP_IRET)
                )
                unconditional = mnem in ("jmp", "ljmp")
                is_trap = mnem in ("ud2", "hlt", "int3")
                direct_target = None
                for operand in instruction.operands:
                    if operand.type == x86_const.X86_OP_IMM:
                        direct_target = int(operand.imm)
                        break
            else:
                is_call = mnem in ("bl", "blr", "blraa", "blrab")
                is_return = mnem in ("ret", "retaa", "retab")
                is_jump = (
                    mnem == "b"
                    or mnem.startswith("b.")
                    or mnem in ("cbz", "cbnz", "tbz", "tbnz", "br", "braa", "brab")
                )
                unconditional = mnem in ("b", "br", "braa", "brab")
                is_trap = mnem in ("brk", "hlt", "udf")
                direct_target = None
                if arm64_const is not None:
                    for operand in reversed(instruction.operands):
                        if operand.type == arm64_const.ARM64_OP_IMM:
                            direct_target = int(operand.imm)
                            break

            if is_call:
                edge = {
                    "source": hex(instruction.address),
                    "target": hex(direct_target) if direct_target is not None else None,
                    "kind": "call" if direct_target is not None else "indirect_call",
                    "within_function": (
                        in_function(direct_target) if direct_target is not None else False
                    ),
                    "followed": False,
                }
                calls.append(edge)
                edges.append(edge)
                enqueue(next_address)
            elif is_jump:
                if direct_target is None:
                    edge = {
                        "source": hex(instruction.address),
                        "target": None,
                        "kind": "indirect_jump",
                        "within_function": False,
                        "followed": False,
                    }
                    edges.append(edge)
                    decoded[current]["terminator"] = "indirect_jump"
                else:
                    edge = {
                        "source": hex(instruction.address),
                        "target": hex(direct_target),
                        "kind": "jump" if unconditional else "branch",
                        "within_function": in_function(direct_target),
                        "followed": False,
                    }
                    if edge["within_function"]:
                        edge["followed"] = enqueue(direct_target, leader=True)
                    edges.append(edge)
                    decoded[current]["terminator"] = (
                        "jump" if unconditional else "conditional_jump"
                    )
                if not unconditional:
                    fallthrough = {
                        "source": hex(instruction.address),
                        "target": hex(next_address),
                        "kind": "fallthrough",
                        "within_function": in_function(next_address),
                        "followed": False,
                    }
                    if fallthrough["within_function"]:
                        fallthrough["followed"] = enqueue(next_address, leader=True)
                    edges.append(fallthrough)
            elif is_return:
                decoded[current]["terminator"] = "return"
            elif is_trap:
                decoded[current]["terminator"] = "trap"
            else:
                enqueue(next_address)

        if pending_index < len(pending) and len(decoded) >= max_instructions:
            truncation_reasons.add("max_instructions")

        blocks = []
        consumed = set()
        by_source = {}
        for edge in edges:
            by_source.setdefault(edge["source"], []).append(edge)

        for block_start in sorted(address for address in leaders if address in decoded):
            if block_start in consumed:
                continue
            block_instructions = []
            address = block_start
            while address in decoded and address not in consumed:
                if address != block_start and address in leaders:
                    break
                record = decoded[address]
                block_instructions.append(record["instruction"])
                consumed.add(address)
                if record["terminator"] is not None:
                    break
                address = record["next"]

            if not block_instructions:
                continue
            last = block_instructions[-1]
            last_record = decoded[int(last["address"], 16)]
            terminator = last_record["terminator"] or "fallthrough"
            successors = []
            if terminator in ("conditional_jump", "jump", "indirect_jump"):
                for edge in by_source.get(last["address"], []):
                    if edge["kind"] in ("branch", "jump", "fallthrough", "indirect_jump"):
                        successors.append({
                            "kind": edge["kind"],
                            "target": edge["target"],
                            "followed": edge["followed"],
                        })
            elif terminator == "fallthrough" and last_record["next"] in decoded:
                successors.append({
                    "kind": "fallthrough",
                    "target": hex(last_record["next"]),
                    "followed": True,
                })
            blocks.append({
                "start": hex(block_start),
                "end": hex(int(last["address"], 16) + len(bytes.fromhex(last["bytes"]))),
                "terminator": terminator,
                "successors": successors,
                "instructions": block_instructions,
            })

        if not decoded:
            raise QueryError(f"函数起始地址 0x{start:x} 没有可解码指令。")
        result = {
            "format": self.format,
            "architecture": self.architecture,
            "entry": hex(self.entry),
            "function": function_name,
            "start_address": hex(start),
            "limit_address": hex(limit),
            "boundary_source": boundary_source,
            "max_blocks": max_blocks,
            "max_instructions": max_instructions,
            "instruction_count": len(decoded),
            "block_count": len(blocks),
            "blocks": blocks,
            "edges": edges,
            "calls": calls,
            "data_references": data_references,
            "undecodable_addresses": undecodable,
            "truncated": bool(truncation_reasons),
            "truncation_reasons": sorted(truncation_reasons),
            "notes": [
                "按静态可达路径遍历；间接跳转目标保留为未解析边。",
                "嵌入代码的数据、混淆和跳转表可能造成静态控制流不完整。",
                "调用目标只记录引用，不递归分析被调用函数。",
            ],
        }
        if symbol_size > 0:
            result["symbol_size"] = symbol_size
        if self.section_for_offset(code_offset) is not None:
            result["section"] = self.section_for_offset(code_offset)
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

        return _scan_strings(self.data, ranges, minimum, section_arg,
                             self.address_for_offset, self.section_for_offset)


class PeFile:
    """轻量 PE32 / PE32+ 解析器（支持 x86 / x86-64 / AArch64 的反汇编、字符串与快检）。"""

    def __init__(self, data):
        self.data = data
        self.sections = []
        self.big_endian = False
        self.endian = "little"
        self._parse()

    def _parse(self):
        data = self.data
        if len(data) < 64 or data[:2] != b"MZ":
            raise QueryError("此文件不是 PE 文件。")
        lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if lfanew + 24 > len(data) or data[lfanew:lfanew + 4] != b"PE\x00\x00":
            raise QueryError("PE 文件头签名无效或被截断。")

        (machine, num_sections, _ts, _sym_ptr, _num_syms,
         opt_size, _chars) = struct.unpack_from("<HHIIIHH", data, lfanew + 4)
        arch_map = {
            IMAGE_FILE_MACHINE_I386: "x86",
            IMAGE_FILE_MACHINE_AMD64: "x86-64",
            IMAGE_FILE_MACHINE_ARM64: "aarch64",
        }
        self.machine = machine
        self.architecture = arch_map.get(machine, f"unknown(0x{machine:x})")

        opt_offset = lfanew + 24
        if opt_size < 28 or opt_offset + opt_size > len(data):
            raise QueryError("PE 可选头超出文件范围。")
        magic = struct.unpack_from("<H", data, opt_offset)[0]
        if magic == 0x10B:
            self.format = "pe32"
            self.is_64 = False
            if opt_size < 32:
                raise QueryError("PE32 可选头不完整。")
            entry_rva = struct.unpack_from("<I", data, opt_offset + 16)[0]
            self.image_base = struct.unpack_from("<I", data, opt_offset + 28)[0]
        elif magic == 0x20B:
            self.format = "pe32+"
            self.is_64 = True
            if opt_size < 32:
                raise QueryError("PE32+ 可选头不完整。")
            entry_rva = struct.unpack_from("<I", data, opt_offset + 16)[0]
            self.image_base = struct.unpack_from("<Q", data, opt_offset + 24)[0]
        else:
            raise QueryError(f"不支持的 PE 可选头魔数：0x{magic:x}。")

        self.entry_rva = entry_rva
        self.entry = self.image_base + entry_rva if entry_rva else 0

        sec_offset = opt_offset + opt_size
        if sec_offset + num_sections * 40 > len(data):
            raise QueryError("PE 节表超出文件范围。")
        for index in range(num_sections):
            off = sec_offset + index * 40
            raw_name, vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<8sIIII", data, off)
            chars = struct.unpack_from("<I", data, off + 36)[0]
            if raw_size > 0 and raw_ptr + raw_size > len(data):
                raw_size = max(0, len(data) - raw_ptr)
            name = raw_name.split(b"\0", 1)[0].decode("ascii", "replace")
            self.sections.append({
                "index": index,
                "name": name,
                "addr": self.image_base + vaddr,
                "rva": vaddr,
                "vsize": vsize,
                "offset": raw_ptr,
                "size": raw_size,
                "flags": chars,
                "executable": bool(chars & IMAGE_SCN_MEM_EXECUTE),
            })

    def section_by_name(self, name):
        for section in self.sections:
            if section["name"] == name:
                return section
        raise QueryError(f'未找到名为 "{name}" 的 PE 节。')

    def section_for_offset(self, offset):
        for section in self.sections:
            if section["size"] > 0 and section["offset"] <= offset < section["offset"] + section["size"]:
                return section["name"] or None
        return None

    def address_for_offset(self, offset):
        for section in self.sections:
            if section["size"] > 0 and section["offset"] <= offset < section["offset"] + section["size"]:
                return section["addr"] + (offset - section["offset"])
        return None

    def offset_for_address(self, address):
        for section in self.sections:
            span = max(section["vsize"], section["size"])
            if section["addr"] <= address < section["addr"] + span:
                delta = address - section["addr"]
                if delta < section["size"]:
                    return section["offset"] + delta
        return None

    def summary(self):
        return {
            "format": self.format,
            "architecture": self.architecture,
            "endian": self.endian,
            "image_base": hex(self.image_base),
            "entry": hex(self.entry),
            "section_count": len(self.sections),
            "sections": [
                {
                    "name": s["name"],
                    "addr": hex(s["addr"]),
                    "offset": s["offset"],
                    "size": s["size"],
                    "executable": s["executable"],
                }
                for s in self.sections[:48]
            ],
        }

    def disassemble(self, request):
        if request.get("symbol") is not None:
            raise QueryError("PE 文件暂不支持按 symbol 反汇编，请指定 address、section 或默认从入口点反汇编。")
        count = _integer(request.get("count"), DEFAULT_COUNT, MIN_COUNT, MAX_COUNT, "count")
        address_arg = request.get("address")
        section_arg = _optional_name(request.get("section"), "section")

        if address_arg is not None:
            start = _parse_address(address_arg)
            offset = self.offset_for_address(start)
            if offset is None:
                raise QueryError(f"地址 0x{start:x} 不在 PE 文件节映射范围内。")
            sec = next((s for s in self.sections if s["offset"] <= offset < s["offset"] + s["size"]), None)
            available = (sec["offset"] + sec["size"] - offset) if sec else (len(self.data) - offset)
        elif section_arg is not None:
            section = self.section_by_name(section_arg)
            if section["size"] == 0:
                raise QueryError(f'节 "{section_arg}" 没有可反汇编的文件内容。')
            start = section["addr"]
            offset = section["offset"]
            available = section["size"]
        else:
            if self.entry == 0:
                raise QueryError("PE 入口地址为 0，请指定 address 或 section。")
            start = self.entry
            offset = self.offset_for_address(start)
            if offset is None:
                raise QueryError(f"入口地址 0x{start:x} 不在 PE 文件节映射范围内。")
            sec = next((s for s in self.sections if s["offset"] <= offset < s["offset"] + s["size"]), None)
            available = (sec["offset"] + sec["size"] - offset) if sec else (len(self.data) - offset)

        _capstone, decoder, max_insn = _capstone_for(self.architecture, False)
        decoder.detail = False
        window = min(available, count * max_insn)
        code = self.data[offset:offset + window]
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
            raise QueryError(f"起始地址 0x{start:x} 处没有可反汇编的 {self.architecture} 指令。")
        result = {
            "format": self.format,
            "architecture": self.architecture,
            "entry": hex(self.entry),
            "start_address": hex(start),
            "instructions": instructions,
            "next_address": hex(next_address),
        }
        if section_arg is not None and address_arg is None:
            result["section"] = section_arg
        return result

    def control_flow(self, _request):
        raise QueryError("PE 文件暂不支持 cfg 控制流图，请使用 disassemble、strings 或 triage。")

    def strings(self, request):
        minimum = _integer(
            request.get("min_length"), DEFAULT_MIN_LENGTH,
            MIN_STRING_LENGTH, MAX_STRING_LENGTH, "min_length",
        )
        section_arg = _optional_name(request.get("section"), "section")
        if section_arg is not None:
            section = self.section_by_name(section_arg)
            if section["size"] == 0:
                raise QueryError(f'节 "{section_arg}" 没有可扫描的文件内容。')
            ranges = [section]
        else:
            ranges = sorted(
                (s for s in self.sections if s["size"] > 0 and not s["executable"]),
                key=lambda s: s["offset"],
            )
            if not ranges:
                ranges = None
        return _scan_strings(self.data, ranges, minimum, section_arg,
                             self.address_for_offset, self.section_for_offset)


def _scan_strings(data, ranges, minimum, section_arg, addr_fn, sec_fn):
    pattern = re.compile(b"[\x20-\x7e]{%d,}" % minimum)
    results = []
    truncated = False

    def add(offset, text, section_name):
        nonlocal truncated
        if len(results) >= MAX_STRINGS:
            truncated = True
            return False
        address = addr_fn(offset)
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
        for match in pattern.finditer(data):
            if not add(match.start(), match.group().decode("ascii"), sec_fn(match.start())):
                break
    else:
        for section in ranges:
            chunk = data[section["offset"]:section["offset"] + section["size"]]
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


def _parse_binary(data):
    if data[:4] == ELF_MAGIC:
        return ElfFile(data)
    if data[:2] == b"MZ":
        return PeFile(data)
    raise QueryError("仅支持 ELF（32/64 位）或 PE（PE32/PE32+）二进制文件；快速特征检测可使用 operation=triage。")


def triage_binary(data):
    parsed = None
    parse_error = None
    if data[:4] == ELF_MAGIC:
        try:
            parsed = ElfFile(data)
        except QueryError as exc:
            parse_error = str(exc)
    elif data[:2] == b"MZ":
        try:
            parsed = PeFile(data)
        except QueryError as exc:
            parse_error = str(exc)

    summary = parsed.summary() if parsed is not None else {
        "format": "raw",
        "architecture": "unknown",
        "section_count": 0,
        "sections": [],
    }
    section_names = [s["name"] for s in summary.get("sections", [])]
    addr_fn = parsed.address_for_offset if parsed is not None else (lambda _off: None)
    sec_fn = parsed.section_for_offset if parsed is not None else (lambda _off: None)

    markers = []
    if (b"UPX!" in data or b"UPX0" in data or b"UPX1" in data
            or any(n.upper().startswith("UPX") for n in section_names)):
        markers.append({"name": "UPX", "kind": "packer"})
    if b"MEI\x0c\x0b\x0a\x0b\x0e" in data or b"pyi-runtime-tmpdir" in data:
        markers.append({"name": "PyInstaller", "kind": "packer"})
    if b"\xff Go buildinf:" in data or ".gopclntab" in section_names:
        markers.append({"name": "Go", "kind": "runtime"})
    if b"rustc/" in data or b"core::panicking" in data or b"panicked at " in data:
        markers.append({"name": "Rust", "kind": "runtime"})
    if b"BSJB" in data and (b"mscoree.dll" in data or b"_CorExeMain" in data):
        markers.append({"name": ".NET", "kind": "runtime"})
    if b"GCC: (" in data:
        markers.append({"name": "GCC", "kind": "compiler"})
    if b"clang version" in data:
        markers.append({"name": "Clang", "kind": "compiler"})
    if b"VCRUNTIME140" in data or b"MSVCR" in data:
        markers.append({"name": "MSVC", "kind": "compiler"})
    if any(n.lower().startswith((".vmp", ".themida")) for n in section_names) or b"VMProtect" in data:
        markers.append({"name": "VMProtect/Themida", "kind": "protector"})

    crypto_hits = []
    for name, needle in CRYPTO_SIGNATURES:
        pos = 0
        found = 0
        while found < 4:
            idx = data.find(needle, pos)
            if idx < 0:
                break
            va = addr_fn(idx)
            crypto_hits.append({
                "algorithm": name,
                "file_offset": idx,
                "address": hex(va) if va is not None else None,
                "section": sec_fn(idx),
            })
            pos = idx + len(needle)
            found += 1

    b64_tables = []
    for match in re.finditer(rb"[A-Za-z0-9+/=_\-!@#$%^&*]{64}", data):
        text = match.group().decode("ascii")
        if len(set(text)) == 64:
            idx = match.start()
            va = addr_fn(idx)
            b64_tables.append({
                "kind": "standard" if text == STANDARD_B64 else "custom_alphabet",
                "file_offset": idx,
                "address": hex(va) if va is not None else None,
                "section": sec_fn(idx),
                "alphabet": text,
            })
            if len(b64_tables) >= 6:
                break

    result = {
        "operation": "triage",
        **summary,
        "markers": markers,
        "crypto_constants": crypto_hits,
        "base64_candidates": b64_tables,
    }
    if parse_error is not None:
        result["parse_warning"] = parse_error
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
    if operation not in ("disassemble", "cfg", "strings", "triage"):
        raise QueryError("operation 必须是 disassemble、cfg、strings 或 triage。")
    data = read_file(request.get("file"))
    if operation == "triage":
        return triage_binary(data)
    binary = _parse_binary(data)
    if operation == "disassemble":
        return binary.disassemble(request)
    if operation == "cfg":
        return binary.control_flow(request)
    return binary.strings(request)


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
