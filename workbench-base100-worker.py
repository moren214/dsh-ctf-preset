from hashlib import sha256
import json
from pathlib import Path
import re
import sys
from time import perf_counter_ns

MAX_ITEMS = 8
MAX_BYTES = 4096
MAX_INPUT_CHARACTERS = 8192
MAX_LINE_BYTES = 512 * 1024
MAX_SOURCE_BYTES = 1024 * 1024


def load_base100(source, expected_sha256):
    with Path(source).open("rb") as module:
        content = module.read(MAX_SOURCE_BYTES + 1)
    if len(content) > MAX_SOURCE_BYTES or sha256(content).hexdigest() != expected_sha256:
        raise ValueError("工作台源码与已验证的 Base100 版本不一致。")
    namespace = {"__name__": "ctf_workbench_base100", "__file__": source}
    exec(compile(content, source, "exec"), namespace)
    return namespace["base100_encode"], namespace["base100_decode"]


def transform(item, encode, decode):
    operation = item.get("operation")
    try:
        value = item["input"]
        if not isinstance(value, str) or len(value) > MAX_INPUT_CHARACTERS:
            raise ValueError("输入须为不超过 8192 字符的文本。")
        if operation == "encode":
            encoding = item.get("input_encoding", "utf8")
            if encoding == "utf8":
                data = value.encode("utf-8")
            elif encoding == "hex" and re.fullmatch(r"(?:[0-9a-fA-F]{2})*", value):
                data = bytes.fromhex(value)
            else:
                raise ValueError("Hex 输入须由成对的十六进制数字组成。")
            if len(data) > MAX_BYTES:
                raise ValueError("待编码的字节数超过 4096。")
            return {
                "operation": operation, "status": "ok", "bytes": len(data),
                "base100": encode(data, "").decode("utf-8"),
            }
        if operation == "decode":
            data = decode(value.encode("utf-8"), "")
            if len(data) > MAX_BYTES:
                raise ValueError("解码所得的字节数超过 4096。")
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = None
            return {
                "operation": operation, "status": "ok", "bytes": len(data),
                "hex": data.hex(), "utf8": text,
            }
        raise ValueError("请选择 Base100 编码或解码。")
    except UnicodeError:
        return {"operation": operation, "status": "error", "reason": "输入不是有效的 UTF-8 文本。"}
    except ValueError as error:
        return {"operation": operation, "status": "error", "reason": str(error)}


def serve(encode, decode):
    while line := sys.stdin.buffer.readline(MAX_LINE_BYTES + 1):
        if len(line) > MAX_LINE_BYTES:
            raise ValueError("请求超过 Base100 的处理上限。")
        items = json.loads(line)["items"]
        if not isinstance(items, list) or not 1 <= len(items) <= MAX_ITEMS:
            raise ValueError("请选择 1 至 8 项 Base100 操作。")
        started = perf_counter_ns()
        results = [transform(item, encode, decode) for item in items]
        elapsed = (perf_counter_ns() - started) / 1_000_000
        print(json.dumps({"results": results, "workbench_ms": round(elapsed, 3)}, ensure_ascii=True), flush=True)


if __name__ == "__main__":
    try:
        encode, decode = load_base100(sys.argv[1], sys.argv[2])
    except OSError:
        print(json.dumps({"startup_error": "无法读取本机工作台的 Base100 源文件。"}), flush=True)
    except ValueError as error:
        print(json.dumps({"startup_error": str(error)}), flush=True)
    else:
        serve(encode, decode)
