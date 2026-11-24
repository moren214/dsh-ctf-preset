"""Inspect a local attachment snapshot read from standard input."""

import hashlib
import base64
import io
import json
import pickletools
import re
import sqlite3
import struct
import sys
import zipfile
import xml.etree.ElementTree as ET
import zlib

MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_IMAGE_PIXELS = 16 * 1024 * 1024
MAX_IMAGE_DIMENSION = 16384
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
IMAGE_FORMATS = ("PNG", "JPEG", "GIF", "BMP", "TIFF", "WEBP")
MAX_PNG_SAMPLE_BYTES = 32 * 1024 * 1024


class InvalidMedia(ValueError):
    pass


class MissingDependency(ImportError):
    pass


def checked_size(image):
    width, height = image.size
    if width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION or width * height > MAX_IMAGE_PIXELS:
        raise InvalidMedia("图像超过 16384 单边像素或 16777216 总像素的上限。")
    return width, height


def local_image(data, formats):
    try:
        from PIL import Image
    except (ImportError, OSError) as error:
        raise MissingDependency("Pillow") from error

    Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
    image = Image.open(io.BytesIO(data), formats=formats)
    try:
        checked_size(image)
    except InvalidMedia:
        image.close()
        raise
    return image


def png_samples(image, color, depth):
    if color == 0:
        if (depth, image.mode) in ((1, "1"), (2, "L"), (4, "L"), (8, "L")):
            return ["L"], 255 // ((1 << depth) - 1)
        if depth == 16 and image.mode in ("I;16", "I;16B", "I"):
            return ["L"], 1
    if color == 3 and depth in (1, 2, 4, 8) and image.mode == "P":
        return ["P"], 1
    modes = {2: "RGB", 4: "LA", 6: "RGBA"}
    if depth == 8 and modes.get(color) == image.mode:
        return list(image.mode), 1
    raise InvalidMedia("此 PNG 通道和位深组合暂不能无损读取样本。")


def selected_pixels(image, bounds, start, end, channels, divisor):
    pixels = image.load()
    for index in range(start, end):
        row, column = divmod(index, bounds["width"])
        x, y = bounds["x"] + column, bounds["y"] + row
        sample = pixels[x, y]
        if isinstance(sample, int):
            sample = (sample,)
        yield x, y, [sample[channel] // divisor for channel in channels]


def png16_data(data, width, height, channels):
    if data[26:29] != b"\0\0\0":
        raise InvalidMedia("多通道 16 位 PNG 原始样本读取支持非交错的标准 PNG。")
    expected = (width * channels * 2 + 1) * height
    if expected > MAX_PNG_SAMPLE_BYTES:
        raise InvalidMedia("16 位 PNG 展开的样本超过 32 MiB。")
    pieces = []
    cursor = 8
    while cursor + 12 <= len(data):
        length = int.from_bytes(data[cursor:cursor + 4], "big")
        end = cursor + 8 + length
        if end + 4 > len(data):
            raise InvalidMedia("PNG 数据块被截断。")
        code = data[cursor + 4:cursor + 8]
        if code == b"IDAT":
            content = memoryview(data)[cursor + 4:end]
            if zlib.crc32(content) != int.from_bytes(data[end:end + 4], "big"):
                raise InvalidMedia("PNG IDAT 校验失败。")
            pieces.append(content[4:])
        if code == b"IEND":
            break
        cursor = end + 4
    else:
        raise InvalidMedia("PNG 缺少完整的 IEND。")
    decoder = zlib.decompressobj()
    pixels = decoder.decompress(b"".join(pieces), expected + 1)
    if len(pixels) != expected or not decoder.eof or decoder.unused_data:
        raise InvalidMedia("PNG 的 16 位样本长度与图像尺寸不符。")
    return pixels


def paeth(left, top, corner):
    predicted = left + top - corner
    a, b, c = abs(predicted - left), abs(predicted - top), abs(predicted - corner)
    if a <= b and a <= c:
        return left
    return top if b <= c else corner


def png16_row(pixels, row, stride, pixel_size, previous):
    offset = row * (stride + 1)
    filter_id = pixels[offset]
    current = bytearray(pixels[offset + 1:offset + 1 + stride])
    if filter_id == 0:
        return current
    if filter_id > 4:
        raise InvalidMedia("PNG 行使用了无效过滤器。")
    for index, value in enumerate(current):
        left = current[index - pixel_size] if index >= pixel_size else 0
        top = previous[index]
        corner = previous[index - pixel_size] if index >= pixel_size else 0
        if filter_id == 1:
            prior = left
        elif filter_id == 2:
            prior = top
        elif filter_id == 3:
            prior = (left + top) // 2
        else:
            prior = paeth(left, top, corner)
        current[index] = (value + prior) & 255
    return current


def selected_png16(data, width, height, native, bounds, start, end, channels):
    pixel_size = native * 2
    stride = width * pixel_size
    pixels = png16_data(data, width, height, native)
    current = bytearray(stride)
    decoded_row = -1
    for index in range(start, end):
        row, column = divmod(index, bounds["width"])
        x, y = bounds["x"] + column, bounds["y"] + row
        while decoded_row < y:
            decoded_row += 1
            current = png16_row(pixels, decoded_row, stride, pixel_size, current)
        offsets = [x * pixel_size + channel * 2 for channel in channels]
        yield x, y, [(current[offset] << 8) | current[offset + 1] for offset in offsets]


def read_png(data, request):
    if len(data) < 33 or not data.startswith(PNG_SIGNATURE) or data[12:16] != b"IHDR":
        raise InvalidMedia("请选择带有效文件头的 PNG 图像。")
    depth, color = data[24], data[25]
    with local_image(data, ("PNG",)) as image:
        frame_index = request.get("frame_index", 0)
        frames = getattr(image, "n_frames", 1)
        animated = bool(getattr(image, "is_animated", False))
        default_image = bool(image.info.get("default_image", False))
        if frame_index >= frames:
            raise InvalidMedia("frame_index 超出 PNG 帧范围。")
        image.seek(frame_index)
        width, height = checked_size(image)
        composite = animated and (frame_index > 0 or not default_image)
        raw16 = not composite and depth == 16 and color in (2, 4, 6)
        if composite:
            view = image.convert("RGBA")
            native_channels, divisor, sample_depth = list("RGBA"), 1, 8
        elif raw16:
            native_channels, divisor, sample_depth = list({2: "RGB", 4: "LA", 6: "RGBA"}[color]), 1, depth
        else:
            native_channels, divisor = png_samples(image, color, depth)
            sample_depth = depth
        channels = request.get("channels", native_channels)
        if any(channel not in native_channels for channel in channels):
            raise InvalidMedia("图片的原始通道为 " + ", ".join(native_channels) + "。")
        bounds = request.get("region", {"x": 0, "y": 0, "width": width, "height": height})
        if bounds["x"] + bounds["width"] > width or bounds["y"] + bounds["height"] > height:
            raise InvalidMedia("所选像素区域超出 PNG 尺寸。")
        count = bounds["width"] * bounds["height"]
        bitstream = request["operation"] == "bitstream"
        if bitstream:
            total_bits = count * len(channels)
            bit_start = request["bit_offset"]
            if bit_start > total_bits:
                raise InvalidMedia("bit_offset 超出所选像素位流。")
            bit_end = min(bit_start + request["bit_count"], total_bits)
            start = bit_start // len(channels)
            end = min((bit_end + len(channels) - 1) // len(channels), count)
        else:
            start = request["pixel_offset"]
            if start > count:
                raise InvalidMedia("pixel_offset 超出所选像素区域。")
            end = min(start + request["pixel_count"], count)
        indices = [native_channels.index(channel) for channel in channels]
        if raw16:
            samples = selected_png16(data, width, height, len(native_channels), bounds, start, end, indices)
        else:
            samples = selected_pixels(view if composite else image, bounds, start, end, indices, divisor)
        report = {
            "status": "ok", "format": "PNG", "width": width, "height": height,
            "operation": request["operation"],
            "frame_index": frame_index, "frame_count": frames, "bit_depth": sample_depth, "source_bit_depth": depth,
            "frame_semantics": "composited_rgba" if composite else "default_image" if default_image else "native_samples",
            "region": bounds, "channels": channels,
            **({} if bitstream else {
                "pixel_offset": start, "pixel_count": end - start,
                "next_pixel_offset": end if end < count else None,
            }),
        }
        if request["operation"] == "pixels":
            report["pixels"] = [{"x": x, "y": y, "values": values} for x, y, values in samples]
            return report

        bit_index = request["bit_index"]
        if bit_index >= sample_depth:
            raise InvalidMedia("bit_index 必须小于当前帧的样本位深。")
        bit_order = request["bit_order"]
        if bitstream:
            bit_count = bit_end - bit_start
            packed = bytearray((bit_count + 7) // 8)
            logical = start * len(channels)
            for _, _, values in samples:
                for sample in values:
                    if bit_start <= logical < bit_end:
                        local = logical - bit_start
                        byte_index, bit = divmod(local, 8)
                        shift = 7 - bit if bit_order == "msb_first" else bit
                        packed[byte_index] |= ((sample >> bit_index) & 1) << shift
                    logical += 1
            return {
                **report, "bit_index": bit_index, "bit_order": bit_order,
                "bit_offset": bit_start, "bit_count": bit_count, "total_bit_count": total_bits,
                "next_bit_offset": bit_end if bit_end < total_bits else None,
                "padding_bits": (-bit_count) % 8, "hex": packed.hex(),
                "packed_sha256": hashlib.sha256(packed).hexdigest(),
            }
        bit_count = (end - start) * len(channels)
        packed = bytearray((bit_count + 7) // 8)
        for index, sample in enumerate(value for _, _, values in samples for value in values):
            byte_index, bit = divmod(index, 8)
            shift = 7 - bit if bit_order == "msb_first" else bit
            packed[byte_index] |= ((sample >> bit_index) & 1) << shift
        return {
            **report, "bit_index": bit_index, "bit_order": bit_order, "bit_count": bit_count,
            "padding_bits": (-bit_count) % 8, "hex": packed.hex(),
            "packed_sha256": hashlib.sha256(packed).hexdigest(),
        }


def inspect_image(data, request):
    with local_image(data, IMAGE_FORMATS) as image:
        frame = request.get("frame_index", 0)
        frames = getattr(image, "n_frames", 1)
        if frame >= frames:
            raise InvalidMedia("frame_index 超出图像帧范围。")
        image.seek(frame)
        width, height = checked_size(image)
        report = {"status": "ok", "format": image.format, "width": width, "height": height,
                  "mode": image.mode, "frame_index": frame, "frame_count": frames,
                  "animated": bool(getattr(image, "is_animated", False))}
        duration = image.info.get("duration")
        if isinstance(duration, (int, float)) and 0 <= duration < 86_400_000:
            report["frame_duration_ms"] = duration
        return report


def read_pdf(data, request):
    if b"%PDF-" not in data[:1024]:
        raise InvalidMedia("未在文件开头找到 PDF 标记。")
    try:
        import pymupdf
    except (ImportError, OSError) as error:
        raise MissingDependency("PyMuPDF") from error

    with pymupdf.open(stream=data, filetype="pdf") as document:
        if document.needs_pass:
            return {"status": "encrypted", "format": "PDF", "reason": "PDF 内容需要密码。"}
        metadata = document.metadata or {}
        fields = {key: value[:512] for key, value in metadata.items() if isinstance(value, str) and value}
        count = document.page_count
        action = request.get("pdf_action", "inspect")
        if action == "list_attachments":
            total = document.embfile_count()
            rows = []
            for index in range(min(total, 64)):
                info = document.embfile_info(index) or {}
                rows.append({"attachment_index": index, "name": str(info.get("filename") or info.get("ufilename") or f"attachment-{index}")[:256],
                             "description": str(info.get("desc") or "")[:256], "size": int(info.get("size", 0))})
            return {"status": "ok", "format": "PDF", "attachment_count": total,
                    "attachments": rows, "attachments_truncated": total > len(rows), "metadata": fields}
        if action == "read_attachment":
            index = request["attachment_index"]
            total = document.embfile_count()
            if index >= total:
                raise InvalidMedia("attachment_index 超出 PDF 附件数量。")
            info = document.embfile_info(index) or {}
            if int(info.get("size", 0)) > 1024 * 1024:
                raise InvalidMedia("PDF 嵌入附件超过 1 MiB 派生结果上限。")
            content = document.embfile_get(index)
            if len(content) > 1024 * 1024:
                raise InvalidMedia("PDF 嵌入附件超过 1 MiB 派生结果上限。")
            return {"status": "ok", "format": "PDF", "attachment_index": index,
                    "name": str(info.get("filename") or info.get("ufilename") or f"attachment-{index}")[:256],
                    "size": len(content), "artifact_sha256": hashlib.sha256(content).hexdigest(),
                    "artifact_base64": base64.b64encode(content).decode("ascii")}
        if action == "render_page":
            index = request["page_offset"]
            if index >= count:
                raise InvalidMedia("page_offset 超出 PDF 页数。")
            page = document.load_page(index)
            dpi = request.get("render_dpi", 144)
            pixmap = page.get_pixmap(matrix=pymupdf.Matrix(dpi / 72, dpi / 72), alpha=False, annots=True)
            if pixmap.width > 4096 or pixmap.height > 4096 or pixmap.width * pixmap.height > 4 * 1024 * 1024:
                raise InvalidMedia("PDF 页面渲染超过 4096 单边像素或 4 MP 上限，请降低 render_dpi。")
            content = pixmap.tobytes("png")
            if len(content) > 12 * 1024 * 1024:
                raise InvalidMedia("渲染 PNG 超过 12 MiB 派生结果上限。")
            return {"status": "ok", "format": "PDF", "page_index": index, "page_count": count,
                    "render_width": pixmap.width, "render_height": pixmap.height, "render_dpi": dpi,
                    "artifact_sha256": hashlib.sha256(content).hexdigest(),
                    "artifact_base64": base64.b64encode(content).decode("ascii")}
        start = request["page_offset"]
        if start > count:
            raise InvalidMedia("page_offset 超出 PDF 页数。")
        end = min(start + request["page_limit"], count)
        pages = []
        for index in range(start, end):
            page = document.load_page(index)
            row = {"page_index": index, "width_pt": page.rect.width, "height_pt": page.rect.height}
            if request["include_text"]:
                text = page.get_text("text")
                row.update(text=text[:2048], text_truncated=len(text) > 2048)
            pages.append(row)
        return {
            "status": "ok", "format": "PDF", "metadata": fields,
            "metadata_truncated": any(isinstance(value, str) and len(value) > 512 for value in metadata.values()),
            "page_count": count, "page_offset": start, "pages": pages,
            "is_repaired": bool(document.is_repaired),
            "next_page_offset": end if end < count else None,
        }


def limited_value(value):
    if isinstance(value, bytes):
        return {"type": "blob", "length": len(value), "sha256": hashlib.sha256(value).hexdigest(),
                "hex_preview": value[:32].hex(), "truncated": len(value) > 32}
    if isinstance(value, str):
        return value[:1024] + ("…" if len(value) > 1024 else "")
    if value is None or isinstance(value, (int, float)):
        return value
    return str(value)[:1024]


def read_sqlite(data, request):
    if not data.startswith(b"SQLite format 3\x00"):
        raise InvalidMedia("未找到有效的 SQLite 3 文件头。")
    connection = sqlite3.connect(":memory:")
    try:
        if not hasattr(connection, "deserialize"):
            raise MissingDependency("Python sqlite3 deserialize")
        connection.deserialize(data)
        connection.execute("PRAGMA query_only=ON")
        forbidden = {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE,
                     sqlite3.SQLITE_CREATE_INDEX, sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_CREATE_TRIGGER,
                     sqlite3.SQLITE_CREATE_VIEW, sqlite3.SQLITE_DROP_INDEX, sqlite3.SQLITE_DROP_TABLE,
                     sqlite3.SQLITE_DROP_TRIGGER, sqlite3.SQLITE_DROP_VIEW, sqlite3.SQLITE_ALTER_TABLE,
                     sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH, sqlite3.SQLITE_PRAGMA,
                     sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_SAVEPOINT, sqlite3.SQLITE_REINDEX,
                     sqlite3.SQLITE_ANALYZE}
        def authorize(action, arg1, arg2, database, trigger):
            return sqlite3.SQLITE_DENY if action in forbidden else sqlite3.SQLITE_OK
        connection.set_authorizer(authorize)
        ticks = [0]
        def progress():
            ticks[0] += 1
            return 1 if ticks[0] > 5000 else 0
        connection.set_progress_handler(progress, 1000)
        query = request.get("query")
        offset, limit = request.get("row_offset", 0), request.get("row_limit", 25)
        if query is not None:
            if not re.match(r"(?is)^\s*(?:select|with)\b", query):
                raise InvalidMedia("只允许单条只读 SELECT 查询。")
            cursor = connection.execute(query)
            columns = [item[0][:256] for item in cursor.description or []]
            cursor.fetchmany(offset) if offset else None
            rows = [[limited_value(value) for value in row] for row in cursor.fetchmany(limit + 1)]
            more = len(rows) > limit
            rows = rows[:limit]
            return {"status": "ok", "format": "SQLite", "query": query[:512], "columns": columns,
                    "row_offset": offset, "rows": rows, "next_row_offset": offset + len(rows) if more else None}
        tables = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        result = {"status": "ok", "format": "SQLite", "table_count": len(tables), "tables": tables[:128],
                  "tables_truncated": len(tables) > 128}
        table = request.get("table")
        if table is None:
            return result
        if table not in tables:
            raise InvalidMedia("sqlite_table 不存在于该数据库。")
        escaped = table.replace('"', '""')
        cursor = connection.execute(f'SELECT * FROM "{escaped}" LIMIT ? OFFSET ?', (limit + 1, offset))
        columns = [item[0][:256] for item in cursor.description or []]
        rows = [[limited_value(value) for value in row] for row in cursor.fetchall()]
        more = len(rows) > limit
        rows = rows[:limit]
        return {**result, "table": table, "columns": columns, "row_offset": offset, "rows": rows,
                "next_row_offset": offset + len(rows) if more else None}
    except sqlite3.Error as error:
        raise InvalidMedia("SQLite 查询被只读规则拒绝，或数据库结构无效。") from error
    finally:
        connection.close()


def read_office(data, request):
    if not data.startswith(b"PK"):
        raise InvalidMedia("仅支持基于 ZIP 的 DOCX、XLSX、PPTX、ODT、ODS 和 ODP。")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError) as error:
        raise InvalidMedia("Office ZIP 容器无效。") from error
    with archive:
        infos = archive.infolist()
        if len(infos) > 512 or sum(info.file_size for info in infos) > 128 * 1024 * 1024:
            raise InvalidMedia("Office 文档超过 512 个部件或 128 MiB 展开上限。")
        names = {info.filename for info in infos if not info.is_dir()}
        natural_sheet = lambda name: int(re.search(r"sheet(\d+)", name).group(1)) if re.search(r"sheet(\d+)", name) else 0
        natural_slide = lambda name: int(re.search(r"slide(\d+)", name).group(1)) if re.search(r"slide(\d+)", name) else 0
        part = request.get("part")
        if part is not None:
            if part.startswith(("/", "\\")) or ".." in part.replace("\\", "/").split("/") or part not in names:
                raise InvalidMedia("office_part 必须是归档内存在的相对部件路径。")
            selected = [part]
        elif "word/document.xml" in names:
            selected = ["word/document.xml"]
        elif "xl/sharedStrings.xml" in names or any(name.startswith("xl/worksheets/") for name in names):
            selected = sorted((name for name in names if name.startswith("xl/worksheets/")), key=natural_sheet)[:16]
            if not selected and "xl/sharedStrings.xml" in names: selected = ["xl/sharedStrings.xml"]
        elif any(name.startswith("ppt/slides/slide") for name in names):
            selected = sorted((name for name in names if re.match(r"ppt/slides/slide\d+\.xml$", name)), key=natural_slide)[:32]
        elif "content.xml" in names:
            selected = ["content.xml"]
        else:
            raise InvalidMedia("未找到受支持的 Office 文档主体。")
        shared = []
        if "xl/sharedStrings.xml" in names:
            if archive.getinfo("xl/sharedStrings.xml").file_size > 8 * 1024 * 1024:
                raise InvalidMedia("XLSX sharedStrings.xml 超过 8 MiB 读取上限。")
            try:
                root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
                shared = ["".join(node.itertext())[:2048] for node in root if node.tag.endswith("}si")]
            except ET.ParseError:
                raise InvalidMedia("XLSX sharedStrings.xml 无法解析。")
        sections = []
        remaining = 32 * 1024
        for name in selected:
            info = archive.getinfo(name)
            if info.file_size > 16 * 1024 * 1024:
                continue
            try:
                root = ET.fromstring(archive.read(name))
            except (ET.ParseError, RuntimeError, zipfile.BadZipFile):
                continue
            values = []
            if "/worksheets/" in name:
                for cell in root.iter():
                    if not cell.tag.endswith("}c"):
                        continue
                    ref = cell.attrib.get("r", "")[:16]
                    value_node = next((node for node in cell if node.tag.endswith("}v")), None)
                    inline = "".join("".join(node.itertext()) for node in cell if node.tag.endswith("}is"))
                    value = inline or (value_node.text if value_node is not None else "")
                    if cell.attrib.get("t") == "s" and value.isdigit() and int(value) < len(shared):
                        value = shared[int(value)]
                    if value != "": values.append(f"{ref}={value}")
                    if len(values) >= 512: break
            elif name == "content.xml":
                for node in root.iter():
                    if node.tag.endswith("}p"):
                        text = "".join(node.itertext()).strip()
                        if text: values.append(text)
                        if sum(len(value) for value in values) >= remaining: break
            else:
                for node in root.iter():
                    if node.tag.endswith("}t") and node.text:
                        values.append(node.text)
                        if sum(len(value) for value in values) >= remaining: break
            raw_content = "\n".join(values)
            content = raw_content[:remaining]
            remaining -= len(content)
            sections.append({"part": name, "text": content, "truncated": len(content) < len(raw_content)})
            if remaining <= 0: break
        if not sections:
            raise InvalidMedia("未找到可读取的 Office 文本或单元格。")
        return {"status": "ok", "format": "Office", "container_parts": len(infos), "sections": sections,
                "text_truncated": remaining <= 0}


def qr_payload(value, corners):
    row = {"corners": [[round(float(point[0]), 2), round(float(point[1]), 2)] for point in corners]}
    if isinstance(value, str):
        return {**row, "text": value[:1024], "text_truncated": len(value) > 1024, "byte_exact": False}
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    return {
        **row, "text": text[:1024] if text is not None else None,
        "text_truncated": text is not None and len(text) > 1024, "byte_exact": True,
        "byte_length": len(value), "hex": value[:1024].hex(), "hex_truncated": len(value) > 1024,
        "payload_sha256": hashlib.sha256(value).hexdigest(),
    }


def read_qr(data):
    try:
        import cv2
        import numpy
    except (ImportError, OSError) as error:
        raise MissingDependency("OpenCV / NumPy") from error

    cv2.setNumThreads(1)
    with local_image(data, ("PNG", "JPEG")) as image:
        source_format = image.format
        gray = numpy.asarray(image.convert("L"))
    detector = cv2.QRCodeDetector()
    multi = getattr(detector, "detectAndDecodeBytesMulti", detector.detectAndDecodeMulti)
    single = getattr(detector, "detectAndDecodeBytes", detector.detectAndDecode)
    detected, values, corners, _ = multi(gray)
    detected_count = len(corners) if corners is not None else 0
    matches = []
    if detected and corners is not None:
        matches = [(value, points) for value, points in zip(values, corners) if value]
    if not matches:
        value, points, _ = single(gray)
        if points is not None:
            detected_count = max(detected_count, len(points))
            if value:
                matches.append((value, points[0]))
    return {
        "status": "ok" if matches else "unreadable" if detected_count else "not_found",
        "format": source_format, "detected_count": detected_count, "decoded_count": len(matches),
        "codes": [qr_payload(value, points) for value, points in matches[:8]],
        "codes_truncated": len(matches) > 8,
    }


RISK_ORDER = {"low": 0, "medium": 1, "high": 2}
HIGH_RISK_MODULES = {
    "os", "posix", "nt", "subprocess", "pty", "commands", "popen2", "shutil",
    "sys", "ctypes", "marshal", "webbrowser", "socket", "http", "http.client",
    "urllib", "urllib.request", "ftplib", "telnetlib", "smtplib", "pickle",
    "_pickle", "cPickle", "importlib", "runpy", "code", "codeop", "timeit",
    "bdb", "pdb", "doctest", "cProfile", "profile", "xmlrpc", "xmlrpc.client",
    "ssl", "asyncio", "multiprocessing", "threading",
}
HIGH_RISK_CALLABLES = {
    ("builtins", "eval"), ("builtins", "exec"), ("builtins", "__import__"),
    ("builtins", "compile"), ("builtins", "open"), ("builtins", "getattr"),
    ("builtins", "setattr"), ("builtins", "delattr"), ("builtins", "globals"),
    ("builtins", "locals"), ("builtins", "breakpoint"),
    ("__builtin__", "eval"), ("__builtin__", "exec"), ("__builtin__", "__import__"),
    ("__builtin__", "compile"), ("__builtin__", "open"), ("__builtin__", "getattr"),
    ("__builtin__", "setattr"),
    ("operator", "attrgetter"), ("operator", "methodcaller"), ("operator", "itemgetter"),
    ("types", "FunctionType"), ("types", "CodeType"), ("functools", "partial"),
    ("torch.serialization", "load"), ("torch.jit", "load"), ("torch", "load"),
    ("numpy", "load"), ("joblib", "load"), ("dill", "loads"), ("cloudpickle", "loads"),
}
BENIGN_MODULES = {
    "collections", "torch", "torch._utils", "torch.storage", "torch.nn",
    "torch.nn.modules", "torch.nn.parameter", "numpy", "numpy.core.multiarray",
    "numpy._core.multiarray", "numpy.dtype", "copyreg", "copy_reg",
    "datetime", "decimal", "fractions", "re",
}
BENIGN_BUILTINS = {
    "object", "set", "frozenset", "slice", "bytes", "bytearray", "complex",
    "range", "dict", "list", "tuple", "str", "int", "float", "bool",
}
SUSPICIOUS_CODE_PATTERNS = (
    (re.compile(r"\b(?:os\.system|os\.popen|subprocess|__import__|eval|exec|compile)\s*\("), "high", "dangerous_call"),
    (re.compile(r"\b(?:socket|urllib|http\.client|requests|ctypes|marshal)\b"), "high", "suspicious_import"),
    (re.compile(r"\bopen\s*\("), "medium", "file_access"),
)


def max_risk(current, candidate):
    return candidate if RISK_ORDER.get(candidate, 0) > RISK_ORDER.get(current, 0) else current


def classify_pickle_global(module, name):
    base_mod = module.split(".", 1)[0]
    if module in HIGH_RISK_MODULES or base_mod in HIGH_RISK_MODULES or (module, name) in HIGH_RISK_CALLABLES:
        return "high"
    if module in ("builtins", "__builtin__"):
        return "low" if name in BENIGN_BUILTINS else "medium"
    if module in BENIGN_MODULES or base_mod in ("torch", "numpy", "collections"):
        return "low"
    return "medium"


def scan_pickle_bytes(data, max_ops=200000):
    mark = object()
    stack = []
    memo = {}
    globals_seen = []
    globals_keys = set()
    findings = []
    strings = []
    strings_seen = set()
    call_ops = {}
    protocol = 0
    op_count = 0
    saw_stop = False
    stop_pos = None
    truncated = False
    parse_error = None
    risk = "low"

    def record_global(mod, name, opcode, pos):
        nonlocal risk
        level = classify_pickle_global(mod, name)
        key = (mod, name)
        if key not in globals_keys and len(globals_seen) < 64:
            globals_keys.add(key)
            globals_seen.append({"module": mod, "name": name, "risk": level, "opcode": opcode, "offset": pos})
        if level != "low" and len(findings) < 64:
            findings.append({
                "severity": level, "kind": "pickle_global", "opcode": opcode,
                "offset": pos, "target": f"{mod}.{name}",
            })
        risk = max_risk(risk, level)

    def push_str(value):
        stack.append(value)
        if isinstance(value, str) and 4 <= len(value) <= 4096 and value not in strings_seen and len(strings) < 32:
            if all(ch.isprintable() or ch in "\t\r\n" for ch in value[:128]):
                strings_seen.add(value)
                strings.append(value[:200])

    try:
        for op, arg, pos in pickletools.genops(data):
            op_count += 1
            if op_count > max_ops:
                truncated = True
                break
            name = op.name
            if name == "PROTO":
                protocol = int(arg)
            elif name in ("SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "STRING", "BINSTRING", "SHORT_BINSTRING"):
                push_str(arg if isinstance(arg, str) else str(arg))
            elif name in ("SHORT_BINBYTES", "BINBYTES", "BINBYTES8", "BYTEARRAY8"):
                stack.append("<bytes>")
            elif name in ("INT", "BININT", "BININT1", "BININT2", "LONG", "LONG1", "LONG4", "FLOAT", "BINFLOAT", "NONE", "NEWTRUE", "NEWFALSE"):
                stack.append(arg)
            elif name in ("EMPTY_LIST", "EMPTY_DICT", "EMPTY_TUPLE", "EMPTY_SET"):
                stack.append(None)
            elif name == "MARK":
                stack.append(mark)
            elif name == "POP":
                if stack:
                    stack.pop()
            elif name == "POP_MARK":
                while stack and stack.pop() is not mark:
                    pass
            elif name == "DUP":
                if stack:
                    stack.append(stack[-1])
            elif name == "MEMOIZE":
                memo[len(memo)] = stack[-1] if stack else None
            elif name in ("PUT", "BINPUT", "LONG_BINPUT"):
                memo[arg] = stack[-1] if stack else None
            elif name in ("GET", "BINGET", "LONG_BINGET"):
                stack.append(memo.get(arg))
            elif name in ("TUPLE", "LIST", "DICT", "FROZENSET"):
                while stack and stack.pop() is not mark:
                    pass
                stack.append(None)
            elif name in ("TUPLE1", "TUPLE2", "TUPLE3"):
                n = int(name[-1])
                del stack[-n:]
                stack.append(None)
            elif name in ("GLOBAL", "INST"):
                raw = str(arg)
                parts = raw.split(" ", 1)
                mod = parts[0]
                attr = parts[1] if len(parts) > 1 else ""
                record_global(mod, attr, name, pos)
                if name == "INST":
                    call_ops[name] = call_ops.get(name, 0) + 1
                    while stack and stack.pop() is not mark:
                        pass
                stack.append(("GLOBAL", mod, attr))
            elif name == "STACK_GLOBAL":
                attr = stack.pop() if stack else None
                mod = stack.pop() if stack else None
                if isinstance(mod, str) and isinstance(attr, str):
                    record_global(mod, attr, name, pos)
                    stack.append(("GLOBAL", mod, attr))
                else:
                    risk = max_risk(risk, "medium")
                    if len(findings) < 64:
                        findings.append({
                            "severity": "medium", "kind": "dynamic_stack_global",
                            "opcode": name, "offset": pos,
                            "detail": "STACK_GLOBAL 使用了非常量/动态栈顶符号。",
                        })
                    stack.append(("GLOBAL", "<dynamic>", "<dynamic>"))
            elif name in ("EXT1", "EXT2", "EXT4"):
                risk = max_risk(risk, "medium")
                if len(findings) < 64:
                    findings.append({
                        "severity": "medium", "kind": "pickle_extension",
                        "opcode": name, "offset": pos, "code": int(arg),
                    })
                stack.append(None)
            elif name in ("REDUCE", "NEWOBJ", "NEWOBJ_EX", "OBJ", "BUILD"):
                call_ops[name] = call_ops.get(name, 0) + 1
                if name == "REDUCE":
                    if len(stack) >= 2:
                        stack.pop()
                        callee = stack.pop()
                        if isinstance(callee, tuple) and len(callee) == 3 and callee[0] == "GLOBAL":
                            if classify_pickle_global(callee[1], callee[2]) == "high" and len(findings) < 64:
                                findings.append({
                                    "severity": "high", "kind": "pickle_reduce_call",
                                    "opcode": name, "offset": pos, "target": f"{callee[1]}.{callee[2]}",
                                })
                    stack.append(None)
                elif name == "OBJ":
                    while stack and stack.pop() is not mark:
                        pass
                    stack.append(None)
                elif name == "NEWOBJ_EX":
                    del stack[-3:]
                    stack.append(None)
                else:
                    del stack[-2:]
                    stack.append(None)
            elif name == "STOP":
                saw_stop = True
                stop_pos = pos + 1
                break
    except Exception as exc:
        parse_error = str(exc)[:200]

    trailing = max(0, len(data) - stop_pos) if saw_stop and stop_pos is not None else 0
    if trailing > 0:
        risk = max_risk(risk, "medium")
        if len(findings) < 64:
            findings.append({
                "severity": "medium", "kind": "trailing_bytes",
                "offset": stop_pos, "byte_length": trailing,
            })

    return {
        "protocol": protocol,
        "op_count": op_count,
        "op_truncated": truncated,
        "saw_stop": saw_stop,
        "trailing_bytes": trailing,
        "risk_level": risk,
        "call_ops": call_ops,
        "globals": globals_seen,
        "findings": findings,
        "string_samples": strings,
        **({"parse_error": parse_error} if parse_error else {}),
    }


def try_inspect_safetensors(data):
    if len(data) < 10:
        return None
    header_len = struct.unpack("<Q", data[:8])[0]
    if header_len < 2 or header_len > 4 * 1024 * 1024 or 8 + header_len > len(data):
        return None
    if data[8:9] != b"{":
        return None
    try:
        header = json.loads(data[8:8 + header_len].decode("utf-8"))
    except Exception:
        return None
    if not isinstance(header, dict):
        return None
    tensors = []
    max_data_end = 0
    raw_meta = header.get("__metadata__")
    if raw_meta is not None and not isinstance(raw_meta, dict):
        return None
    tensor_items = [(k, v) for k, v in header.items() if k != "__metadata__"]
    if not tensor_items and raw_meta is None:
        return None
    for name, info in tensor_items:
        if not isinstance(info, dict) or "dtype" not in info or "shape" not in info or "data_offsets" not in info:
            return None
        offsets = info["data_offsets"]
        if not isinstance(offsets, list) or len(offsets) != 2 or not all(isinstance(v, int) and v >= 0 for v in offsets):
            return None
        if offsets[1] > max_data_end:
            max_data_end = offsets[1]
        if len(tensors) < 64:
            tensors.append({"name": str(name)[:256], "dtype": str(info["dtype"]), "shape": info["shape"], "data_offsets": offsets})
    metadata = {}
    if isinstance(raw_meta, dict):
        for k, v in list(raw_meta.items())[:64]:
            metadata[str(k)[:128]] = str(v)[:1024]
    expected_end = 8 + header_len + max_data_end
    trailing = max(0, len(data) - expected_end)
    findings = []
    risk = "low"
    if trailing > 0:
        risk = "medium"
        findings.append({"severity": "medium", "kind": "trailing_bytes", "offset": expected_end, "byte_length": trailing})
    return {
        "status": "ok",
        "format": "safetensors",
        "byte_length": len(data),
        "header_length": header_len,
        "metadata": metadata,
        "tensor_count": len(tensor_items),
        "tensors": tensors,
        "tensors_truncated": len(tensor_items) > 64,
        "trailing_bytes": trailing,
        "risk_level": risk,
        "findings": findings,
    }


GGUF_SCALAR = {
    0: ("uint8", "<B", 1), 1: ("int8", "<b", 1),
    2: ("uint16", "<H", 2), 3: ("int16", "<h", 2),
    4: ("uint32", "<I", 4), 5: ("int32", "<i", 4),
    6: ("float32", "<f", 4), 7: ("bool", "<?", 1),
    10: ("uint64", "<Q", 8), 11: ("int64", "<q", 8),
    12: ("float64", "<d", 8),
}


def try_inspect_gguf(data):
    if len(data) < 24 or data[:4] != b"GGUF":
        return None
    version = struct.unpack("<I", data[4:8])[0]
    if version < 1 or version > 10:
        return None
    if version == 1:
        tensor_count, kv_count = struct.unpack("<II", data[8:16])
        pos = 16
    else:
        tensor_count, kv_count = struct.unpack("<QQ", data[8:24])
        pos = 24

    def read_u64(offset):
        if offset + 8 > len(data):
            raise EOFError()
        return struct.unpack("<Q", data[offset:offset + 8])[0], offset + 8

    def read_u32(offset):
        if offset + 4 > len(data):
            raise EOFError()
        return struct.unpack("<I", data[offset:offset + 4])[0], offset + 4

    def read_str(offset):
        length, offset = read_u64(offset)
        if length > 16 * 1024 * 1024 or offset + length > len(data):
            raise EOFError()
        raw = data[offset:offset + length]
        return raw[:1024].decode("utf-8", errors="replace"), offset + length

    def read_value(vtype, offset):
        if vtype in GGUF_SCALAR:
            _, fmt, size = GGUF_SCALAR[vtype]
            if offset + size > len(data):
                raise EOFError()
            val = struct.unpack(fmt, data[offset:offset + size])[0]
            return val, offset + size
        if vtype == 8:
            return read_str(offset)
        if vtype == 9:
            elem_type, offset = read_u32(offset)
            count, offset = read_u64(offset)
            if count > 10_000_000:
                raise EOFError()
            preview = []
            if elem_type in GGUF_SCALAR:
                ename, fmt, size = GGUF_SCALAR[elem_type]
                byte_span = count * size
                if offset + byte_span > len(data):
                    raise EOFError()
                for idx in range(min(count, 8)):
                    preview.append(struct.unpack(fmt, data[offset + idx * size:offset + (idx + 1) * size])[0])
                return {"type": "array", "element_type": ename, "count": count, "preview": preview}, offset + byte_span
            if elem_type == 8:
                if count > 65536:
                    raise EOFError()
                for idx in range(count):
                    item, offset = read_str(offset)
                    if idx < 8:
                        preview.append(item[:128])
                return {"type": "array", "element_type": "string", "count": count, "preview": preview}, offset
            raise EOFError()
        raise EOFError()

    metadata = {}
    parse_truncated = False
    limit = min(kv_count, 64)
    try:
        for _ in range(limit):
            key, pos = read_str(pos)
            vtype, pos = read_u32(pos)
            val, pos = read_value(vtype, pos)
            metadata[key[:128]] = val
    except EOFError:
        parse_truncated = True

    findings = []
    risk = "low"
    for key, val in metadata.items():
        if isinstance(val, str) and ("chat_template" in key or "{{" in val or "os.system" in val):
            if any(tok in val for tok in ("__class__", "__subclasses__", "popen", "os.system", "lipsum", "cycler")):
                risk = "high"
                findings.append({"severity": "high", "kind": "suspicious_metadata_template", "key": key})
    return {
        "status": "ok",
        "format": "gguf",
        "version": version,
        "byte_length": len(data),
        "tensor_count": tensor_count,
        "metadata_kv_count": kv_count,
        "metadata": metadata,
        "metadata_truncated": kv_count > 64 or parse_truncated,
        "risk_level": risk,
        "findings": findings,
    }


def try_inspect_pytorch_zip(data):
    if len(data) < 22 or data[:4] not in (b"PK\x03\x04", b"PK\x05\x06"):
        return None
    try:
        zf = zipfile.ZipFile(io.BytesIO(data), "r")
    except Exception:
        return None
    with zf:
        infos = zf.infolist()
        names = [info.filename for info in infos]
        is_pytorch = any(
            name.endswith(".pkl") or name.endswith("/data.pkl") or name == "data.pkl"
            or name.endswith("/version") or "/code/" in name or name.startswith("code/")
            for name in names
        )
        if not is_pytorch:
            return None
        entries = [
            {"name": info.filename, "size": info.file_size, "compressed_size": info.compress_size}
            for info in infos[:64]
        ]
        risk = "low"
        findings = []
        pickle_members = []
        code_files = []
        for info in infos:
            if info.is_dir():
                continue
            if info.filename.endswith(".pkl") and len(pickle_members) < 8:
                if info.file_size > 8 * 1024 * 1024:
                    findings.append({"severity": "medium", "kind": "oversized_pickle_member", "member": info.filename, "size": info.file_size})
                    risk = max_risk(risk, "medium")
                    continue
                member_bytes = zf.read(info)
                scan = scan_pickle_bytes(member_bytes)
                risk = max_risk(risk, scan["risk_level"])
                for item in scan["findings"]:
                    if len(findings) < 64:
                        findings.append({**item, "member": info.filename})
                pickle_members.append({"member": info.filename, "size": len(member_bytes), **scan})
            elif info.filename.endswith(".py") and len(code_files) < 8:
                if info.file_size <= 256 * 1024:
                    text = zf.read(info).decode("utf-8", errors="replace")
                    code_files.append({"member": info.filename, "size": info.file_size, "preview": text[:1024], "truncated": len(text) > 1024})
                    for pattern, level, kind in SUSPICIOUS_CODE_PATTERNS:
                        if pattern.search(text):
                            risk = max_risk(risk, level)
                            if len(findings) < 64:
                                findings.append({"severity": level, "kind": kind, "member": info.filename})
        return {
            "status": "ok",
            "format": "pytorch_zip",
            "byte_length": len(data),
            "entry_count": len(infos),
            "entries": entries,
            "entries_truncated": len(infos) > 64,
            "pickle_members": pickle_members,
            "code_files": code_files,
            "risk_level": risk,
            "findings": findings,
        }


def try_inspect_onnx(data):
    if len(data) < 6:
        return None
    pos = 0
    end = min(len(data), 1024 * 1024)
    ir_version = None
    model_version = None
    producer_name = None
    producer_version = None
    domain = None
    doc_string = None
    has_graph = False
    opset_domains = []
    metadata_props = {}
    valid_fields = 0

    def read_varint(buf, offset):
        shift = 0
        result = 0
        while offset < len(buf) and shift <= 63:
            b = buf[offset]
            offset += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                return result, offset
            shift += 7
        raise ValueError("bad varint")

    try:
        while pos < end and valid_fields < 256:
            tag, pos = read_varint(data, pos)
            field_no = tag >> 3
            wire = tag & 7
            if field_no == 0 or field_no > 32:
                return None
            if wire == 0:
                val, pos = read_varint(data, pos)
                if field_no == 1 and 1 <= val <= 32:
                    ir_version = val
                    valid_fields += 1
                elif field_no == 5:
                    model_version = val
                    valid_fields += 1
                else:
                    return None
            elif wire == 2:
                length, pos = read_varint(data, pos)
                if length > len(data) - pos:
                    return None
                chunk = data[pos:pos + length]
                pos += length
                if field_no == 2:
                    producer_name = chunk[:256].decode("utf-8")
                    valid_fields += 1
                elif field_no == 3:
                    producer_version = chunk[:256].decode("utf-8")
                    valid_fields += 1
                elif field_no == 4:
                    domain = chunk[:256].decode("utf-8")
                    valid_fields += 1
                elif field_no == 6:
                    doc_string = chunk[:512].decode("utf-8", errors="replace")
                    valid_fields += 1
                elif field_no == 7:
                    has_graph = True
                    valid_fields += 1
                elif field_no == 8:
                    opset_domains.append(chunk[:128].decode("utf-8", errors="replace"))
                    valid_fields += 1
                elif field_no == 14:
                    valid_fields += 1
                    p2 = 0
                    mk = mv = None
                    while p2 < len(chunk):
                        t2, p2 = read_varint(chunk, p2)
                        if (t2 & 7) != 2:
                            break
                        l2, p2 = read_varint(chunk, p2)
                        if p2 + l2 > len(chunk):
                            break
                        s2 = chunk[p2:p2 + l2].decode("utf-8", errors="replace")
                        p2 += l2
                        if (t2 >> 3) == 1:
                            mk = s2[:128]
                        elif (t2 >> 3) == 2:
                            mv = s2[:512]
                    if mk and len(metadata_props) < 32:
                        metadata_props[mk] = mv or ""
                else:
                    valid_fields += 1
            elif wire == 1:
                if pos + 8 > len(data):
                    return None
                pos += 8
            elif wire == 5:
                if pos + 4 > len(data):
                    return None
                pos += 4
            else:
                return None
    except Exception:
        return None

    if ir_version is None or (not has_graph and producer_name is None and not opset_domains):
        return None

    findings = []
    risk = "low"
    if domain and domain not in ("", "ai.onnx", "ai.onnx.ml", "ai.onnx.preview.training"):
        risk = "medium"
        findings.append({"severity": "medium", "kind": "custom_onnx_domain", "domain": domain})
    ext_hits = re.findall(rb"(?:\.\.[\\/]|/etc/|[A-Za-z]:\\)[\x20-\x7e]{1,120}", data[:2 * 1024 * 1024])
    for hit in ext_hits[:8]:
        risk = "high"
        findings.append({"severity": "high", "kind": "suspicious_external_path", "sample": hit.decode("utf-8", errors="replace")})
    return {
        "status": "ok",
        "format": "onnx",
        "byte_length": len(data),
        "ir_version": ir_version,
        **({"model_version": model_version} if model_version is not None else {}),
        **({"producer_name": producer_name} if producer_name is not None else {}),
        **({"producer_version": producer_version} if producer_version is not None else {}),
        **({"domain": domain} if domain is not None else {}),
        **({"doc_string": doc_string} if doc_string is not None else {}),
        "has_graph": has_graph,
        "opset_count": len(opset_domains),
        "metadata_props": metadata_props,
        "risk_level": risk,
        "findings": findings,
    }


def inspect_model(data):
    if not data:
        raise InvalidMedia("模型文件为空。")
    for inspector in (try_inspect_gguf, try_inspect_safetensors, try_inspect_pytorch_zip):
        report = inspector(data)
        if report is not None:
            return report
    # Raw pickle: protocol 2..5 starts with \x80\x02..\x80\x05; protocol 0/1 validated by STOP + opcodes.
    looks_proto = len(data) >= 2 and data[0] == 0x80 and 2 <= data[1] <= 5
    pickle_scan = scan_pickle_bytes(data)
    if looks_proto or (pickle_scan["saw_stop"] and pickle_scan["op_count"] >= 2 and not pickle_scan.get("parse_error")):
        return {
            "status": "ok",
            "format": "pickle",
            "byte_length": len(data),
            **pickle_scan,
        }
    onnx_report = try_inspect_onnx(data)
    if onnx_report is not None:
        return onnx_report
    raise InvalidMedia("无法识别为受支持的 AI 模型或 Pickle 格式（支持 safetensors/gguf/pytorch_zip/pickle/onnx）。")


def main():
    request = json.loads(sys.argv[1])
    data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    kind = request["kind"]
    try:
        if len(data) > MAX_INPUT_BYTES:
            raise InvalidMedia("原件超过 32 MiB。")
        if kind == "png":
            report = read_png(data, request)
        elif kind == "image":
            report = inspect_image(data, request)
        elif kind == "pdf":
            report = read_pdf(data, request)
        elif kind == "sqlite":
            report = read_sqlite(data, request)
        elif kind == "office":
            report = read_office(data, request)
        elif kind == "model":
            report = inspect_model(data)
        else:
            report = read_qr(data)
    except MissingDependency as error:
        report = {
            "status": "dependency_missing", "dependency": str(error),
            "reason": "当前工作台 Python 缺少该读取器依赖。",
        }
    except InvalidMedia as error:
        report = {"status": "invalid", "reason": str(error)}
    except Exception:
        report = {"status": "invalid", "reason": "原件损坏，或读取器无法解析此文件。"}
    print(json.dumps(report, allow_nan=False))


main()
