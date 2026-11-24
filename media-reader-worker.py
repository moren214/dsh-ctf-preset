"""Inspect a local attachment snapshot read from standard input."""

import hashlib
import base64
import io
import json
import re
import sqlite3
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
