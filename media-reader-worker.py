"""Inspect a local attachment snapshot read from standard input."""

import hashlib
import io
import json
import sys
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
            "frame_index": frame_index, "frame_count": frames, "bit_depth": sample_depth, "source_bit_depth": depth,
            "frame_semantics": "composited_rgba" if composite else "default_image" if default_image else "native_samples",
            "region": bounds, "channels": channels,
            "pixel_offset": start, "pixel_count": end - start,
            "next_pixel_offset": end if end < count else None,
        }
        if request["operation"] == "pixels":
            report["pixels"] = [{"x": x, "y": y, "values": values} for x, y, values in samples]
            return report

        bit_index = request["bit_index"]
        if bit_index >= sample_depth:
            raise InvalidMedia("bit_index 必须小于当前帧的样本位深。")
        bit_order = request["bit_order"]
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
