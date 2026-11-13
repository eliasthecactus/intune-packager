"""Extract application icons from PE files and MSI packages and save them as PNG."""
from __future__ import annotations

import io
import struct
import subprocess
from pathlib import Path

import pefile
from PIL import Image

from .analysis import MSIINFO

RT_ICON, RT_GROUP_ICON = 3, 14


def _save_png(img: Image.Image, target: Path, size: int = 256) -> Path:
    img = img.convert("RGBA")
    if max(img.size) > size:
        img.thumbnail((size, size), Image.LANCZOS)
    target.parent.mkdir(parents=True, exist_ok=True)
    img.save(target, "PNG")
    return target


def image_bytes_to_png(data: bytes, target: Path) -> Path | None:
    """Convert any Pillow-readable image (ico, png, jpg, gif, bmp, webp) to PNG."""
    try:
        img = Image.open(io.BytesIO(data))
        if getattr(img, "format", "") == "ICO":
            sizes = sorted(img.info.get("sizes", []), key=lambda s: s[0] * s[1])
            if sizes:
                img.size = sizes[-1]
        img.load()
    except Exception:
        return None
    return _save_png(img, target)


def pe_icons(path: Path, target_dir: Path, prefix: str) -> list[Path]:
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    except pefile.PEFormatError:
        return []
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return []

    icons: dict[int, bytes] = {}
    groups: list[bytes] = []
    for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if rtype.id not in (RT_ICON, RT_GROUP_ICON):
            continue
        for entry in rtype.directory.entries:
            for lang in entry.directory.entries:
                data = pe.get_data(lang.data.struct.OffsetToData, lang.data.struct.Size)
                if rtype.id == RT_ICON:
                    icons[entry.id] = data
                else:
                    groups.append(data)
                break
    pe.close()

    results: list[Path] = []
    for gi, group in enumerate(groups[:3]):
        try:
            _reserved, _type, count = struct.unpack_from("<HHH", group, 0)
            entries = [struct.unpack_from("<BBBBHHIH", group, 6 + i * 14) for i in range(count)]
        except struct.error:
            continue
        # build a real .ico file from the group directory
        images = [(e, icons.get(e[7])) for e in entries if icons.get(e[7])]
        if not images:
            continue
        header = struct.pack("<HHH", 0, 1, len(images))
        offset = 6 + 16 * len(images)
        directory, blobs = b"", b""
        for e, blob in images:
            w, h, colors, res, planes, bpp, _size, _id = e
            directory += struct.pack("<BBBBHHII", w, h, colors, res, planes, bpp, len(blob), offset)
            offset += len(blob)
            blobs += blob
        png = image_bytes_to_png(header + directory + blobs, target_dir / f"{prefix}-icon{gi}.png")
        if png:
            results.append(png)
    return results


def msi_icons(path: Path, target_dir: Path, prefix: str) -> list[Path]:
    if not MSIINFO:
        return []
    streams = subprocess.run([MSIINFO, "streams", str(path)], capture_output=True, timeout=60).stdout.decode("utf-8", "replace")
    results: list[Path] = []
    for i, name in enumerate(s for s in streams.splitlines() if s.startswith("Icon.")):
        data = subprocess.run([MSIINFO, "extract", str(path), name], capture_output=True, timeout=60).stdout
        if data[:2] == b"MZ":
            tmp = target_dir / f"_{prefix}-{i}.bin"
            tmp.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_bytes(data)
            results += pe_icons(tmp, target_dir, f"{prefix}-{i}")
            tmp.unlink(missing_ok=True)
        else:
            png = image_bytes_to_png(data, target_dir / f"{prefix}-{i}.png")
            if png:
                results.append(png)
        if len(results) >= 3:
            break
    return results
