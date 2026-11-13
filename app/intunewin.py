"""Create .intunewin packages (same format as Microsoft's IntuneWinAppUtil).

Layout of the result (a plain, uncompressed zip):
    IntuneWinPackage/Contents/IntunePackage.intunewin   encrypted zip of the source folder
    IntuneWinPackage/Metadata/Detection.xml             keys + metadata

Encrypted file = HMAC-SHA256(macKey, IV || ciphertext) || IV || AES-256-CBC(PKCS7, zip)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import tempfile
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CHUNK = 1024 * 1024
IGNORED_NAMES = {".DS_Store", "Thumbs.db", "desktop.ini"}


def _zip_source(source: Path, target: Path) -> None:
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for path in sorted(source.rglob("*")):
            rel = path.relative_to(source)
            if any(part in IGNORED_NAMES or part == "__MACOSX" for part in rel.parts):
                continue
            if path.is_file():
                zf.write(path, rel.as_posix())


def _encrypt(plain: Path, target: Path) -> dict[str, str]:
    enc_key, mac_key, iv = os.urandom(32), os.urandom(32), os.urandom(16)
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    padder = padding.PKCS7(128).padder()
    mac = hmac.new(mac_key, iv, hashlib.sha256)
    digest = hashlib.sha256()

    with plain.open("rb") as src, target.open("wb") as dst:
        dst.write(b"\0" * 32)  # placeholder for the HMAC
        dst.write(iv)
        while chunk := src.read(CHUNK):
            digest.update(chunk)
            data = encryptor.update(padder.update(chunk))
            mac.update(data)
            dst.write(data)
        data = encryptor.update(padder.finalize()) + encryptor.finalize()
        mac.update(data)
        dst.write(data)
        mac_value = mac.digest()
        dst.seek(0)
        dst.write(mac_value)

    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return {
        "EncryptionKey": b64(enc_key),
        "MacKey": b64(mac_key),
        "InitializationVector": b64(iv),
        "Mac": b64(mac_value),
        "FileDigest": b64(digest.digest()),
    }


def build_intunewin(source: Path, setup_file: str, output: Path) -> Path:
    """Package `source` with `setup_file` (relative path inside source) into `output`."""
    source = source.resolve()
    setup_path = (source / setup_file).resolve()
    if not setup_path.is_file() or source not in setup_path.parents:
        raise ValueError(f"Setup file '{setup_file}' does not exist in the package folder")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        tmp_dir = Path(tmp)
        content_zip = tmp_dir / "content.zip"
        encrypted = tmp_dir / "IntunePackage.intunewin"
        _zip_source(source, content_zip)
        info = _encrypt(content_zip, encrypted)
        setup_name = escape(setup_path.name)
        xml = (
            '<ApplicationInfo xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'xmlns:xsd="http://www.w3.org/2001/XMLSchema" ToolVersion="1.8.6.0">\n'
            f"  <Name>{setup_name}</Name>\n"
            f"  <UnencryptedContentSize>{content_zip.stat().st_size}</UnencryptedContentSize>\n"
            "  <FileName>IntunePackage.intunewin</FileName>\n"
            f"  <SetupFile>{escape(setup_file.replace('/', chr(92)))}</SetupFile>\n"
            "  <EncryptionInfo>\n"
            f"    <EncryptionKey>{info['EncryptionKey']}</EncryptionKey>\n"
            f"    <MacKey>{info['MacKey']}</MacKey>\n"
            f"    <InitializationVector>{info['InitializationVector']}</InitializationVector>\n"
            f"    <Mac>{info['Mac']}</Mac>\n"
            "    <ProfileIdentifier>ProfileVersion1</ProfileIdentifier>\n"
            f"    <FileDigest>{info['FileDigest']}</FileDigest>\n"
            "    <FileDigestAlgorithm>SHA256</FileDigestAlgorithm>\n"
            "  </EncryptionInfo>\n"
            "</ApplicationInfo>"
        )
        with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED, allowZip64=True) as zf:
            zf.write(encrypted, "IntuneWinPackage/Contents/IntunePackage.intunewin")
            zf.writestr("IntuneWinPackage/Metadata/Detection.xml", xml)
    return output
