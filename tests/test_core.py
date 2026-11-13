"""Run with: .venv/bin/python -m pytest -q"""
import base64
import hashlib
import hmac
import io
import re
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.agent import PackagingAgent, Workspace
from app.intunewin import build_intunewin


def test_intunewin_roundtrip(tmp_path: Path):
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "install.ps1").write_text("Write-Output hi")
    (src / "sub" / "data.bin").write_bytes(b"\0" * 300_000)
    (src / ".DS_Store").write_bytes(b"junk")
    out = build_intunewin(src, "install.ps1", tmp_path / "out" / "app.intunewin")

    outer = zipfile.ZipFile(out)
    assert {i.filename for i in outer.infolist()} == {
        "IntuneWinPackage/Contents/IntunePackage.intunewin", "IntuneWinPackage/Metadata/Detection.xml"}
    assert all(i.compress_type == zipfile.ZIP_STORED for i in outer.infolist())
    xml = outer.read("IntuneWinPackage/Metadata/Detection.xml").decode()
    enc = outer.read("IntuneWinPackage/Contents/IntunePackage.intunewin")
    get = lambda tag: base64.b64decode(re.search(f"<{tag}>(.*?)</{tag}>", xml).group(1))  # noqa: E731

    assert hmac.new(get("MacKey"), enc[32:], hashlib.sha256).digest() == enc[:32] == get("Mac")
    assert enc[32:48] == get("InitializationVector")
    dec = Cipher(algorithms.AES(get("EncryptionKey")), modes.CBC(get("InitializationVector"))).decryptor()
    plain = dec.update(enc[48:]) + dec.finalize()
    plain = plain[: -plain[-1]]
    assert hashlib.sha256(plain).digest() == get("FileDigest")
    assert int(re.search(r"<UnencryptedContentSize>(\d+)<", xml).group(1)) == len(plain)
    assert sorted(zipfile.ZipFile(io.BytesIO(plain)).namelist()) == ["install.ps1", "sub/data.bin"]
    assert "<SetupFile>install.ps1</SetupFile>" in xml


def test_workspace_blocks_escape(tmp_path: Path):
    ws = Workspace(tmp_path / "job")
    for bad in ("../x", "/etc/passwd", "output/a", "source/../../x"):
        try:
            ws.resolve(bad)
        except Exception:
            continue
        raise AssertionError(f"{bad} was not blocked")
    assert ws.resolve("source/a/b.txt") == (tmp_path / "job" / "source" / "a" / "b.txt").resolve()


def test_finish_validation(tmp_path: Path):
    ws = Workspace(tmp_path / "job")
    (ws.source / "app.msi").write_bytes(b"x")
    agent = PackagingAgent(ws, lambda *_: None, 10)
    good = {
        "feasible": True, "language": "en", "summary": "ok", "app": {"name": "App"}, "setup_file": "app.msi",
        "install_command": 'msiexec /i "app.msi" /qn', "uninstall_command": "msiexec /x {11111111-2222-3333-4444-555555555555} /qn",
        "detection_rules": [{"type": "msi", "msi_product_code": "{11111111-2222-3333-4444-555555555555}"}],
    }
    assert agent.validate_finish(good) == []
    bad = dict(good, setup_file="missing.exe", install_command="PS64 install.ps1", detection_rules=[{"type": "file", "path": "C:\\x"}])
    problems = " ".join(agent.validate_finish(bad))
    assert "missing.exe" in problems and "placeholder" in problems and "file rules need" in problems
    assert agent.validate_finish({"feasible": False, "language": "en", "summary": "no"}) == []
