"""Static analysis of uploaded files. Nothing here ever executes the files."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

import pefile

SEVEN_ZIP = shutil.which("7zz") or shutil.which("7z") or shutil.which("7za")
MSIINFO = shutil.which("msiinfo")
INNOEXTRACT = shutil.which("innoextract")

TEXT_EXTENSIONS = {
    ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".js", ".reg", ".json", ".xml", ".ini",
    ".txt", ".cfg", ".conf", ".config", ".properties", ".md", ".yaml", ".yml", ".iss", ".mst.txt",
    ".inf", ".csv", ".lax", ".sh", ".py",
}

# (marker bytes, framework, silent-install hint)
INSTALLER_MARKERS: list[tuple[bytes, str, str]] = [
    (b"Inno Setup Setup Data", "Inno Setup", "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- ; uninstall: unins000.exe /VERYSILENT"),
    (b"Inno Setup", "Inno Setup", "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-"),
    (b"Nullsoft.NSIS", "NSIS", "/S (case sensitive), optional /D=<path> as last argument; uninstall: uninstall.exe /S"),
    (b"NullsoftInst", "NSIS", "/S (case sensitive), optional /D=<path> as last argument"),
    (b".wixburn", "WiX Burn bundle", "/quiet /norestart (or /passive); uninstall via bundle UninstallString with /uninstall /quiet"),
    (b"WixBundleManifest", "WiX Burn bundle", "/quiet /norestart"),
    (b"InstallAnywhere", "Flexera InstallAnywhere", "-i silent [-f installer.properties]; uninstall: <dir>\\Uninstall_*\\Uninstall *.exe -i silent"),
    (b"InstallShield", "InstallShield", "Basic MSI: /s /v\"/qn\" ; InstallScript: /s /f1\"setup.iss\" (needs recorded response file)"),
    (b"Advanced Installer", "Advanced Installer", "/exenoui /qn  (or /i //qn for MSI-based); see vendor docs"),
    (b"Caphyon", "Advanced Installer", "/exenoui /qn"),
    (b"Squirrel", "Squirrel (per-user)", "--silent ; installs per user into %LocalAppData% - usually needs user context or a machine-wide installer"),
    (b"!@Install@!UTF-8!", "7-Zip SFX", "often extracts and runs an inner setup; try -y or inspect the archive"),
    (b"Setup Factory", "Setup Factory", "/S"),
    (b"WiseMain", "Wise Installer", "/s"),
    (b"electron-builder", "electron-builder (NSIS)", "/S ; per-machine with /allusers"),
    (b"Smart Install Maker", "Smart Install Maker", "/s"),
    (b"InstallAware", "InstallAware", "/s"),
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str], timeout: int = 120, max_chars: int = 200_000) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"[error running {cmd[0]}: {exc}]"
    text = out.stdout.decode("utf-8", "replace")
    if out.returncode != 0 and out.stderr:
        text += "\n[stderr] " + out.stderr.decode("utf-8", "replace")[:2000]
    return text[:max_chars]


def detect_kind(path: Path) -> str:
    try:
        with path.open("rb") as f:
            head = f.read(8)
    except OSError:
        return "unreadable"
    ext = path.suffix.lower()
    if head[:2] == b"MZ":
        return "pe"
    if head == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return {".msp": "msp", ".mst": "mst"}.get(ext, "msi" if ext in (".msi", "") else "ole")
    if head[:4] == b"PK\x03\x04":
        if ext in (".msix", ".appx", ".msixbundle", ".appxbundle"):
            return "msix"
        return "zip"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:4] == b"MSCF":
        return "cab"
    if ext in TEXT_EXTENSIONS:
        return "text"
    if ext in (".png", ".jpg", ".jpeg", ".ico", ".gif", ".bmp", ".svg", ".webp"):
        return "image"
    if ext in (".iso", ".img"):
        return "disk-image"
    try:
        with path.open("rb") as f:
            sample = f.read(4096)
        if sample and _looks_text(sample):
            return "text"
    except OSError:
        pass
    return "binary"


def _looks_text(sample: bytes) -> bool:
    if sample.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
        return True
    return sample.count(b"\0") == 0 and sum(32 <= c < 127 or c in (9, 10, 13) for c in sample) / len(sample) > 0.9


def read_text(path: Path, max_chars: int = 20_000, offset: int = 0) -> str:
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "utf-16") if not raw.startswith((b"\xff\xfe", b"\xfe\xff")) else ("utf-16", "utf-8-sig"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode("latin-1")
    chunk = text[offset: offset + max_chars]
    if offset + max_chars < len(text):
        chunk += f"\n[... truncated, {len(text)} chars total; use offset to read more]"
    return chunk


# --------------------------------------------------------------------------- PE
def _scan_markers(path: Path, overlay_offset: int | None) -> list[str]:
    size = path.stat().st_size
    windows = [(0, min(size, 8 * 1024 * 1024)), (max(0, size - 4 * 1024 * 1024), size)]
    if overlay_offset:
        windows.append((overlay_offset, min(size, overlay_offset + 2 * 1024 * 1024)))
    found: list[str] = []
    with path.open("rb") as f:
        for start, end in windows:
            f.seek(start)
            data = f.read(end - start)
            for marker, name, _hint in INSTALLER_MARKERS:
                if name not in found and marker in data:
                    found.append(name)
    return found


def pe_info(path: Path) -> dict:
    info: dict = {}
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
        ])
    except pefile.PEFormatError as exc:
        return {"error": f"not a valid PE file: {exc}"}

    machine = pe.FILE_HEADER.Machine
    info["architecture"] = {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x1C4: "arm"}.get(machine, hex(machine))
    info["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    info["subsystem"] = {2: "GUI", 3: "console"}.get(pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem))
    sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    info["authenticode_signed"] = sec.Size > 0
    info["sections"] = [s.Name.rstrip(b"\0").decode("latin-1") for s in pe.sections]

    version: dict[str, str] = {}
    for fileinfo in getattr(pe, "FileInfo", []) or []:
        for entry in fileinfo:
            for table in getattr(entry, "StringTable", []) or []:
                for k, v in table.entries.items():
                    key, val = k.decode("utf-8", "replace"), v.decode("utf-8", "replace").strip()
                    if val:
                        version[key] = val
    if hasattr(pe, "VS_FIXEDFILEINFO") and pe.VS_FIXEDFILEINFO:
        ffi = pe.VS_FIXEDFILEINFO[0]
        version["FileVersion(numeric)"] = (
            f"{ffi.FileVersionMS >> 16}.{ffi.FileVersionMS & 0xFFFF}.{ffi.FileVersionLS >> 16}.{ffi.FileVersionLS & 0xFFFF}"
        )
    info["version_info"] = version

    manifest = _pe_manifest(pe)
    if manifest:
        m = re.search(r'requestedExecutionLevel\s+level="([^"]+)"', manifest)
        if m:
            info["requested_execution_level"] = m.group(1)

    overlay = pe.get_overlay_data_start_offset()
    if overlay:
        extra = path.stat().st_size - overlay
        if sec.Size and sec.VirtualAddress >= overlay:  # the Authenticode signature is not a payload
            extra -= sec.Size
        if extra > 0:
            info["overlay_bytes"] = extra
        else:
            overlay = None
    if ".wixburn" in info["sections"]:
        info.setdefault("frameworks", []).append("WiX Burn bundle")
    frameworks = _scan_markers(path, overlay)
    descr = " ".join(version.values())
    for marker, name, _ in INSTALLER_MARKERS:
        if marker.decode("latin-1") in descr and name not in frameworks:
            frameworks.append(name)
    info["frameworks"] = sorted(set(info.get("frameworks", []) + frameworks))
    info["silent_switch_hints"] = {
        name: hint for _m, name, hint in INSTALLER_MARKERS if name in info["frameworks"]
    }
    pe.close()
    return info


def _pe_manifest(pe: pefile.PE) -> str | None:
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return None
    for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if rtype.id == 24:  # RT_MANIFEST
            for name in rtype.directory.entries:
                for lang in name.directory.entries:
                    data = pe.get_data(lang.data.struct.OffsetToData, lang.data.struct.Size)
                    return data.decode("utf-8", "replace")
    return None


# -------------------------------------------------------------------------- MSI
def msi_table(path: Path, table: str, max_chars: int = 30_000) -> str:
    if not MSIINFO:
        return "[msitools not installed]"
    return run([MSIINFO, "export", str(path), table], max_chars=max_chars)


def msi_info(path: Path) -> dict:
    if not MSIINFO:
        return {"error": "msitools (msiinfo) not installed"}
    info: dict = {}
    props: dict[str, str] = {}
    for line in msi_table(path, "Property").splitlines()[3:]:
        if "\t" in line:
            k, v = line.split("\t", 1)
            props[k] = v
    keep = [
        "ProductName", "ProductVersion", "Manufacturer", "ProductCode", "UpgradeCode", "ALLUSERS",
        "ALLUSERS", "MSIINSTALLPERUSER", "ProductLanguage", "ARPNOREMOVE", "ARPSYSTEMCOMPONENT",
        "REBOOT", "INSTALLLEVEL", "SecureCustomProperties", "ARPPRODUCTICON",
    ]
    info["properties"] = {k: props[k] for k in keep if k in props}
    public = [k for k in props if k.isupper() and not k.startswith(("IS_", "WIX", "ARP", "PROGMSG", "IDS"))]
    info["public_properties"] = public[:80]
    summary = run([MSIINFO, "suminfo", str(path)], max_chars=4000)
    info["summary_info"] = {
        k.strip(): v.strip() for k, v in (l.split(":", 1) for l in summary.splitlines() if ":" in l)
        if k.strip() in ("Title", "Subject", "Author", "Template", "Revision number (UUID)", "Name of Creating Application", "Comments")
    }
    template = info["summary_info"].get("Template", "")
    info["architecture"] = "x64" if template.lower().startswith(("x64", "amd64")) else ("arm64" if "arm64" in template.lower() else "x86")
    tables = run([MSIINFO, "tables", str(path)]).split()
    info["tables"] = tables
    for t in ("Upgrade", "LaunchCondition"):
        if t in tables:
            info[t] = msi_table(path, t, 3000)
    if "CustomAction" in tables:
        rows = msi_table(path, "CustomAction").splitlines()[3:]
        info["custom_action_count"] = len(rows)
    if "ServiceInstall" in tables:
        info["installs_services"] = True
    return info


# ----------------------------------------------------------------------- archives
def archive_listing(path: Path, max_lines: int = 300) -> str:
    if not SEVEN_ZIP:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
            return "\n".join(names[:max_lines]) + (f"\n[... {len(names)} entries]" if len(names) > max_lines else "")
        return "[7-Zip not installed]"
    out = run([SEVEN_ZIP, "l", "-ba", str(path)], timeout=180)
    lines = out.splitlines()
    text = "\n".join(lines[:max_lines])
    if len(lines) > max_lines:
        text += f"\n[... {len(lines)} entries total]"
    return text


def msix_manifest(path: Path) -> str | None:
    try:
        with zipfile.ZipFile(path) as zf:
            for name in ("AppxManifest.xml", "AppxMetadata/AppxBundleManifest.xml"):
                if name in zf.namelist():
                    return zf.read(name).decode("utf-8", "replace")[:15000]
    except zipfile.BadZipFile:
        return None
    return None


# ---------------------------------------------------------------------- strings
def search_strings(path: Path, pattern: str, max_hits: int = 60, context: int = 0) -> list[str]:
    regex = re.compile(pattern, re.IGNORECASE)
    ascii_re = re.compile(rb"[\x20-\x7e]{5,}")
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
    hits: list[str] = []
    seen: set[str] = set()
    with path.open("rb") as f:
        while (chunk := f.read(8 * 1024 * 1024)) and len(hits) < max_hits:
            for rx, enc in ((ascii_re, "latin-1"), (utf16_re, "utf-16le")):
                for m in rx.finditer(chunk):
                    s = m.group().decode(enc, "replace")
                    if s not in seen and regex.search(s):
                        seen.add(s)
                        hits.append(s[:500])
                        if len(hits) >= max_hits:
                            break
    return hits


# ------------------------------------------------------------------- overview
def analyze_file(path: Path, root: Path) -> dict:
    rel = path.relative_to(root).as_posix()
    size = path.stat().st_size
    kind = detect_kind(path)
    entry: dict = {"path": rel, "size_bytes": size, "kind": kind}
    if size < 3 * 1024 * 1024 * 1024:
        entry["sha256"] = sha256_file(path)
    try:
        if kind == "pe":
            entry["pe"] = pe_info(path)
        elif kind == "msi":
            entry["msi"] = msi_info(path)
        elif kind in ("msp", "mst"):
            entry["note"] = "Patch/transform file - needs a base MSI"
        elif kind == "msix":
            entry["appx_manifest"] = msix_manifest(path)
        elif kind in ("zip", "7z", "cab", "disk-image"):
            entry["listing"] = archive_listing(path, 80)
        elif kind == "text" and size < 2 * 1024 * 1024:
            entry["content"] = read_text(path, 6000)
    except Exception as exc:  # analysis must never crash the job
        entry["analysis_error"] = f"{type(exc).__name__}: {exc}"
    return entry


def analyze_tree(root: Path, max_files: int = 400) -> list[dict]:
    files = [p for p in sorted(root.rglob("*")) if p.is_file()]
    results = []
    for i, path in enumerate(files):
        if i >= max_files:
            results.append({"note": f"{len(files) - max_files} more files not analysed (use list_files/inspect_file)"})
            break
        # deep analysis only for interesting files; plain listing for the rest in big trees
        if len(files) > 60 and detect_kind(path) not in ("pe", "msi", "msix", "text", "zip", "7z", "cab"):
            results.append({"path": path.relative_to(root).as_posix(), "size_bytes": path.stat().st_size})
            continue
        results.append(analyze_file(path, root))
    return results


def to_prompt_json(data: object, max_chars: int = 60_000) -> str:
    text = json.dumps(data, indent=1, ensure_ascii=False)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n[... truncated]"
    return text
