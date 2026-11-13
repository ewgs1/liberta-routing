"""Install only pinned official executables for parser checks; no upstream data is copied."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import tarfile
import urllib.request
import zipfile

root = Path(__file__).resolve().parents[1]
if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
    raise SystemExit("Pinned native parser toolchain requires Linux amd64")
lock = json.loads((root / "toolchain.json").read_text())
destination = root / ".local" / "bin"
destination.mkdir(parents=True, exist_ok=True, mode=0o700)
for tool in lock["tools"]:
    allowed_prefix = {
        "xray": "https://github.com/XTLS/Xray-core/releases/download/",
        "sing-box": "https://github.com/SagerNet/sing-box/releases/download/",
        "sing-box-current": "https://github.com/SagerNet/sing-box/releases/download/",
    }
    if tool["name"] not in allowed_prefix or not tool["url"].startswith(allowed_prefix[tool["name"]]):
        raise SystemExit("Non-official tool URL refused")
    request = urllib.request.Request(tool["url"], headers={"User-Agent": "LibertaRouting-CI"})
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = response.read(100 * 1024 * 1024 + 1)
    if len(payload) > 100 * 1024 * 1024:
        raise SystemExit("Tool archive exceeds size limit")
    if hashlib.sha256(payload).hexdigest() != tool["sha256"]:
        raise SystemExit("Pinned tool SHA256 mismatch")
    if tool["archive"] == "zip":
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            binary = archive.read(tool["member"])
    elif tool["archive"] == "tar.gz":
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            member = archive.getmember(tool["member"])
            if not member.isfile() or member.size > 100 * 1024 * 1024:
                raise SystemExit("Invalid executable archive member")
            binary = archive.extractfile(member).read()
    else:
        raise SystemExit("Unknown archive format")
    # Extract one executable, never archives, geodata, configuration files or symlinks.
    target = destination / tool["name"]
    temporary = destination / (tool["name"] + ".tmp")
    with temporary.open("xb") as output:
        output.write(binary)
    temporary.chmod(0o700)
    os.replace(temporary, target)
    print(f"Pinned {tool['name']} {tool['version']} verified and installed")
