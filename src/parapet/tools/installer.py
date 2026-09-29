"""Download pinned tool releases and verify them before use.

The manifest shipped with the package is the root of trust. A download is
accepted only if its sha256 matches the value in the manifest. Checksums are
never fetched at install time.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

import httpx

from parapet.core.errors import ToolError
from parapet.tools.locate import ToolLocator, ToolPin, manifest

ALLOWED_HOSTS = {
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}
MAX_DOWNLOAD = 400_000_000
MAX_REDIRECTS = 5
HASH_FILE = ".sha256"


def current_platform() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    if system not in ("linux", "darwin") or arch is None:
        raise ToolError(f"No pinned tools exist for this platform ({system} {machine}).")
    return f"{system}_{arch}"


def check_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ToolError(f"Refusing to download from {parsed.hostname or url!r}.")
    return url


def download(url: str, destination: Path, *, client: httpx.Client | None = None) -> str:
    """Stream a file to disk. Returns its sha256. Redirects must stay on GitHub."""
    owns = client is None
    client = client or httpx.Client(follow_redirects=False, timeout=60, trust_env=False)
    digest = hashlib.sha256()
    size = 0
    try:
        for _ in range(MAX_REDIRECTS + 1):
            with client.stream("GET", check_url(url)) as response:
                if response.status_code in (301, 302, 303, 307, 308):
                    url = str(response.headers["location"])
                    continue
                if response.status_code != 200:
                    raise ToolError(f"Download failed with HTTP {response.status_code}: {url}")
                with destination.open("wb") as fh:
                    for chunk in response.iter_bytes(1 << 16):
                        size += len(chunk)
                        if size > MAX_DOWNLOAD:
                            raise ToolError("Download is larger than the allowed size.")
                        digest.update(chunk)
                        fh.write(chunk)
                return digest.hexdigest()
        raise ToolError("Too many redirects.")
    finally:
        if owns:
            client.close()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_member(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ToolError(f"Archive holds an unsafe path: {name!r}")
    return path


def extract_binary(archive: Path, binary: str, destination: Path) -> None:
    """Take exactly one file, the named binary, out of a zip or tar archive."""
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                if info.is_dir() or _safe_member(info.filename).name != binary:
                    continue
                if stat.S_ISLNK(info.external_attr >> 16):
                    raise ToolError("Archive holds a link where the binary should be.")
                with zf.open(info) as src, destination.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
                return
    elif tarfile.is_tarfile(archive):
        with tarfile.open(archive) as tf:
            for member in tf:
                if _safe_member(member.name).name != binary:
                    continue
                if not member.isfile():
                    raise ToolError("Archive holds a link where the binary should be.")
                extracted = tf.extractfile(member)
                assert extracted is not None
                with extracted as src, destination.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
                return
    else:
        raise ToolError(f"{archive.name} is not a zip or tar archive.")
    raise ToolError(f"The archive does not contain {binary!r}.")


def extract_tree(archive: Path, destination: Path) -> None:
    """Unpack a data archive, dropping its single top-level directory."""
    with tarfile.open(archive) as tf, tempfile.TemporaryDirectory(dir=destination.parent) as tmp:
        tf.extractall(tmp, filter="data")  # refuses links and paths that escape
        entries = list(Path(tmp).iterdir())
        root = entries[0] if len(entries) == 1 and entries[0].is_dir() else Path(tmp)
        if destination.exists():
            shutil.rmtree(destination)
        shutil.move(str(root), destination)


@dataclass(frozen=True)
class ToolState:
    name: str
    version: str
    installed: bool
    verified: bool
    path: Path | None
    detail: str = ""


class Installer:
    def __init__(self, tools_dir: Path) -> None:
        self.tools_dir = tools_dir
        self.locator = ToolLocator(tools_dir)
        self.platform = current_platform()

    def _asset(self, pin: ToolPin) -> dict[str, str]:
        asset = pin.assets.get("any") or pin.assets.get(self.platform)
        if not asset:
            raise ToolError(f"{pin.name} {pin.version} has no build for {self.platform}.")
        return asset

    def install(self, name: str, *, force: bool = False) -> ToolState:
        pin = manifest().get(name)
        if pin is None:
            raise ToolError(f"{name} is not a pinned tool. See 'parapet tools list'.")
        if pin.kind == "python":
            state = self.verify(name)
            if not state.verified:
                raise ToolError(
                    f"{name} {pin.version} comes with the project. Run 'uv sync' to install it."
                )
            return state
        if not force and self.verify(name).verified:
            return self.verify(name)

        asset = self._asset(pin)
        target_dir = self.locator.install_dir(pin)
        target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        final = target_dir / pin.binary

        with tempfile.TemporaryDirectory(dir=target_dir) as tmp:
            archive = Path(tmp) / "download"
            got = download(asset["url"], archive)
            if got != asset["sha256"]:
                raise ToolError(
                    f"{name} failed verification and was not installed.\n"
                    f"  expected sha256 {asset['sha256']}\n"
                    f"  received sha256 {got}"
                )
            if pin.kind == "data":
                extract_tree(archive, final)
                (target_dir / HASH_FILE).write_text(got + "\n")
            else:
                staged = Path(tmp) / pin.binary
                extract_binary(archive, pin.binary, staged)
                staged.chmod(0o755)
                (target_dir / HASH_FILE).write_text(file_sha256(staged) + "\n")
                os.replace(staged, final)

        if pin.kind != "data":
            self._smoke(pin, final)
        return self.verify(name)

    def _smoke(self, pin: ToolPin, path: Path) -> None:
        try:
            with tempfile.TemporaryDirectory() as home:
                subprocess.run(  # noqa: S603 - fixed arguments, verified binary
                    [str(path), *pin.version_args],
                    capture_output=True,
                    timeout=30,
                    check=False,
                    env={"PATH": "/usr/bin:/bin", "HOME": home, "NO_COLOR": "1"},
                    cwd=home,
                )
        except OSError as exc:
            path.unlink(missing_ok=True)
            hint = ""
            if "libpcap" in str(exc) or pin.name == "naabu":
                hint = " It needs libpcap: sudo apt install libpcap0.8"
            raise ToolError(f"{pin.name} was verified but does not run here: {exc}.{hint}") from exc
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"{pin.name} did not answer its version check.") from exc

    def verify(self, name: str) -> ToolState:
        """Check an installed tool is the file that was verified at install time."""
        pin = manifest()[name]
        if pin.kind == "python":
            script = self.locator.resolve(name)
            if script is None:
                return ToolState(name, pin.version, False, False, None, "not installed")
            return ToolState(name, pin.version, True, True, script, "pinned in the lock file")
        path = self.locator.install_dir(pin) / pin.binary
        record = self.locator.install_dir(pin) / HASH_FILE
        if not path.exists():
            return ToolState(name, pin.version, False, False, None, "not installed")
        if not record.is_file():
            return ToolState(name, pin.version, True, False, path, "no install record")
        if pin.kind == "data":
            return ToolState(name, pin.version, True, True, path, "data files")
        expected = record.read_text().strip()
        actual = file_sha256(path)
        if actual != expected:
            return ToolState(
                name, pin.version, True, False, path, "file changed since it was installed"
            )
        return ToolState(name, pin.version, True, True, path, f"sha256 {actual[:16]}")

    def remove(self, name: str) -> None:
        pin = manifest()[name]
        shutil.rmtree(self.tools_dir / pin.name, ignore_errors=True)
