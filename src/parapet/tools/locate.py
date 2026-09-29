"""Find managed tool binaries.

Only the managed tools directory is searched, at the pinned version. PATH is
ignored unless explicitly allowed, because unrelated programs share these names
(the Python httpx package installs its own `httpx` command).
"""

from __future__ import annotations

import os
import shutil
import sys
import tomllib
from dataclasses import dataclass
from functools import lru_cache
from importlib import metadata, resources
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ToolPin:
    name: str
    version: str
    repo: str
    binary: str
    license: str
    version_args: tuple[str, ...]
    assets: dict[str, dict[str, str]]
    kind: str = "binary"  # binary | data | python


@lru_cache(maxsize=1)
def manifest() -> dict[str, ToolPin]:
    raw = resources.files("parapet.tools").joinpath("manifest.toml").read_bytes()
    data: dict[str, Any] = tomllib.loads(raw.decode())
    pins = {}
    for name, entry in data.items():
        pins[name] = ToolPin(
            name=name,
            version=str(entry["version"]),
            repo=str(entry["repo"]),
            binary=str(entry.get("binary", name)),
            license=str(entry.get("license", "")),
            version_args=tuple(entry.get("version_args", ["-version"])),
            assets=dict(entry.get("assets", {})),
            kind=str(entry.get("kind", "binary")),
        )
    return pins


def python_tool(pin: ToolPin) -> Path | None:
    """A tool that is a Python package, installed with the project.

    Its integrity comes from the project's lock file, which pins the version
    and the hash of every file. Here the installed version is checked against
    the manifest, so the two cannot drift apart unnoticed.
    """
    try:
        installed = metadata.version(pin.name)
    except metadata.PackageNotFoundError:
        return None
    if installed != pin.version:
        return None
    script = Path(sys.executable).parent / pin.binary
    return script if script.is_file() and os.access(script, os.X_OK) else None


class ToolLocator:
    def __init__(self, tools_dir: Path, *, allow_path: bool = False) -> None:
        self.tools_dir = tools_dir
        self.allow_path = allow_path

    def install_dir(self, pin: ToolPin) -> Path:
        return self.tools_dir / pin.name / pin.version

    def resolve(self, name: str) -> Path | None:
        pin = manifest().get(name)
        if pin is not None and pin.kind == "python":
            return python_tool(pin)
        if pin is not None:
            candidate = self.install_dir(pin) / pin.binary
            if pin.kind == "data":
                return candidate if candidate.is_dir() else None
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
        if self.allow_path:
            found = shutil.which(name)
            if found:
                return Path(found)
        return None

    def available(self, name: str) -> bool:
        return self.resolve(name) is not None

    def version(self, name: str) -> str | None:
        pin = manifest().get(name)
        return pin.version if pin and self.available(name) else None
