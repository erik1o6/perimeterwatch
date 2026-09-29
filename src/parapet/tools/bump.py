"""Maintainer tool: pin a new release in the manifest.

This is the one place where checksums are fetched from upstream. The result is
a change to manifest.toml, to be reviewed by a person before it is committed.
"""

from __future__ import annotations

import re
import tempfile
import tomllib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import httpx
import tomli_w

from parapet.config import secret
from parapet.core.errors import ToolError
from parapet.tools.installer import check_url, download

HEADER = """\
# Pinned external tools. This file is the root of trust: binaries are checked
# against the sha256 values here, not against anything fetched at install time.
# Entries are written by `parapet tools bump NAME VERSION` and reviewed by a person.

"""


@dataclass(frozen=True)
class Known:
    repo: str
    license: str
    # platform -> asset name pattern, with {v} for the version
    assets: dict[str, str]
    checksums: str | None = "{name}_{v}_checksums.txt"
    binary: str | None = None
    version_args: tuple[str, ...] = ("-version",)
    kind: str = "binary"


def _pd(name: str, checksums: str = "{name}_{v}_checksums.txt") -> Known:
    return Known(
        repo=f"projectdiscovery/{name}",
        license="MIT",
        checksums=checksums,
        assets={
            "linux_amd64": f"{name}_{{v}}_linux_amd64.zip",
            "linux_arm64": f"{name}_{{v}}_linux_arm64.zip",
            "darwin_arm64": f"{name}_{{v}}_macOS_arm64.zip",
            "darwin_amd64": f"{name}_{{v}}_macOS_amd64.zip",
        },
    )


KNOWN: dict[str, Known] = {
    "subfinder": _pd("subfinder"),
    "httpx": _pd("httpx"),
    "tlsx": _pd("tlsx"),
    "naabu": _pd("naabu", checksums="naabu-checksums.txt"),
    "nuclei": _pd("nuclei"),
    "trufflehog": Known(
        repo="trufflesecurity/trufflehog",
        license="AGPL-3.0-only",
        assets={
            "linux_amd64": "trufflehog_{v}_linux_amd64.tar.gz",
            "linux_arm64": "trufflehog_{v}_linux_arm64.tar.gz",
            "darwin_arm64": "trufflehog_{v}_darwin_arm64.tar.gz",
            "darwin_amd64": "trufflehog_{v}_darwin_amd64.tar.gz",
        },
        version_args=("--version",),
    ),
    "betterleaks": Known(
        repo="betterleaks/betterleaks",
        license="MIT",
        assets={
            "linux_amd64": "betterleaks_{v}_linux_x64.tar.gz",
            "linux_arm64": "betterleaks_{v}_linux_arm64.tar.gz",
            "darwin_arm64": "betterleaks_{v}_darwin_arm64.tar.gz",
            "darwin_amd64": "betterleaks_{v}_darwin_x64.tar.gz",
        },
        checksums="checksums.txt",
        # "version" is a subcommand here, not a flag.
        version_args=("version",),
    ),
    "nuclei-templates": Known(
        repo="projectdiscovery/nuclei-templates",
        license="MIT",
        assets={},
        checksums=None,
        binary="templates",
        kind="data",
    ),
}

_VERSION_RE = re.compile(r"^\d{1,4}(\.\d{1,5}){1,3}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def manifest_path() -> Path:
    return Path(str(resources.files("parapet.tools").joinpath("manifest.toml")))


def _client() -> httpx.Client:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "parapet-tools"}
    token = secret("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(headers=headers, timeout=60, follow_redirects=False, trust_env=False)


def _get(client: httpx.Client, url: str) -> httpx.Response:
    for _ in range(5):
        response = client.get(check_url(url))
        if response.status_code in (301, 302, 303, 307, 308):
            url = response.headers["location"]
            continue
        return response
    raise ToolError("Too many redirects.")


def latest_version(name: str) -> str:
    known = _known(name)
    with _client() as client:
        response = _get(client, f"https://api.github.com/repos/{known.repo}/releases/latest")
    if response.status_code != 200:
        raise ToolError(f"GitHub answered HTTP {response.status_code} for {known.repo}.")
    return str(response.json()["tag_name"]).lstrip("v")


def _known(name: str) -> Known:
    if name not in KNOWN:
        raise ToolError(f"{name} is not a known tool. Known: {', '.join(sorted(KNOWN))}.")
    return KNOWN[name]


def _parse_checksums(text: str) -> dict[str, str]:
    sums = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and _SHA_RE.match(parts[0].lower()):
            sums[parts[1].lstrip("*")] = parts[0].lower()
    return sums


def resolve(name: str, version: str) -> dict[str, Any]:
    """Build the manifest entry for one tool version."""
    known = _known(name)
    version = version.lstrip("v")
    if not _VERSION_RE.match(version):
        raise ToolError(f"{version!r} is not a version number.")
    base = f"https://github.com/{known.repo}"
    entry: dict[str, Any] = {
        "version": version,
        "repo": known.repo,
        "binary": known.binary or name,
        "license": known.license,
        "version_args": list(known.version_args),
        "kind": known.kind,
        "assets": {},
    }

    if known.kind == "data":
        url = f"{base}/archive/refs/tags/v{version}.tar.gz"
        with tempfile.TemporaryDirectory() as tmp:
            digest = download(url, Path(tmp) / "archive")
        entry["assets"]["any"] = {"url": url, "sha256": digest}
        return entry

    assert known.checksums is not None
    checksum_name = known.checksums.format(name=name, v=version)
    with _client() as client:
        response = _get(client, f"{base}/releases/download/v{version}/{checksum_name}")
    if response.status_code != 200:
        raise ToolError(
            f"No checksum file for {name} {version} (HTTP {response.status_code}). "
            "Check that the version exists."
        )
    sums = _parse_checksums(response.text)
    for platform_name, pattern in known.assets.items():
        asset = pattern.format(v=version)
        if asset in sums:
            entry["assets"][platform_name] = {
                "url": f"{base}/releases/download/v{version}/{asset}",
                "sha256": sums[asset],
            }
    if not entry["assets"]:
        raise ToolError(f"The checksum file for {name} {version} lists none of the expected files.")
    return entry


def write_entry(name: str, entry: dict[str, Any], path: Path | None = None) -> Path:
    path = path or manifest_path()
    data = tomllib.loads(path.read_text()) if path.exists() else {}
    data[name] = entry
    ordered = {key: data[key] for key in sorted(data)}
    path.write_text(HEADER + tomli_w.dumps(ordered))
    return path
