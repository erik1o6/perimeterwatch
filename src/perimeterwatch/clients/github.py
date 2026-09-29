"""Read-only GitHub API access for public organisation data."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from perimeterwatch.core.context import ScanContext

API = "https://api.github.com"
HOST = "api.github.com"
MAX_PAGES = 5


class GitHubError(Exception):
    pass


class GitHubNotFound(GitHubError):
    pass


def _headers(ctx: ScanContext) -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = ctx.secret("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def get(ctx: ScanContext, path: str, params: dict[str, str] | None = None) -> Any:
    await ctx.limiter.acquire(HOST)
    try:
        response = await ctx.http.get(f"{API}{path}", params=params, headers=_headers(ctx))
    except httpx.TransportError as exc:
        raise GitHubError(f"GitHub could not be reached ({type(exc).__name__}).") from exc
    if response.status_code == 404:
        raise GitHubNotFound(path)
    if response.status_code in (403, 429) and response.headers.get("x-ratelimit-remaining") == "0":
        hint = "" if ctx.secret("GITHUB_TOKEN") else " Set GITHUB_TOKEN for a higher limit."
        raise GitHubError(f"GitHub's request limit was reached.{hint}")
    if response.status_code == 401:
        raise GitHubError("GitHub rejected the token in GITHUB_TOKEN.")
    if response.status_code != 200:
        raise GitHubError(f"GitHub answered HTTP {response.status_code}.")
    return response.json()


async def get_pages(ctx: ScanContext, path: str, params: dict[str, str]) -> tuple[list[Any], bool]:
    """All items up to MAX_PAGES pages of 100. Returns the items and whether more exist."""
    items: list[Any] = []
    for page in range(1, MAX_PAGES + 1):
        batch = await get(ctx, path, {**params, "per_page": "100", "page": str(page)})
        if not isinstance(batch, list):
            break
        items.extend(batch)
        if len(batch) < 100:
            return items, False
    return items, True
