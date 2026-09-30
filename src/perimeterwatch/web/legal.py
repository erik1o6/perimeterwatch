"""The legal and policy drafts, rendered as pages of the hosted service.

The texts are Markdown files in `perimeterwatch/legal/`. They are the project's
own files, not user input. Raw HTML inside them is switched off all the same,
so a careless edit cannot put markup on a page.

Open points in the drafts are written as `[TO DECIDE: ...]`, `[TO CONFIRM: ...]`,
`[NOT YET BUILT: ...]` and `[LAWYER: ...]`. They are shown as marked notes, so
a reader sees at once what is not settled.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

from markdown_it import MarkdownIt
from markupsafe import Markup

BANNER = "DRAFT. Not legal advice. Requires review by a qualified lawyer before use."
REPOSITORY = "https://github.com/erik1o6/perimeterwatch"
SOURCE_DIR = "src/perimeterwatch/legal"


@dataclass(frozen=True)
class Document:
    slug: str
    title: str
    summary: str
    readers: str


DOCUMENTS: tuple[Document, ...] = (
    Document(
        "terms-of-service",
        "Terms of service",
        "The agreement between the operator and an organisation that uses the service.",
        "Organisations using the service",
    ),
    Document(
        "privacy-policy",
        "Privacy policy",
        "What personal data is handled, why, and what rights people have.",
        "Organisations, their staff, the public",
    ),
    Document(
        "scanning-authorisation-and-aup",
        "Scanning authorisation and acceptable use",
        "What proving control of a domain authorises, the three scan depths, and what is "
        "forbidden.",
        "Organisations, operators of scanned hosts",
    ),
    Document(
        "opt-out",
        "Opt-out for operators of scanned hosts",
        "How the operator of a host that received traffic can make it stop.",
        "Operators of scanned hosts",
    ),
    Document(
        "data-retention-policy",
        "Data retention",
        "What is kept, for how long, and how it is deleted.",
        "Organisations, lawyers",
    ),
    Document(
        "dpa-outline",
        "Data processing agreement: outline",
        "Outline of a data processing agreement under GDPR Article 28.",
        "Organisations, lawyers",
    ),
    Document(
        "vulnerability-disclosure",
        "Vulnerability disclosure",
        "How to report a security problem in the service itself.",
        "Security researchers",
    ),
    Document(
        "legitimate-interest-assessment",
        "Legitimate interest assessment: template",
        "A template an organisation can adapt for its own records.",
        "Privacy or security leads",
    ),
)
BY_SLUG = {doc.slug: doc for doc in DOCUMENTS}

MARKERS = {
    "TO DECIDE": ("decide", "Not yet decided"),
    "TO CONFIRM": ("confirm", "To be confirmed"),
    "NOT YET BUILT": ("unbuilt", "Not yet built"),
    "LAWYER": ("lawyer", "For legal review"),
}
_MARKER_RE = re.compile(
    r"(?:<strong>)?\[(LAWYER and TO DECIDE|TO DECIDE|TO CONFIRM|NOT YET BUILT|LAWYER)\b"
    r"[:.,]?\s*([^\]]*)\](?:</strong>)?"
)
_HEADING_RE = re.compile(r"<h2>(.*?)</h2>", re.DOTALL)
_HREF_RE = re.compile(r'href="([^"]*)"')
_TAG_RE = re.compile(r"<[^>]+>")
_SLUG_RE = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class Page:
    document: Document
    html: Markup
    contents: tuple[tuple[str, str], ...]
    open_points: int


def _marker(match: re.Match[str]) -> str:
    kind = "LAWYER" if match.group(1).startswith("LAWYER") else match.group(1)
    css, label = MARKERS[kind]
    text = match.group(2).strip()
    if match.group(1) == "LAWYER and TO DECIDE":
        label = "For legal review, and not yet decided"
    body = f" {text}" if text else ""
    return f'<span class="open-point op-{css}"><span class="op-label">{label}</span>{body}</span>'


def _link(match: re.Match[str]) -> str:
    target = match.group(1)
    if target.startswith(("https://", "mailto:", "#", "/")):
        return match.group(0)
    path, _, fragment = target.partition("#")
    anchor = f"#{fragment}" if fragment else ""
    name = path.removesuffix(".md")
    if path.endswith(".md") and name in BY_SLUG:
        return f'href="/legal/{name}{anchor}"'
    resolved = posixpath.normpath(posixpath.join(SOURCE_DIR, path))
    if resolved.startswith(".."):
        return 'href="#"'
    return f'href="{REPOSITORY}/blob/main/{resolved}{anchor}"'


@lru_cache(maxsize=len(DOCUMENTS))
def page(slug: str) -> Page | None:
    document = BY_SLUG.get(slug)
    if document is None:
        return None
    source = resources.files("perimeterwatch").joinpath("legal", f"{slug}.md").read_text("utf-8")
    lines = source.splitlines()
    if lines and BANNER in lines[0]:
        lines = lines[1:]  # the page shows the banner itself
    # The file's own title is dropped too: the page has one.
    while lines and not lines[0].strip():
        lines = lines[1:]
    if lines and lines[0].startswith("# "):
        lines = lines[1:]

    renderer = MarkdownIt("commonmark", {"html": False}).enable("table")
    html = renderer.render("\n".join(lines))

    contents: list[tuple[str, str]] = []
    seen: set[str] = set()

    def heading(match: re.Match[str]) -> str:
        text = _TAG_RE.sub("", match.group(1)).strip()
        anchor = _SLUG_RE.sub("-", text.lower()).strip("-") or "section"
        while anchor in seen:
            anchor += "-"
        seen.add(anchor)
        contents.append((anchor, text))
        return f'<h2 id="{anchor}">{match.group(1)}</h2>'

    html = _HEADING_RE.sub(heading, html)
    html = _HREF_RE.sub(_link, html)
    html, open_points = _MARKER_RE.subn(_marker, html)
    return Page(document, Markup(html), tuple(contents), open_points)  # noqa: S704
