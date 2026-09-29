"""Self-contained HTML report: inline CSS, no scripts, no external requests.

Everything a scan finds is attacker-influenced text (page titles, certificate
names, repository paths, lookalike domains), so autoescaping is always on and
nothing from a finding is ever marked safe.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from perimeterwatch.report.build import ReportData


def _when(value: str | None) -> str:
    if not value:
        return "unknown"
    try:
        return datetime.fromisoformat(value).strftime("%d %B %Y, %H:%M UTC")
    except ValueError:
        return str(value)


_LABELS = {
    "dns_verified": "Domain control proven by DNS record",
    "acknowledged": "Written acknowledgement",
    "none": "None on record",
    "ips": "Addresses",
    "mx": "Mail servers",
}


def _label(key: str) -> str:
    key = str(key)
    return _LABELS.get(key) or _ucfirst(key.replace("_", " "))


def _ucfirst(text: str) -> str:
    """Capitalise the first letter and leave the rest alone."""
    text = str(text)
    return text[:1].upper() + text[1:]


def _value(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if value is None:
        return "none"
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_value(v) for v in value) if value else "none"
    if isinstance(value, dict):
        return ", ".join(f"{k}: {_value(v)}" for k, v in value.items())
    return str(value)


def environment() -> Environment:
    env = Environment(
        loader=PackageLoader("perimeterwatch.report", "templates"),
        autoescape=select_autoescape(default=True, default_for_string=True),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["when"] = _when
    env.filters["label"] = _label
    env.filters["value"] = _value
    env.filters["ucfirst"] = _ucfirst
    return env


def render_html(report: ReportData) -> str:
    env = environment()
    css = env.loader.get_source(env, "report.css")[0]  # type: ignore[union-attr]
    return env.get_template("report.html.j2").render(r=report, css=css)
