from __future__ import annotations

import json

from parapet.report.build import ReportData


def render_json(report: ReportData) -> str:
    data = report.model_dump(mode="json", exclude={"hosts", "lookalike_assets", "sections"})
    return json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False) + "\n"


def render_jsonl(report: ReportData) -> str:
    """One finding per line, for piping into other tools."""
    lines = [
        json.dumps(f.model_dump(mode="json"), ensure_ascii=False, sort_keys=True)
        for f in report.findings
    ]
    return "\n".join(lines) + ("\n" if lines else "")


def schema() -> str:
    return json.dumps(ReportData.model_json_schema(), indent=2) + "\n"
