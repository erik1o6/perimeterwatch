"""Write docs/modules.md and docs/report.schema.json from the code.

Run after changing a module or a finding kind:  uv run python scripts/gen_docs.py
"""

from __future__ import annotations

from pathlib import Path

from parapet.core.module import all_modules
from parapet.core.severity import KINDS
from parapet.report.render_json import schema

DOCS = Path(__file__).parents[1] / "docs"

DEPTH = {
    "passive": "Passive. No connection is made to the organisation's hosts.",
    "probe": "Probe. One ordinary request per host.",
    "active": "Active. Runs only with authorisation.",
}


def modules_doc() -> str:
    out = [
        "# Checks and findings",
        "",
        "Generated from the code by `scripts/gen_docs.py`. Do not edit by hand.",
        "",
        "## Checks",
        "",
    ]
    modules = sorted(all_modules().values(), key=lambda m: (m.spec.mode.rank, m.spec.name))
    for module in modules:
        spec = module.spec
        needs = []
        if spec.requires_verification:
            needs.append("a verified domain")
        needs += [f"the `{b}` tool" for b in spec.requires_binaries]
        needs += [f"`{k}`" for k in spec.requires_keys]
        needs += [f"{a.replace('_', ' ')} set on the target" for a in spec.requires_target]
        optional = [f"the `{b}` tool" for b in spec.optional_binaries]
        optional += [f"`{k}`" for k in spec.optional_keys]
        out += [
            f"### {spec.title} (`{spec.name}`)",
            "",
            spec.description,
            "",
            f"- Depth: {DEPTH[spec.mode.value]}",
            f"- Contacts: {', '.join(spec.contacts) or 'nothing'}",
            f"- Needs: {', '.join(needs) or 'nothing'}",
        ]
        if optional:
            out.append(f"- Better with: {', '.join(optional)}")
        if spec.depends_on:
            out.append(f"- Runs after: {', '.join(f'`{d}`' for d in spec.depends_on)}")
        out.append("")

    out += [
        "## Findings",
        "",
        "Each kind of finding has a default severity. A check may move it one step up or down",
        "and must then say why in the finding itself.",
        "",
        "| Kind | Area | Default severity | What to do |",
        "|---|---|---|---|",
    ]
    for kind, info in sorted(KINDS.items()):
        advice = info.remediation.replace("|", "/")
        out.append(f"| `{kind}` | {info.category.value} | {info.severity.label} | {advice} |")
    out.append("")
    return "\n".join(out)


def main() -> None:
    DOCS.mkdir(exist_ok=True)
    (DOCS / "modules.md").write_text(modules_doc())
    (DOCS / "report.schema.json").write_text(schema())
    print("wrote docs/modules.md and docs/report.schema.json")


if __name__ == "__main__":
    main()
