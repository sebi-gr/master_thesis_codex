from __future__ import annotations

import html
import json
from pathlib import Path

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except Exception:  # pragma: no cover
    Environment = None
    FileSystemLoader = None
    select_autoescape = None


def render_html(report: dict, template_path: Path) -> str:
    if Environment is None:
        body = html.escape(json.dumps(report, indent=2, sort_keys=True))
        return (
            "<!doctype html><html><head><meta charset='utf-8'><title>Security Report</title></head>"
            f"<body><h1>Security Report</h1><pre>{body}</pre></body></html>"
        )

    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template(template_path.name)
    return template.render(report=report)
