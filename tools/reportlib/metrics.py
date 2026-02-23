from __future__ import annotations

from pathlib import Path
from typing import Iterable

from . import normalize


IGNORED_DIRS = {
    ".git",
    ".github",
    "out",
    "lib",
    "build",
    "dist",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
}


def _strip_comments(line: str, in_block: bool) -> tuple[str, bool]:
    text = line
    if in_block:
        end = text.find("*/")
        if end == -1:
            return "", True
        text = text[end + 2 :]
        in_block = False

    # remove line comments
    if "//" in text:
        idx = text.find("//")
        text = text[:idx]

    # handle block comment start
    if "/*" in text:
        idx = text.find("/*")
        before = text[:idx]
        rest = text[idx + 2 :]
        end = rest.find("*/")
        if end == -1:
            in_block = True
            text = before
        else:
            text = before + rest[end + 2 :]

    return text, in_block


def count_java_loc(repo_root: Path) -> int:
    total = 0
    for path in repo_root.rglob("*.java"):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        in_block = False
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                stripped, in_block = _strip_comments(line, in_block)
                if stripped.strip():
                    total += 1
        except Exception:
            continue
    return total


def compute_metrics(findings: list[dict], clusters: list[dict], repo_root: Path, metrics_override: dict | None) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = (f.get("severity") or "MEDIUM").upper()
        if sev not in counts:
            sev = "MEDIUM"
        counts[sev] += 1

    loc = count_java_loc(repo_root)
    kloc = loc / 1000.0 if loc else 0.0
    total_findings = sum(counts.values())
    vd = (total_findings / kloc) if kloc else 0.0

    cs = max(
        0.0,
        100.0
        - (
            counts["CRITICAL"] * 35
            + counts["HIGH"] * 20
            + counts["MEDIUM"] * 5
            + counts["LOW"] * 1
            + counts["INFO"] * 0.2
        ),
    )

    risk_score = (
        counts["CRITICAL"] * 15
        + counts["HIGH"] * 10
        + counts["MEDIUM"] * 3
        + counts["LOW"] * 1
        + counts["INFO"] * 0.2
    )

    if metrics_override:
        loc = metrics_override.get("loc", loc)
        kloc = metrics_override.get("kloc", kloc)
        if "totals_by_severity" in metrics_override:
            counts = metrics_override["totals_by_severity"]
        if "vd" in metrics_override:
            vd = metrics_override["vd"]
        if "cs" in metrics_override:
            cs = metrics_override["cs"]
        if "risk_score" in metrics_override:
            risk_score = metrics_override["risk_score"]

    severity_mix = {
        sev: {"count": counts[sev]}
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    }

    reproducibility = {
        "actions_pinned": False,
        "tool_versions_pinned": False,
        "container_runner": False,
        "notes": ["Reproducibility flags are not derived automatically."],
    }

    limitations = [
        "Static analysis can have false positives and false negatives.",
        "Business-logic flaws and runtime configuration issues are only partially covered.",
    ]

    return {
        "loc": int(loc),
        "kloc": round(kloc, 3),
        "totals_by_severity": counts,
        "vd": round(vd, 3),
        "cs": round(cs, 2),
        "risk_score": round(risk_score, 2),
        "severity_mix": severity_mix,
        "reproducibility": reproducibility,
        "limitations": limitations,
    }
