from __future__ import annotations

from pathlib import Path
from typing import Any


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
    "artifacts",
    "sarif",
}

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _count_loc(repo_root: Path, code_extensions: set[str]) -> int:
    total = 0
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in code_extensions:
            continue
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.strip():
                    total += 1
        except Exception:
            continue
    return total


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {sev: 0 for sev in SEVERITIES}
    for finding in findings:
        sev = str(finding.get("severity") or "MEDIUM").upper()
        if sev not in counts:
            sev = "MEDIUM"
        counts[sev] += 1
    return counts


def _severity_mix(counts: dict[str, int]) -> dict[str, dict[str, float | int]]:
    total = sum(counts.values())
    mix: dict[str, dict[str, float | int]] = {}
    for sev in SEVERITIES:
        count = int(counts.get(sev, 0))
        pct = round((count / total) * 100.0, 2) if total > 0 else 0.0
        mix[sev] = {"count": count, "percent": pct}
    return mix


def compute_rq1_metrics(
    repo_root: Path,
    findings: list[dict[str, Any]],
    delta_result: dict[str, Any],
    coverage_cfg: dict[str, Any],
) -> dict[str, Any]:
    code_exts = {str(ext).lower() for ext in (coverage_cfg.get("changed_code_extensions") or [])}
    if not code_exts:
        code_exts = {".java"}

    loc = _count_loc(repo_root, code_exts)
    kloc = (loc / 1000.0) if loc else 0.0
    overall_counts = _severity_counts(findings)
    overall_total = sum(overall_counts.values())
    overall_density = (overall_total / kloc) if kloc else None

    delta_counts = delta_result.get("severity_mix_delta") or _severity_counts(delta_result.get("new_findings") or [])

    return {
        "loc": int(loc),
        "kloc": round(kloc, 3),
        "overall_findings_count": overall_total,
        "new_findings_count": len(delta_result.get("new_findings") or []),
        "new_critical_findings_count": int(delta_result.get("new_critical_findings_count") or 0),
        "new_high_findings_count": int(delta_result.get("new_high_findings_count") or 0),
        "new_medium_findings_count": int(delta_result.get("new_medium_findings_count") or 0),
        "new_low_findings_count": int(delta_result.get("new_low_findings_count") or 0),
        "secrets_count_delta": int(delta_result.get("secrets_count_delta") or 0),
        "severity_mix_delta": _severity_mix(delta_counts),
        "severity_mix_overall": _severity_mix(overall_counts),
        "vulnerability_density_delta_per_kloc": delta_result.get("vulnerability_density_delta_per_kloc"),
        "vulnerability_density_overall_per_kloc": round(overall_density, 3) if overall_density is not None else None,
        "all_findings": findings,
        "limitations": [
            "Metrics are based on configured scanner outputs and parsed scope only.",
            "No-finding states can still contain residual risk due to tool blind spots.",
        ],
    }
