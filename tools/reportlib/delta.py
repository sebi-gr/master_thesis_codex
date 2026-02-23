from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def finding_identity(finding: dict[str, Any]) -> str:
    if finding.get("fingerprint"):
        return f"fp::{finding['fingerprint']}"
    tool = str(finding.get("tool") or "")
    rule_id = str(finding.get("rule_id") or "")
    file_path = str(finding.get("file") or "")
    line = str(finding.get("start_line") or "")
    msg = str(finding.get("message") or "")[:200]
    return f"loc::{tool}::{rule_id}::{file_path}::{line}::{msg}"


def _run_git(repo_root: Path, args: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def collect_changed_scope(
    repo_root: Path,
    base_sha: str | None,
    head_sha: str | None,
    changed_files_hint: str | None,
) -> dict[str, Any]:
    notes: list[str] = []

    if changed_files_hint:
        files = sorted({line.strip() for line in changed_files_hint.replace(",", "\n").splitlines() if line.strip()})
        return {
            "changed_files": files,
            "changed_loc": 0,
            "method": "env_hint",
            "is_exact": False,
            "notes": ["Changed files came from CHANGED_FILES hint; changed LOC unavailable."],
        }

    if not base_sha or not head_sha:
        return {
            "changed_files": [],
            "changed_loc": 0,
            "method": "fallback_all_findings",
            "is_exact": False,
            "notes": ["Missing BASE_SHA/HEAD_SHA; delta falls back to findings-only scope."],
        }

    rc_files, out_files, err_files = _run_git(repo_root, ["diff", "--name-only", f"{base_sha}...{head_sha}"])
    rc_stat, out_stat, err_stat = _run_git(repo_root, ["diff", "--numstat", f"{base_sha}...{head_sha}"])

    if rc_files != 0 or rc_stat != 0:
        msg = " ".join(x.strip() for x in [err_files, err_stat] if x.strip())
        notes.append(msg or "git diff failed")
        return {
            "changed_files": [],
            "changed_loc": 0,
            "method": "fallback_all_findings",
            "is_exact": False,
            "notes": [
                "Git diff could not be computed; delta falls back to findings-only scope.",
                *notes,
            ],
        }

    files = sorted({line.strip() for line in out_files.splitlines() if line.strip()})

    changed_loc = 0
    for line in out_stat.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        add_raw, del_raw = parts[0], parts[1]
        try:
            added = int(add_raw) if add_raw.isdigit() else 0
            deleted = int(del_raw) if del_raw.isdigit() else 0
            changed_loc += added + deleted
        except Exception:
            continue

    return {
        "changed_files": files,
        "changed_loc": changed_loc,
        "method": "git_diff",
        "is_exact": True,
        "notes": notes,
    }


def load_baseline_identities(path: Path | None) -> tuple[set[str], dict[str, Any]]:
    if not path:
        return set(), {"source": "none", "count": 0, "notes": ["No baseline file supplied."]}
    if not path.exists():
        return set(), {"source": str(path), "count": 0, "notes": ["Baseline file path does not exist."]}

    raw = json.loads(path.read_text(encoding="utf-8"))
    findings: list[dict] = []

    if isinstance(raw, list):
        findings = [x for x in raw if isinstance(x, dict)]
    elif isinstance(raw, dict):
        if isinstance(raw.get("findings"), list):
            findings = [x for x in raw["findings"] if isinstance(x, dict)]
        elif isinstance(raw.get("groups"), list):
            for group in raw.get("groups") or []:
                if isinstance(group, dict) and isinstance(group.get("findings"), list):
                    findings.extend([x for x in group["findings"] if isinstance(x, dict)])

    identities = {finding_identity(f) for f in findings}
    return identities, {
        "source": str(path),
        "count": len(identities),
        "notes": [],
    }


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {sev: 0 for sev in SEVERITIES}
    for finding in findings:
        sev = str(finding.get("severity") or "MEDIUM").upper()
        if sev not in counts:
            sev = "MEDIUM"
        counts[sev] += 1
    return counts


def compute_delta(
    findings: list[dict[str, Any]],
    changed_scope: dict[str, Any],
    baseline_identities: set[str],
) -> dict[str, Any]:
    changed_files = set(changed_scope.get("changed_files") or [])
    changed_files_known = bool(changed_files)

    def in_changed_scope(finding: dict[str, Any]) -> bool:
        if not changed_files_known:
            return True
        path = finding.get("file")
        return bool(path and str(path) in changed_files)

    delta_candidates = [f for f in findings if in_changed_scope(f)]
    new_findings = [f for f in delta_candidates if finding_identity(f) not in baseline_identities]

    severity_mix_delta = _severity_counts(new_findings)
    severity_mix_overall = _severity_counts(findings)

    secrets_count_delta = sum(1 for f in new_findings if f.get("is_secret"))

    changed_loc = int(changed_scope.get("changed_loc") or 0)
    changed_kloc = (changed_loc / 1000.0) if changed_loc else 0.0
    overall_kloc = 0.0

    density_delta = (len(new_findings) / changed_kloc) if changed_kloc > 0 else None

    return {
        "delta_candidates": delta_candidates,
        "new_findings": new_findings,
        "severity_mix_delta": severity_mix_delta,
        "severity_mix_overall": severity_mix_overall,
        "new_critical_findings_count": severity_mix_delta.get("CRITICAL", 0),
        "new_high_findings_count": severity_mix_delta.get("HIGH", 0),
        "new_medium_findings_count": severity_mix_delta.get("MEDIUM", 0),
        "new_low_findings_count": severity_mix_delta.get("LOW", 0),
        "secrets_count_delta": secrets_count_delta,
        "changed_loc": changed_loc,
        "changed_kloc": round(changed_kloc, 3),
        "vulnerability_density_delta_per_kloc": round(density_delta, 3) if density_delta is not None else None,
        "overall_kloc": overall_kloc,
        "changed_scope": changed_scope,
        "baseline": {
            "used": bool(baseline_identities),
            "count": len(baseline_identities),
        },
        "limitations": [] if changed_files_known else [
            "Exact changed-file scope unavailable; delta fallback uses all parsed findings."
        ],
    }
