from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _rel(path: str, repo_root: Path) -> str:
    p = Path(path)
    try:
        return str(p.resolve().relative_to(repo_root.resolve()))
    except Exception:
        return str(path)


def build_evidence_appendix(
    repo_root: Path,
    config_hashes: dict[str, str],
    config_versions: dict[str, str],
    ingestion_meta: dict[str, Any],
    changed_scope: dict[str, Any],
    baseline_meta: dict[str, Any],
    provenance_result: dict[str, Any],
    profile_name: str,
) -> dict[str, Any]:
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "profile": profile_name,
        "provenance": provenance_result,
        "tool_versions": ingestion_meta.get("tool_versions") or [],
        "tool_inputs": [
            {
                "path": _rel(path, repo_root),
                "type": "sarif" if str(path).endswith(".sarif") else "json",
            }
            for path in (ingestion_meta.get("inputs") or [])
        ],
        "scan_scope": {
            "method": changed_scope.get("method"),
            "is_exact": changed_scope.get("is_exact"),
            "changed_files": changed_scope.get("changed_files") or [],
            "changed_loc": changed_scope.get("changed_loc") or 0,
            "notes": changed_scope.get("notes") or [],
        },
        "baseline": baseline_meta,
        "config_versions": config_versions,
        "config_hashes_sha256": config_hashes,
        "reproducibility": {
            "deterministic_gate_inputs": True,
            "policy_as_code": True,
            "thresholds_as_code": True,
            "notes": [
                "Gate outcome is computed only from parsed findings + profile config + baseline + changed scope.",
                "No absolute security claim is made; results are bounded by scanner coverage and tool limitations.",
            ],
        },
    }
