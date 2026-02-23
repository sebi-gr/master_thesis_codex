from __future__ import annotations

from fnmatch import fnmatch
from typing import Any


def _pct(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round((numerator / denominator) * 100.0, 2)


def _tool_signal_map(tooling_cfg: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    tools = tooling_cfg.get("tools") or {}
    for tool_name, meta in tools.items():
        if not isinstance(meta, dict):
            continue
        out[str(tool_name)] = str(meta.get("signal") or "unknown")
    return out


def _claims_full_scan(tooling_cfg: dict[str, Any], tool_name: str) -> bool:
    tools = tooling_cfg.get("tools") or {}
    meta = tools.get(tool_name.lower()) or tools.get(tool_name) or {}
    return bool(meta.get("claims_full_repo_scan"))


def evaluate_coverage(
    changed_scope: dict[str, Any],
    scanned_files_by_tool: dict[str, list[str]] | dict[str, set[str]],
    tooling_cfg: dict[str, Any],
    coverage_cfg: dict[str, Any],
    profile_name: str,
) -> dict[str, Any]:
    changed_files = sorted({str(f) for f in (changed_scope.get("changed_files") or []) if f})
    changed_code_exts = {str(ext).lower() for ext in (coverage_cfg.get("changed_code_extensions") or [])}
    dep_patterns = [str(p) for p in (coverage_cfg.get("dependency_manifest_patterns") or [])]

    changed_code_files = [f for f in changed_files if any(f.lower().endswith(ext) for ext in changed_code_exts)]
    dependency_files = [f for f in changed_files if any(fnmatch(f.split("/")[-1], pat) for pat in dep_patterns)]
    secrets_scope_files = list(changed_files)

    signal_by_tool = _tool_signal_map(tooling_cfg)
    scanned_sets: dict[str, set[str]] = {
        tool: {str(f) for f in files}
        for tool, files in (scanned_files_by_tool or {}).items()
    }

    tools_present = sorted(scanned_sets.keys())
    signals_present = sorted(
        {
            signal_by_tool.get(tool.lower()) or signal_by_tool.get(tool) or "unknown"
            for tool in tools_present
        }
    )
    required_signals = [str(s) for s in ((tooling_cfg.get("signal_expectations") or {}).get("required_signals") or [])]
    missing_required_signals = sorted([s for s in required_signals if s not in signals_present])
    required_signals_coverage = (
        round(((len(required_signals) - len(missing_required_signals)) / len(required_signals)) * 100.0, 2)
        if required_signals
        else 100.0
    )

    def covered_by_signal(target_files: list[str], signal: str) -> set[str]:
        if not target_files:
            return set()
        target_set = set(target_files)
        covered: set[str] = set()
        for tool in tools_present:
            tool_signal = signal_by_tool.get(tool.lower()) or signal_by_tool.get(tool) or "unknown"
            if tool_signal != signal:
                continue
            if _claims_full_scan(tooling_cfg, tool):
                covered.update(target_set)
                continue
            covered.update(target_set.intersection(scanned_sets.get(tool, set())))
        return covered

    sast_covered = covered_by_signal(changed_code_files, "sast")
    sca_covered = covered_by_signal(dependency_files, "sca")
    secrets_covered = covered_by_signal(secrets_scope_files, "secrets")

    overall_covered = set(changed_code_files)
    if changed_code_files:
        union_scanned = set()
        for tool in tools_present:
            if _claims_full_scan(tooling_cfg, tool):
                union_scanned.update(changed_code_files)
            else:
                union_scanned.update(set(changed_code_files).intersection(scanned_sets.get(tool, set())))
        overall_covered = union_scanned
    else:
        overall_covered = set()

    profile_targets = (coverage_cfg.get("profile_overrides") or {}).get(profile_name, {})

    coverage = {
        "changed_files_total": len(changed_files),
        "changed_code_files_total": len(changed_code_files),
        "dependency_files_total": len(dependency_files),
        "sast_changed_code_percent": _pct(len(sast_covered), len(changed_code_files)),
        "sca_applicability_percent": _pct(len(sca_covered), len(dependency_files)),
        "secrets_changed_files_percent": _pct(len(secrets_covered), len(secrets_scope_files)),
        "overall_changed_code_percent": _pct(len(overall_covered), len(changed_code_files)),
        "targets": {
            "overall_changed_code_min": profile_targets.get("overall_changed_code_min"),
            "sast_changed_code_min": profile_targets.get("sast_changed_code_min"),
            "sca_applicability_min": profile_targets.get("sca_applicability_min"),
            "secrets_changed_files_min": profile_targets.get("secrets_changed_files_min"),
        },
        "scanned_files_by_tool": {tool: sorted(files) for tool, files in scanned_sets.items()},
        "tools_present": tools_present,
        "signals_present": signals_present,
        "required_signals": required_signals,
        "missing_required_signals": missing_required_signals,
        "required_signals_coverage_percent": required_signals_coverage,
        "limitations": [],
    }

    if not changed_files:
        coverage["limitations"].append(
            "No changed files detected. Coverage on changed scope is not measurable in this run."
        )

    if coverage["overall_changed_code_percent"] is None and changed_code_files:
        coverage["limitations"].append(
            "Coverage evidence is incomplete for changed code due to missing scan scope metadata."
        )
    if missing_required_signals:
        coverage["limitations"].append(
            f"Required scan signals missing in this run: {', '.join(missing_required_signals)}."
        )

    return coverage
