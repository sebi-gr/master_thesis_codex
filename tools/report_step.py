#!/usr/bin/env python3
"""
Builds RQ1/RQ2-aligned security metrics, deterministic gate output, and audit-ready reports.

Primary artifacts (written to artifacts/ by default):
- security-report.json (machine-readable structured report)
- security-report.md (human-readable report)
- security-metrics.json (compact CI-oriented metrics)
- gate-result.json (deterministic gate decision payload)
- report.html (human-readable HTML)
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.reportlib import (
    io,
    config,
    provenance,
    ingestion,
    delta,
    coverage,
    compliance,
    gate,
    evidence,
    rq_metrics,
    reporting,
    render,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS_DIR = REPO_ROOT / "artifacts"


def _env(key: str, default: str | None = None) -> str | None:
    return os.environ.get(key, default)


def _resolve_path(base: Path, raw: str | None) -> Path | None:
    if not raw:
        return None
    p = Path(raw)
    if p.is_absolute():
        return p
    return (base / p).resolve()


def _baseline_path(repo_root: Path, artifacts_dir: Path, env: dict[str, str], cli_baseline: str | None) -> Path | None:
    candidates = [
        cli_baseline,
        env.get("BASELINE_FINDINGS_FILE"),
        str(artifacts_dir / "baseline_findings.json"),
    ]
    for candidate in candidates:
        path = _resolve_path(repo_root, candidate)
        if path and path.exists():
            return path
    return None


def _metadata(repo_root: Path, env: dict[str, str], profile_name: str, provenance_result: dict[str, Any]) -> dict[str, Any]:
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "repo": env.get("REPO_NAME") or repo_root.name,
        "run_id": env.get("RUN_ID") or env.get("GITHUB_RUN_ID") or "",
        "workflow": env.get("GITHUB_WORKFLOW") or "",
        "pr_number": env.get("PR_NUMBER") or env.get("GITHUB_REF_NAME") or "",
        "commit_sha": env.get("COMMIT_SHA") or env.get("GITHUB_SHA") or "",
        "profile": profile_name,
        "provenance": provenance_result,
    }


def _config_versions(cfg: config.SecurityConfig) -> dict[str, str]:
    return {
        "profiles": str(cfg.profiles.get("version") or ""),
        "severity_mapping": str(cfg.severity_mapping.get("version") or ""),
        "policies": str(cfg.policies.get("version") or ""),
        "coverage_targets": str(cfg.coverage_targets.get("version") or ""),
        "tooling": str(cfg.tooling.get("version") or ""),
        "provenance": str(cfg.provenance.get("version") or ""),
        "exceptions": str(cfg.exceptions.get("version") or ""),
    }


def _compact_metrics(
    profile_name: str,
    metrics_block: dict[str, Any],
    delta_result: dict[str, Any],
    coverage_result: dict[str, Any],
    compliance_result: dict[str, Any],
    gate_result: dict[str, Any],
) -> dict[str, Any]:
    return {
        "profile": profile_name,
        "gate_status": gate_result.get("status_for_ci"),
        "hard_stop_passed": gate_result.get("hard_stop", {}).get("passed"),
        "new_critical_findings_count": delta_result.get("new_critical_findings_count"),
        "new_high_findings_count": delta_result.get("new_high_findings_count"),
        "severity_mix_delta": delta_result.get("severity_mix_delta"),
        "severity_mix_overall": delta_result.get("severity_mix_overall"),
        "secrets_count_delta": delta_result.get("secrets_count_delta"),
        "vulnerability_density_delta_per_kloc": delta_result.get("vulnerability_density_delta_per_kloc"),
        "vulnerability_density_overall_per_kloc": delta_result.get("vulnerability_density_overall_per_kloc")
        if delta_result.get("vulnerability_density_overall_per_kloc") is not None
        else metrics_block.get("vulnerability_density_overall_per_kloc"),
        "compliance_score": compliance_result.get("score"),
        "coverage_overall_changed_code_percent": coverage_result.get("overall_changed_code_percent"),
        "coverage_details": {
            "sast_changed_code_percent": coverage_result.get("sast_changed_code_percent"),
            "sca_applicability_percent": coverage_result.get("sca_applicability_percent"),
            "secrets_changed_files_percent": coverage_result.get("secrets_changed_files_percent"),
            "required_signals_coverage_percent": coverage_result.get("required_signals_coverage_percent"),
        },
        "hard_violations": gate_result.get("hard_stop", {}).get("violations") or [],
        "soft_warnings": gate_result.get("soft_gate", {}).get("warnings") or [],
        # Legacy-compatible aliases
        "total_issue_groups": delta_result.get("new_findings_count", metrics_block.get("new_findings_count")),
        "severities": {
            "critical": delta_result.get("new_critical_findings_count"),
            "high": delta_result.get("new_high_findings_count"),
            "medium": delta_result.get("new_medium_findings_count", 0),
            "low": delta_result.get("new_low_findings_count", 0),
        },
        "categories": {
            "secret": delta_result.get("secrets_count_delta"),
        },
        "density_per_kloc_grouped": delta_result.get("vulnerability_density_delta_per_kloc"),
    }


def build_report(
    repo_root: Path,
    artifacts_dir: Path,
    env: dict[str, str],
    *,
    sarif_dir: Path | None = None,
    baseline_path: Path | None = None,
    profile_override: str | None = None,
    audience: str | None = None,
    decision_request: str | None = None,
) -> dict[str, Any]:
    cfg = config.load_security_config(repo_root)

    provenance_result = provenance.classify_provenance(
        cfg.provenance,
        explicit_value=env.get("PROVENANCE"),
        pr_body=env.get("PR_BODY"),
    )

    requested_profile = profile_override or env.get("SECURITY_PROFILE")
    if requested_profile:
        profile_name = config.resolve_profile_name(cfg, requested_profile)
    else:
        profile_name = config.resolve_profile_name(cfg, provenance_result.get("profile"))

    profile_cfg = config.get_profile_config(cfg, profile_name)

    findings, ingestion_meta = ingestion.load_findings(
        repo_root=repo_root,
        artifacts_dir=artifacts_dir,
        sarif_dir=sarif_dir,
        tooling_cfg=cfg.tooling,
        severity_cfg=cfg.severity_mapping,
    )

    changed_scope = delta.collect_changed_scope(
        repo_root=repo_root,
        base_sha=env.get("BASE_SHA") or env.get("GITHUB_BASE_SHA"),
        head_sha=env.get("HEAD_SHA") or env.get("GITHUB_SHA"),
        changed_files_hint=env.get("CHANGED_FILES"),
    )

    baseline_ids, baseline_meta = delta.load_baseline_identities(baseline_path)
    delta_result = delta.compute_delta(findings, changed_scope, baseline_ids)

    coverage_result = coverage.evaluate_coverage(
        changed_scope=changed_scope,
        scanned_files_by_tool=ingestion_meta.get("scanned_files_by_tool") or {},
        tooling_cfg=cfg.tooling,
        coverage_cfg=cfg.coverage_targets,
        profile_name=profile_name,
    )

    metrics_block = rq_metrics.compute_rq1_metrics(
        repo_root=repo_root,
        findings=findings,
        delta_result=delta_result,
        coverage_cfg=cfg.coverage_targets,
    )

    metrics_context = {
        "new_critical_findings_count": delta_result.get("new_critical_findings_count", 0),
        "new_high_findings_count": delta_result.get("new_high_findings_count", 0),
        "secrets_count_delta": delta_result.get("secrets_count_delta", 0),
        "coverage_overall_changed_code_percent": coverage_result.get("overall_changed_code_percent")
        if coverage_result.get("overall_changed_code_percent") is not None
        else 0.0,
        "required_signals_coverage_percent": coverage_result.get("required_signals_coverage_percent", 0.0),
    }

    compliance_result = compliance.evaluate_policy_compliance(
        policies_cfg=cfg.policies,
        profile_cfg=profile_cfg,
        profile_name=profile_name,
        metrics_context=metrics_context,
        exceptions_cfg=cfg.exceptions,
    )

    gate_result = gate.evaluate_gate(
        profile_name=profile_name,
        profile_cfg=profile_cfg,
        delta_metrics=delta_result,
        compliance_result=compliance_result,
        coverage_result=coverage_result,
    )

    metadata = _metadata(repo_root, env, profile_name, provenance_result)

    evidence_appendix = evidence.build_evidence_appendix(
        repo_root=repo_root,
        config_hashes=config.config_hashes(cfg),
        config_versions=_config_versions(cfg),
        ingestion_meta=ingestion_meta,
        changed_scope=changed_scope,
        baseline_meta=baseline_meta,
        provenance_result=provenance_result,
        profile_name=profile_name,
    )

    audience_value = audience or env.get("REPORT_AUDIENCE") or "Engineering leadership, security reviewers, release managers"
    decision_request_value = (
        decision_request
        or env.get("DECISION_REQUEST")
        or "Go/No-Go decision for merge and release progression"
    )

    report = reporting.build_structured_report(
        metadata=metadata,
        profile_name=profile_name,
        provenance_result=provenance_result,
        metrics_block=metrics_block,
        gate_result=gate_result,
        compliance_result=compliance_result,
        coverage_result=coverage_result,
        delta_result=delta_result,
        evidence_appendix=evidence_appendix,
        audience=audience_value,
        decision_request=decision_request_value,
    )

    # Compatibility mirrors for existing consumers.
    report["gate"] = gate_result
    report["measure"] = {
        "totals_by_severity": {
            sev: payload["count"]
            for sev, payload in (metrics_block.get("severity_mix_overall") or {}).items()
        },
        "loc": metrics_block.get("loc"),
        "kloc": metrics_block.get("kloc"),
    }

    return report


def _write_html(path: Path, report: dict[str, Any], repo_root: Path) -> None:
    template_path = repo_root / "tools" / "templates" / "report.html.j2"
    html = render.render_html(report, template_path)
    path.write_text(html, encoding="utf-8")


def run(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo_root).resolve()
    artifacts_dir = Path(args.artifacts_dir).resolve()
    io.ensure_dir(artifacts_dir)

    env = dict(os.environ)
    if args.pr_body is not None:
        env["PR_BODY"] = args.pr_body
    if args.provenance is not None:
        env["PROVENANCE"] = args.provenance
    if args.base_sha is not None:
        env["BASE_SHA"] = args.base_sha
    if args.head_sha is not None:
        env["HEAD_SHA"] = args.head_sha
    if args.profile is not None:
        env["SECURITY_PROFILE"] = args.profile

    sarif_dir = _resolve_path(repo_root, args.sarif_dir)
    baseline = _baseline_path(repo_root, artifacts_dir, env, args.baseline_findings)

    try:
        report = build_report(
            repo_root=repo_root,
            artifacts_dir=artifacts_dir,
            env=env,
            sarif_dir=sarif_dir,
            baseline_path=baseline,
            profile_override=args.profile,
            audience=args.audience,
            decision_request=args.decision_request,
        )
    except Exception as exc:
        print(f"[report_step] ERROR: {exc}", file=sys.stderr)
        return 1

    gate_result = report.get("gate") or {}
    metrics_compact = _compact_metrics(
        profile_name=report["executive_decision_summary"]["gate_profile"],
        metrics_block=report.get("measure") or {},
        delta_result=report["key_metrics_gate_outcome"]["metrics"],
        coverage_result={
            "overall_changed_code_percent": report["key_metrics_gate_outcome"]["metrics"].get(
                "coverage_overall_changed_code_percent"
            ),
            "sast_changed_code_percent": report["key_metrics_gate_outcome"]["metrics"].get(
                "coverage_sast_changed_code_percent"
            ),
            "sca_applicability_percent": report["key_metrics_gate_outcome"]["metrics"].get(
                "coverage_sca_applicability_percent"
            ),
            "secrets_changed_files_percent": report["key_metrics_gate_outcome"]["metrics"].get(
                "coverage_secrets_changed_files_percent"
            ),
            "required_signals_coverage_percent": report["key_metrics_gate_outcome"]["metrics"].get(
                "required_signals_coverage_percent"
            ),
        },
        compliance_result={"score": report["key_metrics_gate_outcome"]["metrics"].get("compliance_score")},
        gate_result=gate_result,
    )

    json_path = artifacts_dir / "security-report.json"
    md_path = artifacts_dir / "security-report.md"
    gate_path = artifacts_dir / "gate-result.json"
    metrics_path = artifacts_dir / "security-metrics.json"
    html_path = artifacts_dir / "report.html"

    io.write_json(json_path, report)
    io.write_json(gate_path, gate_result)
    io.write_json(metrics_path, metrics_compact)
    md_path.write_text(reporting.render_markdown_report(report), encoding="utf-8")
    _write_html(html_path, report, repo_root)

    # Backward-compatible file names
    io.write_json(artifacts_dir / "report.json", report)
    io.write_json(artifacts_dir / "metrics.json", metrics_compact)
    (artifacts_dir / "pr_summary.md").write_text(reporting.render_markdown_report(report), encoding="utf-8")

    if args.exit_on_hard_stop and gate_result.get("status_for_ci") == "fail":
        return 1

    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build security report and deterministic gate artifacts")
    parser.add_argument("--repo-root", default=str(REPO_ROOT), help="Repository root")
    parser.add_argument("--artifacts-dir", default=str(ARTIFACTS_DIR), help="Output artifacts directory")
    parser.add_argument("--sarif-dir", default="sarif", help="SARIF directory (relative to repo root unless absolute)")
    parser.add_argument("--baseline-findings", default=None, help="Path to baseline findings JSON")
    parser.add_argument("--base-sha", default=None, help="Base commit SHA for git diff scope")
    parser.add_argument("--head-sha", default=None, help="Head commit SHA for git diff scope")
    parser.add_argument("--profile", default=None, help="Profile override")
    parser.add_argument("--provenance", default=None, help="Explicit provenance value")
    parser.add_argument("--pr-body", default=None, help="PR body text for provenance parsing")
    parser.add_argument("--audience", default=None, help="Audience statement for report")
    parser.add_argument("--decision-request", default=None, help="Decision request statement for report")
    parser.add_argument(
        "--exit-on-hard-stop",
        action="store_true",
        help="Return non-zero if hard-stop gate fails",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
