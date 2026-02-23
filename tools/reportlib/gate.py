from __future__ import annotations

from typing import Any


def _exception_for_metric(active_exceptions: list[dict[str, Any]], metric: str) -> dict[str, Any] | None:
    for exc in active_exceptions:
        if str(exc.get("metric") or "") == metric:
            return exc
    return None


def evaluate_gate(
    profile_name: str,
    profile_cfg: dict[str, Any],
    delta_metrics: dict[str, Any],
    compliance_result: dict[str, Any],
    coverage_result: dict[str, Any],
) -> dict[str, Any]:
    hard_cfg = profile_cfg.get("hard_stop") or {}
    soft_cfg = profile_cfg.get("soft_gate") or {}
    targets = profile_cfg.get("targets") or {}

    active_exceptions = compliance_result.get("active_exceptions") or []

    hard_thresholds = {
        "max_new_critical": int(hard_cfg.get("max_new_critical", 0)),
        "max_new_high": int(hard_cfg.get("max_new_high", 0)),
        "max_secrets_in_delta": int(hard_cfg.get("max_secrets_in_delta", 0)),
        "allow_high_exceptions": bool(hard_cfg.get("allow_high_exceptions", False)),
    }

    hard_metrics = {
        "new_critical_findings_count": int(delta_metrics.get("new_critical_findings_count", 0)),
        "new_high_findings_count": int(delta_metrics.get("new_high_findings_count", 0)),
        "secrets_count_delta": int(delta_metrics.get("secrets_count_delta", 0)),
    }

    hard_violations: list[dict[str, Any]] = []

    if hard_metrics["new_critical_findings_count"] > hard_thresholds["max_new_critical"]:
        hard_violations.append(
            {
                "metric": "new_critical_findings_count",
                "actual": hard_metrics["new_critical_findings_count"],
                "threshold": hard_thresholds["max_new_critical"],
                "reason": "New critical findings exceed hard-stop threshold.",
                "exception_id": None,
            }
        )

    high_exception = _exception_for_metric(active_exceptions, "new_high_findings_count")
    high_exceeded = hard_metrics["new_high_findings_count"] > hard_thresholds["max_new_high"]
    if high_exceeded:
        if high_exception and hard_thresholds["allow_high_exceptions"]:
            pass
        else:
            hard_violations.append(
                {
                    "metric": "new_high_findings_count",
                    "actual": hard_metrics["new_high_findings_count"],
                    "threshold": hard_thresholds["max_new_high"],
                    "reason": "New high findings exceed hard-stop threshold.",
                    "exception_id": high_exception.get("id") if high_exception else None,
                }
            )

    if hard_metrics["secrets_count_delta"] > hard_thresholds["max_secrets_in_delta"]:
        hard_violations.append(
            {
                "metric": "secrets_count_delta",
                "actual": hard_metrics["secrets_count_delta"],
                "threshold": hard_thresholds["max_secrets_in_delta"],
                "reason": "Secrets detected in changed scope.",
                "exception_id": None,
            }
        )

    soft_warnings: list[dict[str, Any]] = []

    medium_warn = int(soft_cfg.get("max_new_medium_warn", 0))
    low_warn = int(soft_cfg.get("max_new_low_warn", 0))
    density_warn = soft_cfg.get("max_vulnerability_density_delta_warn")

    new_medium = int(delta_metrics.get("new_medium_findings_count", 0))
    new_low = int(delta_metrics.get("new_low_findings_count", 0))
    density_delta = delta_metrics.get("vulnerability_density_delta_per_kloc")

    if new_medium > medium_warn:
        soft_warnings.append(
            {
                "metric": "new_medium_findings_count",
                "actual": new_medium,
                "threshold": medium_warn,
                "reason": "New medium findings exceed warning threshold.",
            }
        )

    if new_low > low_warn:
        soft_warnings.append(
            {
                "metric": "new_low_findings_count",
                "actual": new_low,
                "threshold": low_warn,
                "reason": "New low findings exceed warning threshold.",
            }
        )

    if density_warn is not None and density_delta is not None and float(density_delta) > float(density_warn):
        soft_warnings.append(
            {
                "metric": "vulnerability_density_delta_per_kloc",
                "actual": density_delta,
                "threshold": float(density_warn),
                "reason": "Delta vulnerability density exceeds warning threshold.",
            }
        )

    compliance_target = float(targets.get("compliance_score_min", 0))
    compliance_score = float(compliance_result.get("score", 0))
    if compliance_score < compliance_target:
        soft_warnings.append(
            {
                "metric": "compliance_score",
                "actual": compliance_score,
                "threshold": compliance_target,
                "reason": "Compliance score is below profile target.",
            }
        )

    coverage_target = float(targets.get("coverage_changed_code_min", 0))
    coverage_overall = coverage_result.get("overall_changed_code_percent")
    if coverage_overall is not None and float(coverage_overall) < coverage_target:
        soft_warnings.append(
            {
                "metric": "coverage_overall_changed_code_percent",
                "actual": float(coverage_overall),
                "threshold": coverage_target,
                "reason": "Changed-code coverage is below profile target.",
            }
        )

    missing_signals = coverage_result.get("missing_required_signals") or []
    if missing_signals:
        soft_warnings.append(
            {
                "metric": "missing_required_signals",
                "actual": len(missing_signals),
                "threshold": 0,
                "reason": f"Required scan signals missing: {', '.join(missing_signals)}.",
            }
        )

    hard_passed = len(hard_violations) == 0
    if hard_passed and soft_warnings:
        outcome = "pass_with_warnings"
    elif hard_passed:
        outcome = "pass"
    else:
        outcome = "fail"

    return {
        "profile": profile_name,
        "hard_stop": {
            "passed": hard_passed,
            "thresholds": hard_thresholds,
            "metrics": hard_metrics,
            "violations": hard_violations,
        },
        "soft_gate": {
            "warnings": soft_warnings,
            "medium_low_blocking": bool(soft_cfg.get("medium_low_blocking", False)),
        },
        "final_outcome": outcome,
        "status_for_ci": "fail" if not hard_passed else "pass",
        "reason_summary": [v["reason"] for v in hard_violations] + [w["reason"] for w in soft_warnings],
    }
