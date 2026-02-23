from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _resolve_path(data: dict[str, Any], dotted_path: str) -> Any:
    current: Any = data
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _compare(value: float, comparator: str, threshold: float) -> bool:
    if comparator == "<=":
        return value <= threshold
    if comparator == ">=":
        return value >= threshold
    if comparator == "<":
        return value < threshold
    if comparator == ">":
        return value > threshold
    if comparator == "==":
        return value == threshold
    raise ValueError(f"Unsupported comparator: {comparator}")


def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    normalized = ts.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _active_exceptions(
    exceptions_cfg: dict[str, Any],
    profile_name: str,
    now_utc: datetime,
) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for exc in (exceptions_cfg.get("exceptions") or []):
        if not isinstance(exc, dict):
            continue
        metric = str(exc.get("metric") or "")
        if not metric:
            continue
        applies = exc.get("applies_to_profiles") or []
        if applies and profile_name not in applies:
            continue
        expires_at = _parse_ts(exc.get("expires_utc"))
        if expires_at and expires_at < now_utc:
            continue
        out.setdefault(metric, []).append(exc)
    return out


def evaluate_policy_compliance(
    policies_cfg: dict[str, Any],
    profile_cfg: dict[str, Any],
    profile_name: str,
    metrics_context: dict[str, Any],
    exceptions_cfg: dict[str, Any],
) -> dict[str, Any]:
    now_utc = datetime.now(timezone.utc)
    active_exceptions = _active_exceptions(exceptions_cfg, profile_name, now_utc)

    rules_eval: list[dict[str, Any]] = []
    total_weight = 0.0
    passed_weight = 0.0

    for rule in (policies_cfg.get("rules") or []):
        if not isinstance(rule, dict):
            continue

        rid = str(rule.get("id") or "")
        metric = str(rule.get("metric") or "")
        comparator = str(rule.get("comparator") or "<=")
        threshold_ref = str(rule.get("threshold_ref") or "")
        weight = float(rule.get("weight") or 0)
        blocking = bool(rule.get("blocking"))

        metric_value = metrics_context.get(metric)
        threshold = _resolve_path(profile_cfg, threshold_ref) if threshold_ref else None

        passed = False
        evaluation_error = ""
        if metric_value is None:
            evaluation_error = f"Metric '{metric}' is missing"
        elif threshold is None:
            evaluation_error = f"Threshold ref '{threshold_ref}' is missing"
        else:
            try:
                passed = _compare(float(metric_value), comparator, float(threshold))
            except Exception as exc:
                evaluation_error = str(exc)

        exception_used: dict[str, Any] | None = None
        if not passed and metric in active_exceptions:
            # First active exception wins for deterministic behavior.
            exception_used = active_exceptions[metric][0]
            passed = True

        total_weight += weight
        if passed:
            passed_weight += weight

        rules_eval.append(
            {
                "id": rid,
                "title": str(rule.get("title") or ""),
                "description": str(rule.get("description") or ""),
                "metric": metric,
                "value": metric_value,
                "comparator": comparator,
                "threshold": threshold,
                "threshold_ref": threshold_ref,
                "weight": weight,
                "blocking": blocking,
                "passed": passed,
                "exception_id": exception_used.get("id") if exception_used else None,
                "exception_rationale": exception_used.get("rationale") if exception_used else None,
                "evaluation_error": evaluation_error,
            }
        )

    compliance_score = round((passed_weight / total_weight) * 100.0, 2) if total_weight > 0 else 0.0

    blocking_failures = [r for r in rules_eval if (not r["passed"] and r["blocking"])]
    non_blocking_failures = [r for r in rules_eval if (not r["passed"] and not r["blocking"])]
    active_exceptions_flat = [exc for vals in active_exceptions.values() for exc in vals]

    return {
        "score": compliance_score,
        "rules": rules_eval,
        "blocking_failures": blocking_failures,
        "non_blocking_failures": non_blocking_failures,
        "active_exceptions": active_exceptions_flat,
        "evaluated_at_utc": now_utc.isoformat(),
    }
