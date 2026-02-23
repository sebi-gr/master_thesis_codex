#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise FileNotFoundError(f"Required file not found: {path}")
    except Exception as exc:
        raise RuntimeError(f"Failed to parse JSON from {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return data


def enforce_from_gate(gate: dict, metrics: dict | None) -> int:
    hard = gate.get("hard_stop") or {}
    hard_passed = bool(hard.get("passed"))

    print("=== Deterministic Security Quality Gate ===")
    print(f"Profile: {gate.get('profile')}")
    print(f"Gate status for CI: {gate.get('status_for_ci')}")

    hard_metrics = hard.get("metrics") or {}
    print("Hard-stop metrics:")
    print(f"  new_critical_findings_count: {hard_metrics.get('new_critical_findings_count')} ")
    print(f"  new_high_findings_count:     {hard_metrics.get('new_high_findings_count')} ")
    print(f"  secrets_count_delta:         {hard_metrics.get('secrets_count_delta')} ")

    if metrics:
        print("Additional metrics context:")
        print(f"  compliance_score: {metrics.get('compliance_score')}")
        print(f"  coverage_overall_changed_code_percent: {metrics.get('coverage_overall_changed_code_percent')}")
        print(f"  vulnerability_density_delta_per_kloc: {metrics.get('vulnerability_density_delta_per_kloc')}")

    violations = hard.get("violations") or []
    if violations:
        print("Hard-stop violations:")
        for item in violations:
            print(f"  - {item.get('metric')}: {item.get('reason')}")

    soft_warnings = (gate.get("soft_gate") or {}).get("warnings") or []
    if soft_warnings:
        print("Soft warnings (non-blocking by default):")
        for warning in soft_warnings:
            print(f"  - {warning.get('metric')}: {warning.get('reason')}")

    if hard_passed:
        print("[QUALITY-GATE] PASS: hard-stop conditions satisfied.")
        return 0

    print("[QUALITY-GATE] FAIL: hard-stop violation(s) detected.", file=sys.stderr)
    return 1


def enforce_legacy(metrics: dict) -> int:
    critical = int(metrics.get("new_critical_findings_count", 0) or 0)
    high = int(metrics.get("new_high_findings_count", 0) or 0)
    secrets = int(metrics.get("secrets_count_delta", 0) or 0)

    print("=== Legacy Fallback Gate ===")
    print(f"new_critical_findings_count={critical}")
    print(f"new_high_findings_count={high}")
    print(f"secrets_count_delta={secrets}")

    violations = []
    if critical > 0:
        violations.append("new_critical_findings_count > 0")
    if high > 0:
        violations.append("new_high_findings_count > 0")
    if secrets > 0:
        violations.append("secrets_count_delta > 0")

    if not violations:
        print("[QUALITY-GATE] PASS (legacy fallback): no hard-stop violations")
        return 0

    print("[QUALITY-GATE] FAIL (legacy fallback):")
    for violation in violations:
        print(f"  - {violation}")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--gate-file",
        default="artifacts/gate-result.json",
        help="Path to deterministic gate result JSON",
    )
    parser.add_argument(
        "--metrics-file",
        default="security-metrics.json",
        help="Optional metrics JSON for context or legacy fallback",
    )
    args = parser.parse_args()

    gate_path = Path(args.gate_file)
    metrics_path = Path(args.metrics_file)

    metrics: dict | None = None
    if metrics_path.exists():
        try:
            metrics = _read_json(metrics_path)
        except Exception as exc:
            print(f"[QUALITY-GATE] Warning: could not read metrics file: {exc}", file=sys.stderr)
            metrics = None

    if gate_path.exists():
        gate = _read_json(gate_path)
        return enforce_from_gate(gate, metrics)

    if metrics is not None:
        print("[QUALITY-GATE] gate-result.json not found, using legacy fallback logic.")
        return enforce_legacy(metrics)

    print("[QUALITY-GATE] No gate or metrics artifact available.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
