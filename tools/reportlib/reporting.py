from __future__ import annotations

from collections import Counter
from typing import Any


def _top_risks(delta_findings: list[dict[str, Any]], limit: int = 5) -> list[dict[str, Any]]:
    grouped: Counter[tuple[str, str]] = Counter()
    for f in delta_findings:
        grouped[(str(f.get("category") or "other"), str(f.get("severity") or "MEDIUM"))] += 1

    risks: list[dict[str, Any]] = []
    for (category, severity), count in grouped.most_common(limit):
        risks.append({"category": category, "severity": severity, "count": count})
    return risks


def _role_for_category(category: str) -> str:
    mapping = {
        "secret": "Application Security Engineer",
        "sql_injection": "Backend Engineering Lead",
        "path_traversal": "Backend Engineering Lead",
        "weak_crypto": "Security Champion",
        "other": "Product Engineering Owner",
    }
    return mapping.get(category, "Product Engineering Owner")


def _build_action_plan(gate_result: dict[str, Any], delta_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []

    for violation in gate_result.get("hard_stop", {}).get("violations") or []:
        metric = str(violation.get("metric"))
        if metric == "secrets_count_delta":
            recommendation = "Rotate and revoke exposed credential material; remove secret from code and history."
            owner = "Application Security Engineer"
            priority = "P0"
        elif metric == "new_critical_findings_count":
            recommendation = "Fix critical vulnerabilities in changed code before merge."
            owner = "Backend Engineering Lead"
            priority = "P0"
        else:
            recommendation = "Resolve high-severity findings in changed code before merge."
            owner = "Backend Engineering Lead"
            priority = "P1"

        actions.append(
            {
                "item": recommendation,
                "owner_role": owner,
                "priority": priority,
                "follow_up": "Before merge",
                "source": metric,
            }
        )

    categories = Counter(str(f.get("category") or "other") for f in delta_findings)
    for category, count in categories.most_common(3):
        actions.append(
            {
                "item": f"Address {count} finding(s) in category '{category}' and add regression checks.",
                "owner_role": _role_for_category(category),
                "priority": "P2",
                "follow_up": "Next sprint",
                "source": "delta_category_summary",
            }
        )

    # deterministic de-duplication by (item, owner_role)
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for action in actions:
        key = (action["item"], action["owner_role"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(action)

    return deduped


def build_structured_report(
    metadata: dict[str, Any],
    profile_name: str,
    provenance_result: dict[str, Any],
    metrics_block: dict[str, Any],
    gate_result: dict[str, Any],
    compliance_result: dict[str, Any],
    coverage_result: dict[str, Any],
    delta_result: dict[str, Any],
    evidence_appendix: dict[str, Any],
    audience: str,
    decision_request: str,
) -> dict[str, Any]:
    delta_findings = delta_result.get("new_findings") or []

    decision = "NO-GO" if gate_result.get("status_for_ci") == "fail" else "GO"
    if gate_result.get("final_outcome") == "pass_with_warnings":
        decision = "CONDITIONAL_GO"

    hard_reasons = [v.get("reason") for v in (gate_result.get("hard_stop", {}).get("violations") or [])]
    soft_reasons = [w.get("reason") for w in (gate_result.get("soft_gate", {}).get("warnings") or [])]

    action_plan = _build_action_plan(gate_result, delta_findings)

    limitations = [
        *metrics_block.get("limitations", []),
        *coverage_result.get("limitations", []),
        *delta_result.get("limitations", []),
    ]

    confidence = "moderate"
    if provenance_result.get("is_uncertain"):
        confidence = "low"
    elif coverage_result.get("overall_changed_code_percent") is not None and coverage_result.get("overall_changed_code_percent", 0) >= 99:
        confidence = "high"

    evidence_requirement = "standard"
    if profile_name == "partial_ai_provenance":
        evidence_requirement = "elevated"
    if profile_name == "ai_or_unknown_provenance":
        evidence_requirement = "high"

    return {
        "schema_version": "1.0.0",
        "metadata": metadata,
        "executive_decision_summary": {
            "decision": decision,
            "decision_request": decision_request,
            "audience": audience,
            "key_risks": _top_risks(delta_findings),
            "gate_profile": profile_name,
            "evidence_requirement_level": evidence_requirement,
            "provenance": provenance_result,
            "rationale": hard_reasons if hard_reasons else soft_reasons,
        },
        "scope_context": {
            "assessed_assets": sorted({str(f.get("file")) for f in metrics_block.get("all_findings", []) if f.get("file")}),
            "scan_scope": evidence_appendix.get("scan_scope"),
            "exposure_assumptions": [
                "Findings are evaluated for changed code scope first (delta-oriented gating).",
                "Tool outputs are treated as signals; absence of findings does not imply absence of risk.",
            ],
            "scope_boundaries": [
                "Only configured scanners and parsers are included in this report.",
                "Runtime behavior and production-only controls are outside direct static scan evidence.",
            ],
        },
        "key_metrics_gate_outcome": {
            "metrics": {
                "new_findings_count": len(delta_findings),
                "new_critical_findings_count": delta_result.get("new_critical_findings_count"),
                "new_high_findings_count": delta_result.get("new_high_findings_count"),
                "new_medium_findings_count": delta_result.get("new_medium_findings_count"),
                "new_low_findings_count": delta_result.get("new_low_findings_count"),
                "severity_mix_delta": delta_result.get("severity_mix_delta"),
                "severity_mix_overall": delta_result.get("severity_mix_overall"),
                "secrets_count_delta": delta_result.get("secrets_count_delta"),
                "vulnerability_density_delta_per_kloc": delta_result.get("vulnerability_density_delta_per_kloc"),
                "vulnerability_density_overall_per_kloc": metrics_block.get("vulnerability_density_overall_per_kloc"),
                "coverage_overall_changed_code_percent": coverage_result.get("overall_changed_code_percent"),
                "coverage_sast_changed_code_percent": coverage_result.get("sast_changed_code_percent"),
                "coverage_sca_applicability_percent": coverage_result.get("sca_applicability_percent"),
                "coverage_secrets_changed_files_percent": coverage_result.get("secrets_changed_files_percent"),
                "required_signals_coverage_percent": coverage_result.get("required_signals_coverage_percent"),
                "compliance_score": compliance_result.get("score"),
            },
            "thresholds": gate_result.get("hard_stop", {}).get("thresholds"),
            "gate": gate_result,
        },
        "policy_compliance_exceptions": {
            "policy_version": (evidence_appendix.get("config_versions") or {}).get("policies") or "",
            "rules": compliance_result.get("rules") or [],
            "compliance_score": compliance_result.get("score"),
            "blocking_failures": compliance_result.get("blocking_failures") or [],
            "non_blocking_failures": compliance_result.get("non_blocking_failures") or [],
            "active_exceptions": compliance_result.get("active_exceptions") or [],
        },
        "action_plan_with_accountability": action_plan,
        "limitations_confidence_statement": {
            "limitations": [
                {
                    "statement": item,
                    "usability_note": "Report remains decision-useful because thresholds, scope, and provenance are explicit."
                }
                for item in limitations
            ],
            "confidence": confidence,
            "uncertainty_representation": {
                "provenance_uncertain": bool(provenance_result.get("is_uncertain")),
                "coverage_percent": coverage_result.get("overall_changed_code_percent"),
                "evidence_requirement_level": evidence_requirement,
                "false_positive_false_negative_note": "Scanner outputs may contain false positives/false negatives; decisions should include engineering review.",
            },
            "credibility_constraints": [
                "No absolute security guarantee is claimed.",
                "Passing the hard-stop gate indicates threshold compliance within measured scope, not complete security.",
            ],
        },
        "evidence_appendix": {
            **evidence_appendix,
            "raw_delta_findings": delta_findings,
            "all_findings_count": len(metrics_block.get("all_findings", [])),
            "delta_findings_count": len(delta_findings),
        },
    }


def render_markdown_report(report: dict[str, Any]) -> str:
    exec_summary = report["executive_decision_summary"]
    gate = report["key_metrics_gate_outcome"]["gate"]
    metrics = report["key_metrics_gate_outcome"]["metrics"]
    policy = report["policy_compliance_exceptions"]

    lines = [
        "# Security Decision Report",
        "",
        "## 1. Executive Decision Summary",
        f"- Decision: **{exec_summary['decision']}**",
        f"- Decision request: {exec_summary['decision_request']}",
        f"- Audience: {exec_summary['audience']}",
        f"- Profile: `{exec_summary['gate_profile']}`",
        f"- Evidence requirement: `{exec_summary.get('evidence_requirement_level')}`",
        f"- Provenance: `{exec_summary['provenance'].get('raw_value')}` (confidence: {exec_summary['provenance'].get('confidence')})",
        "",
        "## 2. Scope & Context",
        f"- Scan scope method: `{report['scope_context']['scan_scope'].get('method')}`",
        f"- Changed files in scope: {len(report['scope_context']['scan_scope'].get('changed_files') or [])}",
        f"- Assessed assets: {len(report['scope_context']['assessed_assets'])}",
        "",
        "## 3. Key Metrics & Gate Outcome",
        f"- Hard-stop status: **{'PASS' if gate['hard_stop']['passed'] else 'FAIL'}**",
        f"- New critical findings: {metrics['new_critical_findings_count']}",
        f"- New high findings: {metrics['new_high_findings_count']}",
        f"- Secrets in delta: {metrics['secrets_count_delta']}",
        f"- Delta vulnerability density (/KLOC): {metrics['vulnerability_density_delta_per_kloc']}",
        f"- Compliance score: {metrics['compliance_score']}",
        f"- Coverage (changed code): {metrics['coverage_overall_changed_code_percent']}",
        "",
        "## 4. Policy Compliance & Exceptions",
        f"- Policy compliance score: {policy['compliance_score']}",
        f"- Blocking rule failures: {len(policy['blocking_failures'])}",
        f"- Active exceptions: {len(policy['active_exceptions'])}",
        "",
        "## 5. Action Plan with Accountability",
    ]

    for action in report.get("action_plan_with_accountability", []):
        lines.append(
            f"- [{action['priority']}] {action['item']} | owner role: {action['owner_role']} | follow-up: {action['follow_up']}"
        )

    lines.extend(
        [
            "",
            "## 6. Limitations & Confidence Statement",
            f"- Confidence: {report['limitations_confidence_statement']['confidence']}",
            "- Limitations:",
        ]
    )

    for lim in report["limitations_confidence_statement"]["limitations"]:
        lines.append(f"  - {lim['statement']} | why still usable: {lim['usability_note']}")

    lines.extend(
        [
            "",
            "## 7. Evidence Appendix",
            f"- Generated at: {report['evidence_appendix']['generated_at_utc']}",
            f"- Tool versions: {', '.join(report['evidence_appendix'].get('tool_versions') or []) or 'n/a'}",
            f"- Config hashes captured: {len(report['evidence_appendix'].get('config_hashes_sha256') or {})}",
            f"- Baseline source: {report['evidence_appendix'].get('baseline', {}).get('source')}",
        ]
    )

    return "\n".join(lines).strip() + "\n"
