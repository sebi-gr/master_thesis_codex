from pathlib import Path

from tools import report_step
from tools.reportlib import io


def _write_minimal_config(repo_root: Path) -> None:
    cfg = repo_root / "security_config"
    cfg.mkdir(parents=True, exist_ok=True)

    io.write_json(
        cfg / "profiles.yaml",
        {
            "version": "1.0.0",
            "default_profile": "known_provenance",
            "profiles": {
                "known_provenance": {
                    "hard_stop": {
                        "max_new_critical": 0,
                        "max_new_high": 0,
                        "max_secrets_in_delta": 0,
                        "allow_high_exceptions": False,
                    },
                    "soft_gate": {
                        "max_new_medium_warn": 2,
                        "max_new_low_warn": 5,
                        "max_vulnerability_density_delta_warn": 1.0,
                    },
                    "targets": {
                        "compliance_score_min": 95.0,
                        "coverage_changed_code_min": 95.0,
                    },
                }
            },
        },
    )

    io.write_json(
        cfg / "severity_mapping.yaml",
        {
            "version": "1.0.0",
            "security_severity_score": {"critical_min": 9.0, "high_min": 7.0, "medium_min": 4.0},
        },
    )

    io.write_json(
        cfg / "coverage_targets.yaml",
        {
            "version": "1.0.0",
            "changed_code_extensions": [".java"],
            "dependency_manifest_patterns": ["pom.xml"],
            "profile_overrides": {
                "known_provenance": {
                    "overall_changed_code_min": 95.0,
                    "sast_changed_code_min": 95.0,
                    "sca_applicability_min": 90.0,
                    "secrets_changed_files_min": 95.0,
                }
            },
        },
    )

    io.write_json(
        cfg / "tooling.yaml",
        {
            "version": "1.0.0",
            "tools": {"gitleaks": {"signal": "secrets", "claims_full_repo_scan": True}},
            "signal_expectations": {"required_signals": ["sast", "secrets"]},
        },
    )

    io.write_json(
        cfg / "policies.yaml",
        {
            "version": "1.0.0",
            "rules": [
                {
                    "id": "POL-1",
                    "title": "no critical",
                    "metric": "new_critical_findings_count",
                    "comparator": "<=",
                    "threshold_ref": "hard_stop.max_new_critical",
                    "weight": 50,
                    "blocking": True,
                },
                {
                    "id": "POL-2",
                    "title": "no high",
                    "metric": "new_high_findings_count",
                    "comparator": "<=",
                    "threshold_ref": "hard_stop.max_new_high",
                    "weight": 50,
                    "blocking": True,
                },
            ],
        },
    )

    io.write_json(
        cfg / "provenance.yaml",
        {
            "version": "1.0.0",
            "pr_trailer_key": "Provenance",
            "default_if_missing": "ai_or_unknown_provenance",
            "classifications": {
                "known_provenance": {"values": ["human"], "confidence": "high"},
                "ai_or_unknown_provenance": {"values": ["ai", "unknown"], "confidence": "medium"},
            },
            "uncertain_behavior": {"profile": "ai_or_unknown_provenance", "confidence": "low", "note": "fallback"},
        },
    )

    io.write_json(cfg / "exceptions.yaml", {"version": "1.0.0", "exceptions": []})


def test_report_required_keys(tmp_path: Path):
    repo_root = tmp_path
    artifacts = repo_root / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)

    _write_minimal_config(repo_root)

    findings = [
        {
            "tool": "gitleaks",
            "rule_id": "generic-api-key",
            "severity": "HIGH",
            "message": "Potential secret",
            "file": "src/A.java",
            "start_line": 1,
            "end_line": 1,
            "cwe": [],
            "tags": ["secret"],
            "is_secret": True,
        }
    ]
    io.write_json(artifacts / "normalized_findings.json", findings)

    report = report_step.build_report(repo_root, artifacts, {"PROVENANCE": "human", "CHANGED_FILES": "src/A.java"})

    for key in (
        "executive_decision_summary",
        "scope_context",
        "key_metrics_gate_outcome",
        "policy_compliance_exceptions",
        "action_plan_with_accountability",
        "limitations_confidence_statement",
        "evidence_appendix",
    ):
        assert key in report

    assert report["executive_decision_summary"]["audience"]
    assert report["key_metrics_gate_outcome"]["gate"]["hard_stop"]["passed"] is False
