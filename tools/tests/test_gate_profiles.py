from pathlib import Path

from tools import report_step
from tools.reportlib import io


def _write_config(repo_root: Path) -> None:
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
                        "max_new_medium_warn": 1,
                        "max_new_low_warn": 2,
                        "max_vulnerability_density_delta_warn": 1.0,
                    },
                    "targets": {
                        "compliance_score_min": 95.0,
                        "coverage_changed_code_min": 95.0,
                    },
                },
                "partial_ai_provenance": {
                    "hard_stop": {
                        "max_new_critical": 0,
                        "max_new_high": 0,
                        "max_secrets_in_delta": 0,
                        "allow_high_exceptions": False,
                    },
                    "soft_gate": {
                        "max_new_medium_warn": 0,
                        "max_new_low_warn": 1,
                        "max_vulnerability_density_delta_warn": 0.5,
                    },
                    "targets": {
                        "compliance_score_min": 97.0,
                        "coverage_changed_code_min": 97.0,
                    },
                },
                "ai_or_unknown_provenance": {
                    "hard_stop": {
                        "max_new_critical": 0,
                        "max_new_high": 0,
                        "max_secrets_in_delta": 0,
                        "allow_high_exceptions": False,
                    },
                    "soft_gate": {
                        "max_new_medium_warn": 0,
                        "max_new_low_warn": 0,
                        "max_vulnerability_density_delta_warn": 0.5,
                    },
                    "targets": {
                        "compliance_score_min": 98.0,
                        "coverage_changed_code_min": 99.0,
                    },
                },
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
                },
                "partial_ai_provenance": {
                    "overall_changed_code_min": 97.0,
                    "sast_changed_code_min": 97.0,
                    "sca_applicability_min": 95.0,
                    "secrets_changed_files_min": 97.0,
                },
                "ai_or_unknown_provenance": {
                    "overall_changed_code_min": 99.0,
                    "sast_changed_code_min": 99.0,
                    "sca_applicability_min": 97.0,
                    "secrets_changed_files_min": 99.0,
                },
            },
        },
    )

    io.write_json(
        cfg / "tooling.yaml",
        {
            "version": "1.0.0",
            "tools": {
                "semgrep": {"signal": "sast", "claims_full_repo_scan": False},
                "gitleaks": {"signal": "secrets", "claims_full_repo_scan": True},
            },
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
                    "weight": 30,
                    "blocking": True,
                },
                {
                    "id": "POL-2",
                    "title": "no high",
                    "metric": "new_high_findings_count",
                    "comparator": "<=",
                    "threshold_ref": "hard_stop.max_new_high",
                    "weight": 30,
                    "blocking": True,
                },
                {
                    "id": "POL-3",
                    "title": "no secrets",
                    "metric": "secrets_count_delta",
                    "comparator": "<=",
                    "threshold_ref": "hard_stop.max_secrets_in_delta",
                    "weight": 30,
                    "blocking": True,
                },
                {
                    "id": "POL-4",
                    "title": "coverage",
                    "metric": "coverage_overall_changed_code_percent",
                    "comparator": ">=",
                    "threshold_ref": "targets.coverage_changed_code_min",
                    "weight": 10,
                    "blocking": False,
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
                "partial_ai_provenance": {"values": ["mixed"], "confidence": "medium"},
                "ai_or_unknown_provenance": {"values": ["ai", "unknown", "external"], "confidence": "medium"},
            },
            "uncertain_behavior": {"profile": "ai_or_unknown_provenance", "confidence": "low", "note": "fallback"},
        },
    )

    io.write_json(cfg / "exceptions.yaml", {"version": "1.0.0", "exceptions": []})


def test_profile_switches_to_ai_unknown(tmp_path: Path):
    repo = tmp_path
    artifacts = repo / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    _write_config(repo)

    io.write_json(artifacts / "normalized_findings.json", [])

    report = report_step.build_report(
        repo,
        artifacts,
        {
            "PR_BODY": "Provenance: ai",
            "CHANGED_FILES": "src/A.java",
        },
    )

    assert report["executive_decision_summary"]["gate_profile"] == "ai_or_unknown_provenance"


def test_hard_stop_and_soft_warning_behaviour(tmp_path: Path):
    repo = tmp_path
    artifacts = repo / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    _write_config(repo)

    findings = [
        {
            "tool": "semgrep",
            "rule_id": "r-high",
            "severity": "HIGH",
            "message": "high finding",
            "file": "src/A.java",
            "start_line": 10,
            "tags": [],
        },
        {
            "tool": "semgrep",
            "rule_id": "r-med-1",
            "severity": "MEDIUM",
            "message": "m1",
            "file": "src/B.java",
            "start_line": 2,
            "tags": [],
        },
        {
            "tool": "semgrep",
            "rule_id": "r-med-2",
            "severity": "MEDIUM",
            "message": "m2",
            "file": "src/B.java",
            "start_line": 3,
            "tags": [],
        },
    ]
    io.write_json(artifacts / "normalized_findings.json", findings)

    report_fail = report_step.build_report(
        repo,
        artifacts,
        {
            "PROVENANCE": "human",
            "CHANGED_FILES": "src/A.java\nsrc/B.java",
        },
    )

    assert report_fail["gate"]["status_for_ci"] == "fail"

    io.write_json(artifacts / "baseline_findings.json", findings[:1])
    report_warn = report_step.build_report(
        repo,
        artifacts,
        {
            "PROVENANCE": "human",
            "CHANGED_FILES": "src/A.java\nsrc/B.java",
        },
        baseline_path=artifacts / "baseline_findings.json",
    )

    assert report_warn["gate"]["status_for_ci"] == "pass"
    assert report_warn["gate"]["final_outcome"] == "pass_with_warnings"
