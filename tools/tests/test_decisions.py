from tools.reportlib import decisions


def test_decisions_merge():
    clusters = [
        {
            "cluster_id": "mod:src|cat:SQL_INJECTION|sev:HIGH",
            "map": {"affected_files": ["src/A.java"]},
            "measure": {"counts": {"total": 1}},
            "manage": {
                "status": "none",
                "owner": "",
                "sla_days": None,
                "ticket": "",
                "exception_ttl_days": None,
                "recommended_actions": [],
                "next_steps": [],
            },
            "govern": {
                "policy_ids": [],
                "compliance_status": "unknown",
                "provenance_policy_applied": False,
                "decision_audit": "",
            },
        }
    ]

    decisions_map = {
        "mod:src|cat:SQL_INJECTION|sev:HIGH": {
            "manage": {"status": "accepted", "owner": "@team", "ticket": "SEC-1"},
            "govern": {"policy_ids": ["RMF-M1"], "compliance_status": "met"},
        }
    }

    updated, missing = decisions.apply_decisions(clusters, decisions_map, codeowners=[])
    assert updated[0]["manage"]["status"] == "accepted"
    assert updated[0]["manage"]["owner"] == "@team"
    assert updated[0]["manage"]["ticket"] == "SEC-1"
    assert updated[0]["govern"]["policy_ids"] == ["RMF-M1"]
    assert updated[0]["govern"]["compliance_status"] == "met"
