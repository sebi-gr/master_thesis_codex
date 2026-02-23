from tools.reportlib import cluster


def test_cluster_id_stability():
    findings = [
        {"tool": "codeql", "rule_id": "r1", "severity": "HIGH", "message": "x", "file": "src/A.java"},
        {"tool": "codeql", "rule_id": "r2", "severity": "LOW", "message": "x", "file": "src/B.java"},
    ]
    clusters = cluster.cluster_findings(findings, rmf_map=[])
    assert clusters
    cluster_id = clusters[0]["cluster_id"]
    assert cluster_id.startswith("mod:src|cat:")
    # max severity should be HIGH
    assert cluster_id.endswith("|sev:HIGH")
