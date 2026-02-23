from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

from . import normalize
from .mapping import determine_category


def _severity_max(current: str, incoming: str) -> str:
    return incoming if normalize.severity_rank(incoming) > normalize.severity_rank(current) else current


def _severity_mix(counts: dict) -> dict:
    total = sum(counts.values()) or 1
    mix = {}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        mix[sev] = {
            "count": int(counts.get(sev, 0)),
            "percent": round((counts.get(sev, 0) / total) * 100, 2),
        }
    return mix


def cluster_findings(findings: Iterable[dict], rmf_map: list[dict]) -> list[dict]:
    clusters: dict[tuple[str, str], dict] = {}

    for f in findings:
        module = normalize.derive_module(f.get("file"))
        category, match = determine_category(f, rmf_map)
        severity = f.get("severity") or "MEDIUM"

        key = (module, category)
        if key not in clusters:
            clusters[key] = {
                "module": module,
                "category": category,
                "severity_max": severity,
                "findings": [],
                "affected_files": set(),
                "example_locations": [],
                "rules": set(),
                "tools": set(),
                "cwe": set(),
                "threat": match.get("threat") if match else "",
                "cia": list(match.get("cia") or []) if match else [],
                "policy_ids": list(match.get("policy_ids") or []) if match else [],
                "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            }

        cluster = clusters[key]
        cluster["severity_max"] = _severity_max(cluster["severity_max"], severity)
        cluster["findings"].append(f)
        if f.get("file"):
            cluster["affected_files"].add(f["file"])
        if f.get("rule_id"):
            cluster["rules"].add(f["rule_id"])
        if f.get("tool"):
            cluster["tools"].add(f["tool"])
        for cwe in f.get("cwe") or []:
            cluster["cwe"].add(cwe)

        if f.get("file"):
            loc = f["file"]
            if f.get("start_line"):
                loc = f"{loc}:{f['start_line']}"
            if loc not in cluster["example_locations"] and len(cluster["example_locations"]) < 3:
                cluster["example_locations"].append(loc)

        sev = f.get("severity") or "MEDIUM"
        cluster["severity_counts"][sev] = cluster["severity_counts"].get(sev, 0) + 1

    output: list[dict] = []
    for cluster in clusters.values():
        cluster_id = f"mod:{cluster['module']}|cat:{cluster['category']}|sev:{cluster['severity_max']}"
        measure = {
            "counts": {
                "total": len(cluster["findings"]),
                "by_severity": dict(cluster["severity_counts"]),
            },
            "severity_mix": _severity_mix(cluster["severity_counts"]),
            "rules": sorted(cluster["rules"]),
            "tools": sorted(cluster["tools"]),
            "coverage_notes": [],
            "confidence_notes": [],
        }

        map_section = {
            "module": cluster["module"],
            "category": cluster["category"],
            "threat": cluster["threat"],
            "cia": cluster["cia"],
            "cwe": sorted(cluster["cwe"]),
            "affected_files": sorted(cluster["affected_files"]),
            "example_locations": list(cluster["example_locations"]),
        }

        manage = {
            "status": "none",
            "owner": "",
            "sla_days": None,
            "ticket": "",
            "exception_ttl_days": None,
            "recommended_actions": [],
            "next_steps": [],
        }

        govern = {
            "policy_ids": list(cluster["policy_ids"]),
            "compliance_status": "unknown",
            "provenance_policy_applied": False,
            "decision_audit": "",
        }

        output.append(
            {
                "cluster_id": cluster_id,
                "map": map_section,
                "measure": measure,
                "manage": manage,
                "govern": govern,
            }
        )

    output.sort(
        key=lambda c: (
            -normalize.severity_rank(c["cluster_id"].split("|sev:")[1]),
            c["map"]["module"],
            c["map"]["category"],
        )
    )
    return output
