from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
import fnmatch

from .io import read_yaml


ALLOWED_STATUS = {"planned", "accepted", "fixed", "none"}
ALLOWED_COMPLIANCE = {"met", "violated", "unknown"}


def load_decisions(path: Path) -> tuple[dict, list[str]]:
    if not path.exists():
        return {}, []
    data = read_yaml(path)
    if data is None:
        return {}, []

    decisions: dict[str, dict] = {}
    errors: list[str] = []

    if isinstance(data, dict) and "decisions" in data:
        items = data.get("decisions") or []
    elif isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = []
        for cid, val in data.items():
            if isinstance(val, dict):
                val = dict(val)
                val["cluster_id"] = cid
                items.append(val)
    else:
        return {}, ["Invalid decisions.yml format"]

    for item in items:
        if not isinstance(item, dict):
            continue
        cid = item.get("cluster_id")
        if not cid:
            errors.append("Decision missing cluster_id")
            continue
        manage = item.get("manage") or {}
        govern = item.get("govern") or {}
        decisions[str(cid)] = {"manage": manage, "govern": govern, "audit": item.get("audit")}

    return decisions, errors


def load_codeowners(path: Path) -> list[tuple[str, list[str]]]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    entries: list[tuple[str, list[str]]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        pattern = parts[0]
        owners = parts[1:]
        entries.append((pattern, owners))
    return entries


def _match_codeowner(path: str, entries: list[tuple[str, list[str]]]) -> str | None:
    best = None
    best_len = -1
    for pattern, owners in entries:
        if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch("/" + path, pattern):
            if len(pattern) > best_len:
                best_len = len(pattern)
                best = owners[0] if owners else None
    return best


def apply_decisions(clusters: list[dict], decisions: dict, codeowners: list[tuple[str, list[str]]]) -> tuple[list[dict], dict]:
    missing_fields = {
        "missing_owner": 0,
        "missing_status": 0,
        "missing_ticket": 0,
        "missing_policy_ids": 0,
        "missing_compliance_status": 0,
        "invalid_values": 0,
    }

    for cluster in clusters:
        cid = cluster.get("cluster_id")
        decision = decisions.get(cid) if cid else None

        if decision:
            manage = decision.get("manage") or {}
            govern = decision.get("govern") or {}

            for key, val in manage.items():
                if key in cluster["manage"]:
                    cluster["manage"][key] = val
            for key, val in govern.items():
                if key in cluster["govern"]:
                    cluster["govern"][key] = val
            if decision.get("audit"):
                cluster["govern"]["decision_audit"] = decision.get("audit")

        # Validate manage status
        status = (cluster["manage"].get("status") or "none").lower()
        if status not in ALLOWED_STATUS:
            missing_fields["invalid_values"] += 1
            cluster["manage"]["status"] = "none"
        if status == "none":
            missing_fields["missing_status"] += 1

        owner = cluster["manage"].get("owner") or ""
        if not owner:
            # CODEOWNERS fallback
            for f in cluster["map"].get("affected_files") or []:
                owner = _match_codeowner(f, codeowners) or owner
                if owner:
                    break
            cluster["manage"]["owner"] = owner
        if not cluster["manage"].get("owner"):
            missing_fields["missing_owner"] += 1

        if not cluster["manage"].get("ticket"):
            missing_fields["missing_ticket"] += 1

        if not cluster["govern"].get("policy_ids"):
            missing_fields["missing_policy_ids"] += 1

        compliance = (cluster["govern"].get("compliance_status") or "unknown").lower()
        if compliance not in ALLOWED_COMPLIANCE:
            missing_fields["invalid_values"] += 1
            cluster["govern"]["compliance_status"] = "unknown"
            compliance = "unknown"
        if compliance == "unknown":
            missing_fields["missing_compliance_status"] += 1

    return clusters, missing_fields
