from __future__ import annotations

import re
from typing import Any


def _normalize(value: str | None) -> str:
    if not value:
        return ""
    return str(value).strip().lower().replace(" ", "_")


def _extract_from_pr_body(pr_body: str | None, trailer_key: str) -> str:
    if not pr_body:
        return ""
    pattern = rf"^{re.escape(trailer_key)}\s*:\s*([A-Za-z0-9_\-]+)\s*$"
    m = re.search(pattern, pr_body, re.IGNORECASE | re.MULTILINE)
    return _normalize(m.group(1)) if m else ""


def classify_provenance(
    provenance_cfg: dict[str, Any],
    explicit_value: str | None,
    pr_body: str | None,
) -> dict[str, Any]:
    trailer_key = str(provenance_cfg.get("pr_trailer_key") or "Provenance")
    raw_from_env = _normalize(explicit_value)
    raw_from_pr = _extract_from_pr_body(pr_body, trailer_key)

    if raw_from_env:
        raw_value = raw_from_env
        source = "env"
    elif raw_from_pr:
        raw_value = raw_from_pr
        source = "pr_body"
    else:
        raw_value = ""
        source = "missing"

    classifications = provenance_cfg.get("classifications") or {}
    for profile_name, profile_cfg in classifications.items():
        values = {_normalize(v) for v in (profile_cfg.get("values") or [])}
        if raw_value and raw_value in values:
            return {
                "raw_value": raw_value,
                "profile": profile_name,
                "confidence": str(profile_cfg.get("confidence") or "medium"),
                "determination_source": source,
                "is_uncertain": False,
                "note": "",
            }

    uncertain = provenance_cfg.get("uncertain_behavior") or {}
    fallback_profile = str(
        uncertain.get("profile")
        or provenance_cfg.get("default_if_missing")
        or "ai_or_unknown_provenance"
    )
    return {
        "raw_value": raw_value or "unknown",
        "profile": fallback_profile,
        "confidence": str(uncertain.get("confidence") or "low"),
        "determination_source": source,
        "is_uncertain": True,
        "note": str(
            uncertain.get("note")
            or "Provenance could not be determined with confidence; stricter profile applied."
        ),
    }
