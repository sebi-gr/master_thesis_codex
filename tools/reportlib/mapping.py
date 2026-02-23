from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

from .io import read_yaml


DEFAULT_KEYWORD_MAP = {
    "SECRET": ["secret", "credential", "password", "api-key", "token", "hardcoded"],
    "SQL_INJECTION": ["sql-injection", "sqli", "formatted-sql-string"],
    "PATH_TRAVERSAL": ["path-traversal", "path-injection", "directory-traversal"],
    "WEAK_CRYPTO": ["md5", "weak-cryptographic", "weak-crypto"],
    "XXE": ["xxe", "xml external entity"],
}


def normalize_category_name(name: str) -> str:
    if not name:
        return "OTHER"
    clean = "_".join(str(name).strip().replace("-", " ").split())
    return clean.upper() or "OTHER"


def load_rmf_map(path) -> list[dict]:
    data = read_yaml(path)
    if data is None:
        raise ValueError("rmf_map.yaml is empty")

    if isinstance(data, dict) and "categories" in data:
        entries = data.get("categories") or []
    elif isinstance(data, list):
        entries = data
    else:
        raise ValueError("rmf_map.yaml has unsupported format")

    normalized: list[dict] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        category = normalize_category_name(entry.get("category") or entry.get("name") or "OTHER")
        cwe = [str(c).upper() for c in (entry.get("cwe") or []) if c]
        keywords = [str(k).lower() for k in (entry.get("keywords") or []) if k]
        normalized.append(
            {
                "category": category,
                "threat": entry.get("threat") or "",
                "cia": list(entry.get("cia") or []),
                "cwe": cwe,
                "keywords": keywords,
                "policy_ids": list(entry.get("policy_ids") or []),
            }
        )

    return normalized


def _match_cwe(cwes: Iterable[str], rmf_map: list[dict]) -> dict | None:
    cwe_set = {c.upper() for c in cwes if c}
    if not cwe_set:
        return None
    for entry in rmf_map:
        for cwe in entry.get("cwe") or []:
            if cwe.upper() in cwe_set:
                return entry
    return None


def _match_keyword(text: str, rmf_map: list[dict]) -> dict | None:
    low = text.lower()
    for entry in rmf_map:
        for kw in entry.get("keywords") or []:
            if kw and kw in low:
                return entry
    return None


def _match_default_keyword(text: str) -> str | None:
    low = text.lower()
    for cat, kws in DEFAULT_KEYWORD_MAP.items():
        for kw in kws:
            if kw in low:
                return cat
    return None


def determine_category(finding: dict, rmf_map: list[dict]) -> tuple[str, dict | None]:
    cwes = finding.get("cwe") or []
    match = _match_cwe(cwes, rmf_map)
    if match:
        return match["category"], match

    text_parts = [
        str(finding.get("rule_id") or ""),
        str(finding.get("message") or ""),
        " ".join(finding.get("tags") or []),
    ]
    text = " ".join(p for p in text_parts if p)

    match = _match_keyword(text, rmf_map)
    if match:
        return match["category"], match

    default_cat = _match_default_keyword(text)
    if default_cat:
        return default_cat, None

    return "OTHER", None
