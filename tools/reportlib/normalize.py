from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse, unquote


SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def normalize_message(message: str | None) -> str:
    if not message:
        return ""
    return " ".join(str(message).split())


def normalize_severity(label: str | None) -> str:
    if not label:
        return "MEDIUM"
    s = str(label).strip().lower()
    if s in ("critical",):
        return "CRITICAL"
    if s in ("high",):
        return "HIGH"
    if s in ("medium", "moderate", "warning"):
        return "MEDIUM"
    if s in ("low", "note"):
        return "LOW"
    if s in ("info", "none"):
        return "INFO"
    if s in ("error",):
        return "HIGH"
    return "MEDIUM"


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.get(sev.upper(), 0)


def normalize_path(path: Path, repo_root: Path) -> str:
    try:
        rel = path.resolve().relative_to(repo_root.resolve())
        return rel.as_posix()
    except Exception:
        return path.as_posix()


def normalize_uri(uri: str | None, repo_root: Path) -> str | None:
    if not uri:
        return None
    if uri.startswith("file://"):
        parsed = urlparse(uri)
        path = unquote(parsed.path)
        if os.name == "nt" and len(path) >= 3 and path[0] == "/" and path[2] == ":":
            path = path[1:]
        return normalize_path(Path(path), repo_root)
    p = Path(uri)
    if p.is_absolute():
        return normalize_path(p, repo_root)
    return p.as_posix()


def normalize_artifact_location(artifact: dict, repo_root: Path) -> str | None:
    uri = artifact.get("uri") if artifact else None
    if not uri:
        return None
    base = (artifact.get("uriBaseId") or "").upper()
    if base == "%SRCROOT%":
        return normalize_path(repo_root / uri, repo_root)
    return normalize_uri(uri, repo_root)


def derive_module(file_path: str | None) -> str:
    if not file_path:
        return "root"
    parts = file_path.split("/")
    if parts and parts[0]:
        return parts[0]
    return "root"
