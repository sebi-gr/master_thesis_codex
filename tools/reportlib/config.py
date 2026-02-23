from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from .io import read_yaml


@dataclass
class SecurityConfig:
    base_dir: Path
    profiles: dict[str, Any]
    severity_mapping: dict[str, Any]
    policies: dict[str, Any]
    coverage_targets: dict[str, Any]
    tooling: dict[str, Any]
    provenance: dict[str, Any]
    exceptions: dict[str, Any]


REQUIRED_FILES = {
    "profiles": "profiles.yaml",
    "severity_mapping": "severity_mapping.yaml",
    "policies": "policies.yaml",
    "coverage_targets": "coverage_targets.yaml",
    "tooling": "tooling.yaml",
    "provenance": "provenance.yaml",
    "exceptions": "exceptions.yaml",
}


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Missing required config file: {path}")
    data = read_yaml(path)
    if not isinstance(data, dict):
        raise ValueError(f"Config file must contain a mapping: {path}")
    return data


def load_security_config(repo_root: Path, base_dir: str = "security_config") -> SecurityConfig:
    cfg_root = repo_root / base_dir
    data: dict[str, Any] = {}
    for key, rel in REQUIRED_FILES.items():
        data[key] = _load_yaml(cfg_root / rel)
    return SecurityConfig(base_dir=cfg_root, **data)


def resolve_profile_name(cfg: SecurityConfig, requested: str | None) -> str:
    default_profile = str(cfg.profiles.get("default_profile") or "known_provenance")
    all_profiles = cfg.profiles.get("profiles") or {}
    if requested and requested in all_profiles:
        return requested
    return default_profile


def get_profile_config(cfg: SecurityConfig, profile_name: str) -> dict[str, Any]:
    profiles = cfg.profiles.get("profiles") or {}
    profile = profiles.get(profile_name)
    if not isinstance(profile, dict):
        raise KeyError(f"Unknown profile: {profile_name}")
    return profile


def config_hashes(cfg: SecurityConfig) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for key, rel in REQUIRED_FILES.items():
        path = cfg.base_dir / rel
        hashes[rel] = sha256(path.read_bytes()).hexdigest()
    return hashes
