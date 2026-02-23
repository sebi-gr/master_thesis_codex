from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

try:
    import orjson  # type: ignore
except Exception:  # pragma: no cover
    orjson = None

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_json(path: Path) -> Any:
    raw = path.read_bytes()
    if orjson:
        return orjson.loads(raw)
    return json.loads(raw.decode("utf-8"))


def write_json(path: Path, data: Any) -> None:
    if orjson:
        option = orjson.OPT_SORT_KEYS | orjson.OPT_INDENT_2
        path.write_bytes(orjson.dumps(data, option=option))
        return
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def read_yaml(path: Path) -> Any:
    raw = read_text(path)
    if yaml is not None:
        return yaml.safe_load(raw)
    # JSON is a YAML subset; this fallback keeps local execution dependency-light.
    return json.loads(raw)


def safe_glob(base: Path, pattern: str) -> list[Path]:
    return sorted(base.glob(pattern), key=lambda p: str(p))


def load_normalized_findings(path: Path) -> list[dict]:
    data = read_json(path)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "findings" in data and isinstance(data["findings"], list):
            return data["findings"]
        if "groups" in data and isinstance(data["groups"], list):
            findings: list[dict] = []
            for group in data["groups"]:
                group_findings = group.get("findings")
                if isinstance(group_findings, list):
                    findings.extend(group_findings)
            return findings
    return []


def load_gate(path: Path) -> dict | None:
    if not path.exists():
        return None
    data = read_json(path)
    if isinstance(data, dict):
        return data
    return None


def unique_sorted(values: Iterable[str]) -> list[str]:
    return sorted({v for v in values if v})
