from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from . import normalize
from .io import load_normalized_findings, read_json, safe_glob


def _security_score_thresholds(severity_cfg: dict[str, Any]) -> tuple[float, float, float]:
    score_cfg = severity_cfg.get("security_severity_score") or {}
    critical_min = float(score_cfg.get("critical_min", 9.0))
    high_min = float(score_cfg.get("high_min", 7.0))
    medium_min = float(score_cfg.get("medium_min", 4.0))
    return critical_min, high_min, medium_min


def _severity_from_score(score: float, severity_cfg: dict[str, Any]) -> str:
    critical_min, high_min, medium_min = _security_score_thresholds(severity_cfg)
    if score >= critical_min:
        return "CRITICAL"
    if score >= high_min:
        return "HIGH"
    if score >= medium_min:
        return "MEDIUM"
    return "LOW"


def _collect_rules(run: dict) -> dict[str, dict]:
    rules: dict[str, dict] = {}

    def add_rules(component: dict | None) -> None:
        if not component:
            return
        for rule in component.get("rules") or []:
            rid = rule.get("id")
            if rid:
                rules[str(rid)] = rule

    tool = run.get("tool", {}) or {}
    add_rules(tool.get("driver") or {})
    for ext in tool.get("extensions") or []:
        add_rules(ext or {})

    return rules


def _extract_tags(res: dict, rule: dict | None) -> list[str]:
    tags: list[str] = []

    def add_from(obj: dict | None) -> None:
        for t in (obj or {}).get("tags") or []:
            val = str(t)
            if val not in tags:
                tags.append(val)

    add_from(res.get("properties") or {})
    add_from((rule or {}).get("properties") or {})
    return tags


def _extract_cwe(tags: list[str]) -> list[str]:
    out: list[str] = []
    for tag in tags:
        t = tag.upper()
        if "CWE-" not in t:
            continue
        idx = t.find("CWE-")
        digits = "".join(ch for ch in t[idx + 4 :] if ch.isdigit())
        if digits:
            cwe = f"CWE-{digits}"
            if cwe not in out:
                out.append(cwe)
    return out


def _extract_fingerprint(res: dict) -> str | None:
    fps = res.get("fingerprints") or {}
    if fps:
        if "matchBasedId/v1" in fps:
            return f"matchBasedId/v1:{fps['matchBasedId/v1']}"
        key = sorted(fps.keys())[0]
        return f"{key}:{fps[key]}"

    pfp = res.get("partialFingerprints") or {}
    for key in ("primaryLocationLineHash", "primaryLocationStartColumnFingerprint"):
        if key in pfp:
            return f"{key}:{pfp[key]}"
    return None


def _infer_category(tool: str, rule_id: str | None, message: str, tags: list[str]) -> tuple[str, bool]:
    parts = [tool, rule_id or "", message, " ".join(tags)]
    text = " ".join(parts).lower()

    if tool.lower() == "gitleaks":
        return "secret", True
    if any(k in text for k in ("secret", "credential", "password", "api-key", "token", "private key")):
        return "secret", True
    if any(k in text for k in ("sql-injection", "sqli", "tainted-sql", "formatted-sql-string")):
        return "sql_injection", False
    if any(k in text for k in ("path-traversal", "path-injection", "directory-traversal")):
        return "path_traversal", False
    if any(k in text for k in ("xxe", "xml external entity")):
        return "xxe", False
    if any(k in text for k in ("weak-crypto", "use-of-md5", "md5")):
        return "weak_crypto", False
    return "other", False


def _tool_signal(tool: str, tooling_cfg: dict[str, Any]) -> str:
    tools = tooling_cfg.get("tools") or {}
    meta = tools.get(tool.lower()) or tools.get(tool) or {}
    signal = meta.get("signal")
    return str(signal) if signal else "unknown"


def _severity_from_result(res: dict, rule: dict | None, severity_cfg: dict[str, Any]) -> str:
    level = res.get("level") or (rule or {}).get("defaultConfiguration", {}).get("level")
    base = normalize.normalize_severity(level)

    res_props = res.get("properties") or {}
    rule_props = (rule or {}).get("properties") or {}

    sec_score = res_props.get("security-severity")
    if sec_score is None:
        sec_score = rule_props.get("security-severity")

    if sec_score is not None:
        try:
            return _severity_from_score(float(sec_score), severity_cfg)
        except Exception:
            pass

    explicit = res_props.get("severity") or rule_props.get("problem.severity") or rule_props.get("severity")
    if explicit:
        return normalize.normalize_severity(str(explicit))

    return base


def _tool_versions(run: dict) -> list[str]:
    out: list[str] = []
    tool = run.get("tool", {}) or {}
    driver = tool.get("driver") or {}
    d_name = driver.get("name")
    d_ver = driver.get("semanticVersion") or driver.get("version")
    if d_name and d_ver:
        out.append(f"{d_name}@{d_ver}")
    for ext in tool.get("extensions") or []:
        e_name = ext.get("name")
        e_ver = ext.get("semanticVersion") or ext.get("version")
        if e_name and e_ver:
            out.append(f"{e_name}@{e_ver}")
    return out


def _parse_sarif(path: Path, repo_root: Path, tooling_cfg: dict[str, Any], severity_cfg: dict[str, Any]) -> tuple[list[dict], list[str], dict[str, set[str]]]:
    data = read_json(path)
    findings: list[dict] = []
    versions: list[str] = []
    scanned_files_by_tool: dict[str, set[str]] = defaultdict(set)

    for run in data.get("runs", []) or []:
        tool = str(run.get("tool", {}).get("driver", {}).get("name") or path.stem)
        signal = _tool_signal(tool, tooling_cfg)
        versions.extend(_tool_versions(run))

        for artifact in run.get("artifacts", []) or []:
            loc = normalize.normalize_artifact_location(artifact.get("location") or {}, repo_root)
            if loc:
                scanned_files_by_tool[tool].add(loc)

        rule_meta = _collect_rules(run)

        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId") or (res.get("rule") or {}).get("id")
            rule = rule_meta.get(str(rule_id)) if rule_id else None
            severity = _severity_from_result(res, rule, severity_cfg)

            locations = res.get("locations") or []
            uri = None
            start_line = None
            end_line = None
            if locations:
                phys = locations[0].get("physicalLocation", {})
                uri = normalize.normalize_artifact_location(phys.get("artifactLocation", {}) or {}, repo_root)
                region = phys.get("region", {})
                start_line = region.get("startLine")
                end_line = region.get("endLine")
                if uri:
                    scanned_files_by_tool[tool].add(uri)

            message = normalize.normalize_message((res.get("message") or {}).get("text") or "")
            tags = _extract_tags(res, rule)
            cwe = _extract_cwe(tags)
            category, is_secret = _infer_category(tool, str(rule_id) if rule_id else None, message, tags)

            findings.append(
                {
                    "tool": tool,
                    "signal": signal,
                    "rule_id": str(rule_id) if rule_id else None,
                    "severity": severity,
                    "message": message,
                    "file": uri,
                    "start_line": int(start_line) if start_line else None,
                    "end_line": int(end_line) if end_line else None,
                    "cwe": cwe,
                    "tags": tags,
                    "fingerprint": _extract_fingerprint(res),
                    "category": category,
                    "is_secret": is_secret,
                }
            )

    return findings, versions, scanned_files_by_tool


def _parse_normalized_findings(
    findings_file: Path,
    tooling_cfg: dict[str, Any],
) -> tuple[list[dict], dict[str, set[str]]]:
    raw = load_normalized_findings(findings_file)
    out: list[dict] = []
    scanned: dict[str, set[str]] = defaultdict(set)
    for item in raw:
        if not isinstance(item, dict):
            continue
        tool = str(item.get("tool") or "unknown")
        signal = _tool_signal(tool, tooling_cfg)
        severity = normalize.normalize_severity(item.get("severity") or item.get("level"))
        file_path = item.get("file")
        if file_path:
            scanned[tool].add(str(file_path))

        category, is_secret = _infer_category(
            tool,
            str(item.get("rule_id") or item.get("ruleId") or ""),
            normalize.normalize_message(item.get("message") or ""),
            [str(t) for t in (item.get("tags") or [])],
        )

        out.append(
            {
                "tool": tool,
                "signal": signal,
                "rule_id": item.get("rule_id") or item.get("ruleId"),
                "severity": severity,
                "message": normalize.normalize_message(item.get("message") or ""),
                "file": file_path,
                "start_line": item.get("start_line") or item.get("startLine"),
                "end_line": item.get("end_line") or item.get("endLine"),
                "cwe": item.get("cwe") or [],
                "tags": item.get("tags") or [],
                "fingerprint": item.get("fingerprint"),
                "category": category,
                "is_secret": bool(item.get("is_secret", is_secret)),
            }
        )

    return out, scanned


def load_findings(
    repo_root: Path,
    artifacts_dir: Path,
    sarif_dir: Path | None,
    tooling_cfg: dict[str, Any],
    severity_cfg: dict[str, Any],
) -> tuple[list[dict], dict[str, Any]]:
    findings: list[dict] = []
    tool_versions: list[str] = []
    scanned_files_by_tool: dict[str, set[str]] = defaultdict(set)
    inputs: list[str] = []
    notes: list[str] = []

    normalized_path = artifacts_dir / "normalized_findings.json"
    if normalized_path.exists():
        norm_findings, norm_scanned = _parse_normalized_findings(normalized_path, tooling_cfg)
        findings.extend(norm_findings)
        for tool, files in norm_scanned.items():
            scanned_files_by_tool[tool].update(files)
        inputs.append(str(normalized_path))

    roots: list[Path] = []
    if sarif_dir and sarif_dir.exists():
        roots.append(sarif_dir)
    if artifacts_dir.exists():
        roots.append(artifacts_dir)

    sarif_files: list[Path] = []
    for root in roots:
        sarif_files.extend(sorted(root.rglob("*.sarif"), key=lambda p: str(p)))

    # de-duplicate while preserving deterministic order
    seen_paths: set[str] = set()
    unique_sarif: list[Path] = []
    for path in sarif_files:
        key = str(path.resolve())
        if key in seen_paths:
            continue
        seen_paths.add(key)
        unique_sarif.append(path)

    for sarif_path in unique_sarif:
        parsed, versions, scanned = _parse_sarif(sarif_path, repo_root, tooling_cfg, severity_cfg)
        findings.extend(parsed)
        tool_versions.extend(versions)
        for tool, files in scanned.items():
            scanned_files_by_tool[tool].update(files)
        inputs.append(str(sarif_path))

    gitleaks_json = artifacts_dir / "gitleaks.json"
    if gitleaks_json.exists():
        data = read_json(gitleaks_json)
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                file_path = item.get("File") or item.get("file") or item.get("Path")
                line = item.get("StartLine") or item.get("line") or item.get("Line")
                if file_path:
                    scanned_files_by_tool["gitleaks"].add(str(file_path))
                findings.append(
                    {
                        "tool": "gitleaks",
                        "signal": _tool_signal("gitleaks", tooling_cfg),
                        "rule_id": str(item.get("RuleID") or item.get("Rule") or "gitleaks"),
                        "severity": "HIGH",
                        "message": "Potential secret detected by gitleaks",
                        "file": normalize.normalize_uri(str(file_path), repo_root) if file_path else None,
                        "start_line": int(line) if line else None,
                        "end_line": int(line) if line else None,
                        "cwe": [],
                        "tags": ["secret"],
                        "fingerprint": None,
                        "category": "secret",
                        "is_secret": True,
                    }
                )
            inputs.append(str(gitleaks_json))

    if not findings:
        notes.append("No findings were parsed from supplied inputs.")

    normalized_findings = sorted(
        findings,
        key=lambda f: (
            str(f.get("severity") or ""),
            str(f.get("tool") or ""),
            str(f.get("file") or ""),
            int(f.get("start_line") or 0),
            str(f.get("rule_id") or ""),
        ),
        reverse=True,
    )

    return normalized_findings, {
        "tool_versions": sorted(set(tool_versions)),
        "scanned_files_by_tool": {k: sorted(v) for k, v in scanned_files_by_tool.items()},
        "inputs": sorted(set(inputs)),
        "notes": notes,
    }
