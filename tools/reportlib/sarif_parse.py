from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from . import normalize
from .schema import Finding
from .io import read_json


def _collect_rules(run: dict) -> dict[str, dict]:
    rules: dict[str, dict] = {}

    def add_rules(component: dict | None) -> None:
        if not component:
            return
        for rule in component.get("rules") or []:
            rid = rule.get("id")
            if rid:
                rules[rid] = rule

    tool = run.get("tool", {}) or {}
    add_rules(tool.get("driver") or {})
    for ext in tool.get("extensions") or []:
        add_rules(ext or {})

    return rules


def _extract_tags(res: dict, rule: dict | None) -> list[str]:
    tags: list[str] = []

    def add_from(obj: dict | None) -> None:
        for t in (obj or {}).get("tags") or []:
            if t not in tags:
                tags.append(t)

    add_from(res.get("properties") or {})
    add_from((rule or {}).get("properties") or {})
    return tags


def _extract_cwe(tags: Iterable[str]) -> list[str]:
    cwes: list[str] = []
    for tag in tags:
        if not tag:
            continue
        t = tag.upper()
        if "CWE-" in t:
            idx = t.find("CWE-")
            cwe = "CWE-" + "".join(ch for ch in t[idx + 4 :] if ch.isdigit())
            if cwe != "CWE-" and cwe not in cwes:
                cwes.append(cwe)
        if "EXTERNAL/CWE/CWE-" in t:
            idx = t.find("EXTERNAL/CWE/CWE-")
            cwe = "CWE-" + "".join(ch for ch in t[idx + 16 :] if ch.isdigit())
            if cwe != "CWE-" and cwe not in cwes:
                cwes.append(cwe)
    return cwes


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


def _severity_from_result(res: dict, rule: dict | None) -> str:
    level = res.get("level") or (rule or {}).get("defaultConfiguration", {}).get("level")
    level = level or "warning"
    severity = normalize.normalize_severity(level)

    res_props = res.get("properties") or {}
    rule_props = (rule or {}).get("properties") or {}

    sec_score = res_props.get("security-severity") or rule_props.get("security-severity")
    if sec_score is not None:
        try:
            return normalize.severity_from_score(float(sec_score))
        except Exception:
            pass

    sev_label = res_props.get("severity") or rule_props.get("problem.severity") or rule_props.get("severity")
    if sev_label:
        return normalize.normalize_severity(sev_label)

    return severity


def _tool_version(run: dict) -> list[str]:
    tool_versions: list[str] = []
    driver = (run.get("tool") or {}).get("driver") or {}
    name = driver.get("name")
    ver = driver.get("semanticVersion") or driver.get("version")
    if name and ver:
        tool_versions.append(f"{name}@{ver}")

    for ext in (run.get("tool") or {}).get("extensions") or []:
        ename = ext.get("name")
        ever = ext.get("semanticVersion") or ext.get("version")
        if ename and ever:
            tool_versions.append(f"{ename}@{ever}")

    return tool_versions


def parse_sarif_file(path: Path, repo_root: Path) -> tuple[list[Finding], list[str]]:
    data = read_json(path)
    findings: list[Finding] = []
    tool_versions: list[str] = []

    for run in data.get("runs", []) or []:
        tool_name = run.get("tool", {}).get("driver", {}).get("name") or path.stem
        tool_versions.extend(_tool_version(run))
        rule_meta = _collect_rules(run)

        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId") or (res.get("rule") or {}).get("id")
            rule = rule_meta.get(rule_id) if rule_id else None

            severity = _severity_from_result(res, rule)
            tags = _extract_tags(res, rule)
            cwe = _extract_cwe(tags)

            uri = None
            start_line = None
            end_line = None
            locations = res.get("locations") or []
            if locations:
                phys = locations[0].get("physicalLocation", {})
                uri = normalize.normalize_artifact_location(phys.get("artifactLocation", {}) or {}, repo_root)
                region = phys.get("region", {})
                start_line = region.get("startLine")
                end_line = region.get("endLine")

            message = normalize.normalize_message((res.get("message") or {}).get("text") or "")
            fingerprint = _extract_fingerprint(res)

            findings.append(
                Finding(
                    tool=str(tool_name),
                    rule_id=rule_id,
                    severity=severity,
                    message=message,
                    file=uri,
                    start_line=int(start_line) if start_line else None,
                    end_line=int(end_line) if end_line else None,
                    cwe=cwe,
                    tags=tags,
                    fingerprint=fingerprint,
                    raw=None,
                )
            )

    return findings, tool_versions


def parse_sarif_paths(paths: Iterable[Path], repo_root: Path) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    versions: list[str] = []
    for p in sorted(paths, key=lambda p: str(p)):
        f, v = parse_sarif_file(p, repo_root)
        findings.extend(f)
        versions.extend(v)
    return findings, sorted(set(versions))


def parse_gitleaks_json(path: Path, repo_root: Path) -> list[Finding]:
    data = read_json(path)
    findings: list[Finding] = []
    if not isinstance(data, list):
        return findings

    for item in data:
        if not isinstance(item, dict):
            continue
        rule_id = item.get("RuleID") or item.get("Rule") or "gitleaks"
        file_path = item.get("File") or item.get("file") or item.get("Path")
        line = item.get("StartLine") or item.get("line") or item.get("Line")
        message = "Potential secret detected by gitleaks"
        findings.append(
            Finding(
                tool="gitleaks",
                rule_id=str(rule_id),
                severity="HIGH",
                message=message,
                file=normalize.normalize_uri(str(file_path), repo_root) if file_path else None,
                start_line=int(line) if line else None,
                end_line=int(line) if line else None,
                cwe=[],
                tags=["secret"],
                fingerprint=None,
                raw=None,
            )
        )
    return findings
