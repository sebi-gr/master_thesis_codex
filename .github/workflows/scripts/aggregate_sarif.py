#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
from collections import Counter, defaultdict
from urllib.parse import urlparse, unquote

# --- Helpers -------------------------------------------------------------

def find_sarif_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.sarif"), key=lambda p: str(p))

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
        # On Windows file URIs, drop the leading slash before drive letter.
        if os.name == "nt" and len(path) >= 3 and path[0] == "/" and path[2] == ":":
            path = path[1:]
        return normalize_path(Path(path), repo_root)
    p = Path(uri)
    if p.is_absolute():
        return normalize_path(p, repo_root)
    return p.as_posix()

def normalize_artifact_location(artifact: dict, repo_root: Path) -> str | None:
    uri = artifact.get("uri")
    if not uri:
        return None
    base = (artifact.get("uriBaseId") or "").upper()
    if base == "%SRCROOT%":
        return normalize_path(repo_root / uri, repo_root)
    return normalize_uri(uri, repo_root)

def infer_category(
    rule_id: str | None,
    tool_name: str,
    message: str,
    tags: list[str],
) -> str:
    """Grober Heuristik-Mapper für Kategorien (zum Gruppieren)."""
    parts = [rule_id or "", tool_name, message] + tags
    s = " ".join(p for p in parts if p).lower()
    t = tool_name.lower()

    if t == "gitleaks":
        return "secret"
    if any(k in s for k in ("secret", "credential", "password", "api-key", "token", "hardcoded-credential")):
        return "secret"
    if "sql-injection" in s or "sqli" in s or "formatted-sql-string" in s:
        return "sql-injection"
    if "path-injection" in s or "path-traversal" in s or "directory-traversal" in s:
        return "path-traversal"
    if "xxe" in s or "xml external entity" in s:
        return "xxe"
    if "md5" in s or "weak-cryptographic" in s:
        return "weak-crypto"
    return "other"

def map_severity(level: str | None) -> str:
    """Mappt SARIF-Level auf eine vereinfachte Severity."""
    if level is None:
        return "medium"
    level = level.lower()
    mapping = {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "info",
    }
    return mapping.get(level, "medium")

def normalize_severity_label(raw: str | None) -> str:
    if not raw:
        return "medium"
    s = str(raw).strip().lower()
    if s == "critical":
        return "high"
    if s in ("high", "medium", "low", "info"):
        return s
    if s in ("error", "warning", "note", "none"):
        return map_severity(s)
    return "medium"

def parse_security_score(value) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None

def severity_from_security_score(score: float) -> str:
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"

def collect_rule_metadata(run: dict) -> dict[str, dict]:
    rules: dict[str, dict] = {}

    def add_rules(component: dict) -> None:
        for rule in component.get("rules") or []:
            rid = rule.get("id")
            if rid:
                rules[rid] = rule

    tool = run.get("tool", {}) or {}
    add_rules(tool.get("driver", {}) or {})
    for ext in tool.get("extensions", []) or []:
        add_rules(ext or {})

    return rules

def extract_tags(res: dict, rule: dict | None) -> list[str]:
    tags: list[str] = []

    def add_from(obj: dict | None) -> None:
        for t in (obj or {}).get("tags") or []:
            if t not in tags:
                tags.append(t)

    add_from(res.get("properties") or {})
    add_from((rule or {}).get("properties") or {})
    return tags

def extract_fingerprint(res: dict) -> str | None:
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

def load_sarif_file(path: Path, repo_root: Path) -> list[dict]:
    """Liest ein SARIF und normalisiert alle Results in eine Liste einfacher Dicts."""
    with path.open("r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except Exception as e:
            print(f"[WARN] Failed to parse {path}: {e}")
            return []

    findings: list[dict] = []
    for run in data.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name") or path.stem

        # Rule-Metadata map (für Severity etc.)
        rule_meta = collect_rule_metadata(run)

        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId") or (res.get("rule") or {}).get("id")
            rule = rule_meta.get(rule_id) if rule_id else None

            # Level & Severity
            level = res.get("level") or (rule or {}).get("defaultConfiguration", {}).get("level")
            level = level or "warning"
            severity = map_severity(level)

            # Prefer tool-provided security severity if available
            sec_score = None
            res_props = res.get("properties") or {}
            rule_props = (rule or {}).get("properties") or {}
            sec_score = parse_security_score(res_props.get("security-severity"))
            if sec_score is None:
                sec_score = parse_security_score(rule_props.get("security-severity"))
            if sec_score is not None:
                severity = severity_from_security_score(sec_score)
            else:
                # Fallbacks to explicit severity labels if present
                sev_label = res_props.get("severity") or rule_props.get("problem.severity") or rule_props.get("severity")
                severity = normalize_severity_label(sev_label) if sev_label else severity

            # Location
            uri = None
            start_line = None
            end_line = None
            locations = res.get("locations") or []
            if locations:
                phys = locations[0].get("physicalLocation", {})
                uri = normalize_artifact_location(phys.get("artifactLocation", {}) or {}, repo_root)
                region = phys.get("region", {})
                start_line = region.get("startLine")
                end_line = region.get("endLine")

            message = (res.get("message") or {}).get("text") or ""
            tags = extract_tags(res, rule)
            category = infer_category(rule_id, tool_name, message, tags)
            fingerprint = extract_fingerprint(res)

            findings.append(
                {
                    "tool": tool_name,
                    "rule_id": rule_id,
                    "severity": severity,
                    "level": level,
                    "file": uri,
                    "start_line": start_line,
                    "end_line": end_line,
                    "message": message,
                    "category": category,
                    "tags": tags,
                    "fingerprint": fingerprint,
                }
            )

    return findings

def count_loc(repo_root: Path) -> int:
    """Zählt grob die nicht-leeren Codezeilen in typischen Source-Dateien."""
    exts = (
        ".java",
        ".py",
        ".js",
        ".ts",
        ".go",
        ".cs",
        ".rb",
        ".php",
        ".scala",
        ".kt",
        ".c",
        ".cpp",
    )
    total = 0
    for dirpath, dirnames, filenames in os.walk(repo_root):
        parts = dirpath.split(os.sep)
        if any(
            p
            in (
                ".git",
                ".github",
                ".venv",
                "venv",
                "node_modules",
                "dist",
                "build",
                "__pycache__",
            )
            for p in parts
        ):
            continue

        for fname in filenames:
            if fname.endswith(exts):
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                        for line in fh:
                            if line.strip():
                                total += 1
                except Exception as e:
                    print(f"[WARN] Failed to read {fpath}: {e}")
    return total

# --- Main aggregation ----------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--sarif-dir",
        default="sarif",
        help="Root directory where SARIF artifacts were downloaded",
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root (for LoC counting)",
    )
    parser.add_argument(
        "--output",
        default="security-metrics.json",
        help="Where to write the aggregated metrics JSON",
    )
    args = parser.parse_args()

    sarif_root = Path(args.sarif_dir)
    repo_root = Path(args.repo_root)

    sarif_files = find_sarif_files(sarif_root)
    if not sarif_files:
        print(f"[WARN] No SARIF files found under {sarif_root}")
        return

    print("Found SARIF files:")
    for p in sarif_files:
        print(f"  - {p}")

    all_findings: list[dict] = []
    for p in sarif_files:
        file_findings = load_sarif_file(p, repo_root)
        all_findings.extend(file_findings)

    print(f"\nTotal normalized findings: {len(all_findings)}")

    # Gruppierung: gleiches File + gleiche Zeile + gleiche Kategorie
    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for f in all_findings:
        if f["file"] and f["start_line"]:
            key = ("loc", f["file"], f["start_line"], f["category"])
        elif f.get("fingerprint"):
            key = ("fp", f["fingerprint"], f["category"])
        else:
            key = ("rule", f["tool"], f["rule_id"], f["message"][:120], f["category"])
        grouped[key].append(f)

    print(f"Unique issue groups: {len(grouped)}\n")

    # Basismetriken
    tool_counts = Counter(f["tool"] for f in all_findings)
    category_counts = Counter(f["category"] for f in all_findings)
    severity_counts = Counter(f["severity"] for f in all_findings)

    loc = count_loc(repo_root)
    density_raw = (len(all_findings) * 1000.0 / loc) if loc else None
    density_grouped = (len(grouped) * 1000.0 / loc) if loc else None

    print("=== Security Metrics Summary ===")
    print(f"Raw findings: {len(all_findings)}")
    print(f"Unique issue groups: {len(grouped)}")
    print("Findings by tool:")
    for tool, cnt in tool_counts.most_common():
        print(f"  {tool}: {cnt}")
    print("Findings by category:")
    for cat, cnt in category_counts.most_common():
        print(f"  {cat}: {cnt}")
    print("Findings by severity:")
    for sev, cnt in severity_counts.most_common():
        print(f"  {sev}: {cnt}")

    print(f"Lines of code (LoC): {loc}")
    if density_raw is not None:
        print(f"Raw vulnerability density: {density_raw:.2f} findings / KLoC")
        print(f"Grouped vulnerability density: {density_grouped:.2f} groups / KLoC")

    # Detail-Output für weitere Auswertung (z. B. fürs Dashboard)
    groups_out = []
    for key, fs in sorted(grouped.items(), key=lambda kv: str(kv[0])):
        sample = fs[0]
        groups_out.append(
            {
                "file": sample.get("file"),
                "start_line": sample.get("start_line"),
                "category": sample.get("category"),
                "grouping": {
                    "kind": key[0],
                    "key": key[1:],
                },
                "tools": sorted({f["tool"] for f in fs}),
                "severity_max": max(
                    (f["severity"] for f in fs),
                    key=lambda s: ["info", "low", "medium", "high"].index(
                        s if s in ("info", "low", "medium", "high") else "medium"
                    ),
                ),
                "findings": fs,
            }
        )

    metrics = {
        "total_raw_findings": len(all_findings),
        "total_issue_groups": len(grouped),
        "tools": tool_counts,
        "categories": category_counts,
        "severities": severity_counts,
        "loc": loc,
        "density_per_kloc_raw": density_raw,
        "density_per_kloc_grouped": density_grouped,
        "sarif_files": [str(p) for p in sarif_files],
        "groups": groups_out,
    }

    # Counter-Objekte in normale Dicts umwandeln (JSON-freundlich)
    for key in ("tools", "categories", "severities"):
        metrics[key] = dict(metrics[key])

    out_path = Path(args.output)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nWrote aggregated metrics to {out_path}")


if __name__ == "__main__":
    main()
