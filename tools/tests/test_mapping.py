from pathlib import Path

from tools.reportlib import mapping


def test_category_mapping_by_cwe(tmp_path: Path):
    rmf_map = tmp_path / "rmf_map.yaml"
    rmf_map.write_text(
        """
[
  {
    "category": "SQL_INJECTION",
    "cwe": ["CWE-89"],
    "threat": "Injection",
    "cia": ["C", "I"]
  }
]
""",
        encoding="utf-8",
    )

    entries = mapping.load_rmf_map(rmf_map)
    finding = {"cwe": ["CWE-89"], "rule_id": "x", "message": ""}
    category, _ = mapping.determine_category(finding, entries)
    assert category == "SQL_INJECTION"
