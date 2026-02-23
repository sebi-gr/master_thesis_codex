from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: Optional[str]
    severity: str
    message: str
    file: Optional[str]
    start_line: Optional[int]
    end_line: Optional[int]
    cwe: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    fingerprint: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Cluster:
    cluster_id: str
    map: Dict[str, Any]
    measure: Dict[str, Any]
    manage: Dict[str, Any]
    govern: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "map": self.map,
            "measure": self.measure,
            "manage": self.manage,
            "govern": self.govern,
        }
