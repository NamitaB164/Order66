# Take Finding objects and persist them as JSON.

import json
from pathlib import Path

from order66.finding import Finding


class FindingStore:
    def __init__(self, path: str = "findings.json") -> None:
        self.path = Path(path)

    def save(self, finding: Finding) -> None:
        findings = self.get_all()

        findings.append(
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "reason": finding.reason,
                "process": finding.process,
                "timestamp": finding.timestamp.isoformat(),
            }
        )

        self.path.write_text(
            json.dumps(findings, indent=4),
            encoding="utf-8",
        )

    def get_all(self) -> list[dict]:
        if not self.path.exists():
            return []

        content = self.path.read_text(encoding="utf-8").strip()

        if not content:
            return []

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []

        if not isinstance(data, list):
            return []

        return data
