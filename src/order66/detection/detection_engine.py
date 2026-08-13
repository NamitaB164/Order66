from collections.abc import Callable

from order66.detection.rules import (
    detect_encoded_powershell,
    detect_execution_policy_manipulation,
    detect_suspicious_powershell,
    detect_suspicious_parent_child,
)
from order66.events import ProcessEvent
from order66.finding import Finding


class DetectionEngine:
    def __init__(self) -> None:
        self.rules: list[Callable[[ProcessEvent], Finding | None]] = [
            detect_encoded_powershell,
            detect_suspicious_powershell,
            detect_execution_policy_manipulation,
            detect_suspicious_parent_child,
        ]

    # Run rules for the detection engine.
    def analyze(self, event: ProcessEvent) -> list[Finding]:
        findings: list[Finding] = []

        for rule in self.rules:
            finding = rule(event)

            if finding is not None:
                findings.append(finding)

        # return list of findings
        return findings
