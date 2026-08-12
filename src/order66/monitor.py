# collect info about the process running
# match detection rules
# Take collected events and run them through detection.
from collections.abc import Callable

from order66.detection.detection_engine import DetectionEngine
from order66.events import ProcessEvent
from order66.finding import Finding


class Monitor:
    def __init__(
        self,
        collector: Callable[[], list[ProcessEvent]],
    ) -> None:
        self.collector = collector
        self.engine = DetectionEngine()

    def run_once(self) -> list[Finding]:
        events = self.collector()

        findings: list[Finding] = []

        for event in events:
            findings.extend(self.engine.analyze(event))

        return findings
