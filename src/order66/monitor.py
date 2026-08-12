from order66.detection.detection_engine import DetectionEngine
from order66.events import ProcessEvent
from order66.finding import Finding

# collect info about the process running
# match detection rules
# Take collected events and run them through detection.


class Monitor:
    def __init__(self) -> None:
        self.engine = DetectionEngine()

    def run_once(self, events: list[ProcessEvent]) -> list[Finding]:
        findings: list[Finding] = []

        for event in events:
            findings.extend(self.engine.analyze(event))

        return findings
