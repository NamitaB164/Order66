# collect info about the process running
# match detection rules
# Take collected events and run them through detection.
from collections.abc import Callable
from datetime import datetime
from order66.detection.detection_engine import DetectionEngine
from order66.events import ProcessEvent
from order66.finding import Finding


class Monitor:
    def __init__(self, collector) -> None:
        self.engine = DetectionEngine()
        self.collector = collector
        self.seen_processes: set[tuple[int, datetime]] = set()

    def run_once(self) -> list[Finding]:
        events = self.collector()
        findings: list[Finding] = []

        for event in events:
            identity = (event.pid, event.creation_time)

            if identity in self.seen_processes:
                continue

            self.seen_processes.add(identity)

            findings.extend(self.engine.analyze(event))

        return findings