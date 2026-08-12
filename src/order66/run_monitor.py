# run monitoring repeatedly
import time

from order66.finding import Finding
from order66.monitor import Monitor


def run_monitor(
    monitor: Monitor,
    iterations: int | None = None,
    interval: float = 5.0,
) -> list[Finding]:
    findings: list[Finding] = []
    completed = 0

    while iterations is None or completed < iterations:
        findings.extend(monitor.run_once())

        completed += 1

        if iterations is not None and completed >= iterations:
            break

        time.sleep(interval)

    return findings
