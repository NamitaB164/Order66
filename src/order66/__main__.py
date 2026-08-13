from datetime import datetime

from order66.collectors.process_monitor import collect_processes
from order66.events import ProcessEvent
from order66.monitor import Monitor
from order66.run_monitor import run_monitor


def main(
    args: list[str],
    collector=collect_processes,
) -> None:
    if "--demo" in args:
        event = ProcessEvent(
            pid=1234,
            parent_pid=5678,
            process_name="powershell.exe",
            command="powershell.exe -EncodedCommand demo",
            timestamp=datetime.now(),
            creation_time=datetime(2026, 1, 1, 12, 0, 0),
        )

        def demo_collector() -> list[ProcessEvent]:
            return [event]

        monitor = Monitor(collector=demo_collector)

        print("ORDER 66 - Local Security Monitor")
        print("----------------------------------")
        print("Running demo detection...\n")

        findings = monitor.run_once()

    else:
        monitor = Monitor(collector=collector)

        print("ORDER 66 - Local Security Monitor")
        print("----------------------------------")

        if "--once" in args:
            print("Scanning running processes...\n")
            findings = run_monitor(
                monitor,
                iterations=1,
                interval=0,
            )
        else:
            print("Continuous monitoring started.\n")
            findings = run_monitor(monitor)

    if not findings:
        print("No suspicious activity detected.")
        return

    for finding in findings:
        print(f"[{finding.severity}] {finding.rule_id}")
        print(f"  {finding.reason}")
        print(f"  Process: {finding.process}")
        print(f"  Time: {finding.timestamp}")
        print()


if __name__ == "__main__":
    import sys

    main(sys.argv[1:])
