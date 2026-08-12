from datetime import datetime

from order66.collectors.process_monitor import collect_processes
from order66.events import ProcessEvent
from order66.monitor import Monitor


def main(args: list[str]) -> None:
    if "--demo" in args:
        event = ProcessEvent(
            pid=1234,
            process_name="powershell.exe",
            command="powershell.exe -EncodedCommand demo",
            timestamp=datetime.now(),
        )

        def demo_collector() -> list[ProcessEvent]:
            return [event]

        monitor = Monitor(collector=demo_collector)
    else:
        monitor = Monitor(collector=collect_processes)

    print("ORDER 66 - Local Security Monitor")
    print("----------------------------------")
    print("Scanning running processes...\n")

    findings = monitor.run_once()

    if not findings:
        print("Scan complete. No suspicious activity detected.")
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
