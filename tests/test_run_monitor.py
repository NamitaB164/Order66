from datetime import datetime

from order66.events import ProcessEvent
from order66.monitor import Monitor
from order66.run_monitor import run_monitor


def test_run_monitor_runs_one_iteration():
    event = ProcessEvent(
        pid=1234,
        parent_pid=5678,
        parent_process_name="explorer.exe",
        process_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        process_name="notepad.exe",
        command="notepad.exe",
        timestamp=datetime.now(),
        creation_time=datetime(2026, 1, 1, 12, 0, 0),
    )

    monitor = Monitor(collector=lambda: [event])

    findings = run_monitor(monitor, iterations=1, interval=0)

    assert findings == []


def test_run_monitor_returns_findings():
    event = ProcessEvent(
        pid=1234,
        parent_pid=5678,
        parent_process_name="explorer.exe",
        process_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        process_name="powershell.exe",
        command="powershell.exe -EncodedCommand abc123",
        timestamp=datetime.now(),
        creation_time=datetime(2026, 1, 1, 12, 0, 0),
    )

    monitor = Monitor(collector=lambda: [event])

    findings = run_monitor(monitor, iterations=1, interval=0)

    assert len(findings) == 1
    assert findings[0].rule_id == "POWERSHELL-001"
