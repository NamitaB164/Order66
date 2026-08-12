from datetime import datetime

from order66.events import ProcessEvent
from order66.finding import Severity
from order66.monitor import Monitor


def test_monitor_returns_findings_from_process_events():
    event = ProcessEvent(
        pid=1234,
        process_name="powershell.exe",
        command="powershell.exe -EncodedCommand abc123",
        timestamp=datetime.now(),
    )

    monitor = Monitor()

    findings = monitor.run_once([event])

    assert len(findings) == 1
    assert findings[0].rule_id == "POWERSHELL-001"
    assert findings[0].severity == Severity.HIGH


def test_monitor_returns_empty_list_when_no_processes_are_suspicious():
    event = ProcessEvent(
        pid=1234,
        process_name="notepad.exe",
        command="notepad.exe",
        timestamp=datetime.now(),
    )

    monitor = Monitor()

    findings = monitor.run_once([event])

    assert findings == []
