from datetime import datetime

from order66.events import ProcessEvent
from order66.finding import Severity
from order66.monitor import Monitor


def test_monitor_collects_and_detects_processes():
    event = ProcessEvent(
        pid=1234,
        process_name="powershell.exe",
        command="powershell.exe -EncodedCommand abc123",
        timestamp=datetime.now(),
    )

    def fake_collector() -> list[ProcessEvent]:
        return [event]

    monitor = Monitor(collector=fake_collector)

    findings = monitor.run_once()

    assert len(findings) == 1
    assert findings[0].rule_id == "POWERSHELL-001"
    assert findings[0].severity == Severity.HIGH


def test_monitor_returns_empty_list_when_no_process_is_suspicious():
    event = ProcessEvent(
        pid=1234,
        process_name="notepad.exe",
        command="notepad.exe",
        timestamp=datetime.now(),
    )

    def fake_collector() -> list[ProcessEvent]:
        return [event]

    monitor = Monitor(collector=fake_collector)

    findings = monitor.run_once()

    assert findings == []
