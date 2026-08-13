from datetime import datetime
from order66.storage.finding_store import FindingStore
from order66.events import ProcessEvent
from order66.finding import Severity
from order66.monitor import Monitor


def test_monitor_collects_and_detects_processes():
    event = ProcessEvent(
        pid=1234,
        parent_pid=5678,
        parent_process_name="WINWORD.EXE",
        process_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        process_name="powershell.exe",
        command="powershell.exe -EncodedCommand abc123",
        timestamp=datetime.now(),
        creation_time=datetime(2026, 1, 1, 12, 0, 0),
    )

    def fake_collector() -> list[ProcessEvent]:
        return [event]

    monitor = Monitor(collector=fake_collector)

    findings = monitor.run_once()

    assert len(findings) == 2

    rule_ids = {finding.rule_id for finding in findings}

    assert "POWERSHELL-001" in rule_ids
    assert "PROCESS-001" in rule_ids


def test_monitor_returns_empty_list_when_no_process_is_suspicious():
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

    def fake_collector() -> list[ProcessEvent]:
        return [event]

    monitor = Monitor(collector=fake_collector)

    findings = monitor.run_once()

    assert findings == []


def test_monitor_does_not_analyze_same_process_twice():
    creation_time = datetime(2026, 1, 1, 12, 0, 0)

    event = ProcessEvent(
        pid=1234,
        parent_pid=5678,
        parent_process_name="explorer.exe",
        process_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        process_name="powershell.exe",
        command="powershell.exe -EncodedCommand abc123",
        timestamp=datetime.now(),
        creation_time=creation_time,
    )

    monitor = Monitor(collector=lambda: [event])

    first_scan = monitor.run_once()
    second_scan = monitor.run_once()

    assert len(first_scan) == 1
    assert len(second_scan) == 0


def test_monitor_treats_pid_reuse_as_new_process():
    first_creation_time = datetime(2026, 1, 1, 12, 0, 0)
    second_creation_time = datetime(2026, 1, 1, 12, 5, 0)

    first_event = ProcessEvent(
        pid=1234,
        parent_pid=5678,
        parent_process_name="explorer.exe",
        process_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        process_name="powershell.exe",
        command="powershell.exe -EncodedCommand first",
        timestamp=datetime.now(),
        creation_time=first_creation_time,
    )

    second_event = ProcessEvent(
        pid=1234,
        parent_pid=5678,
        parent_process_name="explorer.exe",
        process_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        process_name="powershell.exe",
        command="powershell.exe -EncodedCommand second",
        timestamp=datetime.now(),
        creation_time=second_creation_time,
    )

    events = [first_event, second_event]
    monitor = Monitor(collector=lambda: events)

    findings = monitor.run_once()

    assert len(findings) == 2

def test_monitor_stores_findings(tmp_path):
    event = ProcessEvent(
        pid=1234,
        parent_pid=5678,
        parent_process_name="explorer.exe",
        process_path=(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        ),
        process_name="powershell.exe",
        command="powershell.exe -EncodedCommand abc123",
        timestamp=datetime.now(),
        creation_time=datetime(2026, 1, 1, 12, 0, 0),
    )

    def fake_collector() -> list[ProcessEvent]:
        return [event]

    store = FindingStore(tmp_path / "findings.json")

    monitor = Monitor(
        collector=fake_collector,
        finding_store=store,
    )

    findings = monitor.run_once()

    assert len(findings) == 1

    stored_findings = store.get_all()

    assert len(stored_findings) == 1
    assert stored_findings[0]["rule_id"] == "POWERSHELL-001"