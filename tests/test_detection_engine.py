from datetime import datetime

from order66.detection.detection_engine import DetectionEngine
from order66.events import ProcessEvent
from order66.finding import Severity


def test_engine_returns_finding_for_encoded_powershell():
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

    engine = DetectionEngine()

    findings = engine.analyze(event)

    assert len(findings) == 1
    assert findings[0].rule_id == "POWERSHELL-001"
    assert findings[0].severity == Severity.HIGH


def test_engine_returns_no_findings_for_normal_process():
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

    engine = DetectionEngine()

    findings = engine.analyze(event)

    assert findings == []

def test_engine_returns_finding_for_suspicious_execution_location():
    event = ProcessEvent(
        pid=1234,
        parent_pid=5678,
        parent_process_name="explorer.exe",
        process_name="something.exe",
        process_path="C:\\Users\\Test\\AppData\\Local\\Temp\\something.exe",
        command="something.exe",
        timestamp=datetime.now(),
        creation_time=datetime(2026, 1, 1, 12, 0, 0),
    )

    findings = DetectionEngine().analyze(event)

    assert any(
        finding.rule_id == "PROCESS-002"
        for finding in findings
    )

