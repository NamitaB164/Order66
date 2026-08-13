from datetime import datetime

from order66.detection.detection_engine import DetectionEngine
from order66.detection.rules import (
    detect_encoded_powershell,
    detect_execution_policy_manipulation,
    detect_suspicious_powershell,
)
from order66.events import ProcessEvent
from order66.finding import Severity


def test_detects_encoded_powershell_command():
    event = ProcessEvent(
        pid=1234,
        parent_pid=5678,
        process_name="powershell.exe",
        command="powershell.exe -EncodedCommand SGVsbG8=",
        timestamp=datetime.now(),
        creation_time=datetime(2026, 1, 1, 12, 0, 0),
    )

    finding = detect_encoded_powershell(event)

    assert finding is not None
    assert finding.rule_id == "POWERSHELL-001"
    assert finding.severity == Severity.HIGH
    assert "Encoded PowerShell command" in finding.reason
    assert finding.process == "powershell.exe"


def test_detects_suspicious_powershell_options():
    event = ProcessEvent(
        pid=1234,
        parent_pid=5678,
        process_name="powershell.exe",
        command="powershell.exe -NoProfile -WindowStyle Hidden",
        timestamp=datetime.now(),
        creation_time=datetime(2026, 1, 1, 12, 0, 0),
    )

    finding = detect_suspicious_powershell(event)

    assert finding is not None
    assert finding.rule_id == "POWERSHELL-002"
    assert finding.severity == Severity.MEDIUM


def test_detects_execution_policy_bypass():
    event = ProcessEvent(
        pid=1234,
        parent_pid=5678,
        process_name="powershell.exe",
        command="powershell.exe -ExecutionPolicy Bypass",
        timestamp=datetime.now(),
        creation_time=datetime(2026, 1, 1, 12, 0, 0),
    )

    finding = detect_execution_policy_manipulation(event)

    assert finding is not None
    assert finding.rule_id == "POWERSHELL-003"


def test_ignores_normal_execution_policy():
    event = ProcessEvent(
        pid=1234,
        parent_pid=5678,
        process_name="powershell.exe",
        command="powershell.exe -ExecutionPolicy RemoteSigned",
        timestamp=datetime.now(),
        creation_time=datetime(2026, 1, 1, 12, 0, 0),
    )

    finding = detect_execution_policy_manipulation(event)

    assert finding is None


def test_detects_short_execution_policy_bypass():
    event = ProcessEvent(
        pid=1234,
        parent_pid=5678,
        process_name="pwsh.exe",
        command="pwsh.exe -ep bypass",
        timestamp=datetime.now(),
        creation_time=datetime(2026, 1, 1, 12, 0, 0),
    )

    finding = detect_execution_policy_manipulation(event)

    assert finding is not None
    assert finding.rule_id == "POWERSHELL-003"


def test_ignores_normal_powershell():
    event = ProcessEvent(
        pid=1234,
        parent_pid=5678,
        process_name="powershell.exe",
        command="powershell.exe Get-Process",
        timestamp=datetime.now(),
        creation_time=datetime(2026, 1, 1, 12, 0, 0),
    )

    finding = detect_suspicious_powershell(event)

    assert finding is None


def test_ignores_normal_process():
    event = ProcessEvent(
        pid=1234,
        parent_pid=5678,
        process_name="notepad.exe",
        command="notepad.exe",
        timestamp=datetime.now(),
        creation_time=datetime(2026, 1, 1, 12, 0, 0),
    )

    finding = detect_encoded_powershell(event)

    assert finding is None


def test_engine_returns_finding_for_suspicious_powershell():
    event = ProcessEvent(
        pid=1234,
        parent_pid=5678,
        process_name="powershell.exe",
        command="powershell.exe -NoProfile -WindowStyle Hidden",
        timestamp=datetime.now(),
        creation_time=datetime(2026, 1, 1, 12, 0, 0),
    )

    findings = DetectionEngine().analyze(event)

    assert any(finding.rule_id == "POWERSHELL-002" for finding in findings)
