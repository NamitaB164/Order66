from datetime import datetime

from order66.detection.rules import detect_encoded_powershell
from order66.events import ProcessEvent
from order66.finding import Severity


def test_detects_encoded_powershell_command():
    event = ProcessEvent(
        pid=1234,
        process_name="powershell.exe",
        command="powershell.exe -EncodedCommand SGVsbG8=",
        timestamp=datetime.now(),
    )

    finding = detect_encoded_powershell(event)

    assert finding is not None
    assert finding.rule_id == "POWERSHELL-001"
    assert finding.severity == Severity.HIGH
    assert "Encoded PowerShell command" in finding.reason
    assert finding.process == "powershell.exe"


def test_ignores_normal_process():
    event = ProcessEvent(
        pid=1234,
        process_name="notepad.exe",
        command="notepad.exe",
        timestamp=datetime.now(),
    )

    finding = detect_encoded_powershell(event)

    assert finding is None
