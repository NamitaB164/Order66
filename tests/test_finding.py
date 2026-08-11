#Test that a finding can be created correctly
from datetime import datetime

from order66.finding import Finding, Severity


def test_finding_stores_detection_information():
    timestamp = datetime.now()

    finding = Finding(
        rule_id="POWERSHELL-001",
        severity=Severity.HIGH,
        reason="Encoded PowerShell command detected",
        process="powershell.exe",
        timestamp=timestamp,
    )

    assert finding.rule_id == "POWERSHELL-001"
    assert finding.severity == Severity.HIGH
    assert finding.reason == "Encoded PowerShell command detected"
    assert finding.process == "powershell.exe"
    assert finding.timestamp == timestamp