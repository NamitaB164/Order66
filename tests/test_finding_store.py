"""Test 1
Can we save a finding?

Test 2
Does the file actually get created?

Test 3
Does the saved JSON contain the correct information?

Test 4
Can multiple findings be stored?

Test 5
What happens if the file doesn't exist yet?

Test 6
What happens if there are no findings?"""
from datetime import datetime

from order66.finding import Finding, Severity
from order66.storage.finding_store import FindingStore


# Test 1:
# Can we save a finding?
def test_save_finding(tmp_path):
    store = FindingStore(tmp_path / "findings.json")

    finding = Finding(
        rule_id="POWERSHELL-001",
        severity=Severity.HIGH,
        reason="Encoded PowerShell command detected",
        process="powershell.exe",
        timestamp=datetime.now(),
    )

    store.save(finding)

    findings = store.get_all()

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "POWERSHELL-001"
    assert findings[0]["severity"] == "high"
    assert findings[0]["reason"] == "Encoded PowerShell command detected"
    assert findings[0]["process"] == "powershell.exe"


# Test 2:
# Does saving a finding actually create the JSON file?
def test_store_creates_json_file(tmp_path):
    store = FindingStore(tmp_path / "findings.json")

    finding = Finding(
        rule_id="PROCESS-002",
        severity=Severity.MEDIUM,
        reason="Process executed from a suspicious location",
        process="something.exe",
        timestamp=datetime.now(),
    )

    store.save(finding)

    assert (tmp_path / "findings.json").exists()


# Test 3:
# Does the saved JSON contain the correct information?
def test_saved_json_contains_correct_information(tmp_path):
    store = FindingStore(tmp_path / "findings.json")

    timestamp = datetime.now()

    finding = Finding(
        rule_id="POWERSHELL-003",
        severity=Severity.HIGH,
        reason="PowerShell execution policy manipulation detected",
        process="powershell.exe",
        timestamp=timestamp,
    )

    store.save(finding)

    findings = store.get_all()

    assert findings[0]["rule_id"] == "POWERSHELL-003"
    assert findings[0]["severity"] == "high"
    assert findings[0]["reason"] == (
        "PowerShell execution policy manipulation detected"
    )
    assert findings[0]["process"] == "powershell.exe"
    assert findings[0]["timestamp"] == timestamp.isoformat()


# Test 4:
# Can multiple findings be stored?
def test_multiple_findings_are_stored(tmp_path):
    store = FindingStore(tmp_path / "findings.json")

    finding1 = Finding(
        rule_id="POWERSHELL-001",
        severity=Severity.HIGH,
        reason="Encoded PowerShell command detected",
        process="powershell.exe",
        timestamp=datetime.now(),
    )

    finding2 = Finding(
        rule_id="POWERSHELL-002",
        severity=Severity.MEDIUM,
        reason="PowerShell executed with suspicious options",
        process="powershell.exe",
        timestamp=datetime.now(),
    )

    store.save(finding1)
    store.save(finding2)

    findings = store.get_all()

    assert len(findings) == 2
    assert findings[0]["rule_id"] == "POWERSHELL-001"
    assert findings[1]["rule_id"] == "POWERSHELL-002"


# Test 5:
# What happens if the JSON file doesn't exist yet?
def test_missing_file_returns_empty_list(tmp_path):
    store = FindingStore(tmp_path / "findings.json")

    findings = store.get_all()

    assert findings == []


# Test 6:
# What happens if the JSON file exists but contains no findings?
def test_empty_findings_file_returns_empty_list(tmp_path):
    path = tmp_path / "findings.json"

    path.write_text("[]", encoding="utf-8")

    store = FindingStore(path)

    findings = store.get_all()

    assert findings == []