from order66.events import ProcessEvent
from order66.finding import Finding, Severity


def detect_encoded_powershell(event: ProcessEvent) -> Finding | None:
    # Normalize the process name
    process_name = event.process_name.lower()
    command = event.command.lower()
    # Check whether it's PowerShell
    if process_name not in {"powershell.exe", "pwsh.exe"}:
        return None
    # Check the command line
    if "-encodedcommand" not in command and "-enc" not in command:
        return None
    # Generate the finding
    return Finding(
        rule_id="POWERSHELL-001",
        severity=Severity.HIGH,
        reason="Encoded PowerShell command detected",
        process=event.process_name,
        timestamp=event.timestamp,
    )
