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


def detect_suspicious_powershell(event: ProcessEvent) -> Finding | None:
    process_name = event.process_name.lower()
    command = event.command.lower()

    if process_name not in {"powershell.exe", "pwsh.exe"}:
        return None

    suspicious_options = {
        "-noprofile",
        "-nop",
        "-noninteractive",
        "-noni",
        "-windowstyle hidden",
        "-w hidden",
    }

    if not any(option in command for option in suspicious_options):
        return None

    return Finding(
        rule_id="POWERSHELL-002",
        severity=Severity.MEDIUM,
        reason="PowerShell executed with suspicious options",
        process=event.process_name,
        timestamp=event.timestamp,
    )


def detect_execution_policy_manipulation(
    event: ProcessEvent,
) -> Finding | None:
    process_name = event.process_name.lower()
    command = event.command.lower()

    if process_name not in {"powershell.exe", "pwsh.exe"}:
        return None

    suspicious_policies = {
        "-executionpolicy bypass",
        "-executionpolicy unrestricted",
        "-ep bypass",
        "-ep unrestricted",
    }

    if not any(policy in command for policy in suspicious_policies):
        return None

    return Finding(
        rule_id="POWERSHELL-003",
        severity=Severity.HIGH,
        reason="PowerShell execution policy manipulation detected",
        process=event.process_name,
        timestamp=event.timestamp,
    )


def detect_suspicious_parent_child(
    event: ProcessEvent,
) -> Finding | None:
    process_name = event.process_name.lower()
    parent_process_name = (
        event.parent_process_name.lower() if event.parent_process_name else None
    )

    # This rule currently focuses on PowerShell.
    if process_name not in {"powershell.exe", "pwsh.exe"}:
        return None

    # We cannot determine whether the parent is suspicious.
    if parent_process_name is None:
        return None

    normal_parents = {
        "explorer.exe",
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "conhost.exe",
    }

    if parent_process_name in normal_parents:
        return None

    return Finding(
        rule_id="PROCESS-001",
        severity=Severity.HIGH,
        reason="PowerShell spawned by a suspicious parent process",
        process=event.process_name,
        timestamp=event.timestamp,
    )

def detect_suspicious_execution_location(
    event: ProcessEvent,
) -> Finding | None:
    process_path = event.process_path

    if process_path is None:
        return None

    suspicious_locations = {
        "\\appdata\\local\\temp\\",
        "\\appdata\\roaming\\",
        "\\windows\\temp\\",
    }

    path = process_path.lower()

    if not any(location in path for location in suspicious_locations):
        return None

    return Finding(
        rule_id="PROCESS-002",
        severity=Severity.MEDIUM,
        reason="Process executed from a suspicious location",
        process=event.process_name,
        timestamp=event.timestamp,
    )