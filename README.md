# Order66
Local Host-Based Behavioral Threat Monitor

Order66 is a prototype that watches running processes on a computer
and looks for simple, common signs of suspicious behavior. It collects basic process
information, runs a few predefined detection rules, and records any findings to a JSON file.


Install dependencies (in a virtual environment):

```powershell
python -m pip install --upgrade pip
python -m pip install psutil
python -m pip install -e .
```

Run the monitor once (scan running processes and exit):

```powershell
python -m order66 --once
```

Run a short demo mode (uses a hardcoded event):

```powershell
python -m order66 --demo
```

Print stored finding history from `findings.json`:

```powershell
python -m order66 --history
```

Run continuous monitoring (default):

```powershell
python -m order66
```

## Execution steps
- Collects a snapshot of running processes.
- Converts each process into a `ProcessEvent`.
- Passes events to the `DetectionEngine`.
- If a rule thinks something is suspicious it returns a `Finding` object.
- Findings are saved to `findings.json` by `FindingStore`.

## Detection Rules
- `POWERSHELL-001` — Encoded PowerShell command detected (HIGH): looks for
	`-EncodedCommand`/`-Enc` usage. Encoded commands are often used to hide
	what a script is doing.
- `POWERSHELL-002` — PowerShell executed with suspicious options (MEDIUM):
	flags like `-NoProfile`, `-WindowStyle Hidden`, `-NonInteractive` can indicate
	scripted or stealthy PowerShell usage.
- `POWERSHELL-003` — PowerShell execution policy manipulation (HIGH): flags
	like `-ExecutionPolicy Bypass` or `-EP Unrestricted` which allow scripts to
	run without normal protections.
- `PROCESS-001` — PowerShell spawned by a suspicious parent (HIGH): if a
	PowerShell process's parent is not one of the common, expected parents
	(for example `explorer.exe` or `cmd.exe`), this rule flags it.
- `PROCESS-002` — Process executed from a suspicious location (MEDIUM): the
	executable path contains places where malware commonly runs from, for example
	AppData temporary folders.

## Storage and output
Order66 writes findings as a JSON list to `findings.json` by default. 
Each entry contains: `rule_id`, `severity`, `reason`, `process`, and an ISO
timestamp.



## Development and testing
- Run tests with `pytest` from the project root:

```powershell
python -m pytest
```
