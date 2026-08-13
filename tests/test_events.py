# Test how process event stores process info.

from datetime import datetime

from order66.events import ProcessEvent


def test_process_information():
    timestamp = datetime.now()
    creation_time = datetime.now()

    event = ProcessEvent(
        pid=1234,
        parent_pid=5678,
        parent_process_name="explorer.exe",
        process_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        process_name="python.exe",
        command="python app.py",
        timestamp=timestamp,
        creation_time=creation_time,
    )

    assert event.pid == 1234
    assert event.parent_pid == 5678
    assert event.parent_process_name == "explorer.exe"
    assert (
        event.process_path
        == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    )
    assert event.process_name == "python.exe"
    assert event.command == "python app.py"
    assert event.timestamp == timestamp
    assert event.creation_time == creation_time
