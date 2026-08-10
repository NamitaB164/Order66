# Test how process event stores process info.
from datetime import datetime

from order66.events import ProcessEvent


def test_process_information():
    timestamp = datetime.now()

    event = ProcessEvent(
        pid=1234,
        process_name="python.exe",
        command="python app.py",
        timestamp=timestamp,
    )

    assert event.pid == 1234
    assert event.process_name == "python.exe"
    assert event.command == "python app.py"
    assert event.timestamp == timestamp
