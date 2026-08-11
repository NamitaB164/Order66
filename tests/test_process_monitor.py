from order66.collectors.process_monitor import collect_processes
from order66.events import ProcessEvent


def test_collect_processes_returns_process_events():
    events = collect_processes()

    assert isinstance(events, list)
    assert len(events) > 0
    assert all(isinstance(event, ProcessEvent) for event in events)