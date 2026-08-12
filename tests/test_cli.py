from order66.__main__ import main


def test_main_runs_without_error(monkeypatch):
    calls = []

    def fake_run_monitor(monitor, iterations=None, interval=5.0):
        calls.append((monitor, iterations, interval))
        return []

    monkeypatch.setattr(
        "order66.__main__.run_monitor",
        fake_run_monitor,
    )

    main([], collector=lambda: [])

    assert len(calls) == 1


def test_demo_mode_runs_without_error():
    main(["--demo"])


def test_once_mode_runs_one_iteration(monkeypatch):
    calls = []

    def fake_run_monitor(monitor, iterations=None, interval=5.0):
        calls.append((monitor, iterations, interval))
        return []

    monkeypatch.setattr(
        "order66.__main__.run_monitor",
        fake_run_monitor,
    )

    main(["--once"], collector=lambda: [])

    assert len(calls) == 1
    assert calls[0][1] == 1
    assert calls[0][2] == 0
