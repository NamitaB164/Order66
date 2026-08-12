from order66.__main__ import main


def test_main_runs_without_error():
    main([])


def test_demo_mode_runs_without_error():
    main(["--demo"])
