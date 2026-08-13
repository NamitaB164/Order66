from datetime import datetime

import psutil

from order66.events import ProcessEvent


def collect_processes() -> list[ProcessEvent]:
    events = []

    for process in psutil.process_iter(
        ["pid", "ppid", "exe", "name", "cmdline", "create_time"]
    ):
        try:
            info = process.info

            parent_process_name = None

            if info["ppid"]:
                try:
                    parent_process = psutil.Process(info["ppid"])
                    parent_process_name = parent_process.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    parent_process_name = None

            command = " ".join(info["cmdline"] or [])
            process_path = info["exe"]
            creation_time = datetime.fromtimestamp(info["create_time"])

            event = ProcessEvent(
                pid=info["pid"],
                parent_pid=info["ppid"],
                parent_process_name=parent_process_name,
                process_path=process_path,
                process_name=info["name"] or "unknown",
                command=command,
                timestamp=datetime.now(),
                creation_time=creation_time,
            )

            events.append(event)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return events
