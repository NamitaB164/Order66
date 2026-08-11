from datetime import datetime

import psutil

from order66.events import ProcessEvent


def collect_processes() -> list[ProcessEvent]:
    events = []
    # iterate over process and retrieve: pid, name and command line.
    for process in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            info = process.info

            command = " ".join(info["cmdline"] or [])

            event = ProcessEvent(
                pid=info["pid"],
                process_name=info["name"] or "unknown",
                command=command,
                timestamp=datetime.now(),
            )

            events.append(event)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return events
