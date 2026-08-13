# define the structure of the event
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ProcessEvent:
    pid: int
    parent_pid: int | None
    process_name: str
    command: str
    timestamp: datetime
    creation_time: datetime
