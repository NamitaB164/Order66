from dataclasses import dataclass
from datetime import datetime

# define the structure of the event


@dataclass
class ProcessEvent:
    pid: int
    process_name: str
    command: str
    timestamp: datetime
