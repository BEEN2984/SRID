
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional, Any

@dataclass
class SharedState:
    lock: Lock = field(default_factory=Lock, repr=False)

    # 갱신된 것만 넣어두는 슬롯들
    last_event: Optional[Any] = None
    last_ip: Optional[str] = None
    last_ip_stats: Optional[Any] = None

    last_user: Optional[str] = None
    last_user_stats: Optional[Any] = None

shared = SharedState()
