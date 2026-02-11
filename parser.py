# 로그 받아와서 파싱
import re
from datetime import datetime
from dataclasses import dataclass
from enums import EventType

@dataclass
class RawLogEvent:
    timestamp : float
    ip : str
    user : str
    event_type : EventType

LOG_REGEX_USER_IP = re.compile(
    r"(?P<timestamp>^[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2}).*?"                                    
    r"(?:for\s+)?(?P<user>\S+)"       
    r".*?from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

LOG_REGEX_IP = re.compile(
    r"(?P<timestamp>^[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2}).*?"  
    r".*?from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

def Parse_line(line):
    m = None
    raw_ts = 0.0
    raw_user = "unknown"
    raw_ip = "0.0.0.0"
    raw_event = EventType.FAIL_PW

    # parsing + event
    if "[preauth]" in line:
        m = LOG_REGEX_IP.search(line)
        raw_event = EventType.PREAUTH

    elif "Failed password for invalid user" in line:
        m = LOG_REGEX_IP.search(line)
        raw_event = EventType.INVALID_USER

    elif "Accepted password" in line:
        m = LOG_REGEX_USER_IP.search(line)
        raw_event = EventType.LOGIN_SUCCESS

    elif "Failed password" in line:
        m = LOG_REGEX_USER_IP.search(line)
        raw_event = EventType.FAIL_PW

    # 매칭 안된 경우 
    if not m:
        return None

    # data 담기
    raw_ts = TimeChangeToStamp(m.group("timestamp"))
    raw_ip = m.group("ip")
    if raw_event in (EventType.LOGIN_SUCCESS, EventType.FAIL_PW):
        raw_user = m.group("user")

    return RawLogEvent(raw_ts, raw_ip, raw_user, raw_event)


def TimeChangeToStamp(ts_str):
    if not ts_str:
        return datetime.now().timestamp()

    now = datetime.now()
    dt = datetime.strptime(f"{now.year} {ts_str}", "%Y %b %d %H:%M:%S")
    
    return dt.timestamp()

