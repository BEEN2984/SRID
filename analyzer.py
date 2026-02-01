from datetime import datetime
from dataclasses import dataclass
from enum import Enum
import parser

# Alert
class AlertType(Enum):
    # ip = 1x , user = 2x
    IP_FAIL_PW = 11
    IP_INVALID_USER = 12
    IP_PREAUTH = 13
    IP_ROOT_TRY = 14
    IP_BRUTEFORCE_SUCCESS = 15
    IP_ATTACK_PERSISTENT = 16

    USER_FAIL_PW = 21
    USER_BRUTEFORCE_SUCCESS = 25
    USER_MULTI_IP_TO_SINGLE_USER = 27

class Severity(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4

@dataclass
class Alert:
    alert_type : AlertType
    target : str
    Evidence : str
    severity : Severity
    last_alert_time : datetime

class Anaylzer():
    def __init__(self):
        pass

    def Main_anay(self, event:parser.RawLogEvent):
        if event.event_type == parser.EventType.FAIL_PW:
            return
        
    def 
