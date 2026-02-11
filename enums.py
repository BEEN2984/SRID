from enum import Enum

class EventType(Enum):
    FAIL_PW = 1
    INVALID_USER = 2
    PREAUTH = 3
    LOGIN_SUCCESS = 4