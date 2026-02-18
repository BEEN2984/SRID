from collections import deque
from datetime import datetime
import parser
from enums import EventType

# 장기간 보관되는 데이터 

# Stats, 일정 기간 동안 유지
class Dispatcher():
    def __init__(self):
        self.IP_table :dict[str, IPStats]= {}
        self.User_table :dict[str, UserStats]= {}
        self.Recent_Update_IP : tuple[str, EventType] = None
        self.Recent_Update_User : tuple[str, EventType] = None

    def Clean(self, ttl_seconds: int = 3600):
        # 3600s 마다 실행을 메인에 넣기
        now_ts = datetime.now().timestamp()

        # IP 정리
        for ip, ipstat in list(self.IP_table.items()):
            if ipstat.lastseen and (now_ts - ipstat.lastseen) > ttl_seconds:
                del self.IP_table[ip]

        # User 정리
        for user, userstat in list(self.User_table.items()):
            if userstat.lastseen and (now_ts - userstat.lastseen) > ttl_seconds:
                del self.User_table[user]

    def add_event(self, event:parser.RawLogEvent):
        window = 300

        # 1. Update or Create new IPstat
        if event.ip not in self.IP_table:
            self.IP_table[event.ip] = IPStats(event.ip, event.timestamp)
        self.IP_table[event.ip]._add_event(event, window)
        self.Recent_Update_IP = (event.ip, event.event_type)

        # 2. Update or create UserStats only when the EventType is FAIL_PW
        if event.event_type == EventType.FAIL_PW and event.user != "unknown":
            if event.user not in self.User_table:
                self.User_table[event.user] = UserStats(event.user, event.timestamp)
            self.User_table[event.user]._add_event(event, window)
            self.Recent_Update_User = (event.user, event.event_type)
        else : self.Recent_Update_User = None

    def print_state(self):
        print("\n====== Dispatcher State ======")

        print("\n-- IP Table --")
        for ip, stat in self.IP_table.items():
            print(stat)

        print("\n-- User Table --")
        for user, stat in self.User_table.items():
            print(stat)

        print("\nRecent_Update_IP:", self.Recent_Update_IP)
        print("Recent_Update_User:", self.Recent_Update_User)
        print("================================\n")



class IPStats:
    # accepted, fail, preauth, invalid
    def __init__(self,ip,timestamp):
        self.ip = ip
        self.fail_count = 0
        self.invalid_count = 0
        self.preauth_count = 0
        # window_deque = { ( time, event_type:EventType)}
        self.firstseen = timestamp
        self.lastseen = timestamp
        self.event_history = deque()

    def _add_event(self, event:parser.RawLogEvent, window:int):
        self.event_history.append((event.timestamp, event.event_type))
        self.lastseen = self.event_history[-1][0]

        match event.event_type:
            case EventType.FAIL_PW:
                self.fail_count += 1
            case EventType.INVALID_USER:
                self.invalid_count += 1
            case EventType.PREAUTH:
                self.preauth_count += 1

        # Evict old events
        while self.event_history and (self.lastseen-self.event_history[0][0] > window):
            evicted = self.event_history.popleft()

            # count 정리
            match evicted[1]:
                case EventType.FAIL_PW:
                    self.fail_count -= 1
                case EventType.INVALID_USER:
                    self.invalid_count -= 1
                case EventType.PREAUTH:
                    self.preauth_count -= 1

        self.firstseen = self.event_history[0][0]

    def __str__(self):
        return (
            f"[IPStats] ip={self.ip} "
            f"fail={self.fail_count} "
            f"invalid={self.invalid_count} "
            f"preauth={self.preauth_count} "
            f"firstseen={self.firstseen} "
            f"lastseen={self.lastseen}"
        )


class UserStats:
    def __init__(self, user, timestamp):
        self.user = user
        self.fail_count = 0
        self.firstseen = timestamp
        self.lastseen = timestamp
        # event_history = { ( time, ip) }
        self.event_history = deque()
    
    def _add_event(self, event:parser.RawLogEvent, window:int):
        self.event_history.append((event.timestamp, event.ip))
        self.lastseen = self.event_history[-1][0]
        self.fail_count += 1

        # Evict old events
        while self.event_history and (self.lastseen-self.event_history[0][0] > window):
            self.event_history.popleft()
            self.fail_count -= 1

        self.firstseen = self.event_history[0][0]

    def __str__(self):
        return (
            f"[UserStats] user={self.user} "
            f"fail={self.fail_count} "
            f"firstseen={self.firstseen} "
            f"lastseen={self.lastseen}"
        )