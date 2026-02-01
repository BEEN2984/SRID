from collections import deque
from datetime import datetime
import parser

# 장기간 보관되는 데이터 

# Stats, 일정 기간 동안 유지
class Dispatcher():
    def __init__(self):
        self.IP_table :dict[str, IPStats]= {}
        self.User_table :dict[str, UserStats]= {}

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
        if event.event_type == parser.EventType.FAIL_PW:
            UserStats.add_event(event, window)

        IPStats.add_event(event,window)

        if event.ip not in self.IP_table:
            # 처음 보는 IP라면 새로 생성
            self.IP_table[event.ip] = IPStats(event.ip, event.timestamp)
        self.IP_table[event.ip].add_event(event, window)

        # 2. 유저 기반 통계 업데이트 (비밀번호 실패 시에만)
        if event.event_type == parser.EventType.FAIL_PW and event.user != "unknown":
            # 없으면 생성
            self.User_table[event.user] = UserStats(event.user, event.timestamp)
        self.User_table[event.user].add_event(event, window)

        


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

    def add_event(self, event:parser.RawLogEvent, window:int):
        self.event_history.append((event.timestamp, event.event_type))
        self.lastseen = self.event_history[-1][0]

        match event.event_type:
            case parser.EventType.FAIL_PW:
                self.fail_count += 1
            case parser.EventType.INVALID_USER:
                self.invalid_count += 1
            case parser.EventType.PREAUTH:
                self.preauth_count += 1
            case parser.EventType.LOGIN_SUCCESS:
                # Alert!!!
                return

        # Evict old events
        while self.event_history and (self.lastseen-self.event_history[0][0] > window):
            evicted = self.event_history.popleft()

            # count 정리
            match evicted[1]:
                case parser.EventType.FAIL_PW:
                    self.fail_count -= 1
                case parser.EventType.INVALID_USER:
                    self.invalid_count -= 1
                case parser.EventType.PREAUTH:
                    self.preauth_count -= 1

        self.firstseen = self.event_history[0][0]



class UserStats:
    def __init__(self, user, timestamp):
        self.user = user
        self.fail_count = 0
        self.firstseen = timestamp
        self.lastseen = timestamp
        # event_history = { ( time, ip) }
        self.event_history = deque()
    
    def add_event(self, event:parser.RawLogEvent, window:int):
        self.event_history.append((event.timestamp, event.ip))
        self.lastseen = self.event_history[-1][0]
        self.fail_count += 1

        # Evict old events
        while self.event_history and (self.lastseen-self.event_history[0][0] > window):
            self.event_history.popleft()
            self.fail_count -= 1

        self.firstseen = self.event_history[0][0]
