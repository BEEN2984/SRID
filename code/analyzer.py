from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Callable, Dict, Optional, Any, Tuple
from utils import Color
from enums import EventType


class AlertType(Enum):
    # IP 관련 (1x)
    IP_FAIL_PW = 10
    IP_INVALID_USER = 11
    IP_PREAUTH = 12
    IP_BRUTEFORCE_SUCCESS = 13
    IP_ATTACK = 14

    # USER 관련 (2x)
    USER_FAIL_PW = 20
    USER_BRUTEFORCE_SUCCESS = 21
    USER_MULTI_IP_TO_SINGLE_USER = 22

    # ROOT 관련 (3x)
    USER_ROOT_TRY = 30
    USER_ROOT_SUCCESS = 31

class Severity(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4

@dataclass
class Alert:
    alert_type: AlertType
    target: str
    evidence: str
    severity: Severity
    last_alert_time: datetime


# Analyzer
class Analyzer:
    """
    Engine Structure
    - Dispatcher: EventType에 따라 적절한 핸들러 호출
    - Strategy: RULES 설정에 기반하여 임계치 및 심각도 결정
    - Alert Layer: (Target, AlertType) 쌍으로 중복 알람 방지 및 Cooldown 관리
    """

    DEFAULT_TTL_SECONDS = 3600
    DEFAULT_COOLDOWN_SECONDS = 300

    # RULES (threshold, window, severity)
    RULES = {
        ("ip", AlertType.IP_FAIL_PW):      {"threshold": 5, "window_s": 300, "severity": Severity.MEDIUM, "field": "fail_count"},
        ("user", AlertType.USER_FAIL_PW):  {"threshold": 5, "window_s": 300, "severity": Severity.MEDIUM, "field": "fail_count"},
        
        ("ip", AlertType.IP_INVALID_USER): {"threshold": 5, "window_s": 300, "severity": Severity.MEDIUM, "field": "invalid_count"},
        ("ip", AlertType.IP_PREAUTH):      {"threshold": 5, "window_s": 300, "severity": Severity.MEDIUM, "field": "preauth_count"},

        ("ip", AlertType.IP_BRUTEFORCE_SUCCESS):   {"threshold": 5, "window_s": 300, "severity": Severity.HIGH},
        ("user", AlertType.USER_BRUTEFORCE_SUCCESS): {"threshold": 5, "window_s": 300, "severity": Severity.HIGH},

        ("user", AlertType.USER_ROOT_TRY):     {"threshold": 1, "window_s": 60, "severity": Severity.HIGH, "field": "fail_count"},
        ("user", AlertType.USER_ROOT_SUCCESS): {"threshold": 1, "window_s": 60, "severity": Severity.CRITICAL},
    }

    def __init__(self):
        self.alert_table_ip: Dict[Tuple[str, AlertType], Alert] = {}
        self.alert_table_user: Dict[Tuple[str, AlertType], Alert] = {}
        self.alert_tables = {
            "ip": self.alert_table_ip,
            "user": self.alert_table_user,
        }

        # evnet dispatch
        self.handlers: Dict[EventType, Callable[..., None]] = {
            EventType.FAIL_PW: self._on_fail_pw,
            EventType.INVALID_USER: self._on_invalid_user,
            EventType.PREAUTH: self._on_preauth,
            EventType.LOGIN_SUCCESS: self._on_login_success,
        }

    # -----------------------------
    # Data Access Helpers
    def _get_stats(self, scope: str, target: str, dispatcher):
        if not dispatcher: return None
        table = dispatcher.IP_table if scope == "ip" else dispatcher.User_table
        return table.get(target)

    @staticmethod
    def _safe_get(d: Any, key: str):
        if d is None: return None
        try:
            return d.get(key) or d[key]
        except (AttributeError, KeyError, TypeError):
            return None

    @staticmethod
    def _as_dt(ts_or_dt) -> datetime:
        if isinstance(ts_or_dt, datetime): return ts_or_dt
        try:
            return datetime.fromtimestamp(float(ts_or_dt))
        except:
            return datetime.now()
    # -----------------------------



    # -----------------------------
    # Core Logic Layer
    def _process_threshold_rule(self, scope: str, target: str, alert_type: AlertType, dm):
        if not target: return
        cfg = self.RULES.get((scope, alert_type))
        if not cfg: return

        stats = self._get_stats(scope, target, dm)
        if not stats: return

        count = getattr(stats, cfg["field"], 0)
        if count >= cfg["threshold"]:
            lastseen = self._as_dt(getattr(stats, "lastseen", None))
            window_m = cfg["window_s"] 
            evidence = f"{target}: {count} {cfg['field']} detected (Window: {window_m/60} m)"
            self._raise_alert(scope, target, alert_type, evidence, lastseen, severity=cfg["severity"])

    def _raise_alert(
        self,
        scope: str,
        target: str,
        alert_type: AlertType,
        evidence: str,
        event_time: datetime,
        cooldown_seconds: int = DEFAULT_COOLDOWN_SECONDS,
        severity: Optional[Severity] = None,
    ) -> None:
        table = self.alert_tables[scope]
        key = (target, alert_type)
        
        # 설정에 정의된 기본 Severity 적용
        if severity is None:
            severity = self.RULES.get((scope, alert_type), {}).get("severity", Severity.MEDIUM)

        existing = table.get(key)
        if existing and (event_time - existing.last_alert_time) < timedelta(seconds=cooldown_seconds):
            return

        new_alert = Alert(
            alert_type=alert_type,
            target=target,
            evidence=evidence,
            severity=severity,
            last_alert_time=event_time,
        )
        table[key] = new_alert
        self._print_alert(new_alert)

    
    def _print_alert(self, alert: Alert):
        
        if alert.severity == Severity.CRITICAL:
            color = Color.CRITICAL
            symbol = "🚨 [CRITICAL]"
        elif alert.severity == Severity.HIGH:
            color = Color.ALERT
            symbol = "🔥 [HIGH]"
        elif alert.severity == Severity.MEDIUM:
            color = Color.WARNING
            symbol = "⚠️  [MEDIUM]"
        else:
            color = Color.EVENT
            symbol = "ℹ️  [LOW]"

        # 2. print formating
        header = f"{color}{'='*60}{Color.RESET}"
        footer = f"{color}{'='*60}{Color.RESET}"
        
        print(f"\n{header}")
        print(f"{color}{symbol} SECURITY ALERT DETECTED{Color.RESET}")
        print(f"{Color.SUCCESS}Time    :{Color.RESET} {alert.last_alert_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Color.SUCCESS}Type    :{Color.RESET} {alert.alert_type.name}")
        print(f"{Color.SUCCESS}Target  :{Color.RESET} {Color.WARNING}{alert.target}{Color.RESET}")
        print(f"{Color.SUCCESS}Evidence:{Color.RESET} {alert.evidence}")
        print(f"{header}\n")
    # ----------------------------




    # ----------------------------
    # Event Handlers
    def _on_fail_pw(self, ip = None, user = None, dm = None) -> None:
        if ip:
            self._process_threshold_rule("ip", ip, AlertType.IP_FAIL_PW, dm)
        if user:
            self._process_threshold_rule("user", user, AlertType.USER_FAIL_PW, dm)
            if user.lower() == "root":
                self._process_threshold_rule("user", user, AlertType.USER_ROOT_TRY, dm)

    def _on_invalid_user(self, ip = None, user = None, dm = None) -> None:
        self._process_threshold_rule("ip", ip, AlertType.IP_INVALID_USER, dm)

    def _on_preauth(self, ip = None, user = None, dm = None) -> None:
        self._process_threshold_rule("ip", ip, AlertType.IP_PREAUTH, dm)

    def _on_login_success(self, ip = None, user = None, dm = None) -> None:
        now = datetime.now()
        
        # 1. Root 로그인 성공 체크
        if user and user.lower() == "root":
            self._raise_alert("user", user, AlertType.USER_ROOT_SUCCESS, "Critical: Root login success", now)

        # 2. 브루트포스 성공 여부 (IP 및 User 기준)
        for scope, target, a_type in [("ip", ip, AlertType.IP_BRUTEFORCE_SUCCESS), 
                                    ("user", user, AlertType.USER_BRUTEFORCE_SUCCESS)]:
            if not target: continue
            
            stats = self._get_stats(scope, target, dm)
            cfg = self.RULES.get((scope, a_type))
            
            if stats and cfg and getattr(stats, "fail_count", 0) >= cfg["threshold"]:
                evidence = f"Login success after {stats.fail_count} failed attempts."
                self._raise_alert(scope, target, a_type, evidence, now, severity=cfg["severity"])
    # ----------------------------




    # ----------------------------
    # Public API
    def check_alert(self, recent_update_ip=None, recent_update_user=None, dm=None) -> None:
        if recent_update_ip:
            target, et = recent_update_ip
            self.handlers.get(et, lambda **k: None)(ip=target, user=None,dm=dm)

        if recent_update_user:
            target, et = recent_update_user
            self.handlers.get(et, lambda **k: None)(ip=None, user=target, dm=dm)

    def clean(self, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        now = datetime.now()
        ttl = timedelta(seconds=ttl_seconds)
        for table in self.alert_tables.values():
            expired_keys = [k for k, v in table.items() if (now - v.last_alert_time) > ttl]
            for k in expired_keys:
                del table[k]