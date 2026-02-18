from DataManager import dispatcher_data, alert_data
from parser import Parse_line, Print_RawLogEvent
import time
import os

print("main.py run")

disp = dispatcher_data
ana = alert_data
LOG_PATH = "/var/log/remote/srid-target/sshd.log"


def log_line(log):  
    event = Parse_line(log)
    if not event : return
    # Print_RawLogEvent(event)

    disp.add_event(event)  
    # disp.print_state()

    ana.check_alert(disp.Recent_Update_IP, disp.Recent_Update_User, disp)  

def run_realtime_monitor(log_path="/var/log/remote/srid-target/sshd.log"):
    # 1. 파일이 생성될 때까지 대기 (rsyslog가 파일을 만들기 전일 수 있음)
    while not os.path.exists(log_path):
        print(f"Waiting for log file: {log_path}...")
        time.sleep(2)
        
    print(f"Monitoring started: {log_path}")
    
    with open(log_path, "r") as f:
        # 2. 파일의 맨 끝으로 이동 (이전 로그 무시, 실시간 탐지 집중)
        f.seek(0, os.SEEK_END)
        
        while True:
            line_content = f.readline()
            if not line_content:
                # 3. 새로운 라인이 없으면 잠시 대기
                time.sleep(0.1)
                continue
            
            # 4. 분석 로직 호출
            # line(line_content) 함수가 분석 로직의 입구라고 가정
            # print(f"New Log: {line_content.strip()}") # 디버깅용
            log_line(line_content)

# if __name__ == "__main__":
run_realtime_monitor()

