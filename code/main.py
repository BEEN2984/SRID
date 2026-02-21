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
    while not os.path.exists(log_path):                 # 파일 생성 대기
        print(f"Waiting for log file: {log_path}...")
        time.sleep(2)

    print(f"Monitoring started: {log_path}")
    
    with open(log_path, "r") as f:
        f.seek(0, os.SEEK_END)
        
        while True:
            line_content = f.readline()
            if not line_content:
                time.sleep(0.1)
                continue

            # print(f"New Log: {line_content.strip()}") 
            log_line(line_content)

def clean_table(disp, ana):
    disp.Clean()


run_realtime_monitor()


