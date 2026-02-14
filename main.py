import DataManager
import parser

disp = DataManager.dispatcher_data
ana = DataManager.alert_data

def line(log):  
    event = parser.Parse_line(log)
    if not event : return

    disp.add_event(event)  
    ana.check_alert(disp.Recent_Update_IP, disp.Recent_Update_User,disp)  
    



