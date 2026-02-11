import parser
import dispatcher
import analyzer


# data 총괄
dispatcer_data = dispatcher.Dispatcher()
alert_data = analyzer.Anaylzer()

# These codes may move to main.py
alert_data.Check_Alert(dispatcer_data.Recent_Update_IP, dispatcer_data.Recent_Update_User)