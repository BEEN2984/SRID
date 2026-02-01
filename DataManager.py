import parser
import dispatcher
import analyzer

statsManager = dispatcher.Dispatcher()

log = ""

rawlogevent = parser.Parse_line(log)
statsManager.add_event(rawlogevent)


class DataManager():
    def __init__(self):
        self.StatsManager