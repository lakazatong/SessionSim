# imports
import sys
from ..classes import *
# init

def osu_function(session_sim, i, before=True):
	# i is the ith request in the har file (the first is the 0th)
	# runs before the request is sent
	if before:
		match i:
			case _:
				pass
	# runs after the request is sent
	else:
		match i:
			case 1:
				sel = Selector(session_sim.response.content.decode('utf-8'))
				data_initial_data = json.loads(sel.xpath('/html/body/div[8]/div/@data-initial-data').get())
				print_json(data_initial_data)
			case _:
				pass

session_sim = SessionSim()
session_sim.cookie_manager.load_cookies_keys('cookies_keys.json')

# simulate login
session_sim.critical_function = osu_function

session_sim.load_har('lakazatong.har')

session_sim.sim(0) # ...
session_sim.sim(1) # ...

...

session_sim.cookie_manager.save_cookies_keys('cookies_keys.json')
