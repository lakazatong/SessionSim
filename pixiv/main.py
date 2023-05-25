# imports
import sys
sys.path.append('../libs')
from classes import *
# init

def pixiv_function(i, session_sim, before=True):
	# i is the ith request in the har file (the first is the 0th)
	# runs before the request is sent
	if before:
		match i:
			case _:
				pass
	# runs after the request is sent
	else:
		match i:
			case _:
				pass

# os.system('clear')

session_sim = SessionSim()
session_sim.cookie_manager.load_cookies_keys('../libs/cookies_keys.json')

# simulate login
session_sim.critical_function = pixiv_function
session_sim.load_har('pixiv.har')

...

session_sim.cookie_manager.save_cookies_keys('../libs/cookies_keys.json')