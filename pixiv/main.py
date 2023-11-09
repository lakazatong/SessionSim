# imports
import sys
from ..classes import *
# init

def pixiv_function(session_sim, i, before=True):
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

def accept_function(session_sim, i, har_request, har_response):
	response_status = int(har_response['status'])
	return response_status < 400 and response_status > 0

# os.system('clear')

session_sim = SessionSim()
session_sim.cookie_manager.load_cookies_keys('../libs/cookies_keys.json')

# simulate login
session_sim.critical_function = pixiv_function
# session_sim.load_har('google_login_phone_verif.har')

session_sim.run_sim('google_login_phone_verif.har', accept_function=accept_function)

...

session_sim.cookie_manager.save_cookies_keys('../libs/cookies_keys.json')
