# imports

import requests, json, time
from funcs import *
from classes import CookieManager, CustomResponse, SessionSim
from parsel import Selector
# init

def zalando_function(i, session_sim, before=True):
	# i is the ith request in the har file (the first is the 0th)
	# runs before the request is sent
	if before:
		match i:
			case 0:
				pass
			# case 1:
			# 	base_url, params = deconstruct_get_url(session_sim.request_list[1]['request']['url'])
			# 	params.pop('nonce')
			# 	params.pop('request_id')
			# 	params.pop('state')
			# 	url = build_get_url(base_url, params)
			# 	session_sim.request['url'] = url
			case 9:
				session_sim.prepared_request['headers']['x-csrf-token'] = session_sim.cookie_manager.get_cookie('csrf-token')
			case 11:
				print_json(json.loads(session_sim.prepared_request['data']))
				print_json(session_sim.prepared_request)
				exit(0)
			case _:
				pass
	# runs after the request is sent
	else:
		match i:
			case 0:
				# base_url, params = deconstruct_get_url(session_sim.response.headers['location'])
				# session_sim.mem['state'] = params['state']
				pass
			case 3:
				session_sim.prepared_request['headers']['x-flow-id'] = json.loads(decode_url(Selector(session_sim.response.content.decode('utf-8')).xpath('/html/body/div[1]/@data-render-headers').get()))['x-flow-id']
				pass
			case _:
				pass

# os.system('clear')

session_sim = SessionSim()

# simulate login
session_sim.critical_function = zalando_function
session_sim.load_har('simple.har')

session_sim.sim(0)
session_sim.sim(1)
session_sim.sim(2) # A FIX / IMPROVE ----------------- PROBLEME DE REDIRECTION? ----------------- A FIX / IMPROVE
session_sim.sim(3)
session_sim.sim(9)
# session_sim.sim(10) # login schema
session_sim.sim(11)
print_json(session_sim.json_request)

# session_sim.cookie_manager.print_cookies()


# final cookies
# session_sim.cookie_manager.print_cookies()

exit(0)

# random old stuff

# (jsplus cmt jlai trouve, il a l'air permanent comme zalando_client_id)
# client_id = '5bc6d482-5c1a-4a57-9c64-4ba6fc2a9ff4'
# (expire en 2025 askip)
# zalando_client_id = '907f8924-89c6-4c94-909a-67d2bdf8116e'