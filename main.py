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
			case 9:
				session_sim.prepared_request['headers']['x-csrf-token'] = session_sim.cookie_manager.get_cookie('csrf-token')
			case 11:
				# print_json(session_sim.prepared_request)
				data = json.loads(session_sim.prepared_request['data'])
				transfer_json_data(session_sim.mem['get_url_data'], data['request'])
				session_sim.prepared_request['data'] = json.dumps(data)
				session_sim.prepared_request['headers']['Content-Length'] = str(len(session_sim.prepared_request['data']))
				session_sim.prepared_request['headers']['Referer'] = build_get_url('https://accounts.zalando.com/authenticate', session_sim.mem['get_url_data'])
				print_json(session_sim.prepared_request)
			case _:
				pass
	# runs after the request is sent
	else:
		match i:
			case 3:
				sel = Selector(session_sim.response.content.decode('utf-8'))
				data_props = json.loads(decode_url(sel.xpath('/html/body/div[1]/@data-props').get()))
				# data_translations = json.loads(decode_url(sel.xpath('/html/body/div[1]/@data-translations').get()))
				data_render_headers = json.loads(decode_url(sel.xpath('/html/body/div[1]/@data-render-headers').get()))
				# print_json(data_props)
				# print_json(data_translations)
				# print_json(data_render_headers)
				session_sim.prepared_request['headers']['x-flow-id'] = data_render_headers['x-flow-id']

				session_sim.mem['get_url_data'] = {}
				transfer_json_data(data_props['request'], session_sim.mem['get_url_data'], value_action=lambda value: value[0])
				session_sim.mem['get_url_data']['request_id'] = data_props['compromisedCheckPayload']['request_id'][0]
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

# session_sim.cookie_manager.print_cookies()


# final cookies
# session_sim.cookie_manager.print_cookies()

exit(0)

# random old stuff

# (jsplus cmt jlai trouve, il a l'air permanent comme zalando_client_id)
# client_id = '5bc6d482-5c1a-4a57-9c64-4ba6fc2a9ff4'
# (expire en 2025 askip)
# zalando_client_id = '907f8924-89c6-4c94-909a-67d2bdf8116e'