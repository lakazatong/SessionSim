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
			case 1:
				session_sim.prepared_request['params'] = {}
				session_sim.prepared_request['url'] = session_sim.previous_response.headers['location']
				print(session_sim.prepared_request['url'])
			case 2:
				session_sim.prepared_request['params'] = {}
				session_sim.prepared_request['url'] = 'https://accounts.zalando.com'+session_sim.previous_response.headers['location']
				print(session_sim.prepared_request['url'])
			case 3:
				session_sim.prepared_request['params'] = {}
				session_sim.prepared_request['url'] = 'https://accounts.zalando.com'+session_sim.previous_response.headers['location']
				print(session_sim.prepared_request['url'])
			case 9:
				session_sim.prepared_request['headers']['x-csrf-token'] = session_sim.mem['csrf-token']
				session_sim.prepared_request['headers']['x-flow-id'] = session_sim.mem['x-flow-id']
			case 11:
				data = json.loads(session_sim.prepared_request['data'])
				transfer_json_data(session_sim.mem['get_url_data'], data['request'], key_action=lambda key:decode_url(key), value_action=lambda value:decode_url(value))
				session_sim.prepared_request['data'] = json.dumps(data)
				session_sim.prepared_request['headers']['Content-Length'] = str(len(session_sim.prepared_request['data']))
				session_sim.prepared_request['headers']['Referer'] = build_get_url('https://accounts.zalando.com/authenticate', session_sim.mem['get_url_data'])
				session_sim.prepared_request['headers']['x-flow-id'] = session_sim.mem['x-flow-id']
				session_sim.prepared_request['headers']['x-csrf-token'] = session_sim.mem['csrf-token']
				print_json(session_sim.prepared_request)
			case _:
				pass
	# runs after the request is sent
	else:
		match i:
			case 2:
				base_url, params = deconstruct_get_url(session_sim.response.headers['location'])
				session_sim.mem['get_url_data'] = {}
				transfer_json_data(params, session_sim.mem['get_url_data'], force=True)
			case 3:
				sel = Selector(session_sim.response.content.decode('utf-8'))
				# data_props = json.loads(decode_url(sel.xpath('/html/body/div[1]/@data-props').get()))
				# data_translations = json.loads(decode_url(sel.xpath('/html/body/div[1]/@data-translations').get()))
				data_render_headers = json.loads(decode_url(sel.xpath('/html/body/div[1]/@data-render-headers').get()))
				# print_json(data_props)
				# print_json(data_translations)
				# print_json(data_render_headers)
				# session_sim.prepared_request['headers']['x-flow-id'] = data_render_headers['x-flow-id']
				session_sim.mem['x-flow-id'] = data_render_headers['x-flow-id']
				session_sim.mem['csrf-token'] = session_sim.cookie_manager.get_cookie('csrf-token')

				# transfer_json_data(data_props['request'], session_sim.mem['get_url_data'], value_action=lambda value: value[0], force=True)
				# session_sim.mem['get_url_data']['request_id'] = data_props['compromisedCheckPayload']['request_id'][0]
				pass
			case _:
				pass

# os.system('clear')

session_sim = SessionSim()

# simulate login
session_sim.critical_function = zalando_function
session_sim.load_har('simple.har')

session_sim.sim(0) # login page
session_sim.sim(1) # login page redirection
session_sim.sim(2) # login page redirection
session_sim.sim(3) # login page response

session_sim.sim(4) # bullshit
session_sim.sim(5) # bullshit

session_sim.sim(6) # update ak_bmsc cookie

session_sim.sim(7) # bullshit

session_sim.sim(8) # update _abck cookie

session_sim.sim(9) # credentials check
session_sim.sim(10) # login schema

session_sim.sim(11) # login