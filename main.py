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
			case 2:
				session_sim.prepared_request['params'] = {}
				session_sim.prepared_request['url'] = 'https://accounts.zalando.com'+session_sim.previous_response.headers['location']
			case 3:
				session_sim.prepared_request['params'] = {}
				session_sim.prepared_request['url'] = 'https://accounts.zalando.com'+session_sim.previous_response.headers['location']
			
			case 4:
				session_sim.prepared_request['url'] = session_sim.mem['bullshit_url']
			case 5:
				session_sim.prepared_request['url'] = session_sim.mem['bullshit_url']
			case 6:
				session_sim.prepared_request['url'] = session_sim.mem['bullshit_url']
			
			case 7:
				session_sim.prepared_request['url'] = session_sim.mem['pixel_url']
			
			case 8:
				session_sim.prepared_request['url'] = session_sim.mem['bullshit_url']
			case 9:
				session_sim.prepared_request['url'] = session_sim.mem['bullshit_url']

			case 10:
				session_sim.prepared_request['headers']['x-csrf-token'] = session_sim.mem['csrf-token']
				session_sim.prepared_request['headers']['x-flow-id'] = session_sim.mem['x-flow-id']
			case 12:
				data = json.loads(session_sim.prepared_request['data'])
				# transfer_json_data(session_sim.mem['get_url_data'], data['request'], key_action=lambda key:decode_url(key), value_action=lambda value:decode_url(value))
				transfer_json_data(session_sim.mem['get_url_data'], data['request'])
				session_sim.prepared_request['data'] = decode_url(json.dumps(data).strip().replace(' ', ''))
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
				url = split_path(sel.xpath('/html/head/script[2]/@src').get())
				session_sim.mem['pixel_url'] = url[0]+'/pixel_'+url[1]
				session_sim.mem['bullshit_url'] = 'https://accounts.zalando.com'+sel.xpath('/html/body/script[4]/@src').get()
			case _:
				pass

# os.system('clear')

session_sim = SessionSim()

# simulate login
session_sim.critical_function = zalando_function
session_sim.load_har('simple2.har')

session_sim.sim(0) # new cookies (login page)
session_sim.sim(1) # update cookies (login page redirection)
session_sim.sim(2) # new cookies (login page redirection)
session_sim.sim(3) # new cookies + x-flow-id (login page response)

session_sim.sim(10) # new cookie (credentials verification)

session_sim.sim(4) # (bullshit_url)
session_sim.sim(5) # (bullshit_url)
session_sim.sim(6) # (bullshit_url)

session_sim.sim(7) # update cookie (pixel_url)

session_sim.sim(8) # update cookie (bullshit_url)
session_sim.sim(9) # update cookie (bullshit_url)

session_sim.sim(11) # update cookie (login schema)

session_sim.sim(12) # new cookies (login) ---------- :c ----------