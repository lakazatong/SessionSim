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
				# session_sim.headers['x-csrf-token'] = session_sim.cookie_manager.cookies['csrf-token']['value']
				# cprint(json.dumps(session_sim.rq, indent=3), CYAN)
				pass
			case 158:
				zalando_client_id = session_sim.cookie_manager.get_cookie('zalando-client-id')
				session_sim.rq['url'] = f'https://accounts.zalando.com/authenticate?redirect_uri=https://www.zalando.fr/sso/callback&client_id=fashion-store-web&response_type=code&scope=openid&request_id=oVVH8RLALfs%20ROHv:{zalando_client_id}:d3uF5dvfb2JSmO-X&nonce=99787c27-50f5-4a6c-89a5-73340402f5dd&state=eyJvcmlnaW5hbF9yZXF1ZXN0X3VyaSI6Imh0dHBzOi8vd3d3LnphbGFuZG8uZnIvYXNpY3MtZ2VsLWNoYWxsZW5nZXItMTMtY2hhdXNzdXJlcy1kZS10ZW5uaXMtdG91dGVzLXN1cmZhY2VzLXN0ZWVsLWJsdWV3aGl0ZS1hczE0MmEwdTctazEyLmh0bWwiLCJ0cyI6IjIwMjMtMDUtMTdUMTY6NTE6MTZaIn0=&passwordMeterFT=true&ui_locales=fr-FR&zalando_client_id={zalando_client_id}&sales_channel=733af55a-4133-4d7c-b5f3-d64d42c135fe&client_country=FR&client_category=fs'
			case _:
				pass
	# runs after the request is sent
	else:
		match i:
			case 1:
				pass
			case 2:
				# session_sim.headers['x-flow-id'] = json.loads( decode_url(Selector(session_sim.response.content.decode('utf-8')).xpath('/html/body/div[1]/@data-render-headers').get()) )['x-flow-id']
				pass
			case 3:
				pass
			case 4:
				pass
			case 156:
				location = session_sim.response.headers['location']
				print(location)
			case _:
				pass


user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0"

# os.system('clear')

session_sim = SessionSim()

# simulate login

session_sim.critical_function = zalando_function
session_sim.load_har('zalando.har')
session_sim.sim(0)
session_sim.sim(41)
session_sim.sim(175)
session_sim.sim(156)
session_sim.sim(158)
session_sim.sim(176)
session_sim.sim(341)



cprint('-'*100+'\n', YELLOW)

# final cookies
# session_sim.cookie_manager.print_cookies()

exit(0)

# random old stuff

# (jsplus cmt jlai trouve, il a l'air permanent comme zalando_client_id)
# client_id = '5bc6d482-5c1a-4a57-9c64-4ba6fc2a9ff4'
# (expire en 2025 askip)
# zalando_client_id = '907f8924-89c6-4c94-909a-67d2bdf8116e'