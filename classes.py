import requests, copy, itertools
from funcs import *

class CookieManager:
	# parses : response.headers['Set-Cookie'] <class 'str'>

	cookies_keys = ['csrf-token', '_abck', 'ak_bmsc', 'bm_mi', 'bm_sz', 'bm_sv', 'frsx', 'zalando-client-id', 'fvgs_ml', 'mpulseinject', 'zsn', 'zss', 'zsr', 'zsa', '5572cbed-2524-4e11-b0f1-f574f1d2ccb1']
	cookies_params_keys = ['path', 'secure', 'samesite', 'domain', 'expires', 'max-age', 'httponly']
	is_http_only = {
		"csrf-token": False,
		"_abck": False,
		"ak_bmsc": True,
		"bm_mi": False,
		"bm_sz": False,
		"bm_sv": False,
		"frsx": False,
		"zalando-client-id": True,
		"fvgs_ml": False,
		"mpulseinject": False,
		"zsn": True,
		"zss": True,
		"zsr": True,
		"zsa": True,
		"5572cbed-2524-4e11-b0f1-f574f1d2ccb1": True
	}
	cookies = {}
	tmp_cookies = {}

	def get_value(self, cookies, key, end_tokens):
		start = cookies.find(key)+len(key)
		ends = []
		for end_token in end_tokens:
			token_index = cookies[start:].find(end_token)
			if token_index != -1:
				ends.append(token_index+len(cookies[:start]))
		end = min(ends) if ends != [] else len(cookies)
		value = cookies[start:end]
		cookies = cookies[end+1:].strip()
		return value, cookies

	def _get_cookie(self, cookie_key, cookies):
		cookie_value, cookies = self.get_value(cookies, cookie_key+'=', [',', ';'])
		return True, (cookie_key, cookie_value), cookies
	def get_param(self, param_key, cookies):
		param_value, cookies = self.get_value(cookies, param_key, [';', ',']) if param_key != 'Expires' else self.get_value(cookies, param_key, [';'])
		return False, (param_key, param_value[1:] if param_value != '' else True), cookies

	def get_next_pair(self, cookies):
		# a opti
		cookie_index, cookie_key = get_next_key(cookies, self.cookies_keys)
		param_index, param_key = get_next_key(cookies, self.cookies_params_keys)
		old_cookies = copy.deepcopy(cookies)
		if cookie_index == -1:
			if param_index == -1:
				cprint('no more pair found in the keys provided', RED)
				print('cookies were:\n' + old_cookies)
				exit(1)
			else: 
				pair = self.get_param(param_key, cookies)
		else:
			if param_index == -1: 
				pair = self._get_cookie(cookie_key, cookies)
			elif cookie_index < param_index:
				pair = self._get_cookie(cookie_key, cookies)
			else: 
				pair = self.get_param(param_key, cookies)
		return pair

	def parse_cookies(self, cookies, cur_cookie_key, tmp_cookies):
		if cookies == '':
			return tmp_cookies
		old_cookies = cookies
		is_cookie, pair, cookies = self.get_next_pair(cookies)
		# print('next is:\n'+str(pair))
		# print()
		# print('new cookies:\n'+cookies)
		# print('\n')
		if is_cookie:
			tmp_cookies[pair[0]] = {}
			tmp_cookies[pair[0]]['value'] = pair[1]
			self.parse_cookies(cookies, pair[0], tmp_cookies)
		elif cur_cookie_key != '':
			tmp_cookies[cur_cookie_key][pair[0]] = pair[1]
			self.parse_cookies(cookies, cur_cookie_key, tmp_cookies)
		else:
			cprint('cookies started with a cookie param? ' + str(pair), RED)
			print('cookies were:\n' + old_cookies + '\n')
			exit(1)
		return tmp_cookies

	def update_cookies(self, cookies, always_replace=False):
		tmp_cookies = {}
		tmp_cookies = self.parse_cookies(cookies, '', tmp_cookies)
		for cookie_key, cookie_params in tmp_cookies.items():
			# Expires is set to Session if no Expire param is provided
			if not 'Expires' in cookie_params:
				tmp_cookies[cookie_key]['Expires'] = 'Session'
			if not 'Size' in cookie_params:
				tmp_cookies[cookie_key]['Size'] = str(len(cookie_params['value'])+len(cookie_key))
			if not 'HttpOnly' in cookie_params:
				tmp_cookies[cookie_key]['HttpOnly'] = self.is_http_only[cookie_key]

			# existing cookie and is not expired
			if not always_replace and cookie_key in self.cookies and tmp_cookies[cookie_key]['Expires'] != 'Session' and convert_to_unix_time(self.cookies[cookie_key]['Expires']) > time.time():
				continue
			# else either always_replace, new cookie, session cookie, or expired cookie, then add/replace it
			if not cookie_key in self.cookies:
				cprint('new cookie : ' + cookie_key, PURPLE)
				self.cookies[cookie_key] = {}
			# print('updating cookie : ' + cookie_key)
			for param_key, param_value in cookie_params.items():
				self.cookies[cookie_key][param_key] = param_value
		print()

	def __init__(self, cookies=''):
		if cookies != '':
			self.update_cookies(cookies)

	def print_cookies(self, indent=3):
		print('CookieManager\'s cookies:')
		print(json.dumps(self.cookies, indent=indent))

	def get_cookies(self, as_str=False):
		if as_str:
			cookies = ''
			for key, params in self.cookies.items():
				value = params['value']
				cookies += f'{key}={value}; '
			cookies.strip()
			if cookies != '':
				cookies = cookies[:-2]
			return cookies
		else:
			cookies = {}
			for key, params in self.cookies.items():
				cookies[key] = params['value']
			return cookies

	def add_cookie(self, key, value):
		self.cookies[key] = {}
		self.cookies[key]['value'] = value
		self.cookies[key]['HttpOnly'] = self.is_http_only[key]
		self.cookies[key]['Size'] = str(len(value)+len(key))

	def get_cookie(self, key):
		return self.cookies[key]['value']

class CustomResponse(requests.Response):
	def __init__(self, response):
		super().__init__()
		self.__dict__ = response.__dict__
	def items(self):
		for attr, value in self.__dict__.items():
			yield attr, value
	def print_all_attrib(self):
		for attr, value in self.items():
			print(f'{attr} = {value}\n\n')

'''
status codes

	Informational responses (100 – 199)
	Successful responses (200 – 299)
	Redirection messages (300 – 399)
	Client error responses (400 – 499)
	Server error responses (500 – 599)

'''

class SessionSim:

	# list of har formated requests to simulate
	rq_list = []
	nb_requests = -1
	saved_responses_indent = 3

	def load_har(self, har):
		self.har = har
		# load har file
		if os.path.exists(har):
			with open(har, 'rb') as f:
				self.rq_list = json.loads(f.read().decode('utf-8'))['log']['entries']
				if self.nb_requests == -1: self.nb_requests = len(self.rq_list)
		else:
			cprint(f'{har} was not found', RED)

	def manage_folder(self, single=False):
		if not single:
			os.system('rm -rf ' + self.folder)
		if not os.path.exists(self.folder):
			os.system('mkdir ' + self.folder)

	def critical_function_check(self):
		# check for critical function
		if self.critical_function == None:
			cprint(f'must provide a critical_function(i, {self.__class__.__name__}, before=True) function that must:\n\tmodify this class when encountering the ith url according to the before argument\n\nbase code:\n\ndef critical_function(i, session_sim, before=True):\n\t# i is the ith request in the har file (the first is the 0th)\n\t# runs before the request is sent\n\tif before:\n\t\tmatch i:\n\t\t\tcase 1:\n\t\t\t\tpass\t\n\t\t\tcase 3:\n\t\t\t\tpass\n\t\t\tcase 12:\n\t\t\t\tpass\n\t\t\tcase _:\n\t\t\t\tpass\n\t# runs after the request is sent\n\telse:\n\t\tmatch i:\n\t\t\tcase 1:\n\t\t\t\tpass\n\t\t\tcase 3:\n\t\t\t\tpass\n\t\t\tcase 12:\n\t\t\t\tpass\n\t\t\tcase _:\n\t\t\t\tpass\n\n', RED)

	def save_response(self):
		r = self.response
		filename = f'{self.code}_{self.method}'
		full_path = f'{self.wd}/{self.folder}/{self.index}_{filename}'
		print(f'writing to {full_path}...', end='')

		# self.response.print_all_attrib()
		# exit(0)

		# r = self.response
		# headers = {}
		# for key, value in r.headers.items():
		# 	headers[key] = value
		# saved_response = {
		# 	"_content": r._content,
		# 	"_content_consumed": r._content_consumed,
		# 	"_next": r._next,
		# 	"status_code": r.status_code,
		# 	"headers": headers,
		# 	"url": r.url,
		# 	"encoding": r.encoding,
		# 	"history": r.history,
		# 	"reason": r.reason,
		# 	"elapsed": str(r.elapsed)
		# }

		# with open(full_path, 'wb+') as f:
		# 	f.write(json.dumps(saved_response))
		print(' done')
		

	def __init__(self, headers={}, cookies='', save_responses=True, critical_function=None, website='', wd=None):
		# currently used headers throughout a simulation
		self.headers = headers
		# manages the cookies of the session
		self.cookie_manager = CookieManager(cookies)
		# saves requests' responses that sent back ressources
		self.save_responses = save_responses
		# function for critical cases to be handled manually
		self.critical_function = critical_function
		# website to simulate login
		self.website = website
		# working directory
		self.wd = os.getcwd() if wd == None else wd

	def create_request(self):
		def custom_request():
			if self.rq['method'] == 'POST':
				if type(self.rq['postData']) is dict:
					self.response = requests.request('POST', self.rq['url'], headers=self.headers, params=har_to_json(self.rq['queryString']), json=self.rq['postData'], allow_redirects=False)
				else:
					self.response = requests.request('POST', self.rq['url'], headers=self.headers, params=har_to_json(self.rq['queryString']), data=self.rq['postData'], allow_redirects=False)
			else:

				# if self.previous_response != None:
				# 	self.previous_response.print_all_attrib()
				# 	if self.previous_response.content != b'' and self.previous_response.content.startswith(b'https://accounts.zalando.com/'):
				# 		self.rq['url'] = self.previous_response['content']['text']
				# 	# if 'redirectURL' in self.previous_response:
				# 		# self.rq['url'] = 'https://accounts.zalando.com'+self.previous_response['redirectURL']

				self.response = requests.request('GET', self.rq['url'], headers=self.headers, params=har_to_json(self.rq['queryString']), allow_redirects=False)
			return CustomResponse(self.response)
		return custom_request

	def report_error(self):
		
		cprint(f'({self.index}) {self.code} | {self.method} | {self.url}\n', RED)
		# cprint('request headers were:\n', RED)
		# print(json.dumps(self.headers, indent=3))

	def response_ok(self):
		cprint(f'({self.index}) {self.code} | {self.method} | {self.url}\n', GREEN)
		if self.save_responses:
			self.save_response()

	def response_client_error(self):
		self.report_error()

	def response_server_error(self, custom_request, max_retries):
		k = 0
		# retry
		while self.response.status_code >= 500 and k < max_retries:
			time.sleep(0.5)
			self.response = custom_request()
			self.code = str(self.response.status_code)+'_'+requests.status_codes._codes[self.response.status_code][0]
			k += 1
		# success
		if self.response.status_code < 400:
			response_ok()
		# failed
		elif self.response.status_code >= 500:
			self.report_error()
		# request was initially good
		else:
			cprint('??? impossible case reached\n', RED)

	def make_request_from_HAR(self, max_retries=3):
		# create and send the request
		custom_request = self.create_request()
		self.response = custom_request()
		self.code = str(self.response.status_code)+'_'+requests.status_codes._codes[self.response.status_code][0]
		# only consider first response
		if self.response.history != []: self.response = self.response.history[0]
		# good
		if self.response.status_code < 400:
			self.response_ok()
		# server error
		elif self.response.status_code >= 500:
			self.response_server_error(custom_request, max_retries)
		# client error
		else:
			self.response_client_error()

	def run(self):
		self.method = self.rq['method']
		self.url = self.rq['url'].strip()
		# build headers
		for key, value in har_to_json(self.rq['headers']).items():
			self.headers[key if key[0] != ':' else key[1:]] = value
		if self.cookie_manager.cookies != {}:
			self.headers['Cookie'] = self.cookie_manager.get_cookies(as_str=True)
		# make request
		self.critical_function(self.index, self, before=True)
		self.make_request_from_HAR()
		self.critical_function(self.index, self, before=False)
		# update cookies
		if 'Set-Cookie' in self.response.headers: self.cookie_manager.update_cookies(self.response.headers['Set-Cookie'])
		time.sleep(0.5)

	def sim(self, index):
		# init
		self.critical_function_check()
		self.folder = os.path.splitext(self.har)[0]+'_single'
		self.manage_folder(True)
		if self.rq_list == []:
			cprint(f'sim({index}): request list empty', RED)
			return
		if self.nb_requests != -1 and index < self.nb_requests:
			self.rq = self.rq_list[index]['request']
		else:
			cprint(f'sim({index}): out of range', RED)
			return
		self.index = index
		self.run()

	def run_sim(self, har):
		# init
		self.load_har(har)
		self.critical_function_check()
		# run sim
		self.folder = os.path.splitext(har)[0]+'_sim'
		self.manage_folder()
		self.index = 0
		self.previous_response = None
		while self.index < self.nb_requests:
			self.rq = self.rq_list[self.index]['request']
			self.run()
			self.index += 1
			self.previous_response = self.response
		# return last response
		return self.response

	def print_cookies(self):
		self.cookie_manager.print_cookies()