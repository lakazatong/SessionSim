import requests, copy, itertools, shutil, zlib
try:
	import brotli
except:
	os.system('pip install brotli')
	import brotli
from funcs import *

class CookieManager:
	# parses : response.headers['Set-Cookie'] <class 'str'>

	cookies_keys = []
	cookies_params_keys = ['Path', 'path', 'Secure', 'secure', 'SameSite', 'samesite', 'Domain', 'domain', 'Expires', 'expires', 'Max-Age', 'max-age', 'HttpOnly', 'httponly', 'Priority', 'priority']
	cookies = {}
	tmp_cookies = {}

	def _get_value(self, cookies, key, end_tokens):
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
		cookie_value, cookies = self._get_value(cookies, cookie_key+'=', [',', ';'])
		return True, (cookie_key, cookie_value), cookies
	def _get_param(self, param_key, cookies):
		param_value, cookies = self._get_value(cookies, param_key, [';', ',']) if (param_key != 'Expires' and param_key != 'expires') else self._get_value(cookies, param_key, [';'])
		return False, (param_key, param_value[1:] if param_value != '' else True), cookies

	def _get_next_pair(self, cookies):
		# a opti
		cookie_index, cookie_key = get_next_key(cookies, self.cookies_keys)
		param_index, param_key = get_next_key(cookies, self.cookies_params_keys)
		old_cookies = copy.deepcopy(cookies)
		if cookie_index == -1:
			# no more cookie key, next param should be at 0
			if param_index == 0:
				r = self._get_param(param_key, cookies)
			# new cookie key, let _parse_cookies handle it
			else:
				return False, (None, None), cookies, True
		else:
			if param_index == -1: 
				r = self._get_cookie(cookie_key, cookies)
			elif cookie_index < param_index:
				r = self._get_cookie(cookie_key, cookies)
			else: 
				r = self._get_param(param_key, cookies)
		return *r, False

	def parse_key(self, cookies):
		return 

	def _parse_cookies(self, cookies, cur_cookie_key, tmp_cookies):
		# print(cookies)
		# print()
		if cookies == '': return ''
		old_cookies = copy.deepcopy(cookies)
		is_cookie, pair, cookies, new_cookie = self._get_next_pair(cookies)

		if new_cookie:
			# add new key found
			self.cookies_keys.append(old_cookies[:old_cookies.find('=')])
			# try again
			self._parse_cookies(old_cookies, '', tmp_cookies)
		elif is_cookie:
			tmp_cookies[pair[0]] = {}
			tmp_cookies[pair[0]]['value'] = pair[1]
			self._parse_cookies(cookies, pair[0], tmp_cookies)
		elif cur_cookie_key != '':
			tmp_cookies[cur_cookie_key][pair[0]] = pair[1]
			self._parse_cookies(cookies, cur_cookie_key, tmp_cookies)
		else:
			cprint('impossible case reached?', RED)
			
		return tmp_cookies

	def update_cookies(self, cookies, always_replace=False):
		tmp_cookies = {}
		tmp_cookies = self._parse_cookies(cookies, '', tmp_cookies)
		for cookie_key, cookie_params in tmp_cookies.items():
			# Expires is set to Session if no Expire param is provided
			if not ('Expires' in cookie_params or 'expires' in cookie_params):
				tmp_cookies[cookie_key]['Expires'] = 'Session'
			if not 'Size' in cookie_params:
				tmp_cookies[cookie_key]['Size'] = str(len(cookie_params['value'])+len(cookie_key))
			# if not 'HttpOnly' in cookie_params:
			# 	tmp_cookies[cookie_key]['HttpOnly'] = self.is_http_only[cookie_key]

			# existing cookie and is not expired
			if not always_replace and cookie_key in self.cookies and (('Expires' in tmp_cookies[cookie_key] and tmp_cookies[cookie_key]['Expires'] != 'Session') or ('expires' in tmp_cookies[cookie_key] and tmp_cookies[cookie_key]['expires'] != 'Session')) and (('Expires' in self.cookies[cookie_key] and convert_to_unix_time(self.cookies[cookie_key]['Expires']) > time.time()) or ('expires' in self.cookies[cookie_key] and convert_to_unix_time(self.cookies[cookie_key]['expires']) > time.time())):
				continue
			# else either always_replace, new cookie, session cookie, or expired cookie, then add/replace it
			if not cookie_key in self.cookies:
				if self.debug_mode: cprint('new cookie : ' + cookie_key, PURPLE)
				self.cookies[cookie_key] = {}
				transfer_json_data(cookie_params, self.cookies[cookie_key], force=True)
			# known cookie, notify if modified
			else:
				old_cookie = copy.copy(self.cookies[cookie_key])
				transfer_json_data(cookie_params, self.cookies[cookie_key])
				if self.debug_mode and self.cookies[cookie_key] != old_cookie:
					cprint('updated cookie : ' + cookie_key, PURPLE)
		if self.debug_mode: print()

	def load_cookies_keys(self, full_path):#, folder='', filename=''):
		if os.path.exists(full_path):
			with open(full_path, 'r') as f:
				for key in json.loads(f.read()):
					if not key in self.cookies_keys:
						self.cookies_keys.append(key)

	def __init__(self, full_path='', cookies='', debug_mode=True):
		if full_path != '':
			self.load_cookies_keys(full_path)
		if cookies != '':
			self.update_cookies(cookies)
		# prints bunch of stuff for debugging
		self.debug_mode = debug_mode

	def print_cookie(self, key, color=WHITE):
		if key in self.cookies:
			cprint(self.cookies[key], color)
		else:
			cprint(key+' cookie unknown', RED)

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
		# self.cookies[key]['HttpOnly'] = self.is_http_only[key]
		self.cookies[key]['Size'] = str(len(value)+len(key))
		cprint('new cookie : ' + key, PURPLE)

	def get_cookie(self, key):
		return self.cookies[key]['value'] if key in self.cookies else None

	def save_cookies_keys(self, full_path):#, folder='', filename=''):
		combined_cookies_keys = []
		if os.path.exists(full_path):
			with open(full_path, 'r') as f:
				combined_cookies_keys.extend(json.loads(f.read()))
		for key in self.cookies_keys:
			if key not in combined_cookies_keys:
				combined_cookies_keys.append(key)
		with open(full_path, 'w+') as f:
			f.write(json.dumps(combined_cookies_keys, indent=3))

	def load_snek_cookies(self, cookies):
		for cookie in cookies:
			self.cookies[cookie['name']] = {}
			for key, value in cookie.items():
				if key != 'name':
					self.cookies[cookie['name']][key] = value



class CustomResponse(requests.Response):
	def __init__(self, response):
		super().__init__()
		self.__dict__ = response.__dict__
	def items(self):
		for attr, value in self.__dict__.items():
			yield attr, value
	def print_all_attributes(self):
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

	# copy of the current har request in the har file
	request = {}
	# list of har formated requests to simulate
	request_list = []
	nb_requests = -1
	# indent of saved json formatted responses
	saved_responses_indent = 3
	
	previous_response = None

	# use this to cache information during the session
	mem = {}

	def load_har(self, har):
		self.har_filename = har
		# load har file
		if os.path.exists(har):
			with open(har, 'rb') as f:
				self.request_list = json.loads(f.read().decode('utf-8'))['log']['entries']
				if self.nb_requests == -1:
					n = len(self.request_list)
					self.nb_requests = n
					self.nb_digits = len(str(n))
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
		method = self.request['method']
		filename = f'{self.code}_{method}'
		index = (self.nb_digits - len(str(self.index)))*'0'+str(self.index)
		full_path = f'{self.wd}/{self.folder}/{index}_{filename}'
		if self.debug_mode: print(f'writing to {full_path}...', end='')

		headers = {}
		for key, value in r.headers.items():
			headers[key] = value
		saved_response = {
			# "_content": r._content.decode('utf-8'),
			"_content_consumed": str(r._content_consumed),
			"_next": str(r._next),
			"status_code": str(r.status_code),
			"headers": headers,
			"url": str(r.url),
			"encoding": str(r.encoding),
			"history": str(r.history),
			"reason": str(r.reason),
			"elapsed": str(r.elapsed)
		}

		with open(full_path, 'w+') as f:
			f.write(json.dumps(saved_response, indent=self.saved_responses_indent))
		if r._content != b'':
			
			# decode

			content_encoding = None
			content_encoding_in_headers = True
			if 'Content-Encoding' in headers: content_encoding = 'Content-Encoding'
			elif 'content-encoding' in headers: content_encoding = 'content-encoding'
			else: content_encoding_in_headers = False

			if content_encoding in headers:
				if 'gzip' in headers[content_encoding] or 'compress' in headers[content_encoding] or 'deflate' in headers[content_encoding]:
					content = zlib.decompress(r._content)
				elif 'br' in headers[content_encoding]:
					# content = brotli.decompress(r._content) fails :c
					content = r._content.decode('utf-8', 'ignore')
			else:
				content = r._content.decode('utf-8', 'ignore')

			# format and write

			# f.write(json.dumps(json.loads(r._content.decode('utf-8')), indent=self.saved_responses_indent))
			
			content_type = None
			content_type_in_headers = True
			if 'Content-Type' in headers: content_type = 'Content-Type'
			elif 'content-type' in headers: content_type = 'content-type'
			else: content_type_in_headers = False

			if content_type_in_headers:
				if 'text/plain' in headers[content_type]:
					with open(full_path+'_content', 'w+') as f:
						f.write(content)
				elif 'text/html' in headers[content_type]:
					with open(full_path+'_content.html', 'w+') as f:
						f.write(BeautifulSoup(content, 'html.parser').prettify(indent_width=self.saved_responses_indent))
				elif 'application/json' in headers[content_type]:
					with open(full_path+'_content.json', 'w+') as f:
						f.write(json.dumps(json.loads(content), indent=self.saved_responses_indent))
				elif 'application/x-www-form-urlencoded' in headers[content_type]:
					with open(full_path+'_content', 'w+') as f:
						f.write(decode_url(content))
			else:
				with open(full_path+'_content', 'w+') as f:
					f.write(content)
		if self.debug_mode: print(' done')

	def __init__(self, headers={}, cookies='', save_responses=True, critical_function=None, wd=None, allow_redirects=False, timeout=10, debug_mode=True):
		# currently used headers throughout a simulation
		self.request['headers'] = headers
		# manages the cookies of the session
		self.cookie_manager = CookieManager(cookies, debug_mode=debug_mode)
		# saves requests' responses that sent back ressources
		self.save_responses = save_responses
		# function for critical cases to be handled manually
		self.critical_function = critical_function
		# working directory
		self.wd = os.getcwd() if wd == None else wd

		self.allow_redirects = allow_redirects
		self.timeout = timeout

		# prints bunch of stuff for debugging
		self.debug_mode = debug_mode

	def prepare_post_request(self):
		is_json = False
		data_type = 'text/plain;charset=UTF-8'
		
		content_type = None
		content_type_in_headers = True
		if 'Content-Type' in self.har_request['headers']: content_type = 'Content-Type'
		elif 'content-type' in self.har_request['headers']: content_type = 'content-type'
		else: content_type_in_headers = False

		if content_type_in_headers:
			data_type = self.har_request['headers'][content_type]
			is_json = data_type == 'application/json'
		elif 'mimeType' in self.har_request['postData']:
			data_type = self.har_request['postData']['mimeType']
			is_json = data_type == 'application/json'
		else:
			cprint(f'could not determine type of postData, setting it to "{data_type}" by default\
				(the prepared request can be modified and is accessible at self.prepared_request)', RED)
		data = self.request['postData']['text']
		return data_type, data

	def prepare_get_request(self):
		if self.previous_response == None: return
	 	
	 	# check for redirections
		# if self.previous_response.content != b'' and self.previous_response.content.startswith(bytes(self.base_url)):
		# 	cprint('following url in previous response content', YELLOW)
		# 	self.request['url'] = self.previous_response['content']['text']
		# if 'redirectURL' in self.previous_response:
		# 	cprint('following redirectURL in previous response', YELLOW)
		# 	if self.previous_response['redirectURL'].startswith(self.base_url):
		# 		self.request['url'] = self.previous_response['redirectURL']
		# 	else:
		# 		self.request['url'] = self.base_url+self.previous_response['redirectURL']
		# if 'location' in self.previous_response.headers:
		# 	cprint('following location in previous response headers', YELLOW)
		# 	if self.previous_response.headers['location'].startswith(self.base_url):
		# 		self.request['url'] = self.previous_response.headers['location']
		# 	else:
		# 		self.request['url'] = self.base_url+self.previous_response.headers['location']

		# keep track of referer only if previous response was not a redirection ?
		if self.previous_response.status_code < 300 and self.previous_response.status_code >= 400:
			self.request['headers']['Referer'] = self.previous_request['url']

	def prepare_request(self):
		data_type, data = "", ""
		method = self.request['method']
		if method == 'POST':
			data_type, data = self.prepare_post_request()
		elif method == 'GET':
			self.prepare_get_request()
		else:
			cprint(f'{method} method not supported, set it to "GET" request by default\n(the prepared request can be modified and is accessible at self.prepared_request)', RED)
			method = 'GET'
		# json representation of the request that will be made and an be modified
		url = self.request['url']
		headers = self.request['headers']
		cookies = self.request['cookies']
		params = har_to_json(self.request['queryString'])
		self.prepared_request = {
			"method": method,
			"url": url,
			"headers": headers,
			"cookies": cookies,
			"params": params,
			"data_type": data_type,
			"data": data
		}
		def send_request():
			return CustomResponse(requests.request(self.prepared_request['method'], self.prepared_request['url'], headers=self.prepared_request['headers'], cookies=self.prepared_request['cookies'], params=self.prepared_request['params'], data=self.prepared_request['data'], allow_redirects=self.allow_redirects, timeout=(self.timeout, self.timeout)))
		self.send_request = send_request

	def report_error(self):
		if self.debug_mode:
			method, url = self.prepared_request['method'], self.prepared_request['url']
			cprint(f'({self.index}) {self.code} | {method} | {url}\n', RED)

	def response_ok(self):
		if self.debug_mode:
			method, url = self.prepared_request['method'], self.prepared_request['url']
			cprint(f'({self.index}) {self.code} | {method} | {url}\n', GREEN)
		if self.save_responses:
			self.save_response()

	def response_client_error(self):
		self.report_error()

	def response_server_error(self, max_retries):
		k = 0
		# retry
		while self.response.status_code >= 500 and k < max_retries:
			time.sleep(0.5)
			self.response = self.send_request()
			self.code = str(self.response.status_code)+'_'+requests.status_codes._codes[self.response.status_code][0]
			k += 1
		# success
		if self.response.status_code < 400:
			self.response_ok()
		# failed
		elif self.response.status_code >= 400:
			self.report_error()
		# request was initially good
		else:
			cprint(f'??? impossible case reached, status code was {self.code}\n', RED)

	def make_request_from_HAR(self, max_retries=3):
		# create and send the request
		self.prepare_request()
		self.critical_function(self, self.index, before=True)
		self.response = self.send_request()
		# only consider first response
		# if self.response.history != []:
		# 	cprint(f'response history non empty ({len(self.response.history)})', YELLOW)
		# 	for i in range(len(self.response.history)):
		# 		if 'Set-Cookie' in self.response.history[i].headers: self.cookie_manager.update_cookies(self.response.history[i].headers['Set-Cookie'])
		# 		if 'set-cookie' in self.response.history[i].headers: self.cookie_manager.update_cookies(self.response.history[i].headers['set-cookie'])
		# 	self.response = self.response.history[0]
		self.code = str(self.response.status_code)+'_'+requests.status_codes._codes[self.response.status_code][0]
		# good
		if self.response.status_code < 400:
			self.response_ok()
		# server error
		elif self.response.status_code >= 500:
			self.response_server_error(max_retries)
		# client error
		else:
			self.response_client_error()

	def get_required_cookies(self):
		self.request['headers']['Cookie'] = ''
		self.request['cookies'] = {}
		if self.cookie_manager.cookies == {}: return
		for cookie in self.har_request['cookies']:
			key = cookie['name']
			if key in self.cookie_manager.cookies_keys:
				value = self.cookie_manager.get_cookie(key)
				if value != None:
					self.request['headers']['Cookie'] += f'{key}={value}; '
					self.request['cookies'][key] = value
				elif self.debug_mode:
					cprint('missing cookie : '+key, RED)
			elif self.debug_mode:
				cprint('unknown cookie : '+key, RED)
		self.request['headers']['Cookie'].strip()
		if self.request['headers']['Cookie'] != '': self.request['headers']['Cookie'] = self.request['headers']['Cookie'][:-2]
		# self.request['headers']['Cookie'] = self.cookie_manager.get_cookies(as_str=True)
		# self.request['cookies'] = self.cookie_manager.get_cookies()

	def run(self):
		# format headers
		self.request['headers'] = {}
		for key, value in har_to_json(self.har_request['headers']).items():
			self.request['headers'][key if key[0] != ':' else key[1:]] = value
		# get cookies
		self.get_required_cookies()
		# make request
		self.make_request_from_HAR()
		# update cookies
		if 'Set-Cookie' in self.response.headers: self.cookie_manager.update_cookies(self.response.headers['Set-Cookie'])
		if 'set-cookie' in self.response.headers: self.cookie_manager.update_cookies(self.response.headers['set-cookie'])
		self.critical_function(self, self.index, before=False)
		time.sleep(0.5)

	def sim(self, index, prompt=False):
		if self.debug_mode:	print('-'*shutil.get_terminal_size().columns)
		# init
		self.critical_function_check()
		self.folder = os.path.splitext(self.har_filename)[0]+'_single'
		self.manage_folder(True)
		# load request from har file
		if self.request_list == []:
			cprint(f'sim({index}): request list empty', RED)
			return
		if self.nb_requests != -1 and index < self.nb_requests:
			self.har_request = self.request_list[index]['request']
			self.request = copy.copy(self.har_request)
		else:
			cprint(f'sim({index}): out of range', RED)
			return
		self.index = index
		# run the request
		self.run()
		self.previous_response = self.response
		self.previous_har_request = self.har_request
		self.previous_request = self.request
		if prompt: input()
		if self.debug_mode: print('-'*shutil.get_terminal_size().columns)

	def _run_sim_with_filter(self, response_codes_filter):
		self.index = 0
		while self.index < self.nb_requests:
			if not int(self.request_list[self.index]['response']['status']) in response_codes_filter:
				self.index += 1
				continue
			if self.debug_mode: print('-'*shutil.get_terminal_size().columns)
			self.har_request = self.request_list[self.index]['request']
			self.request = copy.copy(self.har_request)
			self.run()
			self.index += 1
			self.previous_response = self.response
			self.previous_har_request = self.har_request
			self.previous_request = self.request
			if self.debug_mode: print('-'*shutil.get_terminal_size().columns)

	def _run_sim_with_indices_filter(self, indices, response_codes_filter):
		i = 0
		self.index = indices[i]
		while i < len(indices):
			if not int(self.request_list[self.index]['response']['status']) in response_codes_filter:
				i += 1
				self.index = indices[i]
				continue
			if self.debug_mode: print('-'*shutil.get_terminal_size().columns)
			self.har_request = self.request_list[self.index]['request']
			self.request = copy.copy(self.har_request)
			self.run()
			i += 1
			self.index = indices[i]
			self.previous_response = self.response
			self.previous_har_request = self.har_request
			self.previous_request = self.request
			if self.debug_mode: print('-'*shutil.get_terminal_size().columns)

	def _run_sim_with_indices(self, indices):
		i = 0
		self.index = indices[i]
		while i < len(indices):
			if self.debug_mode: print('-'*shutil.get_terminal_size().columns)
			self.har_request = self.request_list[self.index]['request']
			self.request = copy.copy(self.har_request)
			self.run()
			i += 1
			self.index = indices[i]
			self.previous_response = self.response
			self.previous_har_request = self.har_request
			self.previous_request = self.request
			if self.debug_mode: print('-'*shutil.get_terminal_size().columns)

	def _run_sim(self):
		self.index = 0
		while self.index < self.nb_requests:
			if self.debug_mode: print('-'*shutil.get_terminal_size().columns)
			self.har_request = self.request_list[self.index]['request']
			self.request = copy.copy(self.har_request)
			self.run()
			self.index += 1
			self.previous_response = self.response
			self.previous_har_request = self.har_request
			self.previous_request = self.request
			if self.debug_mode: print('-'*shutil.get_terminal_size().columns)

	def _run_sim_with_func(self, accept_function):
		self.index = 0
		while self.index < self.nb_requests:
			if not accept_function(self, self.index, self.request_list[self.index]['request'], self.request_list[self.index]['response']):
				self.index += 1
				continue
			if self.debug_mode: print('-'*shutil.get_terminal_size().columns)
			self.har_request = self.request_list[self.index]['request']
			self.request = copy.copy(self.har_request)
			self.run()
			self.index += 1
			self.previous_response = self.response
			self.previous_har_request = self.har_request
			self.previous_request = self.request
			if self.debug_mode: print('-'*shutil.get_terminal_size().columns)

	def run_sim(self, har, indices=[], response_codes_filter=[], accept_function=None):
		self.load_har(har)
		self.critical_function_check()
		self.folder = os.path.splitext(har)[0]+'_sim'
		self.manage_folder()

		if accept_function != None:
			self._run_sim_with_func(accept_function)
		else:
			if indices != []:
				if response_codes_filter != []:
					self._run_sim_with_indices_filter(indices, response_codes_filter)
				else:
					self._run_sim_with_indices(indices)
			else:
				if response_codes_filter != []:
					self._run_sim_with_filter(response_codes_filter)
				else:
					self._run_sim()

		

	def print_cookies(self):
		self.cookie_manager.print_cookies()