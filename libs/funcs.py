import os, time, inspect, json, urllib.parse, re, platform
from pprint import pprint
from datetime import datetime

try:
	from bs4 import BeautifulSoup
except:
	os.system('pip install beautifulsoup4')
	from bs4 import BeautifulSoup
try:
	from parsel import Selector
except:
	import os
	os.system('pip install parsel')
	from parsel import Selector

# make it work for windows?
BLACK, RED, GREEN, YELLOW, BLUE, PURPLE, CYAN, WHITE = 30, 31, 32, 33, 34, 35, 36, 37
def cprint(string, color_code=30, end='\n'):
	print(f"\033[{color_code}m{string}\033[0m", end=end)

def wget(url:str, output_filename:str=None, output_dir:str=None, show_progress:bool=True, quiet:bool=True, auth:tuple[str, str]=None, headers:dict=None, print_cmd:bool=False):
	output_opt = f'-O "{output_filename}"' if output_filename != None else ''
	progress_opt = '--show-progress' if show_progress else ''
	quiet_opt = '-q' if quiet else ''
	auth_opt = f'--user "{auth[0]}" --password "{auth[1]}"' if auth != None else ''
	header_opt = ' '.join([f'--header="{key}: {value}"' for key, value in headers.items()]) if headers != None else ''
	if platform.system() == 'Windows':
		cmd = f'wsl wget {quiet_opt} {progress_opt} {output_opt} {auth_opt} {header_opt} "{url}"'
	else:
		cmd = f'wget {quiet_opt} {progress_opt} {output_opt} {auth_opt} {header_opt} "{url}"'
	if print_cmd:
		if header_opt != '': header_opt = '--header=...'
		print(f'wget {quiet_opt} {progress_opt} {output_opt} {auth_opt} {header_opt} {url}')
	
	if output_dir != None:
		if os.path.exists(output_dir):
			os.system(f'cd "{output_dir}" && {cmd}')
		else:
			cprint(f'\ncould not wget "{url}" in "{output_dir}" because it does not exists', RED)
			return False
	else:
		os.system(cmd)

	if output_filename == None:
		output_filename = max(os.listdir(), key=os.path.getmtime)
	full_path = f'{output_dir}/{output_filename}' if output_dir != None else output_filename
	if os.path.exists(full_path):
		with open(full_path, 'rb') as f:
			if f.read() == b'':
				cprint(f'\nthis command:\n{cmd}\ndownloaded a file of 0 bytes', RED)
				return False
	else:
		cprint(f'\nthis command:\n{cmd}\nseemed to have failed', RED)
		return False
	return True

def har_to_json(har_headers):
	headers = {}
	for e in har_headers:
		headers[e['name']] = e['value']
	return headers

def get_attributes(obj):
	return [a for a in dir(obj) if not a.startswith('__') and not callable(getattr(obj, a))]

def print_var(var):
	callers_local_vars = inspect.currentframe().f_back.f_locals.items()
	pprint(str([k for k, v in callers_local_vars if v is var][0])+' = '+str(var), indent=3)
	print()

def print_all_attributes(obj):
	for attr, value in obj.__iter__():
		print(f'{attr} = {value}\n\n')

def print_all_items(obj):
	for key, value in obj.items():
		print(f'{key} = {value}\n\n')

def print_json(obj, indent=3):
	if type(obj) is str:
		obj = json.loads(obj)
	print(json.dumps(obj, indent=indent))

def convert_to_unix_time(date_string):
	# Define the input date format
	date_format = "%a, %d %b %Y %H:%M:%S %Z"
	parsed_date = datetime.strptime(date_string, date_format)
	unix_time = int(time.mktime(parsed_date.timetuple()))
	return unix_time

def get_next_key(string, keys):
	start_index = 0
	minimum_index = -1
	n = len(keys)
	if n > 0:
		minimum_index = string.find(keys[start_index])
	else:
		return -1, None
	while minimum_index == -1 and start_index < n-1:
		start_index += 1
		minimum_index = string.find(keys[start_index])
	if start_index == n:
		return -1, None
	minimum_key = keys[start_index]
	if minimum_index > 0:
		for i in range(start_index+1, n):
			cur_index = string.find(keys[i])
			if cur_index < minimum_index and cur_index != -1:
				minimum_key = keys[i]
				minimum_index = cur_index
	return minimum_index, minimum_key

def decode_url(url):
	return urllib.parse.unquote(url)

def encode_url(url):
	return urllib.parse.quote(url)

def code_to_txt(code):
	return code.replace('	', '\\t').replace('''
''', '\\n')

def txt_to_code(code):
	code.replace('\\\\t', '\\t')
	code.replace('\\\\n', '\\n')
	return code.replace('\\t', '	').replace('\\n', '''
''')

def get_from_link(original_link, key):
	link = original_link
	index = link.find(key)
	if index == -1:	return None
	end = link[index+len(key):].find('&')

def build_get_url(base_url, params):
	url = base_url
	L = list(params.items())
	i = 0
	if i < len(L):
		url += f'?{L[i][0]}={L[i][1]}'
		i += 1
	else:
		return url
	while i < len(L):
		url += f'&{L[i][0]}={L[i][1]}'
		i += 1
	return url

def deconstruct_get_url(get_url):
	i = get_url.find('&')
	params = {}
	if i == -1:
		return get_url, params
	base_url = get_url[:i]
	get_url = get_url[i+1:]
	j = base_url.find('?')
	if j != -1:
		base_url_cpy = base_url
		base_url = base_url[:j]
		base_url_cpy = base_url_cpy[j+1:]
		j = base_url_cpy.find('=')
		params[base_url_cpy[:j]] = base_url_cpy[j+1:]
	while get_url != '':
		i = get_url.find('=')
		key = get_url[:i]
		get_url = get_url[i+1:]
		i = get_url.find('&')
		if i == -1: i = len(get_url)
		value = get_url[:i]
		get_url = get_url[i+1:]
		params[key] = value
	return base_url, params


def txt_headers_to_json_headers(txt, filters=[]):
	headers = {}
	lines = txt.split('\n')
	first = lines[0].split(' ')
	method, url, http = first[0].strip(), first[1].strip(), first[2].strip()
	if filters != []:
		for e in lines[1:]:
			semi_colon_index = e.find(':')
			left = e[:semi_colon_index].strip()
			if left in filters:
				headers[left] = e[semi_colon_index+1:].strip()
	else:
		for e in lines[1:]:
			semi_colon_index = e.find(':')
			left = e[:semi_colon_index].strip()
			headers[left] = e[semi_colon_index+1:].strip()
	return method, url, http, headers


def transfer_json_data(source, dest, keys=[], key_action=None, value_action=None, force=False):
	if key_action == None: key_action = lambda key: key
	if value_action == None: value_action = lambda value: value
	if force:
		if keys == []:
			for key, value in source.items():
				dest[ key_action(key) ] = value_action(value)
		else:
			for key, value in source.items():
				key = key_action(key)
				if key in keys:
					dest[ key ] = value_action(value)
	else:
		if keys == []:
			for key, value in source.items():
				key = key_action(key)
				if key in dest:
					dest[ key ] = key_action(value)
		else:
			for key, value in source.items():
				key = key_action(key)
				if key in dest and key in keys:
					dest[ key ] = value_action(value)

def split_path(path):
	return os.path.split(path)

# source : https://stackoverflow.com/a/15513483
orig_prettify = BeautifulSoup.prettify
r = re.compile(r'^(\s*)', re.MULTILINE)
def prettify(self, encoding=None, formatter="minimal", indent_width=4):
	return r.sub(r'\1' * indent_width, orig_prettify(self, encoding, formatter))
BeautifulSoup.prettify = prettify



# ------------------- old -------------------

def make_request_from_domain_and_headers(domain, headers, print_request=False, filters=[]):
	method, url, http, headers = txt_headers_to_json_headers(headers, filters=filters)
	url = 'https://'+domain+url
	if print_request:
		pretty_headers = json.dumps(headers, indent=3)
		print(f'\n\nrequests.request(\n\t{method},\n\t{url},\n\theaders={pretty_headers}\n)\n\n')
	response = requests.request(method, url, headers=headers)
	print(response.status_code)
	return response

def jsp():
	print_all = False
	i = 0
	for request in [(accounts_domain, r1), (accounts_domain, r2), (base_domain, r3)]:
		r = make_request_from_domain_and_headers(request[0], request[1], print_request=print_all)
		with open('r'+str(i), 'wb') as f:
			f.write(r.content)
		with open('r'+str(i)+'_headers', 'w') as f:
			f.write(json.dumps(dict(r.headers)))
		i += 1

def make_request_from_HAR(rq):
	headers = har_to_json(rq['headers'])
	cookies = har_to_json(rq['cookies'])
	# queryString = har_to_json(rq['queryString'])
	# print(json.dumps(headers, indent=3))
	# print('doing '+rq['url'])
	r = requests.request(rq['method'], rq['url'], headers=headers, cookies=cookies)
	# print(r.status_code, rq['url'], '\n')
	return r

def make_bunch_from_har(har, n, index=None):
	with open(har, 'rb') as f:
		content = json.loads(f.read().decode('utf-8'))
	if index == None:
		responses = []
		for i in range(n):
			responses.append(CustomResponse(make_request_from_HAR(content['log']['entries'][i]['request'])))
		return responses
	else:
		return CustomResponse(make_request_from_HAR(content['log']['entries'][index]['request']))