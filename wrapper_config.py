#coding: utf-8

# proxy types: http|https|socks4|socks5


DEBUG = True # False - without logs
#DEBUG = False # False - without logs
LOG_FILE = 'wrapper_session.log'

SQLMAP_DUMPS = 'dumps'
WRAPPER_TXT_DUMPS = 'txt_dumps'

URLS_FILE = 'sites.txt'
Check_List = True
PROXY = False # False if work without it
PROXY_TYPE = 'socks5'
PROXY_URL = '' # first
PROXY_FILE = '' # second if not first
PROXY_USERNAME = ''
PROXY_PASSWORD = ''
THREADS = 10
URLS_LIMIT = 10000000
DUMP_FOLDER = 'dumps'
DUMP_COLUMN_LIMIT = 20 # 91 - 100 ...
TIMEOUT = 240 # sec
RETRIES = 5

DELETE=True

RISK = 3
LEVEL = 5
