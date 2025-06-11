#!/usr/bin/env python3

import re
import os
import requests
import argparse
import concurrent.futures
import websocket
from urllib3.exceptions import InsecureRequestWarning
import urllib3

urllib3.disable_warnings(InsecureRequestWarning)

# Argument parser
parser = argparse.ArgumentParser(description="Hash Cracker Tool")
parser.add_argument('-s', '--single', help='Single hash')
parser.add_argument('-f', '--file', help='File containing hashes')
parser.add_argument('-d', '--dir', help='Directory to scan for hashes')
parser.add_argument('-t', '--threads', help='Number of threads', type=int, default=4)
args = parser.parse_args()

# Colors
red = '\033[91m'
green = '\033[92m'
yellow = '\033[93m'
white = '\033[97m'
info = f"{yellow}[!]\033[0m"
good = f"{green}[+]\033[0m"
bad = f"{red}[-]\033[0m"

print(f'''{white}
_  _ ____ ____ _  _    ___  _  _ ____ ___ ____ ____ 
|| || [__  ||    |] |  | [__   |  |___ |_/ |  | |  | 
] || ]  |  | |  \\     {red}v4.0\033[0m 
''')

# Utilities
results = {}
found_flag = False
found_value = ''

# Hash cracker backends
def beta(hashvalue, hashtype):
    try:
        url = "wss://md5hashing.net/sockjs/697/etstxji0/websocket"
        ws = websocket.create_connection(url, timeout=10)
        ws.send(r'["{\"msg\":\"connect\",\"version\":\"1\",\"support\":[\"1\",\"pre2\",\"pre1\"]}"]')
        method = r'[{{\"msg\":\"method\",\"method\":\"hash.get\",\"params\":[\"{0}\",\"{1}\"],\"id\":\"1\"}}]'.format(hashtype, hashvalue)
        ws.send(method)
        ws.recv()
        response = ws.recv()
        match = re.search(r'value\\\":\\\"([^\\]+)', response)
        if match:
            return match.group(1)
    except Exception as e:
        print(f"{bad} WebSocket error: {e}")
    return False

def gamma(hashvalue, hashtype):
    try:
        response = requests.get(f'https://www.nitrxgen.net/md5db/{hashvalue}', verify=False, timeout=10)
        if response.text:
            return response.text.strip()
    except Exception as e:
        print(f"{bad} Error with nitrxgen API: {e}")
    return False

def theta(hashvalue, hashtype):
    try:
        url = f'https://md5decrypt.net/Api/api.php?hash={hashvalue}&hash_type={hashtype}&email=noyile6983@lofiey.com&code=fa9e66f3c9e245d6'
        response = requests.get(url, timeout=10)
        if response.text:
            return response.text.strip()
    except Exception as e:
        print(f"{bad} Error with md5decrypt API: {e}")
    return False

# Backends by hash type
md5 = [beta, gamma, theta]
sha1 = [beta, theta]
sha256 = [beta, theta]
sha384 = [beta, theta]
sha512 = [beta, theta]

hash_algos = {
    32: ('MD5', md5),
    40: ('SHA1', sha1),
    64: ('SHA256', sha256),
    96: ('SHA384', sha384),
    128: ('SHA512', sha512),
}

def crack(hashvalue):
    algo_info = hash_algos.get(len(hashvalue))
    if not algo_info:
        print(f"{bad} Unsupported hash length: {len(hashvalue)}")
        return False
    name, apis = algo_info
    print(f"{info} Hash function: {name}")
    for api in apis:
        res = api(hashvalue, name.lower())
        if res:
            return res
    return False

def threaded(hashvalue):
    res = crack(hashvalue)
    if res:
        print(f"{green}{hashvalue} : {res}")
        results[hashvalue] = res

def grep_hashes(directory):
    hashfile = os.path.join(os.getcwd(), f"{os.path.basename(directory)}.txt")
    os.system(f'''grep -Pr "[a-f0-9]{{32,128}}" "{directory}" --exclude=*.{{png,jpg,jpeg,mp3,mp4,zip,gz}} | grep -Po "[a-f0-9]{{32,128}}" >> "{hashfile}"''')
    print(f"{info} Results saved in {hashfile}")

def miner(filepath):
    if not os.path.isfile(filepath):
        print(f"{bad} File not found: {filepath}")
        return
    found = set()
    with open(filepath, 'r') as f:
        for line in f:
            found.update(re.findall(r'[a-f0-9]{32,128}', line.strip()))
    print(f"{info} Hashes found: {len(found)}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        list(executor.map(threaded, found))
    with open(f"cracked-{os.path.basename(filepath)}", 'w') as out:
        for h, r in results.items():
            out.write(f"{h}:{r}\n")
    print(f"{info} Results saved in cracked-{os.path.basename(filepath)}")

# Entry point
if args.dir:
    grep_hashes(args.dir)
elif args.file:
    miner(args.file)
elif args.single:
    out = crack(args.single)
    if out:
        print(f"{good} {args.single} : {out}")
    else:
        print(f"{bad} Hash not found in any database")
else:
    parser.print_help()
