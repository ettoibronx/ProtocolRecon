import argparse
import socket
import json
import os
import requests
from pprint import pprint


class ProtocolRecon:
    def __init__ (self, args):
        if args.auth:
            if os.path.exists('.api_key'):
                exit(".api_key detected, If you want to re-authenticate, delete or edit the .api_key file")
            else:
                with open('.api_key', 'w') as file:
                    self.api_key = args.auth
                    file.write(self.api_key)
                    file.close()
                exit("API key is Successfully saved to the .api_key file")
        else:
            with open('.api_key', 'r') as file:
                self.api_key = file.readline().strip()

        self.url = 'https://api.criminalip.io/v1/ip/data'
        self.headers = {
            "x-api-key": self.api_key,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
        }

        if args.file:
            self.scan_data(file_path=args.file)
        elif args.ip:
            self.scan_data(ip=args.ip)
        elif args.read:
            self.read(file_path=args.read)
        elif args.domain:
            self.scan_domain(domain=args.domain)

    def scan_data(self, ip=None, file_path=None):
        ip_list = []
        print("[Success/Fail] [IP Addr] [Opened Ports] [Product]")

        if file_path:
            with open(file_path, 'r') as file:
                reader = file.readlines()
                for r in reader:
                    self.req_cip(r.strip())
        elif ip:
            self.req_cip(args.ip)

    def req_cip(self, r):
        params = {
            'ip': r, 
        }
        res = requests.get(url=self.url, params=params, headers=self.headers)
        res = res.json()
        if res['status'] == 200:
            for p in res['port']['data']:
                opened_port = str(p['open_port_no'])

                if p['app_name'] and p['app_name'] not in ['Unknown', 'N/A']:
                    if p['app_version'] in ['Unknown', 'N/A']:
                        product_name_version = p['app_name']
                    else:
                        product_name_version = '{}_{}'.format(p['app_name'], p['app_version'])
                elif p['app_name'] in ['Unknown', 'N/A']:
                    product_name_version = ''

                if args.port:
                    if opened_port in args.port:
                        ret_data = "[SUCCESS] [{}] [{}] [{}]".format(r, opened_port, product_name_version)
                        if args.output:
                            self.output(ret_data)

                        print(ret_data)
                else:
                        ret_data = "[SUCCESS] [{}] [{}] [{}]".format(r, opened_port, product_name_version)
                        if args.output:
                            self.output(ret_data)

                        print(ret_data)

    def output(self, result):
        file_path = "{}".format(args.output)

        with open(file_path, "a") as file:
            file.write("{}\n".format(json.dumps(result)))
            file.close()

    def read(self, file_path):
        with open("{}".format(args.read), "r") as file:
            for r in file:
                pprint(json.loads(r))

    def scan_domain(self, domain):
        ips = []
        sock_res = socket.getaddrinfo(domain, 0, 0, 0, 0)
        for sock in sock_res:
            if str(sock[0]).endswith('AF_INET'):
                ips.append(sock[-1][0])

        ips = list(set(ips))

        print("[Success/Fail] [Domain] [City] [AS Name] [AS No.] [Last Update]")

        if ips:
            params = {
                'ip': ips[0]
            }

            res = requests.get(url=self.url, params=params, headers=self.headers)
            res = res.json()
            whois = res['whois']['data'][0]

            print("[Success] [{}] [{}] [{}] [{}] [{}]".format(domain, whois['city'], whois['as_name'], whois['as_no'], whois['confirmed_time']))
        else:
            print("Couldn't find data")
        

def home():
    print('''
 ____            _                  _   ____
|  _ \ _ __ ___ | |_ ___   ___ ___ | | |  _ \ ___  ___ ___  _ __
| |_) | '__/ _ \| __/ _ \ / __/ _ \| | | |_) / _ \/ __/ _ \| '_ /
|  __/| | | (_) | || (_) | (_| (_) | | |  _ <  __/ (_| (_) | | | |
|_|   |_|  \___/ \__\___/ \___\___/|_| |_| \_\___|\___\___/|_| |_|


''')


if __name__ == '__main__':
    home()

    parser = argparse.ArgumentParser(description='protocol_recon', epilog='')
    parser.add_argument('-A', '--auth', help='api authentication with a valid criminalip.io api key', metavar='<api_key>')
    parser.add_argument('-F', '--file', help='csv file', metavar='<file/path>')
    parser.add_argument('-I', '--ip', help='ip', metavar='<ip>')
    parser.add_argument('-P', '--port', help='', nargs='+', metavar='<port_numbers>')
    parser.add_argument('-O', '--output', help='write result to a file', metavar='<file/path>')
    parser.add_argument('-R', '--read', help='read scan result', metavar='<file/path>')
    parser.add_argument('-D', '--domain', help='domain scan', metavar='<domain>')

    args = parser.parse_args()

    protocol_recon = ProtocolRecon(args)
