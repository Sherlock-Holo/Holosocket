#!/usr/bin/env python3

import argparse
import asyncio
import json
import logging
import socket
import struct

import utils
from encrypt import aes_gcm


logging.basicConfig(level=logging.DEBUG,
                    format='{asctime} {levelname} {message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    style='{')


class Remote(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport
        self.server_transport = None
        self.Decrypt = None

    def data_received(self, data):
        pass


class Server(asyncio.Protocol):
    HANDSHAKE, SALT, RELAY = range(3)

    def connection_made(self, transport):
        client_info = transport.get_extra_info('peername')
        logging.debug('connect from {}'.format(client_info))
        self.transport = transport
        self.state = self.HANDSHAKE
        self.data_len = 0
        self.data_buf = b''

    def data_received(self, data):
        if self.state == self.HANDSHAKE:
            self.data_buf += data
            if self.data_buf.endswith(b'\r\n\r\n'):
                request = self.data_buf[:-4]
                request = request.split(b'\r\n')
                header = {}
                for i in request:
                    header[i.split(b': ')[0].decode()] = i.split(b': ')[1]

            else:
                return None

            if request[0] != b'GET /chat HTTP/1.1':
                self.transport.write(utils.not_found())
                self.transport.close()

            elif not utils.certificate(header, AUTH, SERVER_PORT):
                self.transport.write(utils.not_found())
                self.transport.close()

            response = utils.gen_response(header['Sec-WebSocket-Key'])
            self.transport.write(response)


if __name__ == '__main__':
    logging.info('start holosocket server')
    parser = argparse.ArgumentParser(description='holosocket server')
    parser.add_argument('-c', '--config', help='config file')
    args = parser.parse_args()
    if args.config:
        with open(args.config, 'r') as f:
            config = json.load(f)

    SERVER = config['server']
    SERVER_PORT = config['server_port']
    PORT = config['local_port']
    KEY = config['password']
    AUTH = config['auth_addr']

    loop = asyncio.get_event_loop()
    _server = loop.create_server(Server, '127.0.0.2', PORT)
    server = loop.run_until_complete(_server)

    try:
        loop.run_forever()

    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
