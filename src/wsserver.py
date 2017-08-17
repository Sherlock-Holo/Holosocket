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
    HANDSHAKE, SALT, TARGET, RELAY = range(4)

    def clean_buffer(self):
        self.data_len = 0
        self.data_buf = b''

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
            self.state = self.SALT
            self.clean_buffer()

        elif self.state == self.SALT:
            self.data_buf += data
            self.data_len += len(data)
            """if self.data_len < 2:
                return None
            else:
                payload_len1 = self.data_buf[1] & 0x7f
                if payload_len1 <= 125:
                    payload_len = payload_len1
                    continue_read = 0

                elif payload_len1 == 126:
                    if self.data_len < 4:
                        return None
                    else:
                        payload_len = struct.unpack('>H', self.data_buf[2:4])
                        continue_read = 2

                elif payload_len1 == 127:
                    if self.data_len < 10:
                        return None
                    else:
                        payload_len = struct.unpack('>Q', self.data_buf[2:10])
                        continue_read = 8

            if self.data_len < 2 + continue_read + 4:
                return None
            else:
                mask_key = self.data_buf[2 + continue_read:6 + continue_read]

            if self.data_len < 2 + continue_read + 4 + payload_len:
                return None
            else:
                salt = data_buf[5 + continue_read:
                                5 + continue_read + payload_len]"""

            if utils.get_content(self.data_buf, self.data_len, True):
                salt = utils.get_content(self.data_buf, self.data_len, True)
            else:
                return None

                self.Encrypt = aes_gcm(KEY, salt)
                self.Decrypt = aes_gcm(KEY, salt)

            self.data_buf = self.data_buf[5 + continue_read + payload_len:]
            self.data_len = len(self.data_buf)
            self.state = self.TARGET

        elif self.state == self.TARGET:
            self.data_buf += data
            self.data_len += len(data)
            if utils.get_content(self.data_buf, self.data_len, True):
                content = utils.get_content(self.data_buf, self.data_len, True)
            else:
                return None

            target = content[:-16]
            tag = content[-16:]
            try:
                target = self.Decrypt.decrypt(target, tag)
            except ValueError:
                self.transport.close()
                return None


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
