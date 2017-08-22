#!/usr/bin/env python3

import argparse
import asyncio
import json
import logging
#import socket
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
        self.Encrypt = None
        self.Decrypt = None

    def data_received(self, data):
        content, tag = self.Encrypt.encrypt(data)
        content = utils.gen_server_frame(content + tag)
        #logging.debug('content: {}'.format(content))
        self.server_transport.write(content)


class Server(asyncio.Protocol):
    HANDSHAKE, SALT, TARGET, CONNECTING, RELAY = range(5)

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
                    try:
                        header[i.split(b': ')[0].decode()] = i.split(b': ')[1]
                    except IndexError:
                        pass
                logging.debug(header)

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
            self.data_len = 0
            self.data_buf = b''

        elif self.state == self.SALT:
            self.data_buf += data
            self.data_len += len(data)

            if utils.get_content(self.data_buf, self.data_len, True):
                salt, continue_read, payload_len = utils.get_content(self.data_buf,
                                                                     self.data_len,
                                                                     True)
            else:
                return None
            #logging.debug('salt: {}'.format(salt))

            self.Encrypt = aes_gcm(KEY, salt)
            self.Decrypt = aes_gcm(KEY, salt)

            self.data_buf = self.data_buf[6 + continue_read + payload_len:]
            self.data_len = len(self.data_buf)
            if utils.get_content(self.data_buf, self.data_len, True):
                content, continue_read, payload_len = utils.get_content(self.data_buf,
                                                                        self.data_len,
                                                                        True)

                target = content[:-16]
                tag = content[-16:]
                try:
                    target = self.Decrypt.decrypt(target, tag)
                except ValueError:
                    logging.warn('detected attack')
                    self.transport.close()
                    return None

                addr_len = target[0]
                addr = target[1:1 + addr_len]
                port = struct.unpack('>H', target[-2:])[0]
                logging.debug('target: {}:{}'.format(addr, port))

                self.data_buf = self.data_buf[6 + continue_read + payload_len:]
                self.data_len = len(self.data_buf)

                self.connecting = asyncio.ensure_future(self.connect(addr, port))
                self.state = self.CONNECTING

            else:
                self.state = self.TARGET
                return None

        elif self.state == self.TARGET:
            self.data_buf += data
            self.data_len += len(data)
            if utils.get_content(self.data_buf, self.data_len, True):
                content, continue_read, payload_len = utils.get_content(self.data_buf,
                                                                        self.data_len,
                                                                        True)
            else:
                return None

            target = content[:-16]
            tag = content[-16:]
            try:
                target = self.Decrypt.decrypt(target, tag)
            except ValueError:
                logging.warn('detected attack')
                self.transport.close()
                return None

            addr_len = target[0]
            addr = target[1:1 + addr_len]
            port = struct.unpack('>H', target[-2:])[0]
            logging.debug('target: {}:{}'.format(addr, port))

            self.data_buf = self.data_buf[6 + continue_read + payload_len:]
            self.data_len = len(self.data_buf)

            self.connecting = asyncio.ensure_future(self.connect(addr, port))
            self.state = self.CONNECTING

        elif self.state == self.CONNECTING:
            self.data_buf += data
            self.data_len += len(data)
            if self.connecting.done():
                if utils.get_content(self.data_buf, self.data_len, True):
                    content, continue_read, payload_len = utils.get_content(self.data_buf,
                                                                            self.data_len,
                                                                            True)
                    tag = content[-16:]
                    content = content[:-16]
                    content = self.Decrypt.decrypt(content, tag)
                    self.remote_transport.write(content)

                    self.data_buf = self.data_buf[6 + continue_read + payload_len:]
                    self.data_len = len(self.data_buf)

                    self.state = self.RELAY
                    logging.debug('start relay')
                else:
                    return None

        elif self.state == self.RELAY:
            self.data_buf += data
            self.data_len += len(data)
            if utils.get_content(self.data_buf, self.data_len, True):
                content, continue_read, payload_len = utils.get_content(self.data_buf,
                                                                        self.data_len,
                                                                        True)
                tag = content[-16:]
                content = content[:-16]
                try:
                    content = self.Decrypt.decrypt(content, tag)
                except ValueError:
                    logging.debug('detected relay data attack')
                    self.transport.close()
                    return None

                self.remote_transport.write(content)

                self.data_buf = self.data_buf[6 + continue_read + payload_len:]
                self.data_len = len(self.data_buf)

    async def connect(self, addr, port):
        logging.debug('connecting target')
        loop = asyncio.get_event_loop()
        transport, remote = await loop.create_connection(Remote, addr, port)
        logging.debug('connected target')
        remote.server_transport = self.transport
        remote.Encrypt = self.Encrypt
        remote.Decrypt = self.Decrypt
        self.remote_transport = transport
        if utils.get_content(self.data_buf, self.data_len, True):
            content, continue_read, payload_len = utils.get_content(self.data_buf,
                                                                    self.data_len,
                                                                    True)
            tag = content[-16:]
            content = content[:-16]
            try:
                content = self.Decrypt.decrypt(content, tag)
            except ValueError:
                self.transport.close()
                return None

            self.remote_transport.write(content)
            logging.debug('send directly')

            self.data_buf = self.data_buf[6 + continue_read + payload_len:]
            self.data_len = len(self.data_buf)
            self.state = self.RELAY


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
    _server = loop.create_server(Server, '127.0.0.2', SERVER_PORT)
    server = loop.run_until_complete(_server)

    try:
        loop.run_forever()

    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
