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
    HANDSHAKE, RELAY = range(2)

    def connection_made(self, transport):
        self.transport = transport
        self.server_transport = None
        self.Ecrypt = None
        self.Decrypt = None
        self.Sec_WebSocket_Key = None
        self.state = self.HANDSHAKE
        self.data_len = 0
        self.data_buf = b''
        self.salt = None
        self.target = None

    def data_received(self, data):
        if self.state == self.HANDSHAKE:
            self.data_buf += data
            if self.data_buf.endswith(b'\r\n\r\n'):
                request = self.data_buf[:-4]
                request = request.split(b'\r\n')
                #logging.debug('header: {}'.format(request))
                header = {}
                for i in request:
                    try:
                        header[i.split(b': ')[0].decode()] = i.split(b': ')[1]
                    except IndexError:
                        pass

            else:
                return None

            #logging.debug('header: {}'.format(header))

            if not utils.certificate_key(self.Sec_WebSocket_Key,
                                         header['Sec-WebSocket-Accept']):
                self.transport.close()
            else:
                logging.debug('handshake done')
                self.transport.write(utils.gen_local_frame(self.salt))
                #logging.debug('sent salt: {}'.format(self.salt))
                target, tag = self.Encrypt.encrypt(self.target)
                self.transport.write(utils.gen_local_frame(target + tag))
                socks_reponse = b'\x05\x00\x00\x01'
                socks_reponse += socket.inet_aton('0.0.0.0')
                socks_reponse += struct.pack('>H', 0)
                self.server_transport.write(socks_reponse)
                self.state = self.RELAY
                self.data_buf = b''
                self.data_len = 0
                logging.debug('start relay')

        elif self.state == self.RELAY:
            self.data_buf += data
            self.data_len += len(data)
            if utils.get_content(self.data_buf, self.data_len, False):
                #logging.debug('raw data: {}'.format(self.data_buf))
                content, continue_read, payload_len = utils.get_content(self.data_buf,
                                                                        self.data_len,
                                                                        False)
            else:
                return None

            #logging.debug('content: {}'.format(content))
            tag = content[-16:]
            content = content[:-16]
            try:
                content = self.Decrypt.decrypt(content, tag)
            except ValueError:
                logging.warn('detected attack')
                self.transport.close()
                return None

            self.server_transport.write(content)

            self.data_buf = self.data_buf[2 + continue_read + payload_len:]
            self.data_len = len(self.data_buf)


class Server(asyncio.Protocol):
    INIT, REQUEST, HANDSHAKE, RELAY = range(4)

    def connection_made(self, transport):
        client_info = transport.get_extra_info('peername')
        logging.debug('connect from {}'.format(client_info))
        self.transport = transport
        self.state = self.INIT
        self.Sec_WebSocket_Key = None
        self.Encrypt = aes_gcm(KEY)
        self.salt = self.Encrypt.salt
        self.Decrypt = aes_gcm(KEY, self.salt)
        self.data_len = 0
        self.data_buf = b''

    def data_received(self, data):
        if self.state == self.INIT:
            # recv all ask data
            self.data_buf += data
            self.data_len += len(data)
            if self.data_len < 2:
                return None
            else:
                amount = self.data_buf[1]    # Authentication amount
                if self.data_len < 2 + amount:
                    return None

            if self.data_buf[0] == 5:    # version check
                if 0 in self.data_buf[2:]:    # no authentication
                    self.transport.write(b'\x05\x00')
                    self.state = self.REQUEST
                    # clear buffer and counter
                    self.data_len = 0
                    self.data_buf = b''

                else:
                    # authentication not support
                    response = struct.pack('>BB', 0x05, 0xff)
                    logging.error('authentication not support')
                    self.transport.write(response)
                    self.eof_received()
            else:
                self.eof_received()

        elif self.state == self.REQUEST:
            self.data_buf += data
            self.data_len += len(data)
            if self.data_len < 4:
                return None
            else:
                ver, cmd, rsv, addr_type = self.data_buf[:4]
                logging.debug('addr type: {}'.format(addr_type))

                if addr_type == 1:    # ipv4
                    # (ver cmd rsv atyp) addr_ip port
                    if self.data_len < 4 + 8 + 2:
                        return None
                    else:
                        addr = socket.inet_ntoa(self.data_buf[4:8])
                        port = struct.unpack('>H', self.data_buf[-2:])[0]
                        addr_len = struct.pack('>B', len(addr))
                        # target message: addr_len + addr + port
                        target = addr_len + addr.encode()
                        target += self.data_buf[-2:]

                elif addr_type == 3:    # domain name
                    if self.data_len < 4 + 1:
                        return None
                    else:
                        addr_len = self.data_buf[4]
                        if self.data_len < 5 + addr_len + 2:
                            return None
                        else:
                            addr = self.data_buf[5:5 + addr_len]
                            port = struct.unpack('>H', self.data_buf[-2:])[0]
                            # target message: addr_len + addr + port
                            # use socks5 raw message
                            target = self.data_buf[4:]

                else:
                    # addr type not support
                    response = b'\x05\x08\x00\x01'
                    response += socket.inet_aton('0.0.0.0')
                    response += struct.pack('>H', 0)
                    self.transport.write(response)
                    logging.error('addr type not support')
                    self.eof_received()

            logging.debug('target: {}:{}'.format(addr, port))

            # connect to shadowsocks server
            asyncio.ensure_future(self.connect(SERVER, SERVER_PORT, target))
            self.state = self.RELAY
            # clear buffer and counter, actually it is not important here
            self.data_len = 0
            self.data_buf = b''

        elif self.state == self.RELAY:
            content, tag = self.Encrypt.encrypt(data)
            content = utils.gen_local_frame(content + tag)
            self.remote_transport.write(content)

    async def connect(self, addr, port, target):
        loop = asyncio.get_event_loop()
        transport, remote = await loop.create_connection(Remote, addr, port)
        remote.target = target
        remote.server_transport = self.transport
        remote.salt = self.salt
        remote.Encrypt = self.Encrypt
        remote.Decrypt = self.Decrypt
        self.remote_transport = transport
        handshake, remote.Sec_WebSocket_Key = utils.gen_request(AUTH,
                                                                SERVER_PORT)
        transport.write(handshake)


if __name__ == '__main__':
    logging.info('start holosocket local')
    parser = argparse.ArgumentParser(description='holosocket local')
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
