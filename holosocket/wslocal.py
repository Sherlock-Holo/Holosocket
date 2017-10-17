#!/usr/bin/env python3

import argparse
import asyncio
# import functools
import logging
import socket
import struct
import websockets
import yaml
from random import choice
from websockets.exceptions import ConnectionClosed as WsConnectionClosed

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

try:
    # from . import utils
    from .encrypt import Chacha20
except (ModuleNotFoundError, ImportError):  # develop mode
    # import utils
    from encrypt import Chacha20


class Server:
    def __init__(self, server, v6_server, server_port, key, **kwargs):
        self.server = server
        if not v6_server:
            self.v6 = False
        else:
            self.v6_server = v6_server
            self.v6 = True

        self.server_port = server_port
        self.key = key

        self.conn_pool = []

    async def handle(self, reader, writer):
        try:
            request = await reader.readexactly(2)
        except asyncio.IncompleteReadError as e:
            logging.error('read request error')
            writer.close()
            return None

        # socks version not support
        if request[0] != 5:
            writer.close()
            logging.error('socks version not support')
            return None
        else:
            nmethods = request[1]
            try:
                methods = await reader.readexactly(nmethods)
            except asyncio.IncompleteReadError:
                logging.error('read methods error')
                writer.close()
                return None

            if 0 in methods:
                writer.write(b'\x05\x00')
                await writer.drain()
            else:
                writer.write(b'\x05\xff')
                logging.error('Authentication not support')
                writer.close()
                return None

        try:
            data = await reader.readexactly(4)
        except asyncio.IncompleteReadError:
            logging.error('read (ver, cmd, rsv, atyp) error')
            writer.close()
            return None

        ver, cmd, rsv, atyp = data
        # cmd not support
        if cmd != 1:
            data = (
                b'\x05\x07\x00\x01',
                socket.inet_aton('0.0.0.0'),
                struct.pack('>H', 0)
            )
            writer.write(b''.join(data))
            writer.close()
            logging.error('cmd not support')
            return None

        # ipv4
        if atyp == 1:
            try:
                _addr = await reader.readexactly(4)
            except asyncio.IncompleteReadError:
                logging.error('read ipv4 addr error')
                writer.close()
                return None

            addr = socket.inet_ntoa(_addr).encode()

        # domain name
        elif atyp == 3:
            try:
                addr_len = await reader.readexactly(1)
                addr = await reader.readexactly(
                    struct.unpack('>B', addr_len)[0])
            except asyncio.IncompleteReadError:
                logging.error('read domain name error')
                writer.close()
                return None

        # ipv6
        elif atyp == 4:
            try:
                _addr = await reader.readexactly(16)
            except asyncio.IncompleteReadError:
                logging.error('read ipv6 addr error')
                writer.close()
                return None

            addr = socket.inet_ntop(socket.AF_INET6, _addr).encode()

        try:
            port = await reader.readexactly(2)
        except asyncio.IncompleteReadError:
            logging.error('read port error')
            writer.close()
            return None

        # send target addr and port to server
        data_to_send = (
            struct.pack('>B', len(addr)),
            addr,
            port
        )
        data_to_send = b''.join(data_to_send)

        # success response
        data = (
            b'\x05\x00\x00\x01',
            socket.inet_aton('0.0.0.0'),
            struct.pack('>H', 0)
        )
        writer.write(b''.join(data))
        await writer.drain()

        if not self.conn_pool:
            logging.debug('conn_pool is empty')
            ws_conn = Websocket_conn(self.key, self.server, self.server_port)
            self.conn_pool.append(ws_conn)
            await ws_conn.create_conn()

        else:
            for ws_conn in self.conn_pool:
                if ws_conn.using:
                    all_conn_busy = True
                else:
                    all_conn_busy = False
                    break

            if not all_conn_busy:
                while True:
                    logging.debug('conn_pool: {}'.format(self.conn_pool))
                    ws_conn = choice(self.conn_pool)
                    if not ws_conn.using:
                        if ws_conn.ttl <= 0:
                            self.conn_pool.pop(self.conn_pool.index(ws_conn))
                        else:
                            break

            else:
                ws_conn = Websocket_conn(self.key, self.server, self.server_port)
                self.conn_pool.append(ws_conn)
                await ws_conn.create_conn()

        await ws_conn.update(reader, writer, data_to_send)
        asyncio.ensure_future(ws_conn.update(reader, writer, b''.join(data)))


class Websocket_conn:
    def __init__(self, key, server, server_port, ttl=10):
        self.encrypt = Chacha20(key)
        self.decrypt = Chacha20(key)
        self._ttl = ttl
        self.path = 'ws://{}:{}'.format(server, server_port)
        self._using = True
        self.initiative_close = None

    async def create_conn(self):
        self.transport = await websockets.connect(self.path)

    async def update(self, reader, writer, data_to_send):
        self.sock_reader = reader
        self.sock_writer = writer
        await self.send_target_info(self.encrypt.encrypt(data_to_send))

        asyncio.ensure_future(self.sock2remote())
        asyncio.ensure_future(self.remote2sock())

    async def send_target_info(self, data_to_send):
        await self.transport.send(data_to_send)

    async def kill_conn(self):
        self._ttl = -1
        self.sock_writer.close()
        await self.transport.close()
        self._using = False

    @property
    def ttl(self):
        return self._ttl

    @property
    def using(self):
        return self._using

    async def sock2remote(self):
        while True:
            try:
                data = await self.sock_reader.read(8192)
                if not data:
                    self.sock_writer.close()
                    self.initiative_close = True
                    await self.transport.send(self.encrypt.encrypt(b'\x00\xff'))
                    return None

                data = self.encrypt.encrypt(data)
                await self.transport.send(data)

            except OSError as e:
                await self.kill_conn()
                return None

            except ConnectionError as e:
                await self.kill_conn()
                return None

            except WsConnectionClosed as e:
                await self.kill_conn()
                return None

    async def remote2sock(self):
        while True:
            try:
                data = await self.transport.recv()
                data = self.decrypt.decrypt(data)
                if data == b'\x00\xff':
                    if self.initiative_close:
                        self.sock_writer.close()

                    else:
                        await self.transport.send(self.encrypt.encrypt(b'\x00\xff'))
                        self.sock_writer.close()

                    self.ttl -= 1
                    self.initiative_close = None
                    self._using = False
                    return None

                else:
                    data = self.decrypt.decrypt(data)
                    self.sock_writer.write(data)
                    await self.sock_writer.drain()

            except OSError as e:
                await self.kill_conn()
                return None

            except ConnectionError as e:
                await self.kill_conn()
                return None

            except WsConnectionClosed as e:
                await self.kill_conn()
                return None


def main():
    parser = argparse.ArgumentParser(description='holosocket local')
    parser.add_argument('-c', '--config', help='config file')
    parser.add_argument('--debug', action='store_true', help='debug mode')

    args = parser.parse_args()

    if args.config:
        with open(args.config, 'r') as f:
            config = yaml.load(f, Loader=Loader)

    if args.debug:
        LOGGING_MODE = logging.DEBUG
    else:
        LOGGING_MODE = logging.INFO

    logging.basicConfig(
        level=LOGGING_MODE,
        format='{asctime} {levelname} {message}',
        datefmt='%Y-%m-%d %H:%M:%S',
        style='{')

    SERVER = config['server']
    try:
        V6_SERVER = config['v6_server']
    except KeyError:
        V6_SERVER = None

    SERVER_PORT = config['server_port']
    LOCAL = config['local']
    PORT = config['local_port']
    KEY = config['password']

    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        logging.info('uvloop mode')
    except ImportError:
        logging.info('pure asyncio mode')

    loop = asyncio.get_event_loop()
    server = Server(SERVER, V6_SERVER, SERVER_PORT, KEY)
    coro = asyncio.start_server(server.handle, LOCAL, PORT, loop=loop)
    server = loop.run_until_complete(coro)

    try:
        loop.run_forever()

    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()


if __name__ == '__main__':
    main()
