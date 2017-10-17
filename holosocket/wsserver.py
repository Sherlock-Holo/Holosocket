#!/usr/bin/env python3
import argparse
import asyncio
import functools
import logging
import struct
import websockets
import yaml
from websockets.exceptions import ConnectionClosed as WsConnectionClosed

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

try:
    from . import utils
    from .encrypt import Chacha20
    from .utils import Resolver
except (ModuleNotFoundError, ImportError):  # develop mode
    import utils
    from encrypt import Chacha20
    from utils import Resolver


class Server:
    def __init__(self, key, nameservers=None):
        """Create a server.

        key: encrypt key
        nameservers: custom DNS server"""
        self.key = key
        resolver = Resolver(nameservers=nameservers)
        self.resolve = resolver.resolve

    async def handle(self, transport, path):
        """Connection handler."""
        while True:
            initiative_close = None
            try:
                Encrypt = Chacha20(self.key)
                Decrypt = Chacha20(self.key)

                # get target addr, port
                data_to_send = await transport.recv()

                content = Decrypt.decrypt(data_to_send)

                addr_len = content[0]
                addr = content[1:1 + addr_len]
                if not utils.is_ip_addr(addr):
                    try:
                        addr = await self.resolve(addr)
                    except utils.DNSError as e:
                        pass

                logging.debug('addr is {}'.format(addr))
                _port = content[-2:]
                port = struct.unpack('>H', _port)[0]

            except WsConnectionClosed as e:
                await transport.close()
                return None

            # connect to target
            try:
                r_reader, r_writer = await asyncio.open_connection(addr, port)
                remote = Remote(r_reader, r_writer)

            except OSError as e:
                await transport.close()
                return None

            logging.debug('start relay')

            s2r = asyncio.ensure_future(
                self.sock2remote(transport, remote, Encrypt, Decrypt, initiative_close))

            r2s = asyncio.ensure_future(
                self.remote2sock(transport, remote, Encrypt, Decrypt, initiative_close))

            dones, pending = await asyncio.wait((s2r, r2s))
            for done in dones:
                if done.result() == CLOSED or CLOSING:
                    return None

    async def sock2remote(self, transport, remote, encrypt, decrypt, initiative_close):
        while True:
            try:
                data = await transport.recv()
                # Changed in websockets version 3.0: recv() used to return None
                # instead.
                # if not data:
                #     await transport.close()
                #     remote.close()
                #     return None

                data = decrypt.decrypt(data)
                if data == b'\x00\xff':
                    if initiative_close:
                        return None
                    else:
                        await transport.send(encrypt.encrypt(b'\x00\xff'))
                        initiative_close = None
                        return None

                    remote.close()

                else:
                    await remote.write(data)

            # for websocket connect
            except WsConnectionClosed as e:
                await transport.close()
                remote.close()
                return transport.state_name

            except ConnectionError as e:
                remote.close()
                await transport.send(encrypt.encrypt(b'\x00\xff'))
                initiative_close = True
                return None

    async def remote2sock(self, transport, remote, encrypt, decrypt, initiative_close):
        while True:
            try:
                data = await remote.read(8192)
                if not data:
                    remote.close()
                    initiative_close = True
                    await transport.send(encrypt.encrypt(b'\x00\xff'))
                    return None

                data = encrypt.encrypt(data)
                await transport.send(data)

            # for websocket connect
            except WsConnectionClosed as e:
                remote.close()
                await transport.close()
                return transport.state_name

            except ConnectionError as e:
                remote.close()
                initiative_close = True
                await transport.send(encrypt.encrypt(b'\x00\xff'))
                return None


class Remote:
    def __init__(self, reader, writer):
        self._reader = reader
        self._writer = writer

    async def read(self, n):
        return await self._reader.read(n)

    async def write(self, data):
        self._writer.write(data)
        await self.writer.drain()

    def close(self):
        self._writer.close()


def main():
    parser = argparse.ArgumentParser(description='holosocket server')
    parser.add_argument('-c', '--config', help='config file')
    parser.add_argument('-4', '--ipv4', action='store_true', help='ipv4 only')
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

    if args.ipv4:
        SERVER = config['server']

    else:
        SERVER = (config['server'], '::')

    SERVER_PORT = config['server_port']
    KEY = config['password']
    try:
        DNS = config['dns']
    except KeyError:
        DNS = None

    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        logging.info('uvloop mode')
    except ImportError:
        logging.info('pure asyncio mode')

    loop = asyncio.get_event_loop()
    server = Server(KEY, nameservers=DNS)
    loop.run_until_complete(websockets.serve(server.handle, SERVER, SERVER_PORT))

    try:
        loop.run_forever()

    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()


if __name__ == '__main__':
    main()
