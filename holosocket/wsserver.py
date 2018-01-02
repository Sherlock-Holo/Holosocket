#!/usr/bin/env python3
import argparse
import asyncio
import functools
import logging
import socket
import struct
import yaml

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

    async def handle(self, reader, writer):
        """Connection handler.

        reader: stream reader
        writer: stream writer"""

        writer.get_extra_info('socket').setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        try:
            Encrypt = Chacha20(self.key)
            Decrypt = Chacha20(self.key)

            # get target addr, port
            data_to_send = await utils.get_content(reader, True)
            # conn close
            if not data_to_send:
                writer.close()
                return None

            content = Decrypt.decrypt(data_to_send)

            addr_len = content[0]
            addr = content[1:1 + addr_len]
            if not utils.is_ip_addr(addr):
                try:
                    addr = await self.resolve(addr)
                except utils.DNSError as e:
                    logging.error(e)
                    writer.close()
                    return None
            logging.debug('addr is {}'.format(addr))
            _port = content[-2:]
            port = struct.unpack('>H', _port)[0]

        except OSError as e:
            logging.error(e)
            writer.close()
            return None

        except ConnectionResetError as e:
            logging.error(e)
            writer.close()
            return None

        except BrokenPipeError as e:
            logging.error(e)
            writer.close()
            return None

        # connect to target
        try:
            r_reader, r_writer = await asyncio.open_connection(addr, port)

        except OSError as e:
            logging.error(e)
            writer.close()
            return None

        r_writer.get_extra_info('socket').setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        logging.debug('start relay')

        s2r = asyncio.ensure_future(
            self.sock2remote(reader, r_writer, Decrypt))

        r2s = asyncio.ensure_future(
            self.remote2sock(r_reader, writer, Encrypt))

        s2r.add_done_callback(
            functools.partial(self.close_transport, writer, r_writer))

        r2s.add_done_callback(
            functools.partial(self.close_transport, writer, r_writer))

    async def sock2remote(self, reader, writer, cipher):
        """Relay handler (local -> remote).

        reader: stream reader
        writer: stream writer
        cipher: decrypt handler"""
        while True:
            try:
                content = await utils.get_content(reader, True)

                # close Connection
                if not content:
                    break

                # send data
                data = cipher.decrypt(content)

                writer.write(data)
                await writer.drain()

            except OSError as e:
                logging.error(e)
                break

            except ConnectionResetError as e:
                logging.error(e)
                break

            except BrokenPipeError as e:
                logging.error(e)
                break

            except TimeoutError as e:
                logging.error(e)
                break

    async def remote2sock(self, reader, writer, cipher):
        """Relay handler (remote -> server).

        reader: stream reader
        writer: stream writer
        cipher: encrypt handler"""
        while True:
            try:
                data = await reader.read(8192)

                # close Connection
                if not data:
                    break

                # send data
                data = cipher.encrypt(data)
                content = utils.gen_server_frame(data)

                writer.write(content)
                await writer.drain()

            except OSError as e:
                logging.error(e)
                break

            except ConnectionResetError as e:
                logging.error(e)
                break

            except BrokenPipeError as e:
                logging.error(e)
                break

            except TimeoutError as e:
                logging.error(e)
                break

    def close_transport(self, writer, r_writer, future):
        """Close transport.

        writer: sock stream writer
        r_writer: remote stream writer
        future: prepare for `functools.partial`"""
        writer.close()
        r_writer.close()
        logging.debug('stop relay')


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
    coro = asyncio.start_server(server.handle, SERVER, SERVER_PORT, loop=loop)
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
