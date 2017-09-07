#!/usr/bin/env python3
import argparse
import asyncio
import functools
import logging
import struct
import yaml

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

import utils
from encrypt import aes_gcm

logging.basicConfig(
    level=logging.DEBUG,
    format='{asctime} {levelname} {message}',
    datefmt='%Y-%m-%d %H:%M:%S',
    style='{')


class Server:
    async def handle(self, reader, writer):
        # get salt
        salt = await utils.get_content(reader, True)
        Encrypt = aes_gcm(KEY, salt)
        Decrypt = aes_gcm(KEY, salt)

        # get target addr, port
        data_to_send = await utils.get_content(reader, True)
        tag = data_to_send[-16:]
        data = data_to_send[:-16]
        content = Decrypt.decrypt(data, tag)
        addr_len = content[0]
        addr = content[1:1 + addr_len]
        _port = content[-2:]
        port = struct.unpack('>H', _port)[0]

        # connect to target
        try:
            r_reader, r_writer = await asyncio.open_connection(addr, port)

        except OSError as e:
            logging.error(e)
            return None

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
        while True:
            try:
                data = await utils.get_content(reader, True)

                # close Connection
                if not data:
                    break

                # send data
                tag = data[-16:]
                content = data[:-16]
                try:
                    data = cipher.decrypt(content, tag)
                except ValueError:
                    logging.warn('detect attack')
                    await asyncio.sleep(90)
                    return None

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

    async def remote2sock(self, reader, writer, cipher):
        while True:
            try:
                data = await reader.read(8192)

                # close Connection
                if not data:
                    break

                # send data
                data, tag = cipher.encrypt(data)
                content = utils.gen_server_frame(data + tag)

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

    def close_transport(self, writer, r_writer, future):
        writer.close()
        r_writer.close()
        logging.debug('stop relay')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='holosocket server')
    parser.add_argument('-c', '--config', help='config file')
    parser.add_argument('-4', '--ipv4', action='store_true', help='ipv4 only')
    args = parser.parse_args()
    if args.config:
        with open(args.config, 'r') as f:
            config = yaml.load(f, Loader=Loader)

    SERVER = [config['server']]
    if not args.ipv4:
        if 'server_v6' in config:
            SERVER_V6 = config['server_v6']
            SERVER.append(SERVER_V6)

    SERVER_PORT = config['server_port']
    PORT = config['local_port']
    KEY = config['password']

    server = Server()

    loop = asyncio.get_event_loop()
    relay_loop = asyncio.get_event_loop()
    coro = asyncio.start_server(server.handle, SERVER, SERVER_PORT, loop=loop)
    server = loop.run_until_complete(coro)

    try:
        loop.run_forever()

    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
