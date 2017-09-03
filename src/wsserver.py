#!/usr/bin/env python3
import argparse
import asyncio
import functools
import json
import logging
import struct

import utils
from encrypt import aes_gcm

logging.basicConfig(
    level=logging.DEBUG,
    format='{asctime} {levelname} {message}',
    datefmt='%Y-%m-%d %H:%M:%S',
    style='{')


class Server:

    async def handle(self, reader, writer):
        # get local handshake message
        request = await reader.readuntil(b'\r\n\r\n')
        request = request[:-4]
        request = request.split(b'\r\n')

        if request[0] != b'GET /chat HTTP/1.1':
            writer.write(utils.not_found())
            logging.warn('detect http request')
            writer.close()
            return None

        header = {}
        for i in request[1:]:
            header[i.split(b': ')[0].decode()] = i.split(b': ')[1]

        # flitrate http request or attack request
        if not utils.certificate(header, AUTH, SERVER_PORT):
            writer.write(utils.not_found())
            writer.close()
            return None

        response = utils.gen_response(header['Sec-WebSocket-Key'])
        writer.write(response)

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

    async def get_content(self, reader):
        try:
            data = await reader.read(2)  # (FIN, RSV * 3, optcode)

            if not data:
                return None

            FRO, prefix = data

            prefix = prefix & 0x7f
            if prefix <= 125:
                payload_len = prefix

            elif prefix == 126:
                _payload_len = await reader.read(2)
                payload_len = struct.unpack('>H', _payload_len)[0]

            elif prefix == 127:
                _payload_len = await reader.read(8)
                payload_len = struct.unpack('>Q', _payload_len)[0]

            mask_key = await reader.read(4)

            content_len = 0
            content = []

            while True:
                data = await reader.read(payload_len - content_len)
                content.append(data)
                content_len += len(data)
                if content_len == payload_len:
                    break

            payload = b''.join(content)
            content = utils.mask(payload, mask_key)[0]
            return content

        except OSError as e:
            logging.error(e)
            return None

        except ConnectionResetError as e:
            logging.error(e)
            return None

        except BrokenPipeError as e:
            logging.error(e)
            return None


if __name__ == '__main__':
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
