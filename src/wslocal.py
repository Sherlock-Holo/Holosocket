#!/usr/bin/env python3

import argparse
import asyncio
import functools
import json
import logging
import socket
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
        request = await reader.read(2)
        # socks version not support
        if request[0] != 5:
            writer.close()
            logging.error('socks version not support')
            return None
        else:
            nmethods = request[1]
            methods = await reader.read(nmethods)
            if 0 in methods:
                writer.write(b'\x05\x00')
                await writer.drain()
            else:
                writer.write(b'\x05\xff')
                logging.error('Authentication not support')
                writer.close()
                return None

        data = await reader.read(4)
        ver, cmd, rsv, atyp = data
        # cmd not support
        if cmd != 1:
            data = []
            data.append(b'\x05\x07\x00\x01')
            data.append(socket.inet_aton('0.0.0.0'))
            data.append(struct.pack('>H', 0))
            writer.write(b''.join(data))
            writer.close()
            logging.error('cmd not support')
            return None

        # ipv4
        if atyp == 1:
            _addr = await reader.read(4)
            addr = socket.inet_ntoa(_addr)

        # domain name
        elif atyp == 3:
            addr_len = await reader.read(1)
            addr = await reader.read(ord(addr_len))

        # ipv6
        elif atyp == 4:
            _addr = await reader.read(16)
            addr = socket.inet_ntop(socket.AF_INET6, _addr)

        port = await reader.read(2)

        # send target addr and port to server
        data_to_send = []
        addr_len = len(addr)
        data_to_send.append(struct.pack('>B', addr_len))
        if atyp == 1:
            data_to_send.append(socket.inet_aton(addr))

        elif atyp == 3:
            data_to_send.append(addr)

        elif atyp == 4:
            data_to_send.append(socket.inet_pton(socket.AF_INET6, addr))

        data_to_send.append(port)
        data_to_send = b''.join(data_to_send)

        # success response
        data = []
        data.append(b'\x05\x00\x00\x01')
        data.append(socket.inet_aton('0.0.0.0'))
        data.append(struct.pack('>H', 0))
        writer.write(b''.join(data))
        await writer.drain()

        # connect to server
        try:
            r_reader, r_writer = await asyncio.open_connection(
                SERVER, SERVER_PORT)

        except OSError as e:
            logging.error(e)
            return None

        handshake, Sec_WebSocket_Key = utils.gen_request(AUTH, SERVER_PORT)
        r_writer.write(handshake)
        await r_writer.drain()

        # get handshake response
        response = await r_reader.readuntil(b'\r\n\r\n')
        response = response[:-4]
        response = response.split(b'\r\n')
        header = {}
        for i in response[1:]:
            header[i.split(b': ')[0].decode()] = i.split(b': ')[1]

        # certificate server handshake message
        if not utils.certificate_key(Sec_WebSocket_Key,
                                     header['Sec-WebSocket-Accept']):
            writer.close()
            r_writer.close()
            return None

        Encrypt = aes_gcm(KEY)
        salt = Encrypt.salt
        Decrypt = aes_gcm(KEY, salt)

        # send salt
        r_writer.write(utils.gen_local_frame(salt))
        await r_writer.drain()

        data_to_send, tag = Encrypt.encrypt(data_to_send)
        content = utils.gen_local_frame(data_to_send + tag)
        r_writer.write(content)
        await r_writer.drain()

        logging.debug('start relay')

        s2r = asyncio.ensure_future(
            self.sock2remote(reader, r_writer, Encrypt))

        r2s = asyncio.ensure_future(
            self.remote2sock(r_reader, writer, Decrypt))

        s2r.add_done_callback(
            functools.partial(self.close_transport, writer, r_writer))

        r2s.add_done_callback(
            functools.partial(self.close_transport, writer, r_writer))

    def close_transport(self, writer, r_writer, future):
        writer.close()
        r_writer.close()
        logging.debug('stop relay')

    # resolve websocket frame
    async def get_content(self, reader):
        try:
            data = await reader.read(2)  # (FIN, RSV * 3, optcode)
        except OSError as e:
            logging.error(e)
            return None

        except ConnectionResetError as e:
            logging.error(e)
            return None

        except BrokenPipeError as e:
            logging.error(e)
            return None

        if not data:
            return None

        FRO, prefix = data

        if prefix <= 125:
            payload_len = prefix

        elif prefix == 126:
            _payload_len = await reader.read(2)
            payload_len = struct.unpack('>H', _payload_len)[0]

        elif prefix == 127:
            _payload_len = await reader.read(8)
            payload_len = struct.unpack('>Q', _payload_len)[0]

        content_len = 0
        content = []

        while True:
            data = await reader.read(payload_len - content_len)
            content.append(data)
            content_len += len(data)
            if content_len == payload_len:
                break
        return b''.join(content)

    async def sock2remote(self, reader, writer, cipher):
        while True:
            try:
                data = await reader.read(8192)

            except OSError as e:
                logging.error(e)
                break

            except ConnectionResetError as e:
                logging.error(e)
                break

            except BrokenPipeError as e:
                logging.error(e)
                break

            # close Connection
            if not data:
                break

            # send data
            data, tag = cipher.encrypt(data)
            content = utils.gen_local_frame(data + tag)

            try:
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

    async def remote2sock(self, reader, writer, cipher):
        while True:
            try:
                data = await self.get_content(reader)

            except OSError as e:
                logging.error(e)
                break

            except ConnectionResetError as e:
                logging.error(e)
                break

            except BrokenPipeError as e:
                logging.error(e)
                break

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

            try:
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='holosocket local')
    parser.add_argument('-c', '--config', help='config file')
    args = parser.parse_args()
    if args.config:
        with open(args.config, 'r') as f:
            config = json.load(f)

    SERVER = config['server']
    SERVER_PORT = config['server_port']
    LOCAL = config['local']
    PORT = config['local_port']
    KEY = config['password']
    AUTH = config['auth_addr']

    server = Server()

    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(server.handle, LOCAL, PORT, loop=loop)
    server = loop.run_until_complete(coro)

    try:
        loop.run_forever()

    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
