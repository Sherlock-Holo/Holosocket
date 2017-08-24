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

logging.basicConfig(level=logging.DEBUG,
                    format='{asctime} {levelname} {message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    style='{')


async def handle(reader, writer):
    logging.debug('connect from {}'.format(writer.get_extra_info('peername')))
    request = await reader.read(2)
    # socks version not support
    if request[0] != 5:
        writer.close()
        logging.error('socks version not support')
        return None
    else:
        nmethods = request[1]
        #logging.debug('methods number: {}'.format(nmethods))
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

    _port = await reader.read(2)
    port = struct.unpack('>H', _port)[0]
    logging.debug('remote: {}:{}'.format(addr, port))

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

    data_to_send.append(_port)
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
        r_reader, r_writer = await asyncio.open_connection(SERVER, SERVER_PORT)
    except OSError as e:
        logging.error(e)
        return None

    handshake, Sec_WebSocket_Key = utils.gen_request(AUTH, SERVER_PORT)
    r_writer.write(handshake)
    r_writer.drain()

    # get handshake response
    response = []
    #for i in range(5):
    #    response.append(await r_reader.readline())
    #response = b''.join(response)
    response = await r_reader.readuntil(b'\r\n\r\n')
    response = response[:-4]
    response = response.split(b'\r\n')
    header = {}
    for i in response:
        try:
            header[i.split(b': ')[0].decode()] = i.split(b': ')[1]
        except IndexError:
            # ignore GET /chat HTTP/1.1
            pass

    # certificate server handshake message
    if not utils.certificate_key(
        Sec_WebSocket_Key,
        header['Sec-WebSocket-Accept']
    ):
        writer.close()
        r_writer.close()
        return None
    logging.debug('handshake done')

    Encrypt = aes_gcm(KEY)
    salt = Encrypt.salt
    Decrypt = aes_gcm(KEY, salt)

    # send salt
    r_writer.write(utils.gen_local_frame(salt))
    #logging.debug('salt: {}'.format(salt))
    await r_writer.drain()

    data_to_send, tag = Encrypt.encrypt(data_to_send)
    content = utils.gen_local_frame(data_to_send + tag)
    r_writer.write(content)
    await r_writer.drain()

    # resolve websocket frame
    async def get_content():
        FRO = await r_reader.read(1)  # (FIN, RSV * 3, optcode)
        FRO = struct.unpack('>B', FRO)[0]
        if FRO == 1 << 7 | 8:
            logging.debug('receive close frame')
            return None

        prefix = await r_reader.read(1)
        prefix = struct.unpack('>B', prefix)[0]
        if prefix <= 125:
            payload_len = prefix

        elif prefix == 126:
            _payload_len = await r_reader.read(2)
            payload_len = struct.unpack('>H', _payload_len)[0]

        elif prefix == 127:
            _payload_len = await r_reader.read(8)
            payload_len = struct.unpack('>Q', _payload_len)[0]

        content = await r_reader.read(payload_len)
        return content

    async def sock2remote():
        while True:
            try:
                data = await reader.read(4096)
            except ConnectionResetError as e:
                logging.error(e)
                break
            except BrokenPipeError as e:
                logging.error(e)
                break

            # close Connection
            if not data:
                logging.debug('relay stop {}:{}'.format(addr, port))
                close_frame = utils.gen_close_frame(True)
                try:
                    r_writer.write(close_frame)
                    await r_writer.drain()
                except ConnectionResetError as e:
                    logging.error(e)
                    break
                except BrokenPipeError as e:
                    logging.error(e)
                    break
                break

            # send data
            data, tag = Encrypt.encrypt(data)
            content = utils.gen_local_frame(data + tag)

            try:
                r_writer.write(content)
                await r_writer.drain()

            except ConnectionResetError as e:
                logging.error(e)
                break
            except BrokenPipeError as e:
                logging.error(e)
                break

    async def remote2sock():
        while True:
            try:
                data = await get_content()
            except ConnectionResetError as e:
                logging.error(e)
                break
            except BrokenPipeError as e:
                logging.error(e)
                break

            # close Connection
            if not data:
                logging.debug('relay stop {}:{}'.format(addr, port))
                close_frame = utils.gen_close_frame(True)
                try:
                    writer.write(close_frame)
                    await writer.drain()
                except ConnectionResetError as e:
                    logging.error(e)
                    break
                except BrokenPipeError as e:
                    logging.error(e)
                    break
                break

            # send data
            tag = data[-16:]
            content = data[:-16]
            try:
                data = Decrypt.decrypt(content, tag)
            except ValueError:
                break

            try:
                writer.write(data)
                await writer.drain()

            except ConnectionResetError as e:
                logging.error(e)
                break
            except BrokenPipeError as e:
                logging.error(e)
                break

    logging.debug('start relay')

    def close_transport(sock, *args):
        sock.close()

    s2r = asyncio.ensure_future(sock2remote(), loop=relay_loop)
    r2s = asyncio.ensure_future(remote2sock(), loop=relay_loop)

    # expreriment
    s2r.add_done_callback(functools.partial(close_transport, writer))
    r2s.add_done_callback(functools.partial(close_transport, r_writer))


if __name__ == '__main__':
    #logging.info('start holosocket local')
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
    relay_loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle, '127.0.0.2', PORT, loop=loop)
    server = loop.run_until_complete(coro)

    try:
        loop.run_forever()

    except KeyboardInterrupt:
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()
