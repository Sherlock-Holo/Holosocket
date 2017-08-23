#!/usr/bin/env python3
import argparse
import asyncio
import json
import logging
import struct

import utils
from encrypt import aes_gcm

logging.basicConfig(level=logging.DEBUG,
                    format='{asctime} {levelname} {message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    style='{')


async def handle(reader, writer):
    # get local handshake message
    request = []
    for i in range(7):
        request.append(await reader.readline())
    request = b''.join(request)
    request = request[:-4]
    request = request.split(b'\r\n')

    if request[0] != b'GET /chat HTTP/1.1':
        writer.write(utils.not_found())
        writer.close()
        return None

    header = {}
    for i in request:
        try:
            header[i.split(b': ')[0].decode()] = i.split(b': ')[1]
        except IndexError:
            # ignore HTTP/1.1 101 Switching Protocols
            pass
    #logging.debug('header: {}'.format(header))

    # flitrate http request or attack request
    if not utils.certificate(header, AUTH, SERVER_PORT):
        writer.write(utils.not_found())
        writer.close()
        return None

    response = utils.gen_response(header['Sec-WebSocket-Key'])
    writer.write(response)

    async def get_content():
        FRO = await reader.read(1)  # (FIN, RSV * 3, optcode)
        if not FRO:
            return FRO

        prefix = await reader.read(1)
        prefix = struct.unpack('>B', prefix)[0] & 0x7f
        if prefix <= 125:
            payload_len = prefix

        elif prefix == 126:
            _payload_len = await reader.read(2)
            payload_len = struct.unpack('>H', _payload_len)[0]

        elif prefix == 127:
            _payload_len = await reader.read(8)
            payload_len = struct.unpack('>Q', _payload_len)[0]

        mask_key = await reader.read(4)
        payload = await reader.read(payload_len)
        content = utils.mask(payload, mask_key)[0]
        return content

    # get salt
    salt = await get_content()
    #logging.debug('salt: {}'.format(salt))
    Encrypt = aes_gcm(KEY, salt)
    Decrypt = aes_gcm(KEY, salt)

    # get target addr, port
    data_to_send = await get_content()
    tag = data_to_send[-16:]
    data = data_to_send[:-16]
    content = Decrypt.decrypt(data, tag)
    addr_len = content[0]
    addr = content[1: 1 + addr_len]
    _port = content[-2:]
    port = struct.unpack('>H', _port)[0]
    logging.debug('target {}:{}'.format(addr, port))

    # connect to target
    r_reader, r_writer = await asyncio.open_connection(addr, port)

    async def sock2remote():
        while True:
            data = await get_content()
            if not data:
                logging.debug('stop relay')
                break
            tag = data[-16:]
            content = data[:-16]
            try:
                data = Decrypt.decrypt(content, tag)
            except ValueError:
                break
            r_writer.write(data)
            await r_writer.drain()

    async def remote2sock():
        while True:
            data = await r_reader.read(4096)
            if not data:
                logging.debug('stop relay')
                break
            data, tag = Encrypt.encrypt(data)
            content = utils.gen_server_frame(data + tag)
            writer.write(content)
            await writer.drain()

    logging.debug('start relay')

    #def close_transport(sock):
        #sock.close()
    #    logging.debug('relay stop')

    s2r = asyncio.ensure_future(sock2remote(), loop=relay_loop)
    r2s = asyncio.ensure_future(remote2sock(), loop=relay_loop)

    # expreriment
    #s2r.add_done_callback(close_transport(writer))
    #r2s.add_done_callback(close_transport(r_writer))


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
    coro = asyncio.start_server(handle, SERVER, SERVER_PORT, loop=loop)
    server = loop.run_until_complete(coro)

    try:
        loop.run_forever()

    except KeyboardInterrupt:
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()
