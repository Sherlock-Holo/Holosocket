#!/usr/bin/env python3
import asyncio
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
    request = []
    for i in range(7):
        request.append(await reader.readline())
    request = b''.join(header)
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
            pass
    logging.debug('header: {}'.format(header))

    if not utils.certificate(header, AUTH, SERVER_PORT):
        writer.write(utils.not_found())
        writer.close()
        return None

    response = utils.gen_response(header['Sec-WebSocket-Key'])
    writer.write(response)
    FRO = await reader.read(1) # FIN, RSV * 3, optcode
    prefix = await reader.read(1)
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
        payload = await reader.read(payload_len)
        salt = utils.mask(payload, mask_key)



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
    coro = asyncio.start_server(handle, '127.0.0.2', 1089, loop=loop)
    server = loop.run_until_complete(coro)

    try:
        loop.run_forever()

    except KeyboardInterrupt:
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()
