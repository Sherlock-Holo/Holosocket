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
    logging.debug('connect from {}'.format(writer.get_extra_info('peername')))
    request = await reader.read(2)
    if request[0] != 5:
        writer.close()
        logging.error('socks version not support')
        return None
    else:
        nmethods = request[1]
        logging.debug('methods number: {}'.format(nmethods))
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
    if cmd != 1:
        data = []
        data.append(b'\x05\x07\x00\x01')
        data.append(socket.inet_aton('0.0.0.0'))
        data.append(struct.pack('>H', 0))
        writer.write(b''.join(data))
        writer.close()
        logging.error('cmd not support')
        return None
    else:
        if atyp == 1:
            _addr = await reader.read(4)
            addr = socket.inet_ntoa(_addr)

        elif atyp == 3:
            addr_len = await reader.read(1)
            addr = await reader.read(ord(addr_len))

        elif atyp == 4:
            _addr = await reader.read(16)
            addr = socket.inet_ntop(socket.AF_INET6, _addr)

        _port = await reader.read(2)
        port = struct.unpack('>H', _port)[0]
        logging.debug('remote: {}:{}'.format(addr, port))
        data_to_send = []
        addr_len = len(addr)
        data_to_send.append(addr_len)
        if atyp == 1:
            data_to_send.append(socket.inet_aton(addr))
        elif atyp == 3:
            data_to_send.append(addr)
        elif atyp == 4:
            data_to_send.append(socket.inet_pton(socket.AF_INET6, addr))

        data_to_send.append(_port)
        data_to_send = b''.join(data_to_send)

        data = []
        data.append(b'\x05\x00\x00\x01')
        data.append(socket.inet_aton('0.0.0.0'))
        data.append(struct.pack('>H', 0))
        writer.write(b''.join(data))

        r_reader, r_writer = await asyncio.open_connection(SERVER, SERVER_PORT)
        handshake, Sec_WebSocket_Key = utils.gen_request(AUTH, SERVER_PORT)
        r_writer.write(handshake)
        response = []
        for i in range(5):
            response.append(r_reader.readline())
        response = b''.join(response)
        response = response[:-4]
        response = response.split(b'\r\n')
        header = {}
        for i in request:
            try:
                header[i.split(b': ')[0].decode()] = i.split(b': ')[1]
            except IndexError:
                pass

        if not utils.certificate_key(
            Sec_WebSocket_Key,
            header['Sec-WebSocket-Accept']
        ):
            r_writer.close()
            return None
        logging.debug('handshake done')
        Encrypt = aes_gcm(KEY)
        salt = Encrypt.salt
        Decrypt = aes_gcm(KEY, salt)
        r_writer.write(utils.gen_local_frame(salt))
        await r_writer.drain()




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
