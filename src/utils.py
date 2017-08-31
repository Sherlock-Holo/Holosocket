import base64
import hashlib
import secrets
import struct


def gen_data_len(mask_flag, data):
    data_len = len(data)
    if mask_flag:
        if data_len <= 125:
            data_len = data_len | 128
            data_len = struct.pack('>B', data_len)
            return data_len, 0

        elif data_len <= 65535:
            prefix = struct.pack('>B', 126 | 128)
            data_len = struct.pack('>H', data_len)
            return prefix, data_len

        else:
            prefix = struct.pack('>B', 127 | 128)
            data_len = struct.pack('>Q', data_len)
            return prefix, data_len

    else:
        if data_len <= 125:
            data_len = struct.pack('>B', data_len)
            return data_len, 0

        elif data_len <= 65535:
            prefix = struct.pack('>B', 126)
            data_len = struct.pack('>H', data_len)
            return prefix, data_len

        else:
            prefix = struct.pack('>B', 127)
            data_len = struct.pack('>Q', data_len)
            return prefix, data_len


def gen_request(addr, port):
    Sec_WebSocket_Key = secrets.token_urlsafe(16)
    Sec_WebSocket_Key = base64.b64encode(Sec_WebSocket_Key.encode())
    data = [
        b'GET /chat HTTP/1.1\r\n',
        b'Host: ',
        addr.encode(),
        b':',
        str(port).encode(),
        b'\r\n',
        b'Upgrade: websocket\r\n',
        b'Connection: Upgrade\r\n',
        b'Sec-WebSocket-Key: ',
        Sec_WebSocket_Key,
        b'\r\n',
        b'Sec-WebSocket-Version: 13\r\n\r\n'
    ]

    return b''.join(data), Sec_WebSocket_Key


def certificate_key(Sec_WebSocket_Key, Sec_WebSocket_Accept):
    guid = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    Sec_WebSocket_Key += guid
    sha1 = hashlib.sha1()
    sha1.update(Sec_WebSocket_Key)
    Sec_WebSocket_Key = base64.b64encode(sha1.digest())
    if Sec_WebSocket_Accept == Sec_WebSocket_Key:
        return True
    else:
        return False


def gen_response(Sec_WebSocket_Key):
    guid = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    Sec_WebSocket_Key += guid
    sha1 = hashlib.sha1()
    sha1.update(Sec_WebSocket_Key)
    Sec_WebSocket_Accept = base64.b64encode(sha1.digest())
    data = [
        b'HTTP/1.1 101 Switching Protocols\r\n',
        b'Upgrade: websocket\r\n',
        b'Connection: Upgrade\r\n',
        b'Sec-WebSocket-Accept: ',
        Sec_WebSocket_Accept,
        b'\r\n\r\n'
    ]

    return b''.join(data)


def mask(data, mask_key=None):
    if not mask_key:
        mask_key = secrets.token_bytes(4)
    new = []

    for i, d in enumerate(data):
        new.append(struct.pack('>B', d ^ mask_key[i % 4]))

    new_data = b''.join(new)
    return new_data, mask_key


def gen_local_frame(content):
    data = [struct.pack('>B', 1 << 7 | 2)]
    prefix, content_len = gen_data_len(True, content)
    if content_len == 0:
        data.append(prefix)
    else:
        data.append(prefix)
        data.append(content_len)

    content, mask_key = mask(content)
    data.append(mask_key)
    data.append(content)
    return b''.join(data)


def gen_server_frame(content):
    data = [struct.pack('>B', 1 << 7 | 2)]
    prefix, content_len = gen_data_len(False, content)
    if content_len == 0:
        data.append(prefix)
    else:
        data.append(prefix)
        data.append(content_len)

    data.append(content)
    return b''.join(data)


def gen_close_frame(mask):
    if mask:
        data = struct.pack('>B', 1 << 7 | 8)
        data += struct.pack('>B', 1 << 7)

    else:
        data = struct.pack('>B', 1 << 7 | 8)
        data += struct.pack('>B', 0)

    return data


def certificate(header, addr, port):
    if header['Host'] != b':'.join([addr.encode(), str(port).encode()]):
        return False
    elif header['Upgrade'] != b'websocket':
        return False
    elif header['Connection'] != b'Upgrade':
        return False
    elif header['Sec-WebSocket-Version'] != b'13':
        return False

    else:
        return True


def not_found():
    data = b'HTTP/1.1 404 Not Found\r\n'
    data += b'Connection: Closed\r\n\r\n'
    return data
