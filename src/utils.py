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


def gen_request(addr):
    Sec_WebSocket_Key = secrets.token_urlsafe(16)
    Sec_WebSocket_Key = base64.b64encode(Sec_WebSocket_Key.encode())
    data = b'GET /chat HTTP/1.1\r\n'
    data += b'Host: ' + addr.encode() + b':8000\r\n'
    data += b'Upgrade: websocket\r\n'
    data += b'Connection: Upgrade\r\n'
    data += b'Sec-WebSocket-Key: ' + Sec_WebSocket_Key + b'\r\n'
    data += b'Sec-WebSocket-Version: 13\r\n\r\n'
    return data, Sec_WebSocket_Key


def certificate_key(Sec_WebSocket_Key1, Sec_WebSocket_Key2):
    guid = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    Sec_WebSocket_Key1 += guid
    sha1 = hashlib.sha1()
    sha1.update(Sec_WebSocket_Key1)
    Sec_WebSocket_Key1 = base64.b64encode(sha1.digest())
    if Sec_WebSocket_Key2 == Sec_WebSocket_Key1:
        return True
    else:
        return False


def gen_response(Sec_WebSocket_Key):
    guid = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    Sec_WebSocket_Key += guid
    sha1 = hashlib.sha1()
    sha1.update(Sec_WebSocket_Key)
    Sec_WebSocket_Key = base64.b64encode(sha1.digest())
    data = b'HTTP/1.1 101 Switching Protocols\r\n'
    data += b'Upgrade: websocket\r\n'
    data += b'Connection: Upgrade\r\n'
    data += b'Sec-WebSocket-Accept: ' + Sec_WebSocket_Key
    return data


def mask(data, mask_key=None):
    if not mask_key:
        mask_key = secrets.token_bytes(4)
    new = []

    for i, d in enumerate(data):
        new.append(struct.pack('>B', d ^ mask_key[i % 4]))

    new_data = b''.join(new)
    return new_data, mask_key


def gen_local_frame(content):
    data = struct.pack('>B', 1 << 7 | 2)
    prefix, content_len = gen_data_len(True, content)
    if content_len == 0:
        data += prefix
    else:
        data += prefix + content_len

    content, mask_key = mask(content)
    data += mask_key + content
    return data


def gen_server_frame(content):
    data = struct.pack('>B', 1 << 7 | 2)
    prefix, content_len = gen_data_len(False, content)
    if content_len == 0:
        data += prefix
    else:
        data += prefix + content_len

    data += content
    return data


def gen_close_frame(mask):
    if mask:
        data = struct.pack('>B', 1 << 7 | 8)
        data += struct.pack('>B', 1 << 7)

    else:
        data = struct.pack('>B', 1 << 7 | 8)
        data += struct.pack('>B', 0)

    return data
