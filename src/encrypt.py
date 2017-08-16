import struct
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes


Cipher_Tag = {'aes-256-gcm': 16}
Nonce_Len = 8    # fuck you 12 bytes


class aes_cfb:
    def __init__(self, key, iv=None):
        '''Create a new AES-CFB cipher.
        iv: a 16 bytes length byte string, if not provided a random iv is used
        key: Your password like: passw0rd'''

        self.key = SHA256.new(key.encode()).digest()
        if not iv:
            self.iv = get_random_bytes(AES.block_size)

        else:
            if len(iv) != 16:
                error_msg = 'iv length should be 16, not {}'
                raise ValueError(error_msg.format(len(iv)))

            elif type(iv) != bytes:
                raise TypeError('iv should be bytes')

            else:
                self.iv = iv

        self.cipher = AES.new(self.key, AES.MODE_CFB, self.iv)

    def encrypt(self, data):
        '''Return cipher'''
        return self.cipher.encrypt(data)

    def decrypt(self, data):
        '''Return plain text'''
        return self.cipher.decrypt(data)


class aes_gcm:
    def __init__(self, key, salt=None):
        '''Create a new AES-GCM cipher.

        key: Your password like: passw0rd
        salt: a 16 bytes length byte string, if not provided a random salt will be used
        nonce: a 8 bytes length byte string, if not provided a random nonce will be used'''

        self.raw_key = key.encode()
        if not salt:
            self.salt = get_random_bytes(16)
        else:
            if len(salt) != 16:
                error_msg = 'salt length should be 16, not {}'
                raise ValueError(error_msg.format(len(salt)))

            else:
                self.salt = salt
        self.key = SHA256.new(self.raw_key + self.salt).digest()    # generate a 256 bytes key
        self.nonce = 0

    def _new(self):
        nonce = struct.pack('>Q', self.nonce)
        self.cipher = AES.new(self.key, AES.MODE_GCM, nonce)
        self.nonce += 1

    def encrypt(self, data):
        self._new()
        '''Return (cpiher, MAC)'''
        return self.cipher.encrypt(data), self.cipher.digest()

    def decrypt(self, data, mac):
        self._new()
        '''Verify MAC, if matching, will return plain text or raise ValueError'''
        plain = self.cipher.decrypt_and_verify(data, mac)
        return plain


if __name__ == '__main__':
    # AES-CFB
    print('AES-256-CFB')
    en = aes_cfb('test')
    iv = en.iv
    cipher = en.encrypt(b'holo')
    de = aes_cfb('test', iv)
    print(de.decrypt(cipher))

    # AES-GCM
    print('AES-256-GCM')
    gen = aes_gcm('test')
    salt = gen.salt
    nonce = gen.nonce
    gcipher = gen.encrypt(b'holo')
    gde = aes_gcm('test', salt, nonce)
    print(gde.decrypt(*gcipher))
