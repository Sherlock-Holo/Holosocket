import struct
from Cryptodome.Cipher import AES, ChaCha20
from Cryptodome.Hash import SHA3_256
from Cryptodome.Random import get_random_bytes


class aes_gcm:
    def __init__(self, key, salt=None):
        """Create a new AES-GCM cipher.

        key: Your password like: passw0rd
        salt: a 16 bytes length byte string, if not provided a random salt will be used
        nonce: a 8 bytes length byte string, if not provided a random nonce will be used"""

        self.raw_key = key.encode()
        if not salt:
            self._salt = get_random_bytes(16)
        else:
            if len(salt) != 16:
                error_msg = 'salt length should be 16, not {}'
                raise ValueError(error_msg.format(len(salt)))

            else:
                self._salt = salt

        self.key = SHA3_256.new(
            self.raw_key + self._salt).digest()  # generate a 256 bytes key
        self.nonce = 0

    def _new(self):
        nonce = struct.pack('>Q', self.nonce)
        self.cipher = AES.new(self.key, AES.MODE_GCM, nonce)
        self.nonce += 1

    def encrypt(self, data):
        """Encrypt data return cipher.

        data: raw data"""
        self._new()
        return self.cipher.encrypt_and_digest(data)

    def decrypt(self, data, mac):
        """Decrypt data.

        data: cipher
        mac: gmac"""
        self._new()
        # Verify MAC, if matching, will return plain text or raise ValueError
        plain = self.cipher.decrypt_and_verify(data, mac)
        return plain

    @property
    def salt(self):
        return self._salt


class Chacha20:
    def __init__(self, key):
        """Create a new ChaCha20 cipher.

        key: Your password like: passw0rd"""

        raw_key = key.encode()
        self._key = SHA3_256.new(raw_key).digest()
        self._nonce = 0

    def _new(self):
        nonce = struct.pack('>Q', self._nonce)
        self.cipher = ChaCha20.new(key=self._key, nonce=nonce)
        self._nonce += 1

    def encrypt(self, data):
        """Encrypt data return cipher.

        data: raw data"""
        self._new()
        return self.cipher.encrypt(data)

    def decrypt(self, data):
        """Decrypt data.

        data: cipher"""
        self._new()
        return self.cipher.decrypt(data)


def test():
    # AES-GCM
    print('AES-256-GCM')
    gen = aes_gcm('test')
    salt = gen.salt
    gcipher = gen.encrypt(b'holo')
    gde = aes_gcm('test', salt)
    print(gde.decrypt(*gcipher))

    print('ChaCha20')
    c20_en = Chacha20('test')
    c20_cipher = c20_en.encrypt(b'Holo')
    c20_de = Chacha20('test')
    print(c20_de.decrypt(c20_cipher[:3]))
    print(c20_de.decrypt(c20_cipher[3:]))


if __name__ == '__main__':
    test()
