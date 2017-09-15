import struct
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes

#Cipher_Tag = {'aes-256-gcm': 16}
#Nonce_Len = 8  # fuck you 12 bytes


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

        self.key = SHA256.new(self.raw_key +
                              self.salt).digest()  # generate a 256 bytes key
        self.nonce = 0

    def _new(self):
        nonce = struct.pack('>Q', self.nonce)
        self.cipher = AES.new(self.key, AES.MODE_GCM, nonce)
        self.nonce += 1

    def encrypt(self, data):
        '''Encrypt data return cipher

        data: raw data'''
        self._new()
        #Return (cpiher, MAC)
        return self.cipher.encrypt_and_digest(data)

    def decrypt(self, data, mac):
        '''Decrypt data

        data: cipher
        mac: gmac'''
        self._new()
        #Verify MAC, if matching, will return plain text or raise ValueError
        plain = self.cipher.decrypt_and_verify(data, mac)
        return plain


def test():
    # AES-GCM
    print('AES-256-GCM')
    gen = aes_gcm('test')
    salt = gen.salt
    gcipher = gen.encrypt(b'holo')
    gde = aes_gcm('test', salt)
    print(gde.decrypt(*gcipher))


if __name__ == '__main__':
    test()
