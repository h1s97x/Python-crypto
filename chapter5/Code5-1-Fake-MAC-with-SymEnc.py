# THIS IS NOT SECURE. DO NOT USE THIS!!!
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import os, hashlib


class Encryptor:
    def __init__ (self, key, nonce):
        aesContext = Cipher(algorithms.AES(key),
        modes.CTR(nonce),
        backend=default_backend())
        self.encryptor = aesContext.encryptor()
        self.hasher = hashlib.sha256()

    def update_encryptor(self, plaintext):
        ciphertext = self.encryptor.update(plaintext)
        self.hasher.update(ciphertext)
        return ciphertext

    def finalize_encryptor(self):
      return self.encryptor.finalize() + self.hasher.digest()

key = os.urandom(32)
nonce = os.urandom(16)
manager = Encryptor(key, nonce)
ciphertext = manager.update_encryptor(b"Hi Bob, this is Alice !")
print(ciphertext)
print(len(ciphertext))
ciphertext += manager.finalize_encryptor()
print(ciphertext)
print(len(ciphertext))

'''hmac
key = b"CorrectHorseBatteryStaple"
h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
h.update(b"hello world")
print(h.finalize().hex())
示例'''
