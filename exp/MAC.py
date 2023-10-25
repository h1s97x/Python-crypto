from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import os, hashlib



class MAC:
    def __init__ (self, key, nonce):
        aesContext = Cipher(algorithms.AES(key),
        modes.CTR(nonce),
        backend=default_backend())
        self.encryptor = aesContext.encryptor()
        self.hasher = hashlib.sha256()

    def hmac_encrypt(self):
        key = b"CorrectHorseBatteryStaple"
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(b"hello world")
        print(h.finalize().hex())


