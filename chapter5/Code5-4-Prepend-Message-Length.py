# Reasonably secure concept. Still, NEVER use it for production code.
# Use a crypto library instead!
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms,modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def CBCMAC(message, key):
    aesCipher = Cipher(algorithms.AES(key),
    modes.CBC(bytes(16)), # 16 zero bytes
    backend=default_backend())
    aesEncryptor = aesCipher.encryptor()
    padder = padding.PKCS7(128).padder()

    padded_message = padder.update(message)
    padded_message_with_length = len(message).to_bytes(4, "big") + padded_message
    ciphertext = aesEncryptor.update(padded_message_with_length)
    return ciphertext[-16:]