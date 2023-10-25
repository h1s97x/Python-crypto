from cryptography.hazmat.primitives.ciphers import Cipher, algorithms,modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding,cmac
import os

def BROKEN_CBCMAC1(message, key, pad=True):
    aesCipher = Cipher(algorithms.AES (key),
    modes.CBC(bytes(16)), # 16 zero bytes
    backend=default_backend())
    aesEncryptor = aesCipher.encryptor()

    if pad:
        padder = padding.PKCS7(128).padder()
        padded_message = padder.update(message)+padder.finalize()
    elif len(message) % 16 == 0:
        padded_message = message
    else:
        raise Exception("Unpadded input not a multiple of 16!")
    ciphertext = aesEncryptor.update(padded_message)
    return ciphertext[-16:] # the last 16 bytes are the last block



def prependAttack(original, prependMessage, key):
    # assumes prependMessage is multiple of 16
    # assumes original is at least 16
    prependMac = BROKEN_CBCMAC1(prependMessage, key, pad = False)
    newFirstBlock = bytearray(original [:16])
    for i in range (16):
        newFirstBlock[i] ^= prependMac[i]
    newFirstBlock = bytes(newFirstBlock)
    return prependMessage + newFirstBlock + original [16:]

key = os.urandom(32)
mac1 = BROKEN_CBCMAC1(b"hello world, hello world, hello world, hello world", key)
mac2 = BROKEN_CBCMAC1(b"Hello world, hello world, hello world, hello world", key)

key = os.urandom(32)
originalMessage = b"attack the enemy forces at dawn!"
prependMessage = b"do not attack. (End of message, padding follows)"
newMessage = prependAttack(originalMessage, prependMessage, key)
mac1 = BROKEN_CBCMAC1(originalMessage, key)
mac2 = BROKEN_CBCMAC1(newMessage, key)
print("Original Message and mac:", originalMessage, mac1.hex())
print("New message and mac :", newMessage, mac2.hex())
if mac1 == mac2:
    print("\tTwo messages with the same MAC! Attack succeeded!!")


c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
c.update(b"message to authenticate")
mac3= c.finalize()
print(mac3)
c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
c.update(originalMessage)
mac3= c.finalize()
print(mac3)
c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
c.update(newMessage)
mac3= c.finalize()
print(mac3)
