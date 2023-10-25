from cryptography.hazmat.primitives.ciphers import Cipher, algorithms,modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

class EncryptionManager:
    
    def __init__(self):
        key = os.urandom(32)
        iv = os.urandom(16)
        aesContext = Cipher(algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend())
        self.encryptor = aesContext.encryptor()
        self.decryptor = aesContext.decryptor()
        self.padder = padding.PKCS7(128).padder()
        self.unpadder = padding.PKCS7(128).unpadder()

    def encryptMsg(self, plaintext):
        print('明文是' + plaintext.decode())
        paddedmsg = self.padder.update(plaintext)
        if paddedmsg == b'':
            paddedmsg = self.padder.finalize()
        else:
            paddedmsg += self.padder.finalize()
#        if paddedmsg == b'':
#            paddedmsg = self.padder.finalize()
        cipher = self.encryptor.update(paddedmsg)
#       cipherstr= cipher.decode('utf-16')
        cipher += self.encryptor.finalize()
        print('加密后密文是：')
        print(cipher)

#        cipherstr += cipher.decode('utf-16')

        return cipher

    def decryptMsg(self, ciphertext):
        plaintxt = self.decryptor.update(ciphertext)
#        print(self.unpadder.update(self.decryptor.update(ciphertext)))
#        print(self.unpadder.update(self.decryptor.finalize()) + self.unpadder.finalize())

        plaintxt += self.decryptor.finalize()
#        print(plaintxt)
        ptunpad = self.unpadder.update(plaintxt) + self.unpadder.finalize()
        print('解密后明文是:')
        print(ptunpad)
        return

# Auto generate key/IV for encryption

manager = EncryptionManager()
plaintexts = [
    b"SHORT",
    b"MEDIUM MEDIUM MEDIUM",
    b"LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG"
    ]

ciphertexts = []

for m in plaintexts:
    manager = EncryptionManager()
#    ciphertexts.append(manager.encryptMsg(m))
    manager.decryptMsg(manager.encryptMsg(m))


'''for c in ciphertexts:
    manager = EncryptionManager()
    manager.decryptMsg(c)'''

# update()是把最后一块之前的所有数据传递到缓冲区，并进行相应操作，finalize()是把最后一块的内容进行
# 不需要填充，finalize()方法就不需要