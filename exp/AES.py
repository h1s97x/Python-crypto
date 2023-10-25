# import os
#
# from cryptography.hazmat.primitives import padding
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend
#
#
# class AESCrypto(object):
#
#     AES_CBC_KEY = os.urandom(32)
#     AES_CBC_IV = os.urandom(16)
#
#     @classmethod
#     def encrypt(cls, data, mode='cbc'):
#         func_name = '{}_encrypt'.format(mode)
#         func = getattr(cls, func_name)
#         return func(data)
#
#     @classmethod
#     def decrypt(cls, data, mode='cbc'):
#         func_name = '{}_decrypt'.format(mode)
#         func = getattr(cls, func_name)
#         return func(data)
#
#     @staticmethod
#     def pkcs7_padding(data):
#         if not isinstance(data, bytes):
#             data = data.encode()
#
#         padder = padding.PKCS7(algorithms.AES.block_size).padder()
#
#         padded_data = padder.update(data) + padder.finalize()
#
#         return padded_data
#
#     @classmethod
#     def cbc_encrypt(cls, data):
#         if not isinstance(data, bytes):
#             data = data.encode()
#
#         cipher = Cipher(algorithms.AES(cls.AES_CBC_KEY),
#                         modes.CBC(cls.AES_CBC_IV),
#                         backend=default_backend())
#         encryptor = cipher.encryptor()
#
#         padded_data = encryptor.update(cls.pkcs7_padding(data))
#
#         return padded_data
#
#     @classmethod
#     def cbc_decrypt(cls, data):
#         if not isinstance(data, bytes):
#             data = data.encode()
#
#         cipher = Cipher(algorithms.AES(cls.AES_CBC_KEY),
#                         modes.CBC(cls.AES_CBC_IV),
#                         backend=default_backend())
#         decryptor = cipher.decryptor()
#
#         uppaded_data = cls.pkcs7_unpadding(decryptor.update(data))
#
#         uppaded_data = uppaded_data.decode()
#         return uppaded_data
#
#     @staticmethod
#     def pkcs7_unpadding(padded_data):
#         unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
#         data = unpadder.update(padded_data)
#
#         try:
#             uppadded_data = data + unpadder.finalize()
#         except ValueError:
#             raise Exception('无效的加密信息!')
#         else:
#             return uppadded_data
#

from __future__ import unicode_literals

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import numpy
import os

class AESCrypto(object):
    """AESCrypto."""

    def __init__(self, aes_key, aes_iv):
        if not isinstance(aes_key, bytes):
            aes_key = aes_key.encode()

        if not isinstance(aes_iv, bytes):
            aes_iv = aes_iv.encode()

        self.aes_key = aes_key
        self.aes_iv = aes_iv
        self.block_size = 16

    def encrypt(self, data, mode='cbc'):
        """encrypt."""
        func_name = '{}_encrypt'.format(mode)
        func = getattr(self, func_name)
        if not isinstance(data, bytes):
            data = data.encode()

        return func(data)

    def decrypt(self, data, mode='cbc'):
        """decrypt."""
        func_name = '{}_decrypt'.format(mode)
        func = getattr(self, func_name)

        if not isinstance(data, bytes):
            data = data.encode()

        return func(data)

    def ecb_encrypt(self, data):
        """ECB encrypt."""
        cipher = Cipher(algorithms.AES(self.aes_key),
                        modes.ECB(),
                        backend=default_backend())

        return cipher.encryptor().update(data)

    def ecb_decrypt(self, data):
        """ECB decrypt."""
        cipher = Cipher(algorithms.AES(self.aes_key),
                        modes.ECB(),
                        backend=default_backend())

        return cipher.decryptor().update(data)

    def ctr_encrypt(self, data):
        """ctr_encrypt."""
        cipher = Cipher(algorithms.AES(self.aes_key),
                        modes.CTR(self.aes_iv),
                        backend=default_backend())

        return cipher.encryptor().update(self.pkcs7_padding(data))

    def ctr_decrypt(self, data):
        """ctr_decrypt."""
        cipher = Cipher(algorithms.AES(self.aes_key),
                        modes.CTR(self.aes_iv),
                        backend=default_backend())

        uppaded_data = self.pkcs7_unpadding(cipher.decryptor().update(data))
        return uppaded_data.decode()

    def cbc_encrypt(self, data):
        """cbc_encrypt."""
        cipher = Cipher(algorithms.AES(self.aes_key),
                        modes.CBC(self.aes_iv),
                        backend=default_backend())

        return cipher.encryptor().update(self.pkcs7_padding(data))

    def cbc_decrypt(self, data):
        """cbc_decrypt."""
        cipher = Cipher(algorithms.AES(self.aes_key),
                        modes.CBC(self.aes_iv),
                        backend=default_backend())

        uppaded_data = self.pkcs7_unpadding(cipher.decryptor().update(data))
        return uppaded_data.decode()

    def ecbTocbc(self, data):
        if not isinstance(data, bytes):
            data = data.encode()
        iv = self.aes_iv
        block_size = self.block_size
        cipherText = b''
        cipher = Cipher(algorithms.AES(self.aes_key),
                        modes.ECB(),
                        backend=default_backend())

        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]

            # 异或操作，将IV与明文块结合
            xor_result = bytes(x ^ y for x, y in zip(block, iv))

            # 填充并使用ECB加密
            padded_data = self.pkcs7_padding(xor_result)
            encryptor = cipher.encryptor()
            encrypted_block = encryptor.update(padded_data)

            # 存储加密后的块，并将其作为下一个块的IV
            cipherText += encrypted_block
            iv = encrypted_block
        return cipherText


    def ecbToctr(self, data):
        if not isinstance(data, bytes):
            data = data.encode()
        nonce = self.aes_iv
        block_size = self.block_size
        # 初始化计数器
        counter = 0
        cipherText = b''

        cipher = Cipher(algorithms.AES(self.aes_key),
                        modes.ECB(),
                        backend=default_backend())

        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]

            # 组合Nonce和计数器，然后加密
            counter_bytes = counter.to_bytes(length=16, byteorder='big', signed=False)
            counter_nonce = nonce + counter_bytes
            encryptor = cipher.encryptor()
            encrypted_counter = encryptor.update(counter_nonce)

            # 异或操作，将加密后的计数器块与明文块结合
            xor_result = bytes(x ^ y for x, y in zip(block, encrypted_counter))

            # 存储加密后的块
            cipherText += xor_result
            # 更新计数器
            counter += 1
        return cipherText

    @staticmethod
    def pkcs7_padding(data):
        """pkcs7_padding."""
        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        padded_data = padder.update(data) + padder.finalize()

        return padded_data

    @staticmethod
    def pkcs7_unpadding(padded_data):
        """pkcs7_unpadding."""
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data)

        try:
            uppadded_data = data + unpadder.finalize()
        except ValueError:
            raise Exception('无效的加密信息!')
        else:
            return uppadded_data

if __name__ == '__main__':
    KEY = os.urandom(32)
    IV = os.urandom(16)
    crypto = AESCrypto(KEY, IV)

    message = "abcdefghjklmnopqrstuvwxyz1234567890"
    # byte_message = b'abcdefghjklmnopqrstuvwxyz1234567890'
    # byte_message = message.encode('utf-8')
    #
    # padder = padding.PKCS7(algorithms.AES.block_size).padder()
    # padded_data = padder.update(byte_message) + padder.finalize()
    #
    # print(type(byte_message))
    # print(type(padded_data))
    # print(byte_message)
    # print(padded_data)
    # # padded_data = padded_data.decode()
    #
    # binary_string = "{:08b}".format(int(byte_message.hex(), 16))
    # print(len(binary_string))
    # print(len("{:08b}".format(int(padded_data.hex(), 16)) + '0'))
    # print(type(binary_string))



    # data3 = crypto.ctr_encrypt(byte_message)
    # print(data3)
    # print(crypto.ctr_decrypt(data3))

    # data1 = crypto.encrypt(message,'ecb')
    # print(data1)
    # print(crypto.decrypt(data1, 'ecb'))
    #
    # data2 = crypto.encrypt(message, 'cbc')
    # print(data2)
    # print(crypto.decrypt(data2, 'cbc'))
    #
    # data3 = crypto.encrypt(message, 'ctr')
    # print(data3)
    # print(crypto.decrypt(data3, 'ctr'))

    data4 = crypto.ecbTocbc(message)
    print(data4)

    data5 = crypto.ecbToctr(message)
    print(data5)
