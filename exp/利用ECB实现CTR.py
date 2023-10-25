from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# 输入的明文数据
plaintext = b'hello world'

# 生成一个随机的Nonce（16字节）
nonce = os.urandom(16)
key=os.urandom(16)

# AES ECB模式的加密器
aes_cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
encryptor = aes_cipher.encryptor()

# 初始化计数器
counter = 0

# 初始化加密后的数据
ciphertext = b''

# 分块大小（16字节）
block_size = 16

# 对明文数据进行分块处理
for i in range(0, len(plaintext), block_size):
    block = plaintext[i:i + block_size]

    # 组合Nonce和计数器，然后加密
    counter_bytes = counter.to_bytes(16, byteorder='big')
    counter_nonce = nonce + counter_bytes
    encrypted_counter = encryptor.update(counter_nonce)

    # 异或操作，将加密后的计数器块与明文块结合
    xor_result = bytes(x ^ y for x, y in zip(block, encrypted_counter))

    # 存储加密后的块
    ciphertext += xor_result

    # 更新计数器
    counter += 1

print("加密后的数据:", ciphertext.hex())
