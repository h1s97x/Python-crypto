from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# 输入的明文数据
plaintext = b'hello world'

# 使用随机生成的IV(第一个块的“前一个块”)
iv = os.urandom(16)
key=os.urandom(16)
# AES ECB模式的加密器
aes_cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

# 初始化加密后的数据
ciphertext = b''

# 分块大小（16字节）
block_size = 16

# 对明文数据进行分块处理
for i in range(0, len(plaintext), block_size):
    block = plaintext[i:i + block_size]

    # 异或操作，将IV与明文块结合
    xor_result = bytes(x ^ y for x, y in zip(block, iv))

    # 创建填充器
    padder = padding.PKCS7(128).padder()

    # 填充并使用ECB加密
    padded_data = padder.update(xor_result) + padder.finalize()
    encryptor = aes_cipher.encryptor()
    encrypted_block = encryptor.update(padded_data)

    # 存储加密后的块，并将其作为下一个块的IV
    ciphertext += encrypted_block
    iv = encrypted_block

print("加密结果为:", ciphertext.hex())
