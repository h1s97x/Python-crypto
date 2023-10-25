import os
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
key = b"aaaabbbbccccdddd"
cipher = Cipher(algorithms.AES(key),
                        modes.ECB(),
                        backend=default_backend())
iv = os.urandom(16)
print(iv)
# iv += bytes('1'.encode())
val = int.from_bytes(iv, byteorder='little', signed=False)
val += 1
print(val > sys.maxsize)
val.to_bytes(length=16, byteorder='little', signed=False)
print(val)
print(iv)
# # 执行这些命令将“tux.bmp”二进制文件读入名为“clear”的变量中。
# with open("tux.bmp", "rb") as f:
#     clear = f.read()
# # 执行这些命令可以查看“清除”数据的长度，以及长度模数 16。
# len(clear)
# len(clear)%16
#
# clear_trimmed = clear[64:-2]
# ciphertext = cipher.encryptor().update(clear_trimmed)
# ciphertext = clear[0:64] + ciphertext + clear[-2:]
# with open("tux_ecb.bmp", "w") as f:
#   f.write(ciphertext)