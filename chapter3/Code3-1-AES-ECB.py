# NEVER USE: ECB is not secure!
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from cryptography.hazmat.primitives import padding

#AES的update方法只对128比特的数据加/解密

key = os.urandom(16)
#key = b"\x81\xff9\xa4\x1b\xbc\xe4\x84\xec9\x0b\x9a\xdbu\xc1\x83"
aesCipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
aesEncryptor = aesCipher.encryptor()
aesDecryptor = aesCipher.decryptor()
e1=aesEncryptor.update(b'alice')
print(e1)
e2=aesEncryptor.update(b'e')
print(e2)
e3=aesEncryptor.update(b'alicealicebobbobbobbobbobbob')
print(e3)
print(aesDecryptor.update(e1))
print(aesDecryptor.update(e2))
print(aesDecryptor.update(e3))


'''print(aesEncryptor.update(b'bob'))
print(aesEncryptor.update(b'bob'))
print(aesEncryptor.update(b'bob'))
print(aesEncryptor.update(b'bob'))'''

'''print(aesDecryptor.update(aesEncryptor.update(b'this is aes ecb mode test')))
encText = aesEncryptor.update(b"a secret message")
decText = aesDecryptor.update(encText)
print(encText)
print(decText)


padder = padding.PKCS7(128).padder()
print(aesEncryptor.update(b''))
message = b'alicealicealicealicealice'
padded_message = padder.update(message)
padded_message += padder.finalize()
print(padded_message)
c = aesEncryptor.update(padded_message)
print('加密后的密文是：{}'.format(c))
m = aesDecryptor.update(c)
print('解密后的明文文是：{}'.format(m))

unpadder = padding.PKCS7(128).unpadder()
print(unpadder.update(m)+unpadder.finalize())
#print(unpadder.finalize())

key = os.urandom(16)
aesCipher = Cipher(algorithms.AES(key),
                   modes.ECB(),
                   backend=default_backend())
aesEncryptor = aesCipher.encryptor()
aesDecryptor = aesCipher.decryptor()

print(aesEncryptor.update(b'0000000000000000'))
print(aesDecryptor.update(b'0000000000000000'))
if(aesCipher.decryptor().update(
    aesCipher.encryptor().update(b'0000000000000000')) ==
        b'0000000000000000'):
    print("[PASS]")
else:
    print("[FAIL]")
'''