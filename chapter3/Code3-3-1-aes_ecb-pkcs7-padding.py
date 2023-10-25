# NEVER USE: ECB is not secure!
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from cryptography.hazmat.primitives import padding

key = os.urandom(16)
aesCipher = Cipher(algorithms.AES(key),
                   modes.ECB(),
                   backend=default_backend())
aesEncryptor = aesCipher.encryptor()
aesDecryptor = aesCipher.decryptor()

padder = padding.PKCS7(128).padder()
#padder = padding.ANSIX923(128).padder()
message = b'alicealicealicealicealice'
padded_message = padder.update(message)
padded_message += padder.finalize()
print(padded_message)
c = aesEncryptor.update(padded_message)
print(c)
print(len(c))
m = aesCipher.decryptor().update(c)
print(m)

unpadder = padding.PKCS7(128).unpadder()
#unpadder = padding.ANSIX923(128).unpadder()
print(unpadder.update(m)+unpadder.finalize())

#print(aesDecryptor.update(b'0000000000000000'))
if(aesCipher.decryptor().update(
    aesCipher.encryptor().update(b'0000000000000000')) ==
        b'0000000000000000'):
    print("[PASS]")
else:
    print("[FAIL]")
