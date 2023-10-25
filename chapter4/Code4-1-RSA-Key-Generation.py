from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import padding
# Generate a private key.
private_key = rsa.generate_private_key(
public_exponent=65537,
key_size=2048,
backend=default_backend()
)

# Extract the public key from the private key.
public_key = private_key.public_key()

# Convert the private key into bytes. We won't encrypt it this time.
private_key_bytes = private_key.private_bytes(
encoding=serialization.Encoding.PEM,
format=serialization.PrivateFormat.TraditionalOpenSSL,
encryption_algorithm=serialization.NoEncryption()
)
print(private_key_bytes)
# Convert the public key into bytes.
public_key_bytes = public_key.public_bytes(
encoding=serialization.Encoding.PEM,
format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print(public_key_bytes)

# Convert the private key bytes back to a key.
# Because there is no encryption of the key, there is no password.
private_key = serialization.load_pem_private_key(
private_key_bytes,
backend=default_backend(),
password=None)

message = b"encrypted data"
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

if (plaintext == message):
    print('加解密成功')
