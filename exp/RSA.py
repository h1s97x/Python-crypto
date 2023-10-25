import gmpy2, os, binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
class RSACrypto(object):
    '''
    RSACrypto
    '''
    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key

    @staticmethod
    def int_to_bytes(i):
        # i might be a gmpy2 big integer; convert back to a Python int
        i = int(i)
        return i.to_bytes((i.bit_length()+7)//8, byteorder='big')

    @staticmethod
    def bytes_to_int(b):
        return int.from_bytes(b, byteorder='big')

    @staticmethod
    def simple_rsa_encrypt(m, public_key):
        numbers = public_key.public_numbers()
        return gmpy2.powmod(m, numbers.e, numbers.n)

    @staticmethod
    def simple_rsa_decrypt(c, private_key):
        numbers = private_key.private_numbers()
        return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)

    def encrypt(self, message):
        public_key = self.public_key
        if not isinstance(message, bytes):
            message = message.encode()
        if not public_key:
            print("\nNo public key loaded\n")
        else:
            message_as_int = self.bytes_to_int(message)
            cipher_as_int = self.simple_rsa_encrypt(message_as_int,public_key)
            cipher = self.int_to_bytes(cipher_as_int)
            return cipher

    def decrypt(self, cipher_hex):
        private_key = self.private_key
        if not isinstance(cipher_hex, bytes):
            cipher_hex = cipher_hex.encode()
        if not private_key:
            print("\nNo private key loaded\n")
        else:
            cipher = binascii.unhexlify(cipher_hex)
            cipher_as_int = self.bytes_to_int(cipher)
            message_as_int = self.simple_rsa_decrypt(cipher_as_int, private_key)
            message = self.int_to_bytes(message_as_int)
            return message

    def rsa_padding_OAEP_encrypt(self, message):
        if not isinstance(message, bytes):
            message = message.encode()
        cipher = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return cipher

    def rsa_padding_OAEP_decrypt(self, cipher_hex):
        if not isinstance(cipher_hex, bytes):
            cipher_hex = cipher_hex.encode()
        message = private_key.decrypt(
            cipher_hex,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None  # rarely used. Just leave it 'None'
            ))
        return message


    def Create_and_load_key(self):
        private_key_file_temp = input("\nEnter a file name for new private key: ")
        public_key_file_temp = input("\nEnter a file name for a new public key: ")
        if os.path.exists(private_key_file_temp) or os.path.exists(public_key_file_temp):
            print("File already exists.")
        else:
            with open(private_key_file_temp, "wb+") as private_key_file_obj:
                with open(public_key_file_temp, "wb+") as public_key_file_obj:
                    self.private_key = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=2048,
                        backend=default_backend()
                    )
                    self.public_key = private_key.public_key()
                    private_key_bytes = private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    private_key_file_obj.write(private_key_bytes)

                    public_key_bytes = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    public_key_file_obj.write(public_key_bytes)
    def load_public_key_file(self, public_key_file):
        if not os.path.exists(public_key_file):
            print("File {} does not exist.")
        else:
            with open(public_key_file, "rb") as public_key_file_object:
                self.public_key = serialization.load_pem_public_key(
                    public_key_file_object.read(),
                    backend=default_backend())
                print("\nPublic Key file loaded.\n")

    def load_private_key_file(self, private_key_file):
        if not os.path.exists(private_key_file):
            print("File {} does not exist.")
        else:
            with open(private_key_file, "rb") as private_key_file_object:
                self.private_key = serialization.load_pem_private_key(
                    private_key_file_object.read(),
                    backend=default_backend(),
                    password=None)
                print("\nPrivate Key file loaded.\n")
                # self.public_key = private_key.public_key()


if __name__ == "__main__":
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    crypto = RSACrypto(public_key=public_key, private_key=private_key)
    # while True:
    #     print("Simple RSA Crypto")
    #     print("--------------------")
    #     print("\t1. Encrypt Message.")
    #     print("\t2. Decrypt Message.")
    #     print("\t3. Load public key file.")
    #     print("\t4. Load private key file.")
    #     print("\t5. Create and load new public and private key files.")
    #     print("\t6. Quit.\n")
    #     choice = input(" >> ")
    #     if choice == '1':
    #         message = input("\nPlaintext: ")
    #         cipher = crypto.encrypt(message)
    #         print("\nCiphertext (hexlified): {}\n".format(binascii.hexlify(cipher)))
    #         print(len(binascii.hexlify(cipher)))
    #     elif choice == '2':
    #         cipher_hex = input("\nCiphertext (hexlified): ")
    #         message = crypto.decrypt(cipher_hex)
    #         print("\nPlaintext: {}\n".format(message))
    #     elif choice == '3':
    #         public_key_file = input("\nEnter public key file: ")
    #         crypto.load_public_key_file(public_key_file)
    #     elif choice == '4':
    #         private_key_file = input("\nEnter private key file: ")
    #         crypto.load_private_key_file(private_key_file)
    #     elif choice == '5':
    #         crypto.Create_and_load_key()
    #     elif choice == '6':
    #         print("\n\nTermina-Eting. This program will self destruct in 5 seconds.\n")
    #         break
    #     else:
    #         print("\n\nUnknown option {}.\n".format(choice))
    message = input("\nPlaintext: ")
    cipherText = crypto.rsa_padding_OAEP_encrypt(message)
    recoverText = crypto.rsa_padding_OAEP_decrypt(cipherText)
    print("Ciphertext with OAEP padding (hexlified): {}".format(cipherText.hex()))
    print("Recovered: {}".format(recoverText))
