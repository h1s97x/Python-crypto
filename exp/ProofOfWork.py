import sys
import hashlib
class NonceNotFoundError(Exception):
    pass

def encode(str, code='utf-8'):
    return str.encode(code)

def decode(bytes, code='utf-8'):
    return bytes.decode(code)

def sum256_hex(*args):
    m = hashlib.sha256()
    for arg in args:
        if isinstance(arg, str):
            m.update(arg.encode())
        else:
            m.update(arg)
    return m.hexdigest()

def sum256_byte(*args):
    m = hashlib.sha256()
    for arg in args:
        if isinstance(arg, str):
            m.update(arg.encode())
        else:
            m.update(arg)
    return m.digest()

class ProofOfWork(object):
    _N_BITS = 20
    MAX_BITS = 256
    MAX_SIZE = sys.maxsize
    def __init__(self, n_bits=_N_BITS):
        self._n_bits = n_bits
        self._target_bits = 1 << (self.MAX_BITS - n_bits)
    def _prepare_data(self, nonce):
        data_lst = [str(nonce)]
        return encode(''.join(data_lst))
    def run(self):
        nonce = 0
        found = False
        hash_hex = None
        print('Mining a new block')
        while nonce < self.MAX_SIZE:
            data = self._prepare_data(nonce)
            hash_hex = sum256_hex(data)
            hash_val = int(hash_hex, 16)
            sys.stdout.write("try nonce == %d hash_hex == %s \r" % (nonce, hash_hex))
            if (hash_val < self._target_bits):
                found = True
                break

            nonce += 1
        if found: 
            print('Found nonce == %d' % nonce)
        else:
            print('Not Found nonce')
            raise NonceNotFoundError('nonce not found')
        return nonce, hash_hex
if __name__ == "__main__":
    bc = ProofOfWork()
    bc.run()