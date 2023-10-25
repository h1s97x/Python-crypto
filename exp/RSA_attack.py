import gmpy2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


def get_die_inverse_element(x: float, cipher: int, n: int):
    """
        求模反元素
        如果两个正整数a和n互质，那么一定可以找到整数b，使得 ab-1 被n整除，或者说ab被n除的余数是1
        这时，b就叫做a的"模反元素"
        比如，3和11互质，那么3的模反元素就是4，因为 (3 × 4)-1 可以被11整除
        显然，模反元素不止一个，4加减11的整数倍都是3的模反元素 {...,-18,-7,4,15,26,...}，即：
            如果b是a的模反元素，则 b+kn 都是a的模反元素。

        如果ax≡1(mod p)，且a与p互质（gcd(a,p)=1），则称a关于模p的乘法逆元为x。（不互质则乘法逆元不存在）

        两个整数 a、b，若它们除以正整数 n 所得的余数相等，即 a mod n = b mod n, 则称 a 和 b 对于模 n 同余
    """
    if x > 0:
        raise ValueError("invalid parameter x, should be less than 0")
    return 0 - x, gmpy2.invert(cipher, n)
def common_modulus_decrypt(cipher1: int, cipher2: int, pub1: RSAPublicKey, pub2: RSAPublicKey) -> int:
    """
        已知rsa加密运算逻辑：
            c = (m^e) % n
        则对于共模n的两个公钥对同一个明文m加密，有：
            c1 = (m^e1) % n
            c2 = (m^e2) % n
        假设e1、e2的最大公约数为gcd，则根据扩展欧几里德算法可以得出，必定存在一组解使得：
            e1 * x + e2 * y == gcd，其中x、y均为实数
        现在对c1、c2进行如下运算：
            (c1^x * c2^y) % n
        我们可以得出：
            (c1^x * c2^y) % n == ((((m^e1) % n)^x) * (((m^e2) % n)^y)) % n
        通过模运算简化，可以得到：
            (c1^x * c2^y) % n == ((m^e1)^x * (m^e2)^y) % n
        对右边进一步简化可以得到：
            (c1^x * c2^y) % n == ((m^(e1*x)) * (m^(e2*y))) % n
        对右边再进行合并可以得到：
            (c1^x * c2^y) % n == (m^(e1*x + e2*y)) % n
        进一步我们可以得到：
            (c1^x * c2^y) % n == (m^(gcd)) % n
            (c1^x * c2^y) % n == ((m%n)^gcd)%n
        在rsa中，e1与e2必定互斥，即：gcd(e1,e2) == 1:
            (c1^x * c2^y) % n == m%n
        则我们可以进一步简化：
            (c1^x * c2^y) % n = m
        模运算拓展开，即：
            ((c1^x % n) * (c2^y % n)) % n = m
        即只需要我们求出唯一解x、y，就可以根据密文以及模长n计算出明文m
    """
    n1 = pub1.public_numbers().n
    e1 = pub1.public_numbers().e
    n2 = pub2.public_numbers().n
    e2 = pub2.public_numbers().e
    if n1 != n2:
        raise ValueError("required a common modulus")
    if e1 == e2:
        raise ValueError("required different public exponents")
    # 计算e1 和 e2 的 最大公约数gcd以及唯一解x、y，使得：e1 * x + e2 * y = gcd
    gcd, x, y = gmpy2.gcdext(e1, e2)
    print("e1={}, e2={}, gcd={}, x={}, y={}".format(e1, e2, gcd, x, y))
    if gcd != 1:
        raise ValueError("invalid 2 public exponents")
    print("before die inverse element calculate: n={}, x={}, cipher1={}, y={}, cipher2={}".
          format(n1, x, cipher1, y, cipher2))
    """
        假设x<0,记x==-a,则：
            c1^x % n 等价于 c1^-a % n
            右边可以转化为：(1/(c1^a)) % n
            由于在模n下的除法可以用和对应模逆元的乘法来表达。"分数取模"，等价于求分母的模逆元
    """
    if x < 0:
        x, cipher1 = get_die_inverse_element(x, cipher1, n1)
    elif y < 0:
        y, cipher2 = get_die_inverse_element(y, cipher2, n1)
    print("after die inverse element calculate: n={}, x={}, cipher1={}, y={}, cipher2={}".
          format(n1, x, cipher1, y, cipher2))
    plain = (pow(int(cipher1), int(x)) * pow(int(cipher2), int(y))) % n1
    return plain


def simple_rsa_encrypt(m, public_key):
        numbers = public_key.public_numbers()
        return gmpy2.powmod(m, numbers.e, numbers.n)


def simple_rsa_decrypt(c, private_key):
        numbers = private_key.private_numbers()
        return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)

def common_modulus_attack(cipher1, cipher2, public_key1, public_key2):
    # 获取两个公钥的模数和指数
    n1 = public_key1.public_numbers().n
    e1 = public_key1.public_numbers().e
    n2 = public_key2.public_numbers().n
    e2 = public_key2.public_numbers().e

    # 使用中国剩余定理（CRT）求解明文
    gcd, s1, s2 = extended_gcd(e1, e2)
    m1 = pow(cipher1, s1, n1)
    m2 = pow(cipher2, s2, n2)

    # 计算明文乘积
    message =(m1 * m2) % (n1 * n2)
    return message

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

# 假设Alice和Bob分别使用不同的公钥加密了相同的明文
ciphertext_alice = 123
ciphertext_bob = 123
private_key_alice = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=2048,
                        backend=default_backend()
                    )
public_key_alice = private_key_alice.public_key()
private_key_bob = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=2048,
                        backend=default_backend()
                    )
public_key_bob = private_key_bob.public_key()
def homomorphic_attack(message1, message2, public_key):
    # 获取公钥的模数和指数
    n = public_key.public_numbers().n
    e = public_key.public_numbers().e

    cipher1 = simple_rsa_encrypt(message1, public_key)
    cipher2 = simple_rsa_encrypt(message2, public_key)

    # 使用同态性质进行运算
    ciphertext_product = (cipher1 * cipher2) % public_key.public_numbers().n

    # 密文乘积的解是明文的乘积
    # 密文乘积共模取余的解仍然是明文的乘积
    val1 = simple_rsa_decrypt(ciphertext_product, private_key)
    print(val1)
    val2 = simple_rsa_decrypt(cipher1 * cipher2, private_key)
    print(val2)
    val3 = message1 * message2
    print(val3)

    # 解密得到结果
    plaintext_product = pow(ciphertext_product, e, n)
    return plaintext_product

# 示例用法：
# 假设Alice和Bob分别使用相同的公钥加密了不同的明文
ciphertext_alice = 123
ciphertext_bob = 456
private_key = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=2048,
                        backend=default_backend()
                    )
public_key = private_key.public_key()

# 同态攻击
plaintext_product = homomorphic_attack(ciphertext_alice, ciphertext_bob, public_key)
print("结果:", plaintext_product)
# 共模攻击
plaintext = common_modulus_attack(ciphertext_alice, ciphertext_bob, public_key_alice, public_key_bob)
print("明文:", plaintext)