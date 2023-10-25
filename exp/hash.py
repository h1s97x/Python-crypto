import hashlib
import pyscrypt
import secrets


def hash_md5():
    alice = hashlib.md5(b"Alice")
    bob = hashlib.md5(b"Bob")
    print('"Alice" md5:' + alice.hexdigest())
    print('"Bob" md5:' + bob.hexdigest())

def hash_sha256():
    alice = hashlib.sha256(b"Alice")
    bob = hashlib.sha256(b"Bob")
    print('"Alice" sha256:' + alice.hexdigest())
    print('"Bob" sha256:' + bob.hexdigest())

def myhash(str = "Yangjiaqing"):
    res = hashlib.md5(str.encode(encoding="utf-8"))
    print(str + " md5: " + res.hexdigest())

#展示散列函数的雪崩效应
#散列函数在现代密码学中有重要作用。好的散列函数的一个重要且理想的特征是输入和输出没有相关性，或称为“雪崩效应”，这意味着输入的微小变化会导致输出发生显著变化，使其统计上看起来与随机变化没有差别。
# def encode(s):
#     return ' '.join([bin(ord(c)).replace('0b', '') for c in s])
#
#
# def decode(s):
#     return ''.join([chr(i) for i in [int(b, 2) for b in s.split(' ')]])
#
#
# 该函数用于计算两个字符串不同的位数
# def cmpcount(str1, str2):
#     count = 0
#     for i in range(0, len(str1)):
#         if str1[i] != str2[i]:
#             count += 1
#     return count
#
#
# def avalanche(str, nbyte, mbit):
#     # param str:计算哈希值的字符串
#     # param nbyte:str的第几个字节(从低位到高位数)
#     # parem mbit: nbyte的第几个bit位(从低位到高位数)
#     h1 = hashlib.md5(str.encode(encoding="utf-8"))  # 获取原字符串的MD5
#     h1 = h1.hexdigest()
#     nbyte_place = len(str) - nbyte  # 获取目标字节所在位置
#     nbytes = str[nbyte_place]  # 获取目标字节
#     nbyte_str = encode(nbytes)  # 目标字节转换为二进制
#
#     mbit_place = len(nbyte_str) - mbit    # 获取目标bit位置,第一次调试出错点
#     mbits = nbyte_str[mbit_place]   # 获取目标bit
#     # bit位翻转+字节二进制还原
#     if mbits == '0':
#         nbyte_str = nbyte_str[:mbit_place] + '1' + nbyte_str[mbit_place+1:]
#     elif mbits == '1':
#         nbyte_str = nbyte_str[:mbit_place] + '0' + nbyte_str[mbit_place+1:]
#     nbyte_str = decode(nbyte_str)   # 获取修改后的字节
#     str1 = str[:nbyte_place] + nbyte_str + str[nbyte_place+1:]  # 获取修改后的字符串
#     print("str1: " + str1)
#     h2 = hashlib.md5(str1.encode(encoding="utf-8"))
#     h2 = h2.hexdigest()
#     h1 = bin(int(h1, 16))[2:]
#     h2 = bin(int(h2, 16))[2:]
#     if len(h1) != 128:
#         h1 = h1.zfill(128)
#     else:
#         pass
#     if len(h2) != 128:
#         h2 = h2.zfill(128)
#     else:
#         pass
#     print("h1: " + h1)
#     print("h2: " + h2)
#     cout_different = cmpcount(h1, h2)
#     print(cout_different)
def cmpcount(str1, str2):
    count = 0
    for i in range(0, len(str1)):
        if str1[i] != str2[i]:
            count += 1
    return count

def avalanche(str1 = 'bob', str2 = 'aob'):
    bin1 = str1.encode('utf-8')
    bin2 = str2.encode('utf-8')
    hexstring1 = hashlib.md5(bin1).hexdigest()
    binstring1 = '{:08b}'.format(int(hexstring1, 16))
    # binstring1 = bin(int(hexstring1, 16))
    hexstring2 = hashlib.md5(bin2).hexdigest()
    binstring2 = '{:08b}'.format(int(hexstring2, 16))
    # binstring2 = bin(int(hexstring2, 16))
    print(str1 + " md5:" + binstring1)
    print(str2 + " md5:" + binstring2)
    print("两个哈希值不同的位数：" + str(cmpcount(binstring1, binstring2)))

def hash_password(password = b'p@$Sw0rD~7'):
    salt_length = 16
    salt = secrets.token_bytes(salt_length)
    key = pyscrypt.hash(password, salt, 2048, 8, 1, 32)
    return key.hex()
# # 测试：python 2 1
# if __name__ == "__main__":
#     str, nbyte, mbit = input().split()
#     nbyte = int(nbyte)
#     mbit = int(mbit)
#     avalanche(str, nbyte, mbit)

if __name__ == "__main__":
    # str = input("请输入你的姓名：")
    # password = input("请输入你的密钥：")
    # myhash(str)
    hash_md5()
    hash_sha256()
    myhash()
    avalanche()
    print(hash_password())
