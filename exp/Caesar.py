# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

def caesar_encrypt(key,text = 'abcxyzABCXYZ'):
    ciphertext = ''
    for i in range(len(text)):
        char = text[i]
        if (char.isupper()):
            ciphertext += chr((ord(char) + key - 65) % 26 + 65)
        else:
            ciphertext += chr((ord(char) + key - 97) % 26 + 97)
    return ciphertext
# def caesar_decrypt(key,text = 'abcxyzABCXYZ'):
#     key = -key
#     plaintext = ''
#     for i in range(len(text)):
#         char = text[i]
#         if (char.isupper()):
#             plaintext += chr((ord(char) + key - 65) % 26 + 65)
#         else:
#             plaintext += chr((ord(char) + key - 97) % 26 + 97)
#     return plaintext
def caesar_decrypt(message):
    LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    letters = "abcdefghijklmnopqrstuvwxyz"
    for key in range(26):
        translated = ''
        for symbol in message:
            if symbol in LETTERS:
                num = LETTERS.find(symbol)
                num = num - key
                if num < 0:
                    num = num + len(LETTERS)
                translated = translated + LETTERS[num]
            elif symbol in letters:
                num = letters.find(symbol)
                num = num - key
                if num < 0:
                    num = num + len(letters)
                translated = translated + letters[num]
            else:
                translated = translated + symbol
        print('Hacking key #%s: %s' % (key, translated))

SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.'

def caesarCipher(mode, message, key):
    if mode[0] == 'd':
        key = -key
    ciphertext = ''
    for symbol in message:
        symbolIndex = SYMBOLS.find(symbol)
        if symbol.isalpha():
          num = symbolIndex + key
          if num > len(SYMBOLS):
            num -= len(SYMBOLS)
          else:
            num += len(SYMBOLS)
            ciphertext += chr(num)
        else:
            ciphertext += symbol
    return ciphertext



if __name__ == '__main__':
    k = 3
    # text = input("请输入需要加密的字符串：")
    print(caesar_encrypt(k))
    print(caesar_encrypt(4,"AMBIDEXTROUS:Able to pick with equal skill a right-hand pocket or a left."))
    # print(caesar_decrypt(k))
    caesar_decrypt("JASKLjaskldj")

