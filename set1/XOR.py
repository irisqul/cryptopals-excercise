from binascii import hexlify, unhexlify

one = "1c0111001f010100061a024b53535009181c"
two = "686974207468652062756c6c277320657965"
a = unhexlify(one)
b = unhexlify(two)

def xor(a, b):
    #bitwise XOR of bytestrings
    return bytes([ x^y for (x,y) in zip(a, b)])








