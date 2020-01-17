from set1.XOR import xor
from binascii import hexlify

#bites from message
message = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
# bites from key
key = b'ICE'
def xor_with_key(message,key):
    #form keystream, repeat as many times as needed
    keystream = key*(len(message)//len(key) + 1)
    #XOR
    ciphertext = xor(message, keystream)
    return hexlify(ciphertext)

print(xor_with_key(message, key))
