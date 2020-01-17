from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode

hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
b64_string = b64encode(unhexlify(hex_string))
print(b64_string)
