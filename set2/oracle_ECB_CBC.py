from set1.detect_ECB import has_repeated_blocks
from set2.CBC_mode import encrypt_aes_128_cbc
from set2.ECB_with_padding import encrypt_aes_128_ecb
from random import randint
import random
import os

# extra optional parameter if we want to force the mode
def encryption_oracle(message, mode=None):
    key = os.urandom(16)
    random_header = os.urandom(randint(5, 10))
    random_footer = os.urandom(randint(5, 10))
    to_encrypt = random_header + message + random_footer

    if mode==None:
        mode = random.choice(['ECB', 'CBC'])
    if mode == 'ECB':
        return encrypt_aes_128_ecb(to_encrypt, key)
    elif mode == 'CBC':
        iv = os.urandom(16)
        return encrypt_aes_128_cbc(to_encrypt, iv, key)


for _ in range(10):
    mode = random.choice(['ECB', 'CBC'])
    # because of the random header and footer we need more that just 2 blocks of plaintext
    message = b'A ' *50
    ctxt = encryption_oracle(message, mode)
    detected_mode = 'ECB' if has_repeated_blocks(ctxt) else 'CBC'
    assert detected_mode == mode