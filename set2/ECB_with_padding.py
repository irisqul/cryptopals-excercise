from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from set2.padding import pkcs7_padding, pkcs7_strip
from random import randint
import os

backend = default_backend()

def encrypt_aes_128_ecb(msg, key):
    padded_msg = pkcs7_padding(msg, block_size=16)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(padded_msg) + encryptor.finalize()

def decrypt_aes_128_ecb(ctxt, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data =  decryptor.update(ctxt) + decryptor.finalize()
    message = pkcs7_strip(decrypted_data)
    return message

for _ in range(5):
    length = randint(5,50)
    msg = os.urandom(length)
    key = os.urandom(16)
    ctxt = encrypt_aes_128_ecb(msg, key)
    assert decrypt_aes_128_ecb(ctxt, key) == msg