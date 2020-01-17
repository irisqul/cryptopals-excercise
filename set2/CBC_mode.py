from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from math import ceil
from set1.XOR import xor
from set2.padding import pkcs7_padding, pkcs7_strip
from random import randint
import os

backend = default_backend()

def encrypt_aes_128_block(msg, key):
    '''unpadded AES block encryption'''
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(msg) + encryptor.finalize()

def decrypt_aes_128_block(ctxt, key):
    '''unpadded AES block decryption'''
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ctxt) + decryptor.finalize()
    return decrypted_data

def split_bytes_in_blocks(x, blocksize):
    nb_blocks = ceil(len(x)/blocksize)
    return [x[blocksize*i:blocksize*(i+1)] for i in range(nb_blocks)]

def encrypt_aes_128_cbc(msg, iv, key):
    result = b''
    previous_ctxt_block = iv
    padded_ptxt = pkcs7_padding(msg, block_size=16)
    blocks = split_bytes_in_blocks(padded_ptxt, blocksize=16)

    for block in blocks:
        to_encrypt = xor(block, previous_ctxt_block)
        new_ctxt_block = encrypt_aes_128_block(to_encrypt, key)
        result += new_ctxt_block
        # for the next iteration
        previous_ctxt_block = new_ctxt_block

    return result

def decrypt_aes_128_cbc(ctxt, iv, key):
    result = b''
    previous_ctxt_block = iv
    blocks = split_bytes_in_blocks(ctxt, blocksize=16)

    for block in blocks:
        to_xor = decrypt_aes_128_block(block, key)
        result += xor(to_xor, previous_ctxt_block)
        assert len(result) != 0
        # for the next iteration
        previous_ctxt_block = block

    return pkcs7_strip(result)


for _ in range(5):
    length = randint(5, 50)
    msg = os.urandom(length)
    key = os.urandom(16)
    iv = os.urandom(16)
    ctxt = encrypt_aes_128_cbc(msg, iv, key)
    assert decrypt_aes_128_cbc(ctxt, iv, key) == msg

with open("ciphered_10", "rb") as file:
    data = file.read()

key = os.urandom(16)
iv = os.urandom(16)
print(encrypt_aes_128_cbc(data, iv, key))


