from XOR import bxor
from binascii import hexlify, unhexlify


ciphertext = unhexlify('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')


def attack_single_byte_xor(ciphertext):
    # a variable to keep track of the best candidate so far
    best = None
    for i in range(2**8): # for every possible key
        # converting the key from a number to a byte
        candidate_key = i.to_bytes(1, byteorder='big')
        # the byte string we will XOR the message against is usually called the "keystream"
        keystream = candidate_key*len(ciphertext)
        candidate_message = bxor(ciphertext, keystream)
        ascii_text_chars = list(range(97, 122)) + [32]
        nb_letters = sum([ x in ascii_text_chars for x in candidate_message])
        # if the obtained message has more letters than any other candidate before
        if best == None or nb_letters > best['nb_letters']:
            # store the current key and message as our best candidate so far
            best = {"message": candidate_message, 'nb_letters': nb_letters, 'key': candidate_key}
    return best

result = attack_single_byte_xor(ciphertext)

print('key:', result['key'])
print('message:', result['message'])
print('nb of letters:', result['nb_letters'])

