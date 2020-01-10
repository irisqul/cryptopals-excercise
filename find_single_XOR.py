from XOR import xor
from binascii import hexlify, unhexlify

class InvalidMessageException(Exception):
    pass


def attack_single_byte_xor(ciphertext):
    # a variable to keep track of the best candidate so far
    best = None
    for i in range(2 ** 8):  # for every possible key
        # converting the key from a number to a byte
        candidate_key = i.to_bytes(1, byteorder='big')
        # the byte string we will XOR the message against is usually called the "keystream"
        keystream = candidate_key * len(ciphertext)
        candidate_message = xor(ciphertext, keystream)
        ascii_text_chars = list(range(97, 122)) + [32]
        nb_letters = sum([x in ascii_text_chars for x in candidate_message])
        # if the obtained message has more letters than any other candidate before
        if best == None or nb_letters > best['nb_letters']:
            # store the current key and message as our best candidate so far
            best = {"message": candidate_message, 'nb_letters': nb_letters, 'key': candidate_key}
    # if the best message is too low quality
    if best['nb_letters'] > 0.7*len(ciphertext):
        return best
    else:
        raise InvalidMessageException('best candidate message is: %s' % best['message'])


with open('ciphered_4') as data_file:
    ciphertext_list = [
        # the 'strip' is to remove the "newline" character
        # which python keeps when reading a file line by line
        unhexlify(line.strip())
        for line in data_file
    ]

candidates = list()
# for the "enumerate" builtin function, see
# https://docs.python.org/3/library/functions.html#enumerate
for (line_nb, ciphertext) in enumerate(ciphertext_list):
    try:
        message = attack_single_byte_xor(ciphertext)['message']
    except InvalidMessageException:
        pass
    else:
        candidates.append({
            'line_nb': line_nb,
            'ciphertext': ciphertext,
            'message': message
        })
print (candidates)