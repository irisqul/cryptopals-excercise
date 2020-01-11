from XOR import xor
from base64 import b64encode, b64decode
from find_single_XOR import attack_single_byte_xor

def hamming_distance(a, b):
    #humming distance is between two strings of equal length is the number of positions at which the corresponding
    #symbols are different. In other words, it measures the minimum number of substitutions required to change one
    #string into the other, or the minimum number of errors that could have transformed one string into the other
    return sum(bin(byte).count('1') for byte in xor(a, b))

with open("ciphered_6") as file:
    ciphertext = b64decode(file.read())


def score_vigenere_key_size(candidate_key_size, ciphertext):
    # we take samples bigger than just one time the candidate key size
    slice_size = 2 * candidate_key_size

    # the number of samples we can make
    # given the ciphertext length
    nb_measurements = len(ciphertext) // slice_size - 1

    # the "score" will represent how likely it is
    # that the current candidate key size is the good one
    # (the lower the score the *more* likely)
    score = 0
    for i in range(nb_measurements):
        s = slice_size
        k = candidate_key_size
        # in python, "slices" objects are what you put in square brackets
        # to access elements in lists and other iterable objects.
        # see https://docs.python.org/3/library/functions.html#slice
        # here we build the slices separately
        # just to have a cleaner, easier to read code
        slice_1 = slice(i * s, i * s + k)
        slice_2 = slice(i * s + k, i * s + 2 * k)

        score += hamming_distance(ciphertext[slice_1], ciphertext[slice_2])

    # normalization: do not forget this
    # or there will be a strong biais towards long key sizes
    # and your code will not detect key size properly
    score /= candidate_key_size

    # some more normalization,
    # to make sure each candidate is evaluated in the same way
    score /= nb_measurements

    return score

def find_vigenere_key_length(ciphertext, min_length=2, max_length=30):
    # it just outputs the key size for which
    # the score at the "score_vigenere_key_size" function is the *lowest*
    key = lambda x: score_vigenere_key_size(x,ciphertext)
    return min(range(min_length, max_length), key=key)

def attack_repeating_key_xor(ciphertext):
    keysize = find_vigenere_key_length(ciphertext)

    # we break encryption for each character of the key
    key = bytes()
    message_parts = list()
    for i in range(keysize):
        # the "i::keysize" slice accesses elements in an array
        # starting at index 'i' and using a step of 'keysize'
        # this gives us a block of "single-character XOR" (see figure above)
        part = attack_single_byte_xor(bytes(ciphertext[i::keysize]))
        key += part["key"]
        message_parts.append(part["message"])

    # then we rebuild the original message
    # by putting bytes back in the proper order
    message = bytes()
    for i in range(max(map(len, message_parts))):
        message += bytes([part[i] for part in message_parts if len(part)>=i+1])

    return {'message':message, 'key':key}

result = attack_repeating_key_xor(ciphertext)
print("key:",result["key"],'\n')
print('message:\n')
print(result["message"].decode())