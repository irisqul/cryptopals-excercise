def pkcs7_padding(message, block_size):
    #calculate if we need a padding
    padding_length = block_size - (len(message) % block_size)
    if padding_length == 0:
        padding_length = block_size
    padding = bytes([padding_length]) * padding_length
    return message + padding

def pkcs7_strip(data):
    padding_length = data[-1]
    return data[:- padding_length]


# print(pkcs7_padding(b"YELLOW SUBMARINE\n", 16))