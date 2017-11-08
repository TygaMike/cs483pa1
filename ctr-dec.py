import argparse
import random
import sys
import multiprocessing
import copy_reg
import types
import binascii
import base64
from functools import partial
from Crypto.Cipher import AES

def parse_file(arg_file):
    with open(arg_file) as f:
        content = f.readlines()

    return content

# Need for multiprocessing in a class instance.
def _pickle_method(m):
    if m.im_self is None:
        return getattr, (m.im_class, m.im_func.func_name)
    else:
        return getattr, (m.im_self, m.im_func.func_name)

copy_reg.pickle(types.MethodType, _pickle_method)

class CTR(object):
    counter = 1

    def __init__(self, output_file, iv=None):
        if iv is None:
            iv = self.generate_iv()

        if len(str(iv)) > 32:
            iv = self.strip_iv(iv)

        self.iv = iv
        self.output_file = output_file

    def generate_iv(self):
        return random.randint(1, sys.maxsize)

    def strip_iv(self, value):
        return int(str(value)[:32])

    def encrypt(self, key, message):
        cipher_blocks = []
        message_blocks = self.split_message_into_blocks(message)
        self.iv = int("".join(message_blocks[0]))
        del message_blocks[0]
        pool = multiprocessing.Pool(processes=4)
        results = pool.map(partial(self.encrypt_block, key), enumerate(message_blocks))
        pool.close()
        pool.join()
        
        for index, block in enumerate(message_blocks):
            str_block = ''.join(block).decode("hex")
            binary_result = results[index].decode("hex")

            xored = "".join(chr(ord(x) ^ ord(y)) for x, y in zip(str_block, binary_result))
            cipher_blocks.append(xored.encode("hex"))

        cipher_text = ''.join(cipher_blocks)
        print cipher_text.decode("hex")
        self.write_to_file(cipher_text.decode("hex"))

    def encrypt_block(self, key, (index, message_block)):
        count = index + 1

        if len(key) > 16:
            new_key = key[:16]
        elif len(key) < 16:
            new_key = '{0: >16}'.format(key)
        else:
            new_key = key

        cipher = AES.AESCipher(new_key, AES.MODE_ECB)
        new_iv = self.iv + count

        if len(str(new_iv)) < 32:
            str_new_iv = '{0:0>32}'.format(str(new_iv))
        else:
            str_new_iv = str(new_iv)

        output = cipher.encrypt(str_new_iv)
        return binascii.hexlify(bytearray(output)).decode('utf-8')

    def split_message_into_blocks(self, message):
        return [message[i:i+32] for i in range(0, len(message), 32)]
    
    def write_to_file(self, text):
        with open(self.output_file, 'w') as f:
            f.write(text)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    required_group = parser.add_argument_group('required arguments')

    parser.add_argument("-v",
        "--iv_file",
        help="specifies the path of a file storing a valid IV as a hex encoded string, if not present a random IV should be generated",)

    required_group.add_argument("-k", 
        "--key_file", 
        help="specifies a file storing a valid AES key as a hex encoded string",
        required=True)

    required_group.add_argument("-i",
        "--input_file",
        help="specifies the path of the file that is being operated on",
        required=True)

    required_group.add_argument("-o",
        "--output_file",
        help="specifies the path of the file where the resulting output is stored",
        required=True)

    args = parser.parse_args()

    if args.iv_file:
        iv_hex = parse_file(args.iv_file)
        iv = int(iv_hex[0].strip(), 16)
    else:
        iv = None
    
    key_hex = parse_file(args.key_file)
    key = key_hex[0].strip().decode("hex")
    message = []
    for line in parse_file(args.input_file):
        message.extend(list(line))
    output = args.output_file

    ctr = CTR(output, iv=iv) 
    ctr.encrypt(key, message)