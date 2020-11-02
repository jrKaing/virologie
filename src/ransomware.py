import os

# a changer en /tmp
baseUrl = './repertoire'

def encryptFile(filename):
    # process one file here
    print(baseUrl +'/'+ filename)


for root, dirs, files in os.walk(baseUrl, topdown=False):
   for name in files:
      full_path = os.path.join(root, name) 
      print(full_path)
      
