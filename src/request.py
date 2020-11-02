import requests

url = 'http://localhost:8888/key.txt'
resp = requests.get(url)
key=resp.text

url = 'http://localhost:8888/iv.txt'
resp = requests.get(url)
iv=resp.text

#pour voir si la key est bien dans la variable, A SUPPRIMER#
print(key)
print(iv)