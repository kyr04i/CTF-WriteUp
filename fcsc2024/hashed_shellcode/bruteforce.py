from hashlib import sha256
from string import ascii_letters
from itertools import product

start = "FCSC_"
for end in product(ascii_letters, repeat=7-len(start)):
    end = "".join(end)
    hash = sha256((start + end).encode()).hexdigest()
    if hash[0:8] == "525e0f05":
        print(start + end)
        print(hash)
        break

# FCSC_jdijOI