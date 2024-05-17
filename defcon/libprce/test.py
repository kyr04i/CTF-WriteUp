import requests
import subprocess
import os
import hashlib
import datetime


time_string = datetime.datetime(2006, 4, 23, 7)
seconds_since_epoch = int(time_string.timestamp()) // 86400

md5_out = hashlib.md5(f"{str(seconds_since_epoch)}\n".encode()).hexdigest()
with open("a", "w") as f:
    f.write(md5_out * 10)
    
key = subprocess.getoutput(
    "echo 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' | grep -o . | shuf --random-source ./a | tr -d '\n'"
)
print(key)
