with open("babybs.bin", "rb") as f:
    data = bytearray(f.read())

print(data[9:9+15])