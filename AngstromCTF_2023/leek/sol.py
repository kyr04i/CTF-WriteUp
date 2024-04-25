from socket import socket, AF_INET, SOCK_STREAM

HOST = 'challs.actf.co' 
PORT = 31402

with socket(AF_INET, SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    while True:
        data = s.recv(1024).decode()
        print(data)  # add this line to print everything received from the server
        
        if 'name?' in data:
            animal_names = data[data.index('(')+1:data.index(')')].split(' and ')
            animal_code = animal_names[0][:3] + animal_names[1][-3:]
            print(animal_code)  # add this line to see the animal code being sent to the server
            s.sendall(animal_code.encode())
        elif 'actf{' in data:
            print(data)  # add this line to print the flag if it's received
            break