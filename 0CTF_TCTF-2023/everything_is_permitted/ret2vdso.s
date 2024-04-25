push ebp
mov ebp, esp
sub esp, 128
lea eax, buf
push 4096
push eax
push 0
mov eax, 0
call    read
add esp, 12

mov esi, eax

push esi
lea eax, buf
push eax 
lea eax, -128[ebp]
push eax
call memcpy
add esp, 12

lea eax, -128[ebp]
push esi
push eax
push 1
mov eax, 0
call    write
add esp, 12

mov eax, 0
mov esp, ebp
pop ebp
ret