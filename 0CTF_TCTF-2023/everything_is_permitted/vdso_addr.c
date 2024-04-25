// compiled: gcc -g -m32 vdso_addr.c -o vdso_addr
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    printf("vdso addr: %105$p\n");
    return 0;
}