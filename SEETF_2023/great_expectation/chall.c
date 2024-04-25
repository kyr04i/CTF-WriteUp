// gcc -no-pie -fno-stack-protector chall.c -o chall

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#define floatbuffer_len 3
#define string_len 0x107

int idx;

void input_floats()
{
    char canary = 'A';
    char buffer[floatbuffer_len]; // 3

    for (idx = 0; idx < floatbuffer_len; idx++) // 3
    {
        puts("Give me a crazy number!");
        scanf("%f", &buffer[idx]);
    }

    if (canary != 'A')
    {
        exit(0);
    }
}

int main()
{
    char canary = 'A';
    char buffer[string_len]; // 0x107

    setbuf(stdout, 0);
    setbuf(stdin, 0);

    puts("I live my life taking chances. Let's see how much of a risk-taker you are! Tell me an adventurous tale.");
    read(0, buffer, string_len); // 0x107

    input_floats();

    if (canary != 'A')
    {
        exit(0);
    }

    return 0;
}



41007fff
449a4000

0x7fffffffdc7c:	0xffffdda041007fff	0x0040129800007fff
0x7fffffffdc8c:	0x4242414100000000	0x000000400000000a
0x7fffffffdc7c:	0xffffdda0449a4000	0x0040129800007fff
0x7fffffffdc8c:	0x4242414100000000	0x000000400000000a

af30 
3050
b030
9a80
df50