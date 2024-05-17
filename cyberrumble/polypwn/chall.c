#include <stdio.h>
#include <stdlib.h>

static int xgetchar(void) {
    int x = getchar();
    if (x == EOF)
        exit(1);
    return x;
}

static long get_int(void) {
    long x;
    scanf("%ld", &x);
    while (xgetchar() != '\n') {}
    return x;
}

static void add_user(void) {
    char buf[0x20];
    printf("enter user:\n");
    int i = 0, c;
    while ((c = xgetchar()) != '\n') {
        buf[i++] = c;
    }
    printf("user: %s\n", buf);
    // TODO: add user to db
}

int main(void) {
    setbuf(stdout, NULL);
    printf("welcome to advanced user manager 5000!!  menu:  1. add user  2. exit\n");
    for (;;) {
        long choice = get_int();
        if (choice == 1)
            add_user();
        else if (choice == 2)
            return 0;
        else
            printf("invalid choice\n");
    }
}
