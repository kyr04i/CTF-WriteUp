#include <unistd.h>

int main()
{
    char *argv[] = {"/bin/cat", "flag.txt"};
    char *envp[] = {NULL};
    execve("/bin/cat", argv, envp);
}