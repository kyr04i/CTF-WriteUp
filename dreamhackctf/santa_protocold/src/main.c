#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include "include/protocol.h"
#include "include/net_helper.h"

#define PORT 32912

char tree[] = "                                 |L\n                                ,' `\n                               /.o `,\n                               `, |-`,\n                              -',    '  \n                             `,'_)   '\\ \n                             ,'    `-`,  \n                            _`o,-   (_)/ \n                           '_ '    o  `-,\n                           /   ,-L   `-' \n                          _`-`_     ,  `'.\n                         ;.  (,'  `| `.-. \\\n                         ,``_'    (_)  o `'\n                        ,` '_  ,|\\   o   _ \\ \n                       /..-(_)' |','..-`(_)-`\n                                |  |        \n                       -bf-   --'  `--\n\tmade by neko_hat";

static sig_atomic_t gotsigchld = 0;
int global_sock;

static void child_handler(void)
{
    int fd;
    int status;
    pid_t pid;
  
#ifndef WAIT_ANY
#define WAIT_ANY (-1)
#endif /* ! WAIT_ANY */

    while ((pid = waitpid(WAIT_ANY, &status, WNOHANG)) > 0) {
            
    }
    
}

void init() {
  setvbuf(stderr, 0, 2, 0);
}

int daemonize(int nochdir, int noclose)
{
    switch (fork()) {
    case 0:
        break;
    case -1:
        return -1;
    default:
        _exit(0);
    }

    switch (fork()) {
    case 0: 
        break;
    case -1:
        return -1;
    default:
        _exit(0);
    }

    if (!nochdir)
        chdir("/");


    return 0;
}

static packet obj;

int main()
{
    int server_socket, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    pid_t pid;
    
    if ((daemonize(0, 0) != 0))
        exit(-1);

    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Error creating server socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Error binding server socket");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 5) == -1) {
        perror("Error listening for connections");
        exit(EXIT_FAILURE);
    }
    printf("Server is listening on port %d...\n", PORT);

    memset(poll_set, 0, sizeof(poll_set));

    poll_set[0].fd = server_socket;
    poll_set[0].events = POLLIN;
    obj.serversock = server_socket;
    char buf[4096] = {0, };
    
    int flag = 0;

    while (1) {
         if (gotsigchld) {
            gotsigchld = 0;
            child_handler();
            continue;
        }

        int ret = poll(poll_set, num_clients + 1, -1);

        if (ret == -1)
        {
            perror("Error in poll");
            exit(EXIT_FAILURE);
        }

        if (poll_set[0].revents &  (POLLIN | POLLERR | POLLHUP | POLLNVAL))
        {
  
            obj.clientsock = client_sock;
            poll_set[num_clients + 1].fd = client_sock;
            poll_set[num_clients + 1].events = POLLIN;
            num_clients++;
            int len = 0;
            pid = tcp_open(&obj);

            if (pid == 0)
                {
                switch(obj.header.commands)
                {
                case SERVER_HELLO:
                    //puts("GIFT!!");
                    snprintf(buf, 4096, "%s\nI'll send gift for you!\nstderr addr: %p\n", tree, stderr);
                    len = send(obj.clientsock, buf, strlen(buf), 0x0);
                    exit(EXIT_SUCCESS);
                case OPEN_SESSION:
                    if(!flag)
                    {
                        dup2(obj.clientsock, 1);
                        dup2(obj.clientsock, 0);
                        flag=1;
                    }
                    santa_protocol_res(&obj);
                    begin_init(&obj);
                    exit(EXIT_SUCCESS);
                default:
                    exit(EXIT_SUCCESS);
                }
            }
        }   
    }

    close(server_socket);

    return 0;
}
0