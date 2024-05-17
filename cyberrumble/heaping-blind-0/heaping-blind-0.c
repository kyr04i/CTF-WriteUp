#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/sendfile.h>

#define NUM_TRIES 16
#define NUM_ROUNDS 64
#define NUM_MESSAGES 0x10

int round = 1;
int try_count;
int client_socket;
int is_adjacent;
int temp_swapped;
int num_temp_chunks;
FILE* client_read;
char* messages[NUM_MESSAGES];
char* metadata[NUM_MESSAGES];

/**
 * Read the flag from flag.txt and send it to client_socket
 */
void send_flag() {
    // open flag
    int fd = open("flag.txt", O_RDONLY);
    if (fd == -1) {
        perror("failed to open the flag");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    // send flag
    if (sendfile(client_socket, fd, NULL, 256) == -1) {
        perror("failed to send the flag");
        close(fd);
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    // cleanup
    close(fd);
    close(client_socket);
    exit(100);
}

/**
 * Handle the connection of client_socket
 */
void serve_connection() {
    // convert socket to unbuffered file handles
    client_read = fdopen(client_socket, "r");
    if (client_read == NULL) {
        perror("failed to convert socket to file handle");
        close(client_socket);
        exit(EXIT_FAILURE);
    }
    setvbuf(client_read, NULL, _IONBF, 0);

    // enter loop
    while (1) {
        dprintf(client_socket, "Welcome to the secret message service.\n"
            "\n"
            "1: Write a short message\n"
            "2: Write a long message\n"
            "3: Send a message\n"
            "4: Submit answer\n"
            "5: exit\n"
            "> "
        );
        int choice = 0;
        fscanf(client_read, "%d", &choice);
        switch(choice) {
            // Write a short message
            case 1:
                for (int i = 0; i < NUM_MESSAGES; i++) {
                    if (messages[i] == NULL) {
                        void* temp_chunks[2] = { NULL, NULL };
                        for (int j = 0; j < num_temp_chunks; j++) {
                            temp_chunks[j] = malloc(64);
                        }
                        messages[i] = malloc(64);
                        metadata[i] = malloc(16);
                        dprintf(client_socket, "Please enter your short message: ");
                        read(client_socket, messages[i], 0x64);
                        if (temp_swapped) {
                            free(temp_chunks[0]);
                            temp_chunks[0] = NULL;
                        }
                        free(temp_chunks[1]); // detect 2 chunk 
                        free(temp_chunks[0]);
                        dprintf(client_socket, "message stored at index %d\n", i);
                        break;
                    }
                }
                break;
            // Write a long message
            case 2:
                for (int i = 0; i < NUM_MESSAGES; i++) {
                    if (messages[i] == NULL) {
                        messages[i] = malloc(1040);
                        metadata[i] = malloc(16);
                        dprintf(client_socket, "Please enter your long message: ");
                        read(client_socket, messages[i], 1040);
                        dprintf(client_socket, "message stored at index %d\n", i);
                        break;
                    }
                }
                break;
            // Send a message
            case 3:
                dprintf(client_socket, "Please enter the index of the message: ");
                int index = 0;
                fscanf(client_read, "%d", &index);
                if (index < 0 || index >= NUM_MESSAGES) {
                    dprintf(client_socket, "index out of bounds\n");
                    continue;
                }
                // TODO: add logic for actually sending the message
                if (messages[index]) {
                    free(messages[index]);
                    messages[index] = NULL;
                    free(metadata[index]);
                    metadata[index] = NULL;
                }
                break;
            // Submit answer
            case 4:
                // check how many temporary chunks were allocated
                dprintf(client_socket, "How many temporary chunks were used?");
                long tmp_count = 0;
                fscanf(client_read, "%d", &tmp_count);
                if (tmp_count != num_temp_chunks) {
                    dprintf(client_socket, "Wrong!\n");
                    exit(101);
                } else {
                    dprintf(client_socket, "Congratulations, that was correct!\n");
                }

                // check if temporary chunks are swapped
                dprintf(client_socket, "Are the temporary chunks swapped on a malloc/free cycle?");
                long swapped = 0;
                fscanf(client_read, "%d", &swapped);
                if (swapped != temp_swapped) {
                    dprintf(client_socket, "Wrong!\n");
                    exit(101);
                } else {
                    dprintf(client_socket, "Congratulations, that was correct!\n");
                }

                // check if the chunks were adjacent
                dprintf(client_socket, "Are both chunks adjacent?");
                long adjacent = 0;
                fscanf(client_read, "%d", &adjacent);
                if (adjacent != is_adjacent) {
                    dprintf(client_socket, "Wrong!\n");
                    exit(101);
                } else {
                    dprintf(client_socket, "Congratulations, that was correct!\n");
                }

                // print flag or proceed to next round
                if (round >= NUM_ROUNDS) {
                    send_flag();
                } else {
                    exit(100);
                }
                break;
            // exit
            case 5:
                dprintf(client_socket, "Goodbye.\n");
                fclose(client_read);
                exit(EXIT_SUCCESS);
            // also exit on invalid input
            default:
                dprintf(client_socket, "Unsupported option!\n");
                fclose(client_read);
                exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char *argv[])
{
    // set up pipes
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    // get round
    if (argc > 1) {
        round = atoi(argv[1]);
    }

    // randomize heap start
    ssize_t size;
    if (getrandom(&size, 1, 0) == -1) {
        perror("failed to generate size (start)");
        exit(EXIT_FAILURE);
    }
    if (malloc(size << 4) == NULL) {
        perror("failed to malloc (start)");
        exit(EXIT_FAILURE);
    }

    // randomize choices
    long random = 0;
    if (getrandom(&random, sizeof(random), 0) == -1) {
        perror("failed to generate random");
        exit(EXIT_FAILURE);
    }
    is_adjacent = random & 1;  // 0 or 1
    temp_swapped = random >> 1 & 1; // 0 or 1
    do {
        random >>= 2;
        num_temp_chunks = random & 3;
    } while (num_temp_chunks == 3); 
    // num_temp_chunk < 3
    temp_swapped &= num_temp_chunks >> 1;

    // allocate possibly adjacent chunks
    if ((messages[0] = malloc(64)) == NULL) {
        perror("failed to malloc (first)");
        exit(EXIT_FAILURE);
    }
    if (!is_adjacent) {
        if (malloc(0x28) == NULL) {
            perror("failed to malloc (spacer)");
            exit(EXIT_FAILURE);
        }
    }
    if ((messages[1] = malloc(64)) == NULL) {
        perror("failed to malloc (second)");
        exit(EXIT_FAILURE);
    }

    // some more randomization
    if (getrandom(&size, 1, 0) == -1) {
        perror("failed to generate size (end)");
        exit(EXIT_FAILURE);
    }
    if (malloc(size << 4) == NULL) {
        perror("failed to malloc (end)");
        exit(EXIT_FAILURE);
    }
    metadata[0] = malloc(16);
    metadata[1] = malloc(16);

    // get socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("failed to create socket");
        exit(EXIT_FAILURE);
    }

    // bind socket to random port
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(server_socket, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
        perror("failed to bind socket");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // listen on port
    if (listen(server_socket, 0x10) == -1) {
        perror("failed to listen on socket");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // get port
    socklen_t addr_len = sizeof(addr);
    if (getsockname(server_socket, (struct sockaddr*) &addr, &addr_len) == -1) {
        perror("failed to get socket information");
        close(server_socket);
        exit(EXIT_FAILURE);
    }
    printf("listening on port %d\n", ntohs(addr.sin_port));

    // start timer
    alarm(600);

    // allow multiple tries
    for (try_count = 0; try_count < NUM_TRIES; try_count++) {

        client_socket = accept(server_socket, NULL, NULL);
        if (client_socket == -1) {
            perror("failed to accept connection");
            close(server_socket);
            exit(EXIT_FAILURE);
        }

        pid_t child = fork();
        if (child == 0) {
            serve_connection();
        } else if (child == -1) {
            perror("failed to fork child");
            close(server_socket);
            exit(EXIT_FAILURE);
        } else {
            close(client_socket);
        }

        // wait for child
        int status = 0;
        if (waitpid(child, &status, 0) == -1) {
            perror("failed to wait for child");
            close(server_socket);
            exit(EXIT_FAILURE);
        }

        // evaluate status
        switch (WEXITSTATUS(status)) {
            case 100:
                char next_round[4] = "";
                snprintf(next_round, sizeof(next_round), "%hhd", round+1);
                char* new_argv[3] = {argv[0], next_round, NULL};
                execve(argv[0], new_argv, NULL);
                perror("failed to launch next round");
            case 101:
                close(server_socket);
                exit(EXIT_FAILURE);
        }
    }

    return 0;
}
