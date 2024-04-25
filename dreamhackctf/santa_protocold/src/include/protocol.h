#pragma once
#include <stdint.h>
#include <arpa/inet.h>           


#define SIGNATURE_LENGTH 0x10

#define BLOCK_SIZE 0x8

#define REQUEST 0x0
#define RESPONSE 0x1

#define SERVER_HELLO 0x1
#define OPEN_SESSION 0x2
#define CLOSE_SESSION 0x3
#define WRITE_NAME 0x4
#define READ_NAME 0x5

#define ALLOCATION_ERROR 0xfffc
#define INVALID_DATALEN 0xfffd
#define INVALID_SIGNATURE 0xfffe
#define INVALID_HEADER 0xffff

#define SUCCESS 0x0000

struct header_block {
    char signature[SIGNATURE_LENGTH];
    uint8_t flags;
    uint8_t commands;
    uint16_t ID;
    uint16_t data_len;
    union {
        int16_t padd;
        int16_t error_code;
    } header_data;
} typedef header_block;

struct packet {
    header_block header;
    char *data;
    int serversock;
    int clientsock;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    pid_t child_pid;
} typedef packet;