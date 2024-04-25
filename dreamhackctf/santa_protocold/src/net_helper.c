#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "include/net_helper.h"
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>


static char *username;
const char *signature = "Merry_Christmas!";

pid_t tcp_open(packet *obj)
{
    pid_t pid;

    if ((obj->clientsock = accept(obj->serversock, (struct sockaddr *)&obj->client_addr, &(obj->addr_len))) == -1)
    {
        perror("Error accepting connection");
        exit(EXIT_FAILURE);
    }

    pid = fork();

    switch (pid)
    {   
        case 0:
            close(obj->serversock);
            obj->serversock = -1;
            santa_protocol_receive(obj);
            break;
        case -1:
            exit(EXIT_FAILURE);
        default:
            break;
    }
    
    return pid;
}

int write_name(packet *obj)
{
    if(username == NULL)
    {
        username = (char *)malloc(obj->header.data_len + 1);
        int bytes_received = recv(obj->clientsock, username, obj->header.data_len - 1, 0);
        if(username == NULL)
        {
            santa_protocol_error_res(obj, ALLOCATION_ERROR);
            exit(1);
        }
        char *block = malloc(0x40);
        if(block == NULL)
        {
            santa_protocol_error_res(obj, ALLOCATION_ERROR);
            exit(1);
        }
        
        
        snprintf(block, 0x40, "RECORD: %d bytes\n", bytes_received);

        int len = send(obj->clientsock, block, obj->header.data_len, 0x0);

        free(block);
    }
    return 0;
}

int read_name(packet *obj)
{
    if(username != NULL)
    {  
        int len = send(obj->clientsock, username, strlen(username), 0x0);
        free(username);
        username = NULL;
        return 0;
    }
    else
    {
        return -1;
    }
}


void begin_init(packet *obj)
{
    username = NULL;

    while (1) {
        santa_protocol_receive(obj);
          
        switch(obj->header.commands)
        {
            case WRITE_NAME:
                write_name(obj);
                break;
            case READ_NAME:
                read_name(obj);
                break;
            default:
                santa_protocol_error_res(obj, INVALID_HEADER);
                exit(EXIT_FAILURE);
        }
       
    }
}

int santa_protocol_receive(packet *obj) 
{
    char header[HEADER_LEN+1] = {0, };

    int bytes_received = recv(obj->clientsock, header, HEADER_LEN, 0);

    if (bytes_received <= 0)
    {
        close(obj->clientsock);
        exit(1);
    }

    if (memcmp(header, signature, SIGNATURE_LENGTH))
    {
        santa_protocol_error_res(obj, INVALID_SIGNATURE);
        close(obj->clientsock);
        exit(1);
    }

    if(header[0x10+0x0] > 0x1 || header[0x10+0x1] > 0x5)
    {
        santa_protocol_error_res(obj, INVALID_HEADER);
        close(obj->clientsock);
        exit(1);
    }

    memcpy(&obj->header.signature, &header[0], 0x10);
    memcpy(&obj->header.flags, &header[0x10], 1);
    memcpy(&obj->header.commands, &header[0x11], 1);
    obj->header.ID = htons(*(uint16_t *)&header[0x12]);
    obj->header.data_len = htons(*(uint16_t *)&header[0x14]);

    return 0;
}

int santa_protocol_error_res(packet *obj, int error_code)
{
    int len = 0;
    uint8_t *block = (uint8_t *)malloc(0x100);
    memcpy(block, signature, SIGNATURE_LENGTH);
    *(block+0x10) = 0x1;
    *(block+0x10+1) = obj->header.commands;

    *(uint16_t *)(block+0x10+2) = htons(obj->header.ID);
    
    char buf[1024] = {0, };
    uint16_t data_len = 0;

    switch(error_code)
    {
        case INVALID_HEADER:
            snprintf(buf, 0x100,"ERORR: INVALID HEADER\nCODE:%hd", INVALID_HEADER);
            data_len = strlen(buf);
            *(uint16_t *)(block+0x10+4) = htons(data_len);
            *(uint16_t *)(block+0x10+16) = htons(INVALID_HEADER);
            break;
        case INVALID_SIGNATURE:
            snprintf(buf, 0x100 ,"ERORR: INVALID_SIGNATURE\nCODE:%hd", INVALID_SIGNATURE);
            data_len = strlen(buf);
            *(uint16_t *)(block+0x10+4) = htons(data_len);
            *(uint16_t *)(block+0x10+6) = htons(INVALID_SIGNATURE);
            break;
        case INVALID_DATALEN:
            snprintf(buf, 0x100 ,"ERORR: INVALID_DATALEN\nCODE:%hd", INVALID_DATALEN);
            data_len = strlen(buf);
            *(uint16_t *)(block+0x10+4) = htons(data_len);
            *(uint16_t *)(block+0x10+6) = htons(INVALID_DATALEN);
            break;
        case ALLOCATION_ERROR:
            snprintf(buf, 0x100 ,"ERORR: MEMORY ALLOCATION ERROR\nCODE:%hd", ALLOCATION_ERROR);
            data_len = strlen(buf);
            *(uint16_t *)(block+0x10+4) = htons(data_len);
            *(uint16_t *)(block+0x10+6) = htons(ALLOCATION_ERROR);
            break;
    }

    memcpy(block+0x10+0x8, buf, data_len);
    len = send(obj->clientsock, block, HEADER_LEN+data_len, 0x0);
    free(block);

    return len;
}

int santa_protocol_res(packet *obj)
{
    int len = 0;
    char *block = (char *)malloc(HEADER_LEN+1);

    obj->header.flags=1;

    memcpy(&block[0], signature, 0x10);
    memcpy(&block[0x10], &obj->header.flags, 1);
    memcpy(&block[0x11],&obj->header.commands,  1);
    *(uint16_t *)&block[0x12]= htons(obj->header.ID);

    memset(&block[0x14], 0 , 2);
    memset(&block[0x16], SUCCESS, 2);
    memset(&block[0x16], SUCCESS, 2);

    len = send(obj->clientsock, block, HEADER_LEN, 0x0);

    free(block);
    return len;
}
