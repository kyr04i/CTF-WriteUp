#pragma once

#include "protocol.h"
#include <stdbool.h>
#include <sys/types.h>
#include <poll.h>

#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024
#define HEADER_LEN 0x18

static int num_clients = 0;
static struct pollfd poll_set[MAX_CLIENTS + 1];

pid_t tcp_open(packet *obj);
int recv_data(packet *obj);
int santa_protocol_receive(packet *obj);
int santa_protocol_error_res(packet *obj, int error_code);
void begin_init(packet *obj);
int santa_protocol_res(packet *obj);