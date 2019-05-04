#ifndef WEBSOCKETS_H
#define WEBSOCKETS_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <fcntl.h>

#if __BIG_ENDIAN__
    #define htonll(x)   (x)
    #define ntohll(x)   (x)
#else
    #define htonll(x)   ((((uint64_t)htonl(x&0xFFFFFFFF)) << 32) + htonl(x >> 32))
    #define ntohll(x)   ((((uint64_t)ntohl(x&0xFFFFFFFF)) << 32) + ntohl(x >> 32))
#endif

#ifdef __cplusplus
extern "C" {
#endif
char * read_websocket_message(int fd);

int send_websocket_message(int fd, char * payload, unsigned long long payload_length);
#ifdef __cplusplus
}
#endif


#endif
