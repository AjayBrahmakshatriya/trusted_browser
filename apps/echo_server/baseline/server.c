#include "websockets.h"
#include <stdio.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char* argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <fd of web socket>\n", argv[0]);
		return -1;
	}
	int fd = atoi(argv[1]);

        if (fcntl(fd, F_GETFD) == -1 && errno == EBADF) {
                fprintf(stderr, "Bad file descriptor passed\n");
                return -1;
        }
	
	while(1) {
		char *message = read_websocket_message(fd);
		if (message == NULL)
			break;
		printf("%s\n", message);
		if (send_websocket_message(fd, message, strlen(message)+1) != 0){
			free(message);
			break;
		}
		free(message);	
	}
}
