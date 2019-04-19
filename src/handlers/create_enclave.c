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

char * read_websocket_message(int fd) {
	unsigned char a;
	read(fd, &a, sizeof(a));

	int FIN = a >> 7;
	if (FIN != 1) {
		fprintf(stderr, "FIN = 0 currently not handled\n");
		exit(-3);
	}
	
	int opcode = a & 0xf;
	if (opcode != 1) {
		fprintf(stderr, "OPCODE != 1 currently not handled\n");
		exit(-3);
	}

	unsigned char b;
	read(fd, &b, sizeof(b));
	
	int MASK = b >> 7;
	unsigned long long payload_length = b & 0x7f;
	
	if (payload_length == 126) {
		unsigned short c;
		read(fd, &c, sizeof(c));
		c = ntohs(c);
		payload_length = c;
	} else if (payload_length == 127) {
		unsigned long long c;
		read(c, &c, sizeof(c));
		c = ntohll(c);
		payload_length = c;
	}
	unsigned int mask_key = 0;
	if (MASK) {
		read(fd, &mask_key, sizeof(mask_key));
	}

	char * payload = malloc(payload_length + 1);
	if (!payload_length) {
		fprintf(stderr, "malloc for payload failed\n");
		exit(-4);
	}
	unsigned long total_read = 0;
	while(total_read != payload_length) {
		total_read += read(fd, payload, payload_length - total_read);
	}
	if (MASK) {
		char *mask = (void*)&mask_key;
		for (unsigned long i = 0; i < payload_length; i++) {
			payload[i] = payload[i] ^ mask[i % 4];
		}
	}
	payload[payload_length] = 0;
	return payload;
}

void send_websocket_message(int fd, char* payload, unsigned long long payload_length) {
	unsigned char a = 0x81;
	write(fd, &a, sizeof(a));
	unsigned char b = 0;

	if (payload_length < 126) {
		b = b | (unsigned char)payload_length;
		write(fd, &b, sizeof(b));
	}else {
		b = b | (unsigned char) 127;
		write(fd, &b, sizeof(b));
		unsigned long long payload_length_network = htonll(payload_length);
		write(fd, &payload_length_network, sizeof(payload_length_network));
	}
	write(fd, payload, payload_length);
}


int main(int argc, char* argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Not enough arguments to create enclave\n");
		return -1;
	}
	int fd = atoi(argv[1]);
	if (fcntl(fd, F_GETFD) == -1 && errno == EBADF) {
		fprintf(stderr, "Bad file descriptor passed\n");
		return -2;
	}
	char *message = read_websocket_message(fd);
	printf("Message received= %s\n", message);
	send_websocket_message(fd, message, strlen(message));
	free(message);
	return 0;
}
