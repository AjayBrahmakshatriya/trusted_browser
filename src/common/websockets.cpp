#include "websockets.h"

char * read_websocket_message(int fd) {
	unsigned char a;
	if(!read(fd, &a, sizeof(a)))
		return NULL;

	int FIN = a >> 7;
	if (FIN != 1) {
		fprintf(stderr, "FIN = 0 currently not handled\n");
		exit(-3);
	}

	int opcode = a & 0xf;
	if (opcode == 0x8)
		return NULL;
	if (opcode != 1) {
		fprintf(stderr, "OPCODE != 1 currently not handled\n");
		exit(-3);
	}

	unsigned char b;
	if(!read(fd, &b, sizeof(b)))
		return NULL;

	int MASK = b >> 7;
	unsigned long long payload_length = b & 0x7f;

	if (payload_length == 126) {
		unsigned short c;
		if(!read(fd, &c, sizeof(c)))
			return NULL;
		c = ntohs(c);
		payload_length = c;
	} else if (payload_length == 127) {
		unsigned long long c;
		if(!read(c, &c, sizeof(c)))
			return NULL;
		c = ntohll(c);
		payload_length = c;
	}
	unsigned int mask_key = 0;
	if (MASK) {
		if(!read(fd, &mask_key, sizeof(mask_key)))
			return NULL;
	}

	char * payload = (char*)malloc(payload_length + 1);
	if (!payload) {
		fprintf(stderr, "malloc for payload failed\n");
		exit(-4);
	}
	unsigned long total_read = 0;
	while(total_read != payload_length) {
		int read_amount = read(fd, payload+total_read, payload_length - total_read);
		if(read_amount == 0){
			free(payload);
			return NULL;
		}
		total_read += read_amount;
	}
	if (MASK) {
		char *mask = (char*)&mask_key;
		for (unsigned long i = 0; i < payload_length; i++) {
			payload[i] = payload[i] ^ mask[i % 4];
		}
	}
	payload[payload_length] = 0;
	return payload;
}
int send_websocket_message(int fd, char* payload, unsigned long long payload_length) {
	unsigned char a = 0x81;
	if(!write(fd, &a, sizeof(a)))
		return -1;
	unsigned char b = 0;

	if (payload_length < 126) {
		b = b | (unsigned char)payload_length;
		if(!write(fd, &b, sizeof(b)))
			return -1;
	}else {
		b = b | (unsigned char) 127;
		if(!write(fd, &b, sizeof(b)))
			return -1;
		unsigned long long payload_length_network = htonll(payload_length);
		if(!write(fd, &payload_length_network, sizeof(payload_length_network)))
			return -1;
	}
	if(!write(fd, payload, payload_length))
		return -1;
	return 0;
}
