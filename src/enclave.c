#include <stdio.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <string.h>
#define PAGE_SIZE (0x1000)



#include "project_t.h"


int get_remote_report_with_pubkey(
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** remote_report,
    size_t* remote_report_size);

char* message_buffer;

void enclave_init(char* m) {
	message_buffer = m;	
}

oe_result_t enclave_hello(void) {
	fprintf(stdout, "Hello from the enclave\n");
	return OE_OK;
}


int recv_message_wrapper(void) {
	int retval;
	recv_message(&retval);
	return retval;
}
int send_message_wrapper(void) {
	int retval;
	send_message(&retval);
	return retval;
}
char* recv(void) {
	if(recv_message_wrapper() != 0) {
		return NULL;
	}
	int size = strlen(message_buffer)+1;
	char* message = (char*) malloc(size);
	strcpy(message, message_buffer);
	return message;
}
int send(char* message) {
	if(strlen(message) > PAGE_SIZE -2)
		return -1;
	strcpy(message_buffer, message);
	return send_message_wrapper();	
}

void enclave_enter(void) {
	char* message = recv();
	send(message);
	free(message);
}
