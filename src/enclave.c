#include <stdio.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <string.h>
#define PAGE_SIZE (0x1000)

#include "enclave.h"


#include "project_t.h"

#include "attestation_key.h"

int get_remote_report_with_pubkey(
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** remote_report,
    size_t* remote_report_size);
uint8_t * generate_first_message(size_t *);
uint8_t* encrypt_message(uint8_t *message, size_t size, size_t *output_size);
uint8_t* decrypt_message(uint8_t *e_message, size_t e_size, size_t *d_size);

char* message_buffer;

void enclave_init(char* m) {
	message_buffer = m;	
	size_t first_message_size;
	uint8_t *first_message = generate_first_message(&first_message_size);
	*(size_t*)message_buffer = first_message_size;
	memcpy(message_buffer + sizeof(size_t), first_message, first_message_size);
	free(first_message);	
	
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
int send_backend_wrapper(void) {
	int retval;
	send_backend_message(&retval);
	return retval;
}
int recv_backend_wrapper(void) {
	int retval;
	recv_backend_message(&retval);
	return retval;
}
char* recv_browser(void) {
	if(recv_message_wrapper() != 0) {
		return NULL;
	}
	message_buffer[PAGE_SIZE-1] = 0;
	int size = strlen(message_buffer)+1;
	char* message = (char*) malloc(size);
	strcpy(message, message_buffer);
	return message;
}
int send_browser(char* message) {
	if(strlen(message) > PAGE_SIZE -2)
		return -1;
	strcpy(message_buffer, message);
	return send_message_wrapper();	
}
int send_backend(uint8_t *message, size_t size) {
	if (size > PAGE_SIZE -2 - 48)
		return -1;
	size_t e_size;
	uint8_t *encrypted_message = encrypt_message(message, size, &e_size);
	*(size_t*)message_buffer = e_size;
	memcpy(message_buffer + sizeof(size_t) , encrypted_message, e_size);
	free(encrypted_message);
	return send_backend_wrapper();
}
uint8_t* recv_backend(size_t *size) {
	if (recv_backend_wrapper() != 0)
		return NULL;
	size_t e_size = *(size_t*)message_buffer;
	if (e_size > PAGE_SIZE - 2)
		return NULL;
	size_t d_size;
	uint8_t *decrypted_message = decrypt_message(message_buffer + sizeof(size_t), e_size, &d_size);
	*size = d_size;
	return decrypted_message;	
} 

