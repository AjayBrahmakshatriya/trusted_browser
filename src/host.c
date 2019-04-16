#include <openenclave/host.h>
#include <openenclave/edger8r/host.h>
#include <stdio.h>

#include "project_u.h"

/*
static oe_ocall_func_t ocall_function_table[] = {
};
*/
oe_enclave_t *create_enclave(const char *enclave_path) {
	oe_enclave_t* enclave = NULL;
	oe_result_t result = oe_create_project_enclave(enclave_path, 
		OE_ENCLAVE_TYPE_SGX, 		
		0,
		NULL,
		0,
		&enclave);
	if (result != OE_OK) {
		return NULL;
	}
	return enclave;
}



int main(int argc, char* argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <enclave image>\n", argv[0]);
		return -1;
	}
	oe_enclave_t *enclave = NULL;
	enclave = create_enclave(argv[1]);
	if (enclave == NULL) {
		fprintf(stderr, "Enclave creation failed\n");
		return -1;
	}

	enclave_hello(enclave);	

	oe_terminate_enclave(enclave);
	return 0;
}
