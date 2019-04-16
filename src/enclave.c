#include <stdio.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>




oe_result_t enclave_hello(void) {
	fprintf(stdout, "Hello from the enclave\n");
	return OE_OK;
}



