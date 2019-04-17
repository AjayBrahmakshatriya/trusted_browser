#include <stdio.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>


int get_remote_report_with_pubkey(
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** remote_report,
    size_t* remote_report_size);


oe_result_t enclave_hello(void) {
	fprintf(stdout, "Hello from the enclave\n");
	return OE_OK;
}



