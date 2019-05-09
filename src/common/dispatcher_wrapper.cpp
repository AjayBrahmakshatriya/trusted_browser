#include "dispatcher.h"


enclave_config_data_t config_data = {NULL};
static ecall_dispatcher dispatcher("Enclave1", &config_data);

extern "C" {

int get_remote_report_with_pubkey(
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** remote_report,
    size_t* remote_report_size)
{
    return dispatcher.get_remote_report_with_pubkey(
        pem_key, key_size, remote_report, remote_report_size);
}

uint8_t*  generate_first_message(size_t *s) {
	return dispatcher.generate_first_message(s);
}
}
