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

uint8_t* encrypt_message(uint8_t *message, size_t size, size_t *output_size) {
	mbedtls_aes_context aes;
	uint8_t IV[16];
	int ret = mbedtls_ctr_drbg_random(&(dispatcher.m_crypto->m_ctr_drbg_contex), IV, 16);
	if (ret != 0)
		return NULL;
	size_t aligned_size = ((size)/16)*16 + 16;
	uint8_t *padded_message = (uint8_t*)malloc(aligned_size);
	uint8_t padding = aligned_size - size;
	memcpy(padded_message, message, size);
	memset(padded_message + size, padding, padding);
	uint8_t *output = (uint8_t*)malloc(aligned_size + 16);
	memcpy(output, IV, 16);

	
	mbedtls_aes_setkey_enc(&aes, dispatcher.m_crypto->m_symmetric_key, 256);
	mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, aligned_size, IV, padded_message, output + 16);
	free(padded_message);
	*output_size = aligned_size + 16;

	return output;
}
uint8_t* decrypt_message(uint8_t *e_message, size_t e_size, size_t *d_size) {

	uint8_t *IV = e_message;
	e_message += 16;
	*d_size = e_size - 16;
	
	uint8_t *d_message = (uint8_t*) malloc(*d_size);
	
	mbedtls_aes_context aes;
	mbedtls_aes_setkey_dec(&aes, dispatcher.m_crypto->m_symmetric_key, 256);
	mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, *d_size, IV, e_message, d_message);
	int padding = d_message[*d_size - 1];
	*d_size -= padding;
	return d_message;
}
	
}
