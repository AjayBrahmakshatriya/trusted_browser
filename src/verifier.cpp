#include <mbedtls/pk.h>
#include <mbedtls/error.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ctr_drbg.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>


int Sha256(const uint8_t* data, size_t data_size, uint8_t sha256[32])
{
    int ret = 0;
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);

    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, data, data_size);

    mbedtls_sha256_finish(&ctx, sha256);

exit:
    mbedtls_sha256_free(&ctx);
    return ret;
}

int main(int argc, char* argv[]) {


	mbedtls_ctr_drbg_context m_ctr_drbg_contex;	
	mbedtls_entropy_context m_entropy_context;
	mbedtls_ctr_drbg_init(&m_ctr_drbg_contex);
	mbedtls_entropy_init(&m_entropy_context);
	mbedtls_ctr_drbg_seed(&m_ctr_drbg_contex, mbedtls_entropy_func, &m_entropy_context, NULL, 0);

	FILE *private_key_file = fopen(argv[1], "rb");
	uint8_t private_key[4096] = {0};
	fread(private_key, 1, 4096, private_key_file);
	fclose(private_key_file);

	mbedtls_pk_context key;
	mbedtls_pk_init(&key);
	mbedtls_rsa_context *rsa_context;
	int key_size = strlen((char*)private_key) + 1;
	mbedtls_pk_parse_key(&key, private_key, key_size, NULL, 0);
	rsa_context = mbedtls_pk_rsa(key);
	rsa_context->padding = MBEDTLS_RSA_PKCS_V21;
	rsa_context->hash_id = MBEDTLS_MD_SHA256;



	FILE* message_file = fopen(argv[2], "rb");
	uint8_t message[1024] = {0};
	int message_size = fread(message, 1, 1024, message_file);
	fclose(message_file);
	rsa_context->len = message_size;


	uint8_t decrypted[2048];
	size_t decrypted_size = 2048;
	int res;
	mbedtls_rsa_pkcs1_decrypt(rsa_context, mbedtls_ctr_drbg_random, &m_ctr_drbg_contex, MBEDTLS_RSA_PRIVATE, &decrypted_size, message, decrypted, decrypted_size);
	
	uint8_t symmetric_key[32];
	memcpy(symmetric_key, decrypted, 32);
	uint8_t *signature = decrypted + 32;
	
	uint8_t hash[32];
	Sha256(symmetric_key, 32, hash);
	
	FILE *public_key_file = fopen(argv[3], "rb");
	uint8_t public_key[4096] = {0};
	fread(public_key, 1, 4096, public_key_file);
	fclose(public_key_file);
	
	mbedtls_pk_init(&key);
	key_size = strlen((char*)public_key) + 1;
	mbedtls_pk_parse_public_key(&key, public_key, key_size);
	rsa_context = mbedtls_pk_rsa(key);
	rsa_context->padding - MBEDTLS_RSA_PKCS_V21;
	rsa_context->hash_id = MBEDTLS_MD_SHA256;
	
	res  = mbedtls_rsa_pkcs1_verify(rsa_context, mbedtls_ctr_drbg_random, &m_ctr_drbg_contex, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 32, hash, signature);
	printf("%d", res);	
	char str[100];
	mbedtls_strerror(res, str, 100);
	printf("%s", str);	
}
