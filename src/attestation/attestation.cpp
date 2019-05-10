
#define NO_OE_HEADER
#include <iostream>
#include "crypto.h"
#include "attestation.h"
#include <openenclave/bits/report.h>
#include <openenclave/bits/result.h>
#include <cstring>
#include <openenclave/internal/trace.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ctr_drbg.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>

extern "C" oe_result_t oe_verify_report(
		const uint8_t* report,
		size_t report_size,
		oe_report_t* parsed_report);


void load_rsa_key(char* filename, unsigned char** buffer, size_t* size) {
	if (*buffer != NULL) {
		free(*buffer);
	}
	FILE* f = fopen(filename, "rb");
	fseek(f, 0, SEEK_END);
	*size = ftell(f);
	fseek(f, 0, SEEK_SET);
	*buffer = (unsigned char*)malloc(*size+1) ;
	fread(*buffer, *size, 1, f);
	fclose(f);
	(*buffer)[*size] = 0;
	(*size)++;
}	


void load_report_file(char* filename, unsigned char** buffer, size_t* size) {
	if (*buffer != NULL)
		free(*buffer);
	FILE *f = fopen(filename, "rb");
	fseek(f, 0, SEEK_END);
	*size = ftell(f);
	fseek(f, 0, SEEK_SET);
	*buffer = (unsigned char*) malloc(*size);
	fread(*buffer, 1, *size, f);
	fclose(f);	
}

void load_first_message(char* filename, uint8_t ** buffer, size_t *size) {
	if (*buffer != NULL)
		free(*buffer);
	FILE *f = fopen(filename, "rb");
	fseek(f, 0, SEEK_END);
	*size = ftell(f);
	fseek(f, 0, SEEK_SET);
	*buffer = (uint8_t*) malloc(*size);
	fread(*buffer, 1, *size, f);
	fclose(f);
}

#define CHECK_RES(res) if (res != 0) {return res;}

int extract_symmetric_key(Crypto *m_crypto, uint8_t * first_message, size_t first_message_size, uint8_t * enclave_pub_key, uint8_t * attestation_private_key, uint8_t symmetric_key[32]) {
	mbedtls_pk_context key;
	mbedtls_pk_init(&key);
	mbedtls_rsa_context *rsa_context;
	int res;	
	int key_size = strlen((char*) attestation_private_key) + 1;
	res = mbedtls_pk_parse_key(&key, attestation_private_key, key_size, NULL, 0);
	CHECK_RES(res);	
	
	rsa_context = mbedtls_pk_rsa(key);
	rsa_context->padding = MBEDTLS_RSA_PKCS_V21;
	rsa_context->hash_id = MBEDTLS_MD_SHA256;
	
	uint8_t decrypted[2048];
	size_t decrypted_size = 2048;

	rsa_context->len = first_message_size;
	
	res = mbedtls_rsa_pkcs1_decrypt(rsa_context,
					mbedtls_ctr_drbg_random, 
					&(m_crypto->m_ctr_drbg_contex), 
					MBEDTLS_RSA_PRIVATE,
					&decrypted_size,
					first_message,
					decrypted,
					decrypted_size);
	CHECK_RES(res);

	memcpy(symmetric_key, decrypted, 32);
	return 0;	
}
int main(int argc, char* argv[]) {
	if(argc < 4) {
		fprintf(stderr, "Usage: %s <report_file_name> <enclave_pub_key> <signing_public_key>\n", argv[0]);
		return -1;
	}
	unsigned char m_other_enclave_mrsigner[32];
	char * enclave_signing_pubkey_pem = NULL;
	size_t enclave_signing_pubkey_size = 0;
	load_rsa_key(argv[3], (unsigned char**)&enclave_signing_pubkey_pem, &enclave_signing_pubkey_size);

	Crypto *m_crypto = new Crypto(); 		
	uint8_t *modulus = NULL;
	size_t modulus_size;	
	if (!m_crypto->get_rsa_modulus_from_pem(enclave_signing_pubkey_pem, enclave_signing_pubkey_size, &modulus, &modulus_size)){
		fprintf(stderr, "Failed getting modulus from signing key\n");
		return -1;
	}
	// Reverse the modulus and compute sha256 on it.
	for (size_t i = 0; i < modulus_size / 2; i++)
	{
		uint8_t tmp = modulus[i];
		modulus[i] = modulus[modulus_size - 1 - i];
		modulus[modulus_size - 1 - i] = tmp;
	}

	if (m_crypto->Sha256(modulus, modulus_size, m_other_enclave_mrsigner) != 0)
	{
		fprintf(stderr, "SHA256 of signing key failed to compute\n");
		return -1;
	}

	
	Attestation *m_attestation = new Attestation(m_crypto, m_other_enclave_mrsigner);
	if (m_crypto == NULL || m_attestation == NULL) {
		fprintf(stderr, "Crypto + Attestation could not be instantiated\n");
		return -1;
	} 

	unsigned char* enclave_public_key = NULL;
	size_t enclave_public_key_size = 0;
	

	load_rsa_key(argv[2], &enclave_public_key, &enclave_public_key_size);
	enclave_public_key_size --;
	unsigned char* report = NULL;
	size_t report_size;
	load_report_file(argv[1], &report, &report_size);
	if(m_attestation->attest_remote_report(report, report_size, enclave_public_key, enclave_public_key_size)) {
	} else {
		printf("ATTESTATION FAILED\n");
		return -1;
	}
	
	uint8_t * attestation_private_key = NULL;
	size_t attestation_private_key_size = 0;
	load_rsa_key(argv[5], &attestation_private_key, &attestation_private_key_size);
	
	uint8_t * first_message = NULL;
	size_t first_message_size;
	load_first_message(argv[4], &first_message, &first_message_size);
	
	uint8_t symmetric_key[32];
		
	int res = extract_symmetric_key(m_crypto, first_message, first_message_size, enclave_public_key, attestation_private_key, symmetric_key);
	if (res != 0) {
		printf("ATTESTATION FAILED\n");
		return -1;
	}
	printf("ATTESTATION SUCCEEDED\n");
	for (int i = 0; i < 32; i++) {
		printf("%02x", (int)symmetric_key[i]);
	}

	return 0;
}




Attestation::Attestation(Crypto* crypto, unsigned char* enclave_mrsigner)
{
	m_crypto = crypto;
	m_enclave_mrsigner = enclave_mrsigner;
}
bool Attestation::attest_remote_report(
		const uint8_t* remote_report,
		size_t remote_report_size,
		const uint8_t* data,
		size_t data_size)
{
	bool ret = false;
	uint8_t sha256[32];
	oe_report_t parsed_report = {0};
	oe_result_t result = OE_OK;

	// While attesting, the remote report being attested must not be tampered
	// with. Ensure that it has been copied over to the enclave.
	/*
	   if (!oe_is_within_enclave(remote_report, remote_report_size))
	   {
	   TRACE_ENCLAVE("Cannot attest remote report in host memory. Unsafe.");
	   goto exit;
	   }
	 */
	// 1)  Validate the report's trustworthiness
	// Verify the remote report to ensure its authenticity.
	result =
		oe_verify_report(remote_report, remote_report_size, &parsed_report);
	if (result != OE_OK)
	{
		TRACE_ENCLAVE("oe_verify_report failed (%s).\n", oe_result_str(result));
		goto exit;
	}

	// 2) validate the enclave identity's signed_id is the hash of the public
	// signing key that was used to sign an enclave. Check that the enclave was
	// signed by an trusted entity.
	if (memcmp(parsed_report.identity.signer_id, m_enclave_mrsigner, 32) != 0)
	{
		TRACE_ENCLAVE("identity.signer_id checking failed.");
		TRACE_ENCLAVE(
				"identity.signer_id %s", parsed_report.identity.signer_id);

		for (int i = 0; i < 32; i++)
		{
			TRACE_ENCLAVE(
					"m_enclave_mrsigner[%d]=0x%0x\n",
					i,
					(uint8_t)m_enclave_mrsigner[i]);
		}

		TRACE_ENCLAVE("\n\n\n");

		for (int i = 0; i < 32; i++)
		{
			TRACE_ENCLAVE(
					"parsedReport.identity.signer_id)[%d]=0x%0x\n",
					i,
					(uint8_t)parsed_report.identity.signer_id[i]);
		}
		TRACE_ENCLAVE("m_enclave_mrsigner %s", m_enclave_mrsigner);
		goto exit;
	}

	// Check the enclave's product id and security version
	// See enc.conf for values specified when signing the enclave.
	if (parsed_report.identity.product_id[0] != 1)
	{
		TRACE_ENCLAVE("identity.product_id checking failed.");
		goto exit;
	}

	if (parsed_report.identity.security_version < 1)
	{
		TRACE_ENCLAVE("identity.security_version checking failed.");
		goto exit;
	}

	// 3) Validate the report data
	//    The report_data has the hash value of the report data
	if (m_crypto->Sha256(data, data_size, sha256) != 0)
	{
		goto exit;
	}

	if (memcmp(parsed_report.report_data, sha256, sizeof(sha256)) != 0)
	{
		TRACE_ENCLAVE("SHA256 mismatch.");
		goto exit;
	}
	ret = true;
	TRACE_ENCLAVE("remote attestation succeeded.");
exit:
	return ret;
}
extern "C" {

	void oe_log(log_level_t level, const char* fmt, ...)
	{
		OE_UNUSED(level);
		OE_UNUSED(fmt);
	}
	const char* oe_result_str(oe_result_t result)
	{
		switch (result)
		{
			case OE_OK:
				return "OE_OK";
			case OE_FAILURE:
				return "OE_FAILURE";
			case OE_BUFFER_TOO_SMALL:
				return "OE_BUFFER_TOO_SMALL";
			case OE_INVALID_PARAMETER:
				return "OE_INVALID_PARAMETER";
			case OE_REENTRANT_ECALL:
				return "OE_REENTRANT_ECALL";
			case OE_OUT_OF_MEMORY:
				return "OE_OUT_OF_MEMORY";
			case OE_OUT_OF_THREADS:
				return "OE_OUT_OF_THREADS";
			case OE_UNEXPECTED:
				return "OE_UNEXPECTED";
			case OE_VERIFY_FAILED:
				return "OE_VERIFY_FAILED";
			case OE_NOT_FOUND:
				return "OE_NOT_FOUND";
			case OE_INTEGER_OVERFLOW:
				return "OE_INTEGER_OVERFLOW";
			case OE_PUBLIC_KEY_NOT_FOUND:
				return "OE_PUBLIC_KEY_NOT_FOUND";
			case OE_OUT_OF_BOUNDS:
				return "OE_OUT_OF_BOUNDS";
			case OE_OVERLAPPED_COPY:
				return "OE_OVERLAPPED_COPY";
			case OE_CONSTRAINT_FAILED:
				return "OE_CONSTRAINT_FAILED";
			case OE_IOCTL_FAILED:
				return "OE_IOCTL_FAILED";
			case OE_UNSUPPORTED:
				return "OE_UNSUPPORTED";
			case OE_READ_FAILED:
				return "OE_READ_FAILED";
			case OE_SERVICE_UNAVAILABLE:
				return "OE_SERVICE_UNAVAILABLE";
			case OE_ENCLAVE_ABORTING:
				return "OE_ENCLAVE_ABORTING";
			case OE_ENCLAVE_ABORTED:
				return "OE_ENCLAVE_ABORTED";
			case OE_PLATFORM_ERROR:
				return "OE_PLATFORM_ERROR";
			case OE_INVALID_CPUSVN:
				return "OE_INVALID_CPUSVN";
			case OE_INVALID_ISVSVN:
				return "OE_INVALID_ISVSVN";
			case OE_INVALID_KEYNAME:
				return "OE_INVALID_KEYNAME";
			case OE_DEBUG_DOWNGRADE:
				return "OE_DEBUG_DOWNGRADE";
			case OE_REPORT_PARSE_ERROR:
				return "OE_REPORT_PARSE_ERROR";
			case OE_MISSING_CERTIFICATE_CHAIN:
				return "OE_MISSING_CERTIFICATE_CHAIN";
			case OE_BUSY:
				return "OE_BUSY";
			case OE_NOT_OWNER:
				return "OE_NOT_OWNER";
			case OE_INVALID_SGX_CERTIFICATE_EXTENSIONS:
				return "OE_INVALID_SGX_CERTIFICATE_EXTENSIONS";
			case OE_MEMORY_LEAK:
				return "OE_MEMORY_LEAK";
			case OE_BAD_ALIGNMENT:
				return "OE_BAD_ALIGNMENT";
			case OE_JSON_INFO_PARSE_ERROR:
				return "OE_JSON_INFO_PARSE_ERROR";
			case OE_TCB_LEVEL_INVALID:
				return "OE_TCB_LEVEL_INVALID";
			case OE_QUOTE_PROVIDER_LOAD_ERROR:
				return "OE_QUOTE_PROVIDER_LOAD_ERROR";
			case OE_QUOTE_PROVIDER_CALL_ERROR:
				return "OE_QUOTE_PROVIDER_CALL_ERROR";
			case OE_INVALID_REVOCATION_INFO:
				return "OE_INVALID_REVOCATION_INFO";
			case OE_INVALID_UTC_DATE_TIME:
				return "OE_INVALID_UTC_DATE_TIME";
			case OE_INVALID_QE_IDENTITY_INFO:
				return "OE_INVALID_QE_IDENTITY_INFO";
			case OE_UNSUPPORTED_ENCLAVE_IMAGE:
				return "OE_UNSUPPORTED_ENCLAVE_IMAGE";
			case OE_VERIFY_CRL_EXPIRED:
				return "OE_VERIFY_CRL_EXPIRED";
			case __OE_RESULT_MAX:
				break;
		}

		return "UNKNOWN";
	}
	bool oe_is_outside_enclave(void * s) {
		return true;
	}
	int mbedtls_sha256_starts_ret( mbedtls_sha256_context *ctx, int is224 ) {
		mbedtls_sha256_starts(ctx, is224);
		return 0;
	}

	int mbedtls_sha256_update_ret( mbedtls_sha256_context *ctx,
			const unsigned char *input,
			size_t ilen ) {
		mbedtls_sha256_update(ctx, input, ilen);
		return 0;
	}
	int mbedtls_sha256_finish_ret( mbedtls_sha256_context *ctx,
			unsigned char output[32] ) {
		mbedtls_sha256_finish(ctx, output);
		return 0;
	}
	size_t mbedtls_rsa_get_len( const mbedtls_rsa_context *ctx )
	{
		return( ctx->len );
	}
	int mbedtls_rsa_export_raw( const mbedtls_rsa_context *ctx,
			unsigned char *N, size_t N_len,
			unsigned char *P, size_t P_len,
			unsigned char *Q, size_t Q_len,
			unsigned char *D, size_t D_len,
			unsigned char *E, size_t E_len )
	{
		int ret = 0;

		/* Check if key is private or public */
		const int is_priv =
			mbedtls_mpi_cmp_int( &ctx->N, 0 ) != 0 &&
			mbedtls_mpi_cmp_int( &ctx->P, 0 ) != 0 &&
			mbedtls_mpi_cmp_int( &ctx->Q, 0 ) != 0 &&
			mbedtls_mpi_cmp_int( &ctx->D, 0 ) != 0 &&
			mbedtls_mpi_cmp_int( &ctx->E, 0 ) != 0;

		if( !is_priv )
		{
			/* If we're trying to export private parameters for a public key,
			 * something must be wrong. */
			if( P != NULL || Q != NULL || D != NULL )
				return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

		}

		if( N != NULL )
			MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->N, N, N_len ) );

		if( P != NULL )
			MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->P, P, P_len ) );

		if( Q != NULL )
			MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->Q, Q, Q_len ) );

		if( D != NULL )
			MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->D, D, D_len ) );

		if( E != NULL )
			MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->E, E, E_len ) );

cleanup:

		return( ret );
	}
}
