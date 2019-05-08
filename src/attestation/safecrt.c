// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/raise.h>
//#include "common.h"
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <dlfcn.h>
#include <openenclave/internal/calls.h>
#include <openenclave/3rdparty/mbedtls/cmac.h>
#include <openenclave/3rdparty/mbedtls/cipher.h>
#include <errno.h>
void * (*mbedtls_calloc)( size_t n, size_t size ) = calloc;
void (*mbedtls_free)( void *ptr ) = free;
oe_result_t oe_memcpy_s(
    void* dst,
    size_t dst_size,
    const void* src,
    size_t num_bytes)
{
    oe_result_t result = OE_FAILURE;

    if (dst == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (src == NULL || dst_size < num_bytes)
    {
        memset(dst, 0, dst_size);
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Reject overlapping buffers. */
    if ((dst >= src && ((uint8_t*)dst < (uint8_t*)src + num_bytes)) ||
        (dst < src && ((uint8_t*)dst + dst_size > (uint8_t*)src)))
    {
        memset(dst, 0, dst_size);
        OE_RAISE(OE_OVERLAPPED_COPY);
    }

    memcpy(dst, src, num_bytes);
    result = OE_OK;
done:

    return result;
}

oe_result_t oe_memmove_s(
    void* dst,
    size_t dst_size,
    const void* src,
    size_t num_bytes)
{
    oe_result_t result = OE_FAILURE;

    if (dst == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (src == NULL || dst_size < num_bytes)
    {
        memset(dst, 0, dst_size);
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    memmove(dst, src, num_bytes);
    result = OE_OK;
done:
    return result;
}

oe_result_t oe_memset_s(void* dst, size_t dst_size, int value, size_t num_bytes)
{
    oe_result_t result = OE_FAILURE;
    volatile unsigned char* p = dst;

    if (dst == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* The C11 standard states that memset_s will store `value` in
     * `dst[0...dst_size]` even during a runtime violation. */
    if (dst_size < num_bytes)
    {
        result = OE_INVALID_PARAMETER;
        num_bytes = dst_size;
    }
    else
    {
        result = OE_OK;
    }

    /* memset_s cannot be optimized away by the compiler */
    while (num_bytes--)
        *p++ = (volatile unsigned char)value;

done:
    return result;
}

OE_INLINE oe_result_t _oe_validate_string(char* str, size_t size)
{
    if (str != NULL && size > 0)
        return OE_OK;
    return OE_INVALID_PARAMETER;
}

OE_INLINE void _oe_fill_string(char* str, size_t size)
{
    OE_UNUSED(str);
    OE_UNUSED(size);
#ifndef NDEBUG
    // Fill memory with pattern.
    memset(str, 0xFD, size);
#endif
}

OE_INLINE void _oe_reset_string(char* str, size_t size)
{
    *str = '\0';
    _oe_fill_string(str + 1, size - 1);
}

oe_result_t oe_strncat_s(
    char* dst,
    size_t dst_size,
    const char* src,
    size_t num_bytes)
{
    oe_result_t result = OE_FAILURE;
    char* p = dst;
    size_t available = dst_size;

    /* Reject invalid parameters. */
    OE_CHECK(_oe_validate_string(dst, dst_size));

    if (src == NULL)
    {
        _oe_reset_string(dst, dst_size);
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    while (available > 0 && *p != 0)
    {
        if (p == src)
        {
            _oe_reset_string(dst, dst_size);
            OE_RAISE(OE_OVERLAPPED_COPY);
        }

        p++;
        available--;
    }

    /* Not null terimated. */
    if (available == 0)
    {
        _oe_reset_string(dst, dst_size);
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Copy from the end of the destination string. */
    result = oe_strncpy_s(p, available, src, num_bytes);

    if (result != OE_OK)
    {
        _oe_reset_string(dst, dst_size);
        OE_RAISE(result);
    }

    result = OE_OK;
done:
    return result;
}

oe_result_t oe_strncpy_s(
    char* dst,
    size_t dst_size,
    const char* src,
    size_t num_bytes)
{
    oe_result_t result = OE_FAILURE;
    const char* current_src = src;
    char* current_dst = dst;
    size_t current_dst_size = dst_size;

    /* Reject invalid parameters. */
    OE_CHECK(_oe_validate_string(dst, dst_size));

    if (src == NULL)
    {
        _oe_reset_string(dst, dst_size);
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Copy until we hit one of the terminating conditions. */
    while (current_dst_size != 0)
    {
        /* If we detect an overlapped copy, we will return an error. */
        if (current_dst == src || current_src == dst)
        {
            _oe_reset_string(dst, dst_size);
            OE_RAISE(OE_OVERLAPPED_COPY);
        }

        /* Successful terminating conditions for strncpy_s. */
        if (num_bytes == 0 || *current_src == '\0')
        {
            *current_dst = '\0';
            result = OE_OK;
            goto done;
        }

        /* Copy and contine looping. */
        *current_dst++ = *current_src++;
        current_dst_size--;
        num_bytes--;
    }

    /* Destination buffer is not large enough. */
    _oe_reset_string(dst, dst_size);
    OE_RAISE(OE_BUFFER_TOO_SMALL);

done:
    return result;
}
#define MALLOC malloc
#define CALLOC calloc
#define FREE free
#define REALLOC realloc
void* oe_malloc(size_t size)
{
    void* p = MALLOC(size);


    return p;
}
void* oe_host_malloc(size_t size)
{
    void* p = MALLOC(size);


    return p;
}


void oe_free(void* ptr)
{
    FREE(ptr);
}

void oe_host_free(void* ptr)
{
    FREE(ptr);
}

void* oe_calloc(size_t nmemb, size_t size)
{
    void* p = CALLOC(nmemb, size);

    return p;
}

void* oe_host_calloc(size_t nmemb, size_t size)
{
    void* p = CALLOC(nmemb, size);

    return p;
}

void* oe_realloc(void* ptr, size_t size)
{
    void* p = REALLOC(ptr, size);


    return p;
}
void* oe_host_realloc(void* ptr, size_t size)
{
    void* p = REALLOC(ptr, size);


    return p;
}
size_t oe_strlen(const char* s)
{
    const char* p = s;

    while (p[0] && p[1] && p[2] && p[3] && p[4] && p[5])
        p += 6;

    if (!p[0])
        return (size_t)(p - s);
    if (!p[1])
        return (size_t)(p - s + 1);
    if (!p[2])
        return (size_t)(p - s + 2);
    if (!p[3])
        return (size_t)(p - s + 3);
    if (!p[4])
        return (size_t)(p - s + 4);
    if (!p[5])
        return (size_t)(p - s + 5);

    /* Unreachable */
    return 0;
}

size_t oe_strnlen(const char* s, size_t n)
{
    const char* p = s;

    while (n-- && *p)
        p++;

    return (size_t)(p - s);
}

int oe_strcmp(const char* s1, const char* s2)
{
    while ((*s1 && *s2) && (*s1 == *s2))
    {
        s1++;
        s2++;
    }

    return *s1 - *s2;
}

int oe_strncmp(const char* s1, const char* s2, size_t n)
{
    /* Compare first n characters only */
    while (n && (*s1 && *s2) && (*s1 == *s2))
    {
        s1++;
        s2++;
        n--;
    }

    /* If first n characters matched */
    if (n == 0)
        return 0;

    /* Return difference of mismatching characters */
    return *s1 - *s2;
}

size_t oe_strlcpy(char* dest, const char* src, size_t size)
{
    const char* start = src;

    if (size)
    {
        char* end = dest + size - 1;

        while (*src && dest != end)
            *dest++ = (char)*src++;

        *dest = '\0';
    }

    while (*src)
        src++;

    return (size_t)(src - start);
}

size_t oe_strlcat(char* dest, const char* src, size_t size)
{
    size_t n = 0;

    if (size)
    {
        char* end = dest + size - 1;

        while (*dest && dest != end)
        {
            dest++;
            n++;
        }

        while (*src && dest != end)
        {
            n++;
            *dest++ = *src++;
        }

        *dest = '\0';
    }

    while (*src)
    {
        src++;
        n++;
    }

    return n;
}

char* oe_strstr(const char* haystack, const char* needle)
{
    size_t hlen = oe_strlen(haystack);
    size_t nlen = oe_strlen(needle);

    if (nlen > hlen)
        return NULL;

    for (size_t i = 0; i < hlen - nlen + 1; i++)
    {
        if (memcmp(haystack + i, needle, nlen) == 0)
            return (char*)haystack + i;
    }

    return NULL;
}


log_level_t get_current_logging_level(void) {
	return OE_LOG_LEVEL_ERROR;
}	
typedef uint32_t oe_once_t;
typedef pthread_once_t oe_once_type;
int oe_once(oe_once_type* once, void (*func)(void))
{
    return pthread_once(once, func);
}
OE_INLINE char oe_get_hex_char(uint64_t x, size_t i)
{
    uint64_t nbits = (uint64_t)i * 4;
    char nibble = (char)((x & (0x000000000000000fUL << nbits)) >> nbits);
    return (char)((nibble < 10) ? ('0' + nibble) : ('a' + (nibble - 10)));
}
char* oe_hex_string(
    char* str,
    size_t str_size,
    const void* data,
    size_t data_size)
{
    /* Check parameters */
    if (!str || !data || (str_size < (2 * data_size + 1)))
        return NULL;

    char* s = str;
    const uint8_t* p = (const uint8_t*)data;
    size_t n = data_size;

    /* For each byte in data buffer */
    while (n--)
    {
        *s++ = oe_get_hex_char(*p, 1);
        *s++ = oe_get_hex_char(*p, 0);
        p++;
    }

    /* Zero-terminate the string */
    *s = '\0';

    return str;
}

void oe_hex_dump(const void* data, size_t size)
{
    const uint8_t* p = (const uint8_t*)data;
    size_t n = size;
    const size_t chunk_size = 1024;
    char buf[2 * chunk_size + 1];

    /* Return if nothing to print */
    if (!data || !size)
        return;

    /* Print N-sized chunks first to reduce OCALLS */
    while (n >= chunk_size)
    {
        oe_hex_string(buf, sizeof(buf), p, chunk_size);
        OE_TRACE_INFO("%s = ", buf);
        p += chunk_size;
        n -= chunk_size;
    }

    /* Print any remaining bytes */
    if (n)
    {
        oe_hex_string(buf, sizeof(buf), p, n);
        OE_TRACE_INFO("%s = ", buf);
    }
    OE_TRACE_INFO("\n");
}

void* ocall_handle = NULL;
#define xstr(a) str(a)
#define str(a) #a
#define OCALL_HANDLE_PATH_STR xstr(OCALL_HANDLE_PATH)
oe_result_t oe_ocall(uint16_t func, uint64_t arg_in, uint64_t *arg_out) {
	if (!ocall_handle) {
		ocall_handle = dlopen(OCALL_HANDLE_PATH_STR, RTLD_LAZY);
		if (ocall_handle == NULL) {
			fprintf(stderr, "OCALL HANDLER loading failed with loading %s with error = %s\n", OCALL_HANDLE_PATH_STR, dlerror());
			return -1;
		}
	}
	void (*HandleGetQuoteEnclaveIdentityInfo)(int64_t) = dlsym(ocall_handle, "HandleGetQuoteEnclaveIdentityInfo");
	void (*HandleGetQuoteRevocationInfo)(int64_t) = dlsym(ocall_handle, "HandleGetQuoteRevocationInfo");
	switch(func) {
		case OE_OCALL_GET_QE_ID_INFO: 
			if(HandleGetQuoteRevocationInfo == NULL) {
				fprintf(stderr, "HandleGetQuoteEnclaveIdentityInfo not found in ocall handler\n");
				return -1;
			}
			HandleGetQuoteEnclaveIdentityInfo(arg_in); 
			break;
		case OE_OCALL_GET_REVOCATION_INFO:
			if(HandleGetQuoteRevocationInfo == NULL) {
				fprintf(stderr, "HandleGetQuoteRevocationInfo not found in ocall handler\n");
				return -1;
			}
			HandleGetQuoteRevocationInfo(arg_in);
			break;
		default:
			fprintf(stderr, "OCALL not supported in attestation\n");
			return -1;
	}
}
static void cmac_xor_block( unsigned char *output, const unsigned char *input1,
                            const unsigned char *input2,
                            const size_t block_size )
{
    size_t idx;

    for( idx = 0; idx < block_size; idx++ )
        output[ idx ] = input1[ idx ] ^ input2[ idx ];
}

/*
 * Create padded last block from (partial) last block.
 *
 * We can't use the padding option from the cipher layer, as it only works for
 * CBC and we use ECB mode, and anyway we need to XOR K1 or K2 in addition.
 */
static void cmac_pad( unsigned char padded_block[MBEDTLS_CIPHER_BLKSIZE_MAX],
                      size_t padded_block_len,
                      const unsigned char *last_block,
                      size_t last_block_len )
{
    size_t j;

    for( j = 0; j < padded_block_len; j++ )
    {
        if( j < last_block_len )
            padded_block[j] = last_block[j];
        else if( j == last_block_len )
            padded_block[j] = 0x80;
        else
            padded_block[j] = 0x00;
    }
}
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = (unsigned char*)v; while( n-- ) *p++ = 0;
}

static int cmac_multiply_by_u( unsigned char *output,
                               const unsigned char *input,
                               size_t blocksize )
{
    const unsigned char R_128 = 0x87;
    const unsigned char R_64 = 0x1B;
    unsigned char R_n, mask;
    unsigned char overflow = 0x00;
    int i;

    if( blocksize == MBEDTLS_AES_BLOCK_SIZE )
    {
        R_n = R_128;
    }
    else if( blocksize == MBEDTLS_DES3_BLOCK_SIZE )
    {
        R_n = R_64;
    }
    else
    {
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

    for( i = (int)blocksize - 1; i >= 0; i-- )
    {
        output[i] = input[i] << 1 | overflow;
        overflow = input[i] >> 7;
    }

    /* mask = ( input[0] >> 7 ) ? 0xff : 0x00
     * using bit operations to avoid branches */

    /* MSVC has a warning about unary minus on unsigned, but this is
     * well-defined and precisely what we want to do here */
#if defined(_MSC_VER)
#pragma warning( push )
#pragma warning( disable : 4146 )
#endif
    mask = - ( input[0] >> 7 );
#if defined(_MSC_VER)
#pragma warning( pop )
#endif

    output[ blocksize - 1 ] ^= R_n & mask;

    return( 0 );
}
static int cmac_generate_subkeys( mbedtls_cipher_context_t *ctx,
                                  unsigned char* K1, unsigned char* K2 )
{
    int ret;
    unsigned char L[MBEDTLS_CIPHER_BLKSIZE_MAX];
    size_t olen, block_size;

    mbedtls_zeroize( L, sizeof( L ) );

    block_size = ctx->cipher_info->block_size;

    /* Calculate Ek(0) */
    if( ( ret = mbedtls_cipher_update( ctx, L, block_size, L, &olen ) ) != 0 )
        goto exit;

    /*
     * Generate K1 and K2
     */
    if( ( ret = cmac_multiply_by_u( K1, L , block_size ) ) != 0 )
        goto exit;

    if( ( ret = cmac_multiply_by_u( K2, K1 , block_size ) ) != 0 )
        goto exit;

exit:
    mbedtls_zeroize( L, sizeof( L ) );

    return( ret );
}
int mbedtls_cipher_cmac_starts( mbedtls_cipher_context_t *ctx,
                                const unsigned char *key, size_t keybits )
{
    mbedtls_cipher_type_t type;
    mbedtls_cmac_context_t *cmac_ctx;
    int retval;

    if( ctx == NULL || ctx->cipher_info == NULL || key == NULL )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    if( ( retval = mbedtls_cipher_setkey( ctx, key, (int)keybits,
                                          MBEDTLS_ENCRYPT ) ) != 0 )
        return( retval );

    type = ctx->cipher_info->type;

    switch( type )
    {
        case MBEDTLS_CIPHER_AES_128_ECB:
        case MBEDTLS_CIPHER_AES_192_ECB:
        case MBEDTLS_CIPHER_AES_256_ECB:
        case MBEDTLS_CIPHER_DES_EDE3_ECB:
            break;
        default:
            return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

    /* Allocated and initialise in the cipher context memory for the CMAC
     * context */
    cmac_ctx = mbedtls_calloc( 1, sizeof( mbedtls_cmac_context_t ) );
    if( cmac_ctx == NULL )
        return( MBEDTLS_ERR_CIPHER_ALLOC_FAILED );

    ctx->cmac_ctx = cmac_ctx;

    mbedtls_zeroize( cmac_ctx->state, sizeof( cmac_ctx->state ) );

    return 0;
}

int mbedtls_cipher_cmac_update( mbedtls_cipher_context_t *ctx,
                                const unsigned char *input, size_t ilen )
{
    mbedtls_cmac_context_t* cmac_ctx;
    unsigned char *state;
    int ret = 0;
    size_t n, j, olen, block_size;

    if( ctx == NULL || ctx->cipher_info == NULL || input == NULL ||
        ctx->cmac_ctx == NULL )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    cmac_ctx = ctx->cmac_ctx;
    block_size = ctx->cipher_info->block_size;
    state = ctx->cmac_ctx->state;

    /* Is there data still to process from the last call, that's greater in
     * size than a block? */
    if( cmac_ctx->unprocessed_len > 0 &&
        ilen > block_size - cmac_ctx->unprocessed_len )
    {
        memcpy( &cmac_ctx->unprocessed_block[cmac_ctx->unprocessed_len],
                input,
                block_size - cmac_ctx->unprocessed_len );

        cmac_xor_block( state, cmac_ctx->unprocessed_block, state, block_size );

        if( ( ret = mbedtls_cipher_update( ctx, state, block_size, state,
                                           &olen ) ) != 0 )
        {
           goto exit;
        }

        input += block_size - cmac_ctx->unprocessed_len;
        ilen -= block_size - cmac_ctx->unprocessed_len;
        cmac_ctx->unprocessed_len = 0;
    }

    /* n is the number of blocks including any final partial block */
    n = ( ilen + block_size - 1 ) / block_size;

    /* Iterate across the input data in block sized chunks, excluding any
     * final partial or complete block */
    for( j = 1; j < n; j++ )
    {
        cmac_xor_block( state, input, state, block_size );

        if( ( ret = mbedtls_cipher_update( ctx, state, block_size, state,
                                           &olen ) ) != 0 )
           goto exit;

        ilen -= block_size;
        input += block_size;
    }

    /* If there is data left over that wasn't aligned to a block */
    if( ilen > 0 )
    {
        memcpy( &cmac_ctx->unprocessed_block[cmac_ctx->unprocessed_len],
                input,
                ilen );
        cmac_ctx->unprocessed_len += ilen;
    }

exit:
    return( ret );
}

int mbedtls_cipher_cmac_finish( mbedtls_cipher_context_t *ctx,
                                unsigned char *output )
{
    mbedtls_cmac_context_t* cmac_ctx;
    unsigned char *state, *last_block;
    unsigned char K1[MBEDTLS_CIPHER_BLKSIZE_MAX];
    unsigned char K2[MBEDTLS_CIPHER_BLKSIZE_MAX];
    unsigned char M_last[MBEDTLS_CIPHER_BLKSIZE_MAX];
    int ret;
    size_t olen, block_size;

    if( ctx == NULL || ctx->cipher_info == NULL || ctx->cmac_ctx == NULL ||
        output == NULL )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    cmac_ctx = ctx->cmac_ctx;
    block_size = ctx->cipher_info->block_size;
    state = cmac_ctx->state;

    mbedtls_zeroize( K1, sizeof( K1 ) );
    mbedtls_zeroize( K2, sizeof( K2 ) );
    cmac_generate_subkeys( ctx, K1, K2 );

    last_block = cmac_ctx->unprocessed_block;

    /* Calculate last block */
    if( cmac_ctx->unprocessed_len < block_size )
    {
        cmac_pad( M_last, block_size, last_block, cmac_ctx->unprocessed_len );
        cmac_xor_block( M_last, M_last, K2, block_size );
    }
    else
    {
        /* Last block is complete block */
        cmac_xor_block( M_last, last_block, K1, block_size );
    }


    cmac_xor_block( state, M_last, state, block_size );
    if( ( ret = mbedtls_cipher_update( ctx, state, block_size, state,
                                       &olen ) ) != 0 )
    {
        goto exit;
    }

    memcpy( output, state, block_size );

exit:
    /* Wipe the generated keys on the stack, and any other transients to avoid
     * side channel leakage */
    mbedtls_zeroize( K1, sizeof( K1 ) );
    mbedtls_zeroize( K2, sizeof( K2 ) );

    cmac_ctx->unprocessed_len = 0;
    mbedtls_zeroize( cmac_ctx->unprocessed_block,
                     sizeof( cmac_ctx->unprocessed_block ) );

    mbedtls_zeroize( state, MBEDTLS_CIPHER_BLKSIZE_MAX );
    return( ret );
}

int mbedtls_cipher_cmac_reset( mbedtls_cipher_context_t *ctx )
{
    mbedtls_cmac_context_t* cmac_ctx;

    if( ctx == NULL || ctx->cipher_info == NULL || ctx->cmac_ctx == NULL )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    cmac_ctx = ctx->cmac_ctx;

    /* Reset the internal state */
    cmac_ctx->unprocessed_len = 0;
    mbedtls_zeroize( cmac_ctx->unprocessed_block,
                     sizeof( cmac_ctx->unprocessed_block ) );
    mbedtls_zeroize( cmac_ctx->state,
                     sizeof( cmac_ctx->state ) );

    return( 0 );
}

int mbedtls_cipher_cmac( const mbedtls_cipher_info_t *cipher_info,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *input, size_t ilen,
                         unsigned char *output )
{
    mbedtls_cipher_context_t ctx;
    int ret;

    if( cipher_info == NULL || key == NULL || input == NULL || output == NULL )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    mbedtls_cipher_init( &ctx );

    if( ( ret = mbedtls_cipher_setup( &ctx, cipher_info ) ) != 0 )
        goto exit;

    ret = mbedtls_cipher_cmac_starts( &ctx, key, keylen );
    if( ret != 0 )
        goto exit;

    ret = mbedtls_cipher_cmac_update( &ctx, input, ilen );
    if( ret != 0 )
        goto exit;

    ret = mbedtls_cipher_cmac_finish( &ctx, output );

exit:
    mbedtls_cipher_free( &ctx );

    return( ret );
}

oe_result_t oe_get_key(
    const void* sgx_key_request,
    void* sgx_key) {
    fprintf(stderr, "OE_GET_KEY not supported for REMOTE ATTESTATION\n");
    return -1;
}

