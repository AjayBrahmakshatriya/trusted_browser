// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/raise.h>
//#include "common.h"
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
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
void mbedtls_free(void* ptr)
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
void* mbedtls_calloc(size_t nmemb, size_t size)
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
