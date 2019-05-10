#ifndef ENCLAVE_H
#define ENCLAVE_H

#ifdef __cplusplus
extern "C" {
#endif


char* recv_browser(void);
int send_browser(char*);

uint8_t* recv_backend(size_t*);
int send_backend(uint8_t*, size_t);
#ifdef __cplusplus
}
#endif

#endif
