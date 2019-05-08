#include <openenclave/host.h>
#include <openenclave/edger8r/host.h>
#include <stdio.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <fcntl.h>



#include "project_u.h"


#include "websockets.h"


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


int websocket_fd;
#define PAGE_SIZE (0x1000)
char message_buffer[PAGE_SIZE] ;

oe_enclave_t * enclave = NULL;
char download_filename[] = "/tmp/image.XXXXXX";
void cleanup_enclave(void){
	if(enclave)
		oe_terminate_enclave(enclave);
	unlink(download_filename);
}

int recv_message(void) {
	char* message = read_websocket_message(websocket_fd);
	if (message == NULL)
		return -1;
	if (strlen(message) > PAGE_SIZE - 2) {
		fprintf(stderr, "Received message longer than acceptable\n");
		return -2;
	}
	strcpy(message_buffer, message);
	free(message);
	return 0;
}


int send_message(void) {
	message_buffer[PAGE_SIZE-1] = 0;
	int total_length = strlen(message_buffer);
	return send_websocket_message(websocket_fd, message_buffer, total_length);	
}
int main(int argc, char* argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <fd of web socket>\n", argv[0]);
		return -1;
	}
	oe_enclave_t *enclave = NULL;
	int fd = atoi(argv[1]);
	
	if (fcntl(fd, F_GETFD) == -1 && errno == EBADF) {
		fprintf(stderr, "Bad file descriptor passed\n");
		return -1;
	}
	websocket_fd = fd;

	char * enclave_url = read_websocket_message(fd);
	if(enclave_url == NULL) {
		fprintf(stderr, "No encalve URL received\n");
		return -1;
	}
	printf("Enclave URL = %s\n",  enclave_url);
	
	mkstemp(download_filename);
	printf("Saving enclave image at %s\n", download_filename);
	
	CURL* curl = curl_easy_init();
	CURLcode res;
	if (curl) {
		FILE* fp = fopen(download_filename, "wb");
		curl_easy_setopt(curl, CURLOPT_URL, enclave_url);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);
		fclose(fp);
	} else {
		fprintf(stderr, "Image download failure\n");
		return -1;
	}

	if (res != CURLE_OK) {
		send_websocket_message(fd, "FAILED", sizeof("FAILED")-1);
		fprintf(stderr, "Couldn't download image\n");
		return -1;
	} else {
		send_websocket_message(fd, "OK", sizeof("OK")-1);
	}

	free(enclave_url);
	
	
	enclave = create_enclave(download_filename);
		
	if (enclave == NULL) {
		fprintf(stderr, "Enclave creation failed\n");
		return -1;
	}

	enclave_init(enclave, message_buffer);	

	enclave_enter(enclave);



//	enclave_hello(enclave);	
	uint8_t *pem_key = NULL;
        size_t key_size;
	uint8_t *remote_report = NULL;
	size_t remote_report_size;
		
	int retval;
	
	get_remote_report_with_pubkey(enclave, &retval, &pem_key, &key_size, &remote_report, &remote_report_size);
	printf("%s\n", pem_key);
	FILE * f = fopen("enclave_key.pem", "wb");
	fwrite(pem_key, 1, key_size, f);
	fclose(f);
	 f = fopen("report.dat", "wb");
	fwrite(remote_report, 1, remote_report_size, f);
	fclose(f);
	
	cleanup_enclave();


	return 0;
}
