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
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <seccomp.h>
#include <signal.h>

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
int attestation_fd;
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

int recv_fixed_size(uint8_t *buffer, size_t size, int fd) {
	size_t total = 0;
	while(total < size) {
		size_t chunk = read(fd, buffer + total, size - total);
		if (chunk == 0)
			return -1;
		total += chunk;
	}
	return 0;
}
int recv_backend_message(void) {
	char message_size_str[32] = {0};
	if (recv_fixed_size(message_size_str, 18, attestation_fd))
		return -1;
	int message_size;
	sscanf(message_size_str, "%i", &message_size);
	if (message_size > (PAGE_SIZE - 2)) {
		fprintf(stderr, "Too long of a message_received from backend\n");
		return -2;
	}		
	*(size_t*)message_buffer = message_size;
	if(recv_fixed_size(message_buffer + sizeof(size_t), message_size, attestation_fd))
		return -1;	
	return 0;
}

int send_backend_message(void) {
	char message_size_str[32] = {0};
	size_t message_size = *(size_t*)message_buffer;
	sprintf(message_size_str, "0x%016lx", message_size);
	if(18 != write(attestation_fd, message_size_str, 18))
		return -1;
	if(message_size != write(attestation_fd, message_buffer + sizeof(size_t), message_size))
		return -1;
}
#define ADD_SECCOMP_RULE(ctx, ...)                      \
	do {                                                  \
		if(seccomp_rule_add(ctx, __VA_ARGS__) < 0) {        \
			fprintf(stderr, "Could not add seccomp rule");             \
			seccomp_release(ctx);                             \
			exit(-1);                                         \
		}                                                   \
	} while(0)
void sig_handler(int signum) {
	fprintf(stderr, "Process tried to do an action it is not allowed - KILLING\n");
	exit(-1);
}
void insert_seccomp_filters(void) {
	signal(SIGSYS, sig_handler);
	
	static scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_TRAP);
	if(ctx == NULL) {
		fprintf(stderr, "Could not open seccomp context");
		exit(-1);
	}	
	ADD_SECCOMP_RULE(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit      ), 0);
	ADD_SECCOMP_RULE(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	ADD_SECCOMP_RULE(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write     ), 0);
	ADD_SECCOMP_RULE(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read      ), 0);

	ADD_SECCOMP_RULE(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk       ), 0);

	ADD_SECCOMP_RULE(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap      ), 0);
	ADD_SECCOMP_RULE(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat     ), 0);
	if(seccomp_load(ctx) < 0) {
		fprintf(stderr, "Could not load seccomp context\n");
		exit(-1);
	}

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
		goto fail;
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
		goto fail;
	}
	if (res != CURLE_OK) {
		send_websocket_message(fd, "FAILED", sizeof("FAILED")-1);
		fprintf(stderr, "Couldn't download image\n");
		goto fail;
	}
	free(enclave_url);


	char *attestation_url_host = read_websocket_message(fd);
	char *attestation_url_port_string = read_websocket_message(fd);
	if (attestation_url_host == NULL || attestation_url_port_string == NULL) {
		fprintf(stderr, "Attestation server details not received\n");
		goto fail;
	}
	unsigned short attestation_url_port = atoi(attestation_url_port_string);
	free(attestation_url_port_string);

	printf("Creating attestation connection at %s:%d\n", attestation_url_host, (int)attestation_url_port); 

	in_addr_t server_addr;


	int fd_a;

	struct hostent *hostent;
	struct sockaddr_in sockaddr_in;

	struct protoent *protoent = getprotobyname("tcp");
	hostent = gethostbyname(attestation_url_host);

	fd_a = socket(AF_INET, SOCK_STREAM, protoent->p_proto);
	attestation_fd = fd_a;
	server_addr = inet_addr(inet_ntoa(*(struct in_addr*)*(hostent->h_addr_list)));
	sockaddr_in.sin_addr.s_addr = server_addr;
	sockaddr_in.sin_family = AF_INET;
	sockaddr_in.sin_port = htons(attestation_url_port);

	if (connect(fd_a, (struct sockaddr*)&sockaddr_in, sizeof(sockaddr_in)) == -1) {
		fprintf(stderr, "Connection to attestation server failed\n");
		goto fail;
	}

	free(attestation_url_host);


	enclave = create_enclave(download_filename);


	if (enclave == NULL) {
		fprintf(stderr, "Enclave creation failed\n");
		goto fail;
	}

	uint8_t *pem_key = NULL;
	size_t key_size;
	uint8_t *remote_report = NULL;
	size_t remote_report_size;

	int retval;

	get_remote_report_with_pubkey(enclave, &retval, &pem_key, &key_size, &remote_report, &remote_report_size);

	char report_len_string[32];
	sprintf(report_len_string, "0x%016lx", remote_report_size);
	write(fd_a, report_len_string, 18);
	write(fd_a, remote_report, remote_report_size);

	char key_len_string[32];
	sprintf(key_len_string, "0x%016lx", key_size);
	write(fd_a, key_len_string, 18);
	write(fd_a, pem_key, key_size);	

	insert_seccomp_filters();
	enclave_init(enclave, message_buffer);	


	size_t first_message_size = *(size_t*)message_buffer;
	uint8_t *first_message = (uint8_t*)malloc(first_message_size);
	memcpy(first_message, message_buffer + sizeof(size_t), first_message_size);
	char first_message_len_string[32];
	sprintf(first_message_len_string, "0x%016lx", first_message_size);
	write(fd_a, first_message_len_string, 18);
	write(fd_a, first_message, first_message_size);
	free(first_message);


	char attestation_response[32];
	int res_length = 0;
	while (res_length < 18) {
		res_length += read(fd_a, attestation_response + res_length, 18 - res_length);
	}
	attestation_response[18] = 0;

	unsigned int attestation_status = 0x1;
	if (sscanf(attestation_response, "%i", &attestation_status) != 1) {
		fprintf(stderr, "Remote server did not attest enclave\n");
		goto fail;
	}

	if(attestation_status != 0) {
		fprintf(stderr, "Remote server did not attest enclave\n");
		fprintf(stderr, "Received %s\n", attestation_response);
		goto fail;
	}

	printf("Remote server successfully attested enclave\n");

	send_websocket_message(fd, "OK", sizeof("OK")-1);
	enclave_enter(enclave);




	cleanup_enclave();
	return 0;
fail:
	cleanup_enclave();
	send_websocket_message(fd, "FAILED", sizeof("FAILED")-1);	
	return -1;
}
