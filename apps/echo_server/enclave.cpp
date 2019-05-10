#include "project_t.h"
#include "enclave.h"
#include <stdio.h>
#include <string.h>

void enclave_enter(void) {
	uint8_t message_to_send[] = "HELLO FROM SERVER";
	
	send_backend(message_to_send, strlen((char*)message_to_send));
	size_t recv_size;
	uint8_t *message_recv = recv_backend(&recv_size);
	if (message_recv == NULL)
		goto exit;
	message_recv[recv_size] = 0;
	if (strcmp("HELLO FROM ATTESTER", (char*)message_recv))
		goto exit;
	while(1) {
		char *message = recv_browser();
		if (message == NULL)
			break;
		if (send_browser(message) != 0) {
			free(message);
			break;
		}
		free(message);
	}	
exit:
	printf("Server exiting\n");
}
