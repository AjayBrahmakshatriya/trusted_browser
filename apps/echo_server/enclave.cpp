#include "project_t.h"
#include "enclave.h"
#include <stdio.h>

void enclave_enter(void) {
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
	printf("Server exiting\n");
}
