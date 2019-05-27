 #define _GNU_SOURCE 
#include "websockets.h"
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

#include <sched.h>

typedef struct { double x, y; int group; } point_t, *point;

point_t point_list[1000];
void lloyd(point_t*, int, int);

int main(int argc, char* argv[]) {
	cpu_set_t my_set;        /* Define your cpu_set bit mask. */
	CPU_ZERO(&my_set);       /* Initialize it all to 0, i.e. no CPUs selected. */
	CPU_SET(3, &my_set);     /* set the bit that represents core 7. */
	sched_setaffinity(0, sizeof(cpu_set_t), &my_set);
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <fd of web socket>\n", argv[0]);
		return -1;
	}
	int fd = atoi(argv[1]);

	if (fcntl(fd, F_GETFD) == -1 && errno == EBADF) {
		fprintf(stderr, "Bad file descriptor passed\n");
		return -1;
	}
	char *points = read_websocket_message(fd);
	int progress = 0;
	int addition = 0;
	for (int i = 0; i < 1000; i++){
		sscanf(points + progress, "%lf %lf %n", &point_list[i].x, &point_list[i].y, &addition);
		progress += addition;
	}	
	clock_t begin = clock();
	lloyd(point_list, 1000, 11);
	clock_t end = clock();
	char log[100];
	sprintf(log, "Clustering done: %f seconds \n", (double)(end - begin) / CLOCKS_PER_SEC);	
	send_websocket_message(fd, log, strlen(log));
}
