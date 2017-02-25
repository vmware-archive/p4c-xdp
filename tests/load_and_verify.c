#include <linux/bpf.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>

#include "bpf_load.h"
#include "libbpf.h"

int main(int ac, char **argv)
{
	char filename[256];
	struct rlimit r = {115200, 115200};

	snprintf(filename, sizeof(filename), "%s", argv[1]);

    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY)");
		return 1;
	}

	if (ac != 2) {
		printf("usage: %s BPF.o\n", argv[0]);
		return 1;
	}

	if (load_bpf_file(filename)) {
		printf("FAILED: %s", bpf_log_buf);
		return 1;
	}
	printf("PASS\n");

	return 0;
}
