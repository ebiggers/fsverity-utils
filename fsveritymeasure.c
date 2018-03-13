#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "fsverity_api.h"

static void usage(void)
{
	fprintf(stderr,
"Usage: fsveritymeasure FILE EXPECTED_MEASUREMENT\n"
"\n"
"EXPECTED_MEASUREMENT must be a 64-character hex string.\n");
	exit(2);
}

int main(int args, char *argv[])
{
	int fd, i;
	unsigned int byte;
	struct fsverity_root_hash measurement = { 0 };

	if (args != 3 || strlen(argv[2]) != 64)
		usage();

	for (i = 0; i < 32; i++) {
		if (sscanf(&argv[2][i*2], "%02x", &byte) != 1)
			usage();
		measurement.root_hash[i] = byte;
	}
	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open %s: %m\n", argv[1]);
		return 1;
	}
	if (ioctl(fd, FS_IOC_MEASURE_FSVERITY, &measurement)) {
		fprintf(stderr, "FS_IOC_MEASURE_FSVERITY: %m\n");
		return 1;
	}
	close(fd);
	return 0;
}
