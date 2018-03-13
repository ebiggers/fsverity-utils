#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "fsverity_api.h"

static void usage(void)
{
	fprintf(stderr, "Usage: fsverityset FILE\n");
	exit(2);
}

int main(int args, char *argv[])
{
	int fd;
	struct fsverity_set set = { 0 };

	if (args != 2)
		usage();

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open %s: %m\n", argv[1]);
		return 1;
	}
	if (ioctl(fd, FS_IOC_SET_FSVERITY, &set)) {
		fprintf(stderr, "FS_IOC_SET_FSVERITY: %m\n");
		return 1;
	}
	close(fd);
	return 0;
}
