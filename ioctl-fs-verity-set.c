#include <linux/fs.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

int main(int args, char *argv[])
{
  int res, fd;
  struct fsverity_set fsverity_set;
  char *endptr;

  if (args != 3) {
    printf("Usage:\n ioctl-fs-verity-set [filepath] [offset of fs-verity header]\n");
    return -EINVAL;
  }
  fsverity_set.offset = strtol(argv[2], &endptr, 10);
  printf("Parsed offset: [%llu]\n", fsverity_set.offset);
  fsverity_set.flags = 0;
	fd = open(argv[1], O_RDWR);	
	if (fd == -1) {
		printf("Could not open [%s]\n", argv[1]);
		return -EINVAL;
	}
	res = ioctl(fd, FS_IOC_SET_FSVERITY, &fsverity_set);	
	if (res) {
		printf("ioctl() returned [%d]\n", res);
		return 1;
	}
	close(fd);
	return 0;
}
