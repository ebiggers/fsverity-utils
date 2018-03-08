#include <linux/fs.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <string.h>

int main(int args, char *argv[])
{
  int res, fd, i;
  struct fsverity_root_hash root_hash;

  if (args != 3 || strlen(argv[2]) != 64) {
    printf("Usage:\n ioctl-fs-verity [filepath] [root hash in hex; 64 characters]\n");
    return -EINVAL;
  }

  fd = open(argv[1], O_RDONLY);	

  if (fd == -1) {
    printf("Could not open [%s]\n", argv[1]);
    return -EINVAL;
  }
  memset((void*)&root_hash, 0, sizeof(struct fsverity_root_hash));
  for (i = 0; i < 32; i++) {
    char hdigit[3] = {0, 0, 0};

    memcpy(hdigit, &argv[2][i*2], 2);
    res = sscanf(hdigit, "%x", &root_hash.root_hash[i]);
    if (res != 1)
      return -EINVAL;
  }
  res = ioctl(fd, FS_IOC_MEASURE_FSVERITY, &root_hash);
  if (res) {
    printf("ioctl() returned [%d]\n", res);
    return 1;
  }
  close(fd);
  return 0;
}
