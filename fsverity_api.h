#ifndef _FSVERITY_API_H
#define _FSVERITY_API_H

#include <linux/limits.h>
#include <linux/ioctl.h>
#include <linux/types.h>

/* file-based verity support */

#define FS_VERITY_ALG_SHA256	1
#define FS_VERITY_ALG_CRC32	2

struct fsverity_measurement {
	__u16 digest_algorithm;
	__u16 digest_size;
	__u32 reserved1;
	__u64 reserved2[3];
	__u8 digest[];
};

#define FS_IOC_ENABLE_VERITY		_IO('f', 133)
#define FS_IOC_SET_VERITY_MEASUREMENT	_IOW('f', 134, struct fsverity_measurement)

#endif /* _FSVERITY_API_H */
