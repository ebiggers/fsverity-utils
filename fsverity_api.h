#ifndef _FSVERITY_KERNEL_DEFS_H
#define _FSVERITY_KERNEL_DEFS_H

#include <linux/limits.h>
#include <linux/ioctl.h>
#include <linux/types.h>

/* file-based verity support */

/*
 * TODO(ebiggers):  What is the purpose of this structure?  It's not actually
 * used for anything.
 */
struct fsverity_set {
	__u64 offset;
	__u64 flags;
};

/*
 * TODO(ebiggers): why isn't this using the same type code as used in the
 * fsverity_header?
 */
#define FS_VERITY_ROOT_HASH_ALGO_SHA256	0x0000

/*
 * TODO(ebiggers): rename this to 'struct fsverity_measurement' to avoid
 * confusion with the Merkle tree root hash?
 */
struct fsverity_root_hash {
	__u32 root_hash_algorithm;
	__u32 flags;
	__u8 reserved[4];
	__u8 root_hash[64];
};

/*
 * TODO(ebiggers): is there a less confusing name for this?  "measure" makes it
 * sound like it's returning something...
 */
#define FS_IOC_MEASURE_FSVERITY		_IOW('f', 133, \
					      struct fsverity_root_hash)
#define FS_IOC_SET_FSVERITY		_IOW('f', 134, struct fsverity_set)

#endif /* _FSVERITY_KERNEL_DEFS_H */
