/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef FSVERITY_SYS_DECLS_H
#define FSVERITY_SYS_DECLS_H

#include <linux/limits.h>
#include <linux/ioctl.h>
#include <linux/types.h>

/* ========== Ioctls ========== */

#define FS_VERITY_ALG_SHA256	1
#define FS_VERITY_ALG_CRC32	2

/* Same as 'struct fsverity_signed_measurement', but with native endianness */
struct fsverity_measurement {
	__u16 digest_algorithm;
	__u16 digest_size;
	__u32 reserved1;
	__u64 reserved2[3];
	__u8 digest[];
};

#define FS_IOC_ENABLE_VERITY		_IO('f', 133)
#define FS_IOC_SET_VERITY_MEASUREMENT	_IOW('f', 134, struct fsverity_measurement)

/* ========== On-disk footer format ========== */

#define FS_VERITY_MAGIC		"TrueBrew"
#define FS_VERITY_MAJOR		1
#define FS_VERITY_MINOR		0

/* Fixed-length portion of footer (begins after Merkle tree) */
struct fsverity_footer {
	__u8 magic[8];		/* must be FS_VERITY_MAGIC */
	__u8 major_version;	/* must be FS_VERITY_MAJOR */
	__u8 minor_version;	/* must be FS_VERITY_MINOR */
	__u8 log_blocksize;	/* log2(data-bytes-per-hash), e.g. 12 for 4KB */
	__u8 log_arity;		/* log2(leaves-per-node), e.g. 7 for SHA-256 */
	__le16 meta_algorithm;	/* hash algorithm for tree blocks */
	__le16 data_algorithm;	/* hash algorithm for data blocks */
	__le32 flags;		/* flags */
	__le32 reserved1;	/* must be 0 */
	__le64 size;		/* size of the original, unpadded data */
	__u8 authenticated_ext_count; /* number of authenticated extensions */
	__u8 unauthenticated_ext_count; /* number of unauthenticated extensions */
	__u8 reserved2[30];	/* must be 0 */
	/* This structure is 64 bytes long */
}; /* followed by zero or more extensions (struct fsverity_extension) */

#define FS_VERITY_FLAG_INTEGRITY_ONLY	0x00000001

/* extension types */
#define FS_VERITY_EXT_ELIDE		1
#define FS_VERITY_EXT_PATCH		2
#define FS_VERITY_EXT_SALT		3
#define FS_VERITY_EXT_PKCS7_SIGNATURE	4

/* Header of each variable-length metadata item following the fsverity_footer */
struct fsverity_extension {
	/*
	 * Length of this extension in bytes, including this header.  Must be
	 * rounded up to an 8-byte boundary when advancing to the next
	 * extension.
	 */
	__le32 length;
	__le16 type;		/* Type of this extension (see codes above) */
	__le16 reserved;	/* Reserved, must be 0 */
};

struct fsverity_extension_elide {
	__le64 offset;
	__le64 length;
};

struct fsverity_extension_patch {
	__le64 offset;
}; /* followed by variable-length replacement data */

/*
 * Same as 'struct fsverity_measurement', but with fixed endianness, so it can
 * be stored on-disk in the file footer.
 */
struct fsverity_signed_measurement {
	__le16 digest_algorithm;
	__le16 digest_size;
	__le32 reserved1;
	__le64 reserved2[3];
	__u8 digest[];
};

#endif /* FSVERITY_SYS_DECLS_H */
