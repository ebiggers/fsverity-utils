/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef SIGN_H
#define SIGN_H

#include "hash_algs.h"

#include <linux/types.h>

/*
 * Format in which verity file measurements are signed.  This is the same as
 * 'struct fsverity_digest', except here some magic bytes are prepended to
 * provide some context about what is being signed in case the same key is used
 * for non-fsverity purposes, and here the fields have fixed endianness.
 */
struct fsverity_signed_digest {
	char magic[8];			/* must be "FSVerity" */
	__le16 digest_algorithm;
	__le16 digest_size;
	__u8 digest[];
};

bool compute_file_measurement(const char *filename,
			      const struct fsverity_hash_alg *hash_alg,
			      u32 block_size, const u8 *salt,
			      u32 salt_size, u8 *measurement);

bool sign_data(const void *data_to_sign, size_t data_size,
	       const char *keyfile, const char *certfile,
	       const struct fsverity_hash_alg *hash_alg,
	       u8 **sig_ret, u32 *sig_size_ret);

#endif /* SIGN_H */
