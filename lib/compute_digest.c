// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * compute_digest.c
 *
 * Copyright 2018 Google LLC
 */

#include "sign.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#define FS_VERITY_MAX_LEVELS	64

/*
 * Merkle tree properties.  The file measurement is the hash of this structure
 * excluding the signature and with the sig_size field set to 0.
 */
struct fsverity_descriptor {
	__u8 version;		/* must be 1 */
	__u8 hash_algorithm;	/* Merkle tree hash algorithm */
	__u8 log_blocksize;	/* log2 of size of data and tree blocks */
	__u8 salt_size;		/* size of salt in bytes; 0 if none */
	__le32 sig_size;	/* size of signature in bytes; 0 if none */
	__le64 data_size;	/* size of file the Merkle tree is built over */
	__u8 root_hash[64];	/* Merkle tree root hash */
	__u8 salt[32];		/* salt prepended to each hashed block */
	__u8 __reserved[144];	/* must be 0's */
	__u8 signature[];	/* optional PKCS#7 signature */
};

struct block_buffer {
	u32 filled;
	u8 *data;
};

/*
 * Hash a block, writing the result to the next level's pending block buffer.
 * Returns true if the next level's block became full, else false.
 */
static bool hash_one_block(struct hash_ctx *hash, struct block_buffer *cur,
			   u32 block_size, const u8 *salt, u32 salt_size)
{
	struct block_buffer *next = cur + 1;

	/* Zero-pad the block if it's shorter than block_size. */
	memset(&cur->data[cur->filled], 0, block_size - cur->filled);

	hash_init(hash);
	hash_update(hash, salt, salt_size);
	hash_update(hash, cur->data, block_size);
	hash_final(hash, &next->data[next->filled]);

	next->filled += hash->alg->digest_size;
	cur->filled = 0;

	return next->filled + hash->alg->digest_size > block_size;
}

/*
 * Compute the file's Merkle tree root hash using the given hash algorithm,
 * block size, and salt.
 */
static bool compute_root_hash(struct filedes *file, u64 file_size,
			      struct hash_ctx *hash, u32 block_size,
			      const u8 *salt, u32 salt_size, u8 *root_hash)
{
	const u32 hashes_per_block = block_size / hash->alg->digest_size;
	const u32 padded_salt_size = roundup(salt_size, hash->alg->block_size);
	u8 *padded_salt = xzalloc(padded_salt_size);
	u64 blocks;
	int num_levels = 0;
	int level;
	struct block_buffer _buffers[1 + FS_VERITY_MAX_LEVELS + 1] = {};
	struct block_buffer *buffers = &_buffers[1];
	u64 offset;
	bool ok = false;

	if (salt_size != 0)
		memcpy(padded_salt, salt, salt_size);

	/* Compute number of levels */
	for (blocks = DIV_ROUND_UP(file_size, block_size); blocks > 1;
	     blocks = DIV_ROUND_UP(blocks, hashes_per_block)) {
		ASSERT(num_levels < FS_VERITY_MAX_LEVELS);
		num_levels++;
	}

	/*
	 * Allocate the block buffers.  Buffer "-1" is for data blocks.
	 * Buffers 0 <= level < num_levels are for the actual tree levels.
	 * Buffer 'num_levels' is for the root hash.
	 */
	for (level = -1; level < num_levels; level++)
		buffers[level].data = xmalloc(block_size);
	buffers[num_levels].data = root_hash;

	/* Hash each data block, also hashing the tree blocks as they fill up */
	for (offset = 0; offset < file_size; offset += block_size) {
		buffers[-1].filled = min(block_size, file_size - offset);

		if (!full_read(file, buffers[-1].data, buffers[-1].filled))
			goto out;

		level = -1;
		while (hash_one_block(hash, &buffers[level], block_size,
				      padded_salt, padded_salt_size)) {
			level++;
			ASSERT(level < num_levels);
		}
	}
	/* Finish all nonempty pending tree blocks */
	for (level = 0; level < num_levels; level++) {
		if (buffers[level].filled != 0)
			hash_one_block(hash, &buffers[level], block_size,
				       padded_salt, padded_salt_size);
	}

	/* Root hash was filled by the last call to hash_one_block() */
	ASSERT(buffers[num_levels].filled == hash->alg->digest_size);
	ok = true;
out:
	for (level = -1; level < num_levels; level++)
		free(buffers[level].data);
	free(padded_salt);
	return ok;
}

/*
 * Compute the fs-verity measurement of the given file.
 *
 * The fs-verity measurement is the hash of the fsverity_descriptor, which
 * contains the Merkle tree properties including the root hash.
 */
bool compute_file_measurement(const char *filename,
			      const struct fsverity_hash_alg *hash_alg,
			      u32 block_size, const u8 *salt,
			      u32 salt_size, u8 *measurement)
{
	struct filedes file = { .fd = -1 };
	struct hash_ctx *hash = hash_create(hash_alg);
	u64 file_size;
	struct fsverity_descriptor desc;
	bool ok = false;

	if (!open_file(&file, filename, O_RDONLY, 0))
		goto out;

	if (!get_file_size(&file, &file_size))
		goto out;

	memset(&desc, 0, sizeof(desc));
	desc.version = 1;
	desc.hash_algorithm = hash_alg - fsverity_hash_algs;

	ASSERT(is_power_of_2(block_size));
	desc.log_blocksize = ilog2(block_size);

	if (salt_size != 0) {
		if (salt_size > sizeof(desc.salt)) {
			error_msg("Salt too long (got %u bytes; max is %zu bytes)",
				  salt_size, sizeof(desc.salt));
			goto out;
		}
		memcpy(desc.salt, salt, salt_size);
		desc.salt_size = salt_size;
	}

	desc.data_size = cpu_to_le64(file_size);

	/* Root hash of empty file is all 0's */
	if (file_size != 0 &&
	    !compute_root_hash(&file, file_size, hash, block_size, salt,
			       salt_size, desc.root_hash))
		goto out;

	hash_full(hash, &desc, sizeof(desc), measurement);
	ok = true;
out:
	filedes_close(&file);
	hash_free(hash);
	return ok;
}
