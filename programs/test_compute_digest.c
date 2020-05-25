// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Test libfsverity_compute_digest().
 *
 * Copyright 2020 Google LLC
 */
#include "utils.h"

#define SHA256_DIGEST_SIZE 32

struct mem_file {
	u8 *data;
	size_t size;
	size_t offset;
};

static int read_fn(void *fd, void *buf, size_t count)
{
	struct mem_file *f = fd;

	ASSERT(count <= f->size - f->offset);
	memcpy(buf, &f->data[f->offset], count);
	f->offset += count;
	return 0;
}

int main(void)
{
	struct mem_file f = { .size = 1000000 };
	size_t i;
	const struct libfsverity_merkle_tree_params params = {
		.version = 1,
		.hash_algorithm = FS_VERITY_HASH_ALG_SHA256,
		.block_size = 4096,
		.salt_size = 4,
		.salt = (u8 *)"abcd",
		.file_size = f.size,
	};
	struct libfsverity_digest *d;
	static const u8 expected_digest[SHA256_DIGEST_SIZE] =
		"\x91\x79\x00\xb0\xd2\x99\x45\x4a\xa3\x04\xd5\xde\xbc\x6f\x39"
		"\xe4\xaf\x7b\x5a\xbe\x33\xbd\xbc\x56\x8d\x5d\x8f\x1e\x5c\x4d"
		"\x86\x52";
	int err;

	f.data = xmalloc(f.size);
	for (i = 0; i < f.size; i++)
		f.data[i] = (i % 11) + (i % 439) + (i % 1103);

	err = libfsverity_compute_digest(&f, read_fn, &params, &d);
	ASSERT(err == 0);

	ASSERT(d->digest_algorithm == FS_VERITY_HASH_ALG_SHA256);
	ASSERT(d->digest_size == SHA256_DIGEST_SIZE);
	ASSERT(!memcmp(d->digest, expected_digest, SHA256_DIGEST_SIZE));

	free(f.data);
	free(d);
	printf("test_compute_digest passed\n");
	return 0;
}
