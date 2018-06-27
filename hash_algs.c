// SPDX-License-Identifier: GPL-2.0+
/*
 * fs-verity hash algorithms
 *
 * Copyright (C) 2018 Google, Inc.
 *
 * Written by Eric Biggers, 2018.
 */

#include <string.h>
#include <openssl/evp.h>
#include <zlib.h>	/* for crc32() */

#include "fsverity_sys_decls.h"
#include "hash_algs.h"

static void free_hash_ctx(struct hash_ctx *ctx)
{
	free(ctx);
}

/* ========== libcrypto (OpenSSL) wrappers ========== */

struct openssl_hash_ctx {
	struct hash_ctx base;	/* must be first */
	EVP_MD_CTX *md_ctx;
	const EVP_MD *md;
};

static void openssl_digest_init(struct hash_ctx *_ctx)
{
	struct openssl_hash_ctx *ctx = (void *)_ctx;

	if (EVP_DigestInit_ex(ctx->md_ctx, ctx->md, NULL) != 1)
		fatal_error("EVP_DigestInit_ex() failed for algorithm '%s'",
			    ctx->base.alg->name);
}

static void openssl_digest_update(struct hash_ctx *_ctx,
				  const void *data, size_t size)
{
	struct openssl_hash_ctx *ctx = (void *)_ctx;

	if (EVP_DigestUpdate(ctx->md_ctx, data, size) != 1)
		fatal_error("EVP_DigestUpdate() failed for algorithm '%s'",
			    ctx->base.alg->name);
}

static void openssl_digest_final(struct hash_ctx *_ctx, u8 *digest)
{
	struct openssl_hash_ctx *ctx = (void *)_ctx;

	if (EVP_DigestFinal_ex(ctx->md_ctx, digest, NULL) != 1)
		fatal_error("EVP_DigestFinal_ex() failed for algorithm '%s'",
			    ctx->base.alg->name);
}

static void openssl_digest_ctx_free(struct hash_ctx *_ctx)
{
	struct openssl_hash_ctx *ctx = (void *)_ctx;

	EVP_MD_CTX_free(ctx->md_ctx);
	free(ctx);
}

static struct hash_ctx *
openssl_digest_ctx_create(const struct fsverity_hash_alg *alg, const EVP_MD *md)
{
	struct openssl_hash_ctx *ctx;

	ctx = xzalloc(sizeof(*ctx));
	ctx->base.alg = alg;
	ctx->base.init = openssl_digest_init;
	ctx->base.update = openssl_digest_update;
	ctx->base.final = openssl_digest_final;
	ctx->base.free = openssl_digest_ctx_free;

	ctx->md_ctx = EVP_MD_CTX_new();
	if (!ctx->md_ctx)
		fatal_error("out of memory");

	ctx->md = md;
	ASSERT(EVP_MD_size(md) == alg->digest_size);

	return &ctx->base;
}

static struct hash_ctx *create_sha256_ctx(const struct fsverity_hash_alg *alg)
{
	return openssl_digest_ctx_create(alg, EVP_sha256());
}

/* ========== zlib wrapper for CRC-32 ========== */

struct crc32_hash_ctx {
	struct hash_ctx base;	/* must be first */
	u32 remainder;
};

static void crc32_init(struct hash_ctx *_ctx)
{
	struct crc32_hash_ctx *ctx = (void *)_ctx;

	ctx->remainder = 0;
}

static void crc32_update(struct hash_ctx *_ctx, const void *data, size_t size)
{
	struct crc32_hash_ctx *ctx = (void *)_ctx;

	ctx->remainder = crc32(ctx->remainder, data, size);
}

/*
 * Big endian, to be compatible with `veritysetup --hash=crc32`, which uses
 * libgcrypt, which uses big endian CRC-32.
 */
static void crc32_final(struct hash_ctx *_ctx, u8 *digest)
{
	struct crc32_hash_ctx *ctx = (void *)_ctx;
	__be32 remainder = cpu_to_be32(ctx->remainder);

	memcpy(digest, &remainder, sizeof(remainder));
}

static struct hash_ctx *create_crc32_ctx(const struct fsverity_hash_alg *alg)
{
	struct crc32_hash_ctx *ctx = xzalloc(sizeof(*ctx));

	ctx->base.alg = alg;
	ctx->base.init = crc32_init;
	ctx->base.update = crc32_update;
	ctx->base.final = crc32_final;
	ctx->base.free = free_hash_ctx;
	return &ctx->base;
}

/* ========== Hash algorithm definitions ========== */

const struct fsverity_hash_alg fsverity_hash_algs[] = {
	[FS_VERITY_ALG_SHA256] = {
		.name = "sha256",
		.digest_size = 32,
		.cryptographic = true,
		.create_ctx = create_sha256_ctx,
	},
	[FS_VERITY_ALG_CRC32] = {
		.name = "crc32",
		.digest_size = 4,
		.create_ctx = create_crc32_ctx,
	},
};

const struct fsverity_hash_alg *find_hash_alg(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(fsverity_hash_algs); i++) {
		if (fsverity_hash_algs[i].name &&
		    !strcmp(name, fsverity_hash_algs[i].name))
			return &fsverity_hash_algs[i];
	}
	error_msg("unknown hash algorithm: '%s'", name);
	fputs("Available hash algorithms: ", stderr);
	show_all_hash_algs(stderr);
	putc('\n', stderr);
	return NULL;
}

void show_all_hash_algs(FILE *fp)
{
	int i;
	const char *sep = "";

	for (i = 0; i < ARRAY_SIZE(fsverity_hash_algs); i++) {
		if (fsverity_hash_algs[i].name) {
			fprintf(fp, "%s%s", sep, fsverity_hash_algs[i].name);
			sep = ", ";
		}
	}
}
