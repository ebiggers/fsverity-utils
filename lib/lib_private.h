/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Private header for libfsverity
 *
 * Copyright 2020 Google LLC
 */
#ifndef LIB_LIB_PRIVATE_H
#define LIB_LIB_PRIVATE_H

#include "../common/libfsverity.h"
#include "../common/common_defs.h"
#include "../common/fsverity_uapi.h"

#include <stdarg.h>

#define LIBEXPORT	__attribute__((visibility("default")))

/* hash_algs.c */

struct fsverity_hash_alg {
	const char *name;
	unsigned int digest_size;
	unsigned int block_size;
	struct hash_ctx *(*create_ctx)(const struct fsverity_hash_alg *alg);
};

const struct fsverity_hash_alg *libfsverity_find_hash_alg_by_num(u32 alg_num);

struct hash_ctx {
	const struct fsverity_hash_alg *alg;
	void (*init)(struct hash_ctx *ctx);
	void (*update)(struct hash_ctx *ctx, const void *data, size_t size);
	void (*final)(struct hash_ctx *ctx, u8 *out);
	void (*free)(struct hash_ctx *ctx);
};

void libfsverity_hash_init(struct hash_ctx *ctx);
void libfsverity_hash_update(struct hash_ctx *ctx, const void *data,
			     size_t size);
void libfsverity_hash_final(struct hash_ctx *ctx, u8 *digest);
void libfsverity_hash_full(struct hash_ctx *ctx, const void *data, size_t size,
			   u8 *digest);
void libfsverity_free_hash_ctx(struct hash_ctx *ctx);

/* utils.c */

void *libfsverity_zalloc(size_t size);
void *libfsverity_memdup(const void *mem, size_t size);

__cold void
libfsverity_do_error_msg(const char *format, va_list va, int err);

__printf(1, 2) __cold void
libfsverity_error_msg(const char *format, ...);

__printf(1, 2) __cold void
libfsverity_error_msg_errno(const char *format, ...);

__cold void
libfsverity_warn_on(const char *condition, const char *file, int line);

#define WARN_ON(condition)						\
({									\
	bool c = (condition);						\
									\
	if (c)								\
		libfsverity_warn_on(#condition, __FILE__, __LINE__);	\
	c;								\
})

__cold void
libfsverity_bug_on(const char *condition, const char *file, int line);

#define BUG_ON(condition)						\
({									\
	bool c = (condition);						\
									\
	if (c)								\
		libfsverity_bug_on(#condition, __FILE__, __LINE__);	\
	c;								\
})

#endif /* LIB_LIB_PRIVATE_H */
