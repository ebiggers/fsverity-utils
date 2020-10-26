/* SPDX-License-Identifier: MIT */
/*
 * Private header for the 'fsverity' program
 *
 * Copyright 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#ifndef PROGRAMS_FSVERITY_H
#define PROGRAMS_FSVERITY_H

#include "utils.h"
#include "../common/fsverity_uapi.h"

/* The hash algorithm that 'fsverity' assumes when none is specified */
#define FS_VERITY_HASH_ALG_DEFAULT	FS_VERITY_HASH_ALG_SHA256

/*
 * Largest digest size among all hash algorithms supported by fs-verity.
 * This can be increased if needed.
 */
#define FS_VERITY_MAX_DIGEST_SIZE	64

struct fsverity_command;

/* cmd_digest.c */
int fsverity_cmd_digest(const struct fsverity_command *cmd,
			int argc, char *argv[]);

/* cmd_enable.c */
int fsverity_cmd_enable(const struct fsverity_command *cmd,
			int argc, char *argv[]);

/* cmd_measure.c */
int fsverity_cmd_measure(const struct fsverity_command *cmd,
			 int argc, char *argv[]);

/* cmd_sign.c */
int fsverity_cmd_sign(const struct fsverity_command *cmd,
		      int argc, char *argv[]);

/* fsverity.c */
void usage(const struct fsverity_command *cmd, FILE *fp);
bool parse_hash_alg_option(const char *arg, u32 *alg_ptr);
bool parse_block_size_option(const char *arg, u32 *size_ptr);
bool parse_salt_option(const char *arg, u8 **salt_ptr, u32 *salt_size_ptr);
u32 get_default_block_size(void);

#endif /* PROGRAMS_FSVERITY_H */
