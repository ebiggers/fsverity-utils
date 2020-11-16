// SPDX-License-Identifier: MIT
/*
 * The 'fsverity enable' command
 *
 * Copyright 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "fsverity.h"

#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <sys/ioctl.h>

static bool read_signature(const char *filename, u8 **sig_ret,
			   u32 *sig_size_ret)
{
	struct filedes file = { .fd = -1 };
	u64 file_size;
	u8 *sig = NULL;
	bool ok = false;

	if (!open_file(&file, filename, O_RDONLY, 0))
		goto out;
	if (!get_file_size(&file, &file_size))
		goto out;
	if (file_size <= 0) {
		error_msg("signature file '%s' is empty", filename);
		goto out;
	}
	if (file_size > 1000000) {
		error_msg("signature file '%s' is too large", filename);
		goto out;
	}
	sig = xmalloc(file_size);
	if (!full_read(&file, sig, file_size))
		goto out;
	*sig_ret = sig;
	*sig_size_ret = file_size;
	sig = NULL;
	ok = true;
out:
	filedes_close(&file);
	free(sig);
	return ok;
}

enum {
	OPT_HASH_ALG,
	OPT_BLOCK_SIZE,
	OPT_SALT,
	OPT_SIGNATURE,
};

static const struct option longopts[] = {
	{"hash-alg",	required_argument, NULL, OPT_HASH_ALG},
	{"block-size",	required_argument, NULL, OPT_BLOCK_SIZE},
	{"salt",	required_argument, NULL, OPT_SALT},
	{"signature",	required_argument, NULL, OPT_SIGNATURE},
	{NULL, 0, NULL, 0}
};

/* Enable fs-verity on a file. */
int fsverity_cmd_enable(const struct fsverity_command *cmd,
			int argc, char *argv[])
{
	struct libfsverity_merkle_tree_params tree_params = { .version = 1 };
	u8 *salt = NULL;
	u8 *sig = NULL;
	u32 sig_size = 0;
	struct filedes file;
	int status;
	int c;

	while ((c = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
		switch (c) {
		case OPT_HASH_ALG:
			if (!parse_hash_alg_option(optarg,
						   &tree_params.hash_algorithm))
				goto out_usage;
			break;
		case OPT_BLOCK_SIZE:
			if (!parse_block_size_option(optarg,
						     &tree_params.block_size))
				goto out_usage;
			break;
		case OPT_SALT:
			if (!parse_salt_option(optarg, &salt,
					       &tree_params.salt_size))
				goto out_usage;
			tree_params.salt = salt;
			break;
		case OPT_SIGNATURE:
			if (sig != NULL) {
				error_msg("--signature can only be specified once");
				goto out_usage;
			}
			if (!read_signature(optarg, &sig, &sig_size))
				goto out_err;
			break;
		default:
			goto out_usage;
		}
	}

	argv += optind;
	argc -= optind;

	if (argc != 1)
		goto out_usage;

	if (!open_file(&file, argv[0], O_RDONLY, 0))
		goto out_err;

	if (libfsverity_enable_with_sig(file.fd, &tree_params, sig, sig_size)) {
		error_msg_errno("FS_IOC_ENABLE_VERITY failed on '%s'",
				file.name);
		filedes_close(&file);
		goto out_err;
	}
	if (!filedes_close(&file))
		goto out_err;

	status = 0;
out:
	free(salt);
	free(sig);
	return status;

out_err:
	status = 1;
	goto out;

out_usage:
	usage(cmd, stderr);
	status = 2;
	goto out;
}
