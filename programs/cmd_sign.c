// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * The 'fsverity sign' command
 *
 * Copyright 2018 Google LLC
 */

#include "fsverity.h"

#include <fcntl.h>
#include <getopt.h>

static bool write_signature(const char *filename, const u8 *sig, u32 sig_size)
{
	struct filedes file;
	bool ok;

	if (!open_file(&file, filename, O_WRONLY|O_CREAT|O_TRUNC, 0644))
		return false;
	ok = full_write(&file, sig, sig_size);
	ok &= filedes_close(&file);
	return ok;
}

enum {
	OPT_HASH_ALG,
	OPT_BLOCK_SIZE,
	OPT_SALT,
	OPT_KEY,
	OPT_CERT,
};

static const struct option longopts[] = {
	{"hash-alg",	required_argument, NULL, OPT_HASH_ALG},
	{"block-size",	required_argument, NULL, OPT_BLOCK_SIZE},
	{"salt",	required_argument, NULL, OPT_SALT},
	{"key",		required_argument, NULL, OPT_KEY},
	{"cert",	required_argument, NULL, OPT_CERT},
	{NULL, 0, NULL, 0}
};

static int read_callback(void *file, void *buf, size_t count)
{
	errno = 0;
	if (!full_read(file, buf, count))
		return errno ? -errno : -EIO;
	return 0;
}

/* Sign a file for fs-verity by computing its measurement, then signing it. */
int fsverity_cmd_sign(const struct fsverity_command *cmd,
		      int argc, char *argv[])
{
	struct filedes file = { .fd = -1 };
	u8 *salt = NULL;
	struct libfsverity_merkle_tree_params tree_params = { .version = 1 };
	struct libfsverity_signature_params sig_params = {};
	struct libfsverity_digest *digest = NULL;
	char digest_hex[FS_VERITY_MAX_DIGEST_SIZE * 2 + 1];
	u8 *sig = NULL;
	size_t sig_size;
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
		case OPT_KEY:
			if (sig_params.keyfile != NULL) {
				error_msg("--key can only be specified once");
				goto out_usage;
			}
			sig_params.keyfile = optarg;
			break;
		case OPT_CERT:
			if (sig_params.certfile != NULL) {
				error_msg("--cert can only be specified once");
				goto out_usage;
			}
			sig_params.certfile = optarg;
			break;
		default:
			goto out_usage;
		}
	}

	argv += optind;
	argc -= optind;

	if (argc != 2)
		goto out_usage;

	if (tree_params.hash_algorithm == 0)
		tree_params.hash_algorithm = FS_VERITY_HASH_ALG_DEFAULT;

	if (tree_params.block_size == 0)
		tree_params.block_size = get_default_block_size();

	if (sig_params.keyfile == NULL) {
		error_msg("Missing --key argument");
		goto out_usage;
	}
	if (sig_params.certfile == NULL)
		sig_params.certfile = sig_params.keyfile;

	if (!open_file(&file, argv[0], O_RDONLY, 0))
		goto out_err;

	if (!get_file_size(&file, &tree_params.file_size))
		goto out_err;

	if (libfsverity_compute_digest(&file, read_callback,
				       &tree_params, &digest) != 0) {
		error_msg("failed to compute digest");
		goto out_err;
	}

	if (libfsverity_sign_digest(digest, &sig_params,
				    &sig, &sig_size) != 0) {
		error_msg("failed to sign digest");
		goto out_err;
	}

	if (!write_signature(argv[1], sig, sig_size))
		goto out_err;

	ASSERT(digest->digest_size <= FS_VERITY_MAX_DIGEST_SIZE);
	bin2hex(digest->digest, digest->digest_size, digest_hex);
	printf("Signed file '%s' (%s:%s)\n", argv[0],
	       libfsverity_get_hash_name(tree_params.hash_algorithm),
	       digest_hex);
	status = 0;
out:
	filedes_close(&file);
	free(salt);
	free(digest);
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
