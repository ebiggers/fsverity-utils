// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * The 'fsverity sign' command
 *
 * Copyright 2018 Google LLC
 */

#include "commands.h"
#include "fsverity_uapi.h"
#include "sign.h"

#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

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

/* Sign a file for fs-verity by computing its measurement, then signing it. */
int fsverity_cmd_sign(const struct fsverity_command *cmd,
		      int argc, char *argv[])
{
	const struct fsverity_hash_alg *hash_alg = NULL;
	u32 block_size = 0;
	u8 *salt = NULL;
	u32 salt_size = 0;
	const char *keyfile = NULL;
	const char *certfile = NULL;
	struct fsverity_signed_digest *digest = NULL;
	char digest_hex[FS_VERITY_MAX_DIGEST_SIZE * 2 + 1];
	u8 *sig = NULL;
	u32 sig_size;
	int status;
	int c;

	while ((c = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
		switch (c) {
		case OPT_HASH_ALG:
			if (hash_alg != NULL) {
				error_msg("--hash-alg can only be specified once");
				goto out_usage;
			}
			hash_alg = find_hash_alg_by_name(optarg);
			if (hash_alg == NULL)
				goto out_usage;
			break;
		case OPT_BLOCK_SIZE:
			if (!parse_block_size_option(optarg, &block_size))
				goto out_usage;
			break;
		case OPT_SALT:
			if (!parse_salt_option(optarg, &salt, &salt_size))
				goto out_usage;
			break;
		case OPT_KEY:
			if (keyfile != NULL) {
				error_msg("--key can only be specified once");
				goto out_usage;
			}
			keyfile = optarg;
			break;
		case OPT_CERT:
			if (certfile != NULL) {
				error_msg("--cert can only be specified once");
				goto out_usage;
			}
			certfile = optarg;
			break;
		default:
			goto out_usage;
		}
	}

	argv += optind;
	argc -= optind;

	if (argc != 2)
		goto out_usage;

	if (hash_alg == NULL)
		hash_alg = &fsverity_hash_algs[FS_VERITY_HASH_ALG_DEFAULT];

	if (block_size == 0)
		block_size = get_default_block_size();

	if (keyfile == NULL) {
		error_msg("Missing --key argument");
		goto out_usage;
	}
	if (certfile == NULL)
		certfile = keyfile;

	digest = xzalloc(sizeof(*digest) + hash_alg->digest_size);
	memcpy(digest->magic, "FSVerity", 8);
	digest->digest_algorithm = cpu_to_le16(hash_alg - fsverity_hash_algs);
	digest->digest_size = cpu_to_le16(hash_alg->digest_size);

	if (!compute_file_measurement(argv[0], hash_alg, block_size,
				      salt, salt_size, digest->digest))
		goto out_err;

	if (!sign_data(digest, sizeof(*digest) + hash_alg->digest_size,
		       keyfile, certfile, hash_alg, &sig, &sig_size))
		goto out_err;

	if (!write_signature(argv[1], sig, sig_size))
		goto out_err;

	bin2hex(digest->digest, hash_alg->digest_size, digest_hex);
	printf("Signed file '%s' (%s:%s)\n", argv[0], hash_alg->name,
	       digest_hex);
	status = 0;
out:
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
