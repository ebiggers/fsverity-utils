// SPDX-License-Identifier: GPL-2.0+
/*
 * The 'fsverity set_measurement' command
 *
 * Copyright (C) 2018 Google, Inc.
 *
 * Written by Eric Biggers, 2018.
 */

#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include "commands.h"
#include "fsverity_sys_decls.h"
#include "hash_algs.h"

enum {
	OPT_HASH,
};

static const struct option longopts[] = {
	{"hash", required_argument, NULL, OPT_HASH},
	{NULL, 0, NULL, 0}
};

int fsverity_cmd_set_measurement(const struct fsverity_command *cmd,
				 int argc, char *argv[])
{
	const struct fsverity_hash_alg *alg = DEFAULT_HASH_ALG;
	struct fsverity_measurement *measurement = NULL;
	struct filedes file;
	int c;
	int status;

	while ((c = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
		switch (c) {
		case OPT_HASH:
			alg = find_hash_alg(optarg);
			if (!alg)
				goto out_usage;
			break;
		default:
			goto out_usage;
		}
	}
	argv += optind;
	argc -= optind;

	if (argc != 2)
		goto out_usage;

	measurement = xzalloc(sizeof(*measurement) + alg->digest_size);
	measurement->digest_algorithm = alg - fsverity_hash_algs;
	measurement->digest_size = alg->digest_size;
	if (!hex2bin(argv[1], measurement->digest, alg->digest_size)) {
		error_msg("Invalid EXPECTED_MEASUREMENT hex string.\n"
			  "       Expected %u-character hex string for hash algorithm '%s'.",
			  alg->digest_size * 2, alg->name);
		goto out_usage;
	}

	if (!open_file(&file, argv[0], O_RDONLY, 0))
		goto out_err;
	if (ioctl(file.fd, FS_IOC_SET_VERITY_MEASUREMENT, measurement) != 0) {
		error_msg_errno("FS_IOC_SET_VERITY_MEASUREMENT failed on '%s'",
				file.name);
		filedes_close(&file);
		goto out_err;
	}
	if (!filedes_close(&file))
		goto out_err;
	status = 0;
out:
	free(measurement);
	return status;

out_err:
	status = 1;
	goto out;

out_usage:
	usage(cmd, stderr);
	status = 2;
	goto out;
}
