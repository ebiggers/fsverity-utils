// SPDX-License-Identifier: MIT
/*
 * The 'fsverity measure' command
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
#include <sys/ioctl.h>

static const struct option longopts[] = {
	{NULL, 0, NULL, 0}
};

/* Display the fs-verity digest of the given verity file(s). */
int fsverity_cmd_measure(const struct fsverity_command *cmd,
			 int argc, char *argv[])
{
	struct fsverity_digest *d = NULL;
	struct filedes file;
	char digest_hex[FS_VERITY_MAX_DIGEST_SIZE * 2 + 1];
	char _hash_alg_name[32];
	const char *hash_alg_name;
	int status;
	int i;

	/*
	 * No supported options, but run getopt_long() with an empty longopts
	 * array so that any options are rejected and "--" works as expected.
	 */
	if (getopt_long(argc, argv, "", longopts, NULL) != -1)
		goto out_usage;

	argv += optind;
	argc -= optind;

	if (argc < 1)
		goto out_usage;

	d = xzalloc(sizeof(*d) + FS_VERITY_MAX_DIGEST_SIZE);

	for (i = 0; i < argc; i++) {
		d->digest_size = FS_VERITY_MAX_DIGEST_SIZE;

		if (!open_file(&file, argv[i], O_RDONLY, 0))
			goto out_err;
		if (ioctl(file.fd, FS_IOC_MEASURE_VERITY, d) != 0) {
			error_msg_errno("FS_IOC_MEASURE_VERITY failed on '%s'",
					file.name);
			filedes_close(&file);
			goto out_err;
		}
		filedes_close(&file);

		ASSERT(d->digest_size <= FS_VERITY_MAX_DIGEST_SIZE);
		bin2hex(d->digest, d->digest_size, digest_hex);
		hash_alg_name = libfsverity_get_hash_name(d->digest_algorithm);
		if (!hash_alg_name) {
			sprintf(_hash_alg_name, "ALG_%u", d->digest_algorithm);
			hash_alg_name = _hash_alg_name;
		}
		printf("%s:%s %s\n", hash_alg_name, digest_hex, argv[i]);
	}
	status = 0;
out:
	free(d);
	return status;

out_err:
	status = 1;
	goto out;

out_usage:
	usage(cmd, stderr);
	status = 2;
	goto out;
}
