// SPDX-License-Identifier: GPL-2.0
/*
 * fs-verity userspace tool
 *
 * Copyright (C) 2018, Google, Inc.
 */

#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "fsverity_api.h"

#define ARRAY_SIZE(A) (sizeof(A) / sizeof((A)[0]))

static const struct fsverity_hash_alg {
	const char *name;
	int digest_size;
} fsverity_hash_algs[] = {
	[FS_VERITY_ALG_SHA256] = {
		.name = "sha256",
		.digest_size = 32,
	},
	[FS_VERITY_ALG_CRC32] = {
		.name = "crc32",
		.digest_size = 4,
	},
};

static void show_hash_algs(void)
{
	size_t i;

	fprintf(stderr, "Available hash algorithms:");
	for (i = 0; i < ARRAY_SIZE(fsverity_hash_algs); i++) {
		if (fsverity_hash_algs[i].name)
			fprintf(stderr, " %s", fsverity_hash_algs[i].name);
	}
	fprintf(stderr, "\n");
}

static const struct fsverity_hash_alg *find_hash_alg(const char *name)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(fsverity_hash_algs); i++) {
		if (fsverity_hash_algs[i].name &&
		    !strcmp(name, fsverity_hash_algs[i].name))
			return &fsverity_hash_algs[i];
	}
	return NULL;
}

static int hex2bin_char(char c)
{
	if (c >= 'a' && c <= 'f')
		return 10 + c - 'a';
	if (c >= 'A' && c <= 'F')
		return 10 + c - 'A';
	if (c >= '0' && c <= '9')
		return c - '0';
	return -1;
}

static bool parse_hex_digest(const char *hex, __u8 *bin, size_t bin_len)
{
	size_t i;

	if (strlen(hex) != 2 * bin_len)
		return false;

	for (i = 0; i < bin_len; i++) {
		int hi = hex2bin_char(hex[i * 2]);
		int lo = hex2bin_char(hex[i * 2 + 1]);

		if (hi < 0 || lo < 0)
			return false;
		bin[i] = (hi << 4) | lo;
	}
	return true;
}

enum {
	OPT_HASH,
};

static void usage(void)
{
	const char * const usage_str =
"Usage: fsverity enable FILE\n"
"       fsverity set_measurement [--hash=HASH] FILE EXPECTED_MEASUREMENT\n"
"\n"
"EXPECTED_MEASUREMENT must be given as a hex string.\n"
"The default HASH algorithm is sha256.\n"
	;
	fputs(usage_str, stderr);
	show_hash_algs();
	exit(2);
}

static int fsverity_enable(int argc, char *argv[])
{
	int fd;

	if (argc != 2)
		usage();

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open %s: %m\n", argv[1]);
		return 1;
	}
	if (ioctl(fd, FS_IOC_ENABLE_VERITY, NULL)) {
		fprintf(stderr, "FS_IOC_ENABLE_VERITY: %m\n");
		return 1;
	}
	close(fd);
	return 0;
}

static int fsverity_set_measurement(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{"hash", required_argument, NULL, OPT_HASH},
		{NULL, 0, NULL, 0},
	};
	const struct fsverity_hash_alg *alg =
		&fsverity_hash_algs[FS_VERITY_ALG_SHA256];
	int c;
	int fd;
	struct fsverity_measurement *measurement;

	while ((c = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
		switch (c) {
		case OPT_HASH:
			alg = find_hash_alg(optarg);
			if (!alg) {
				fprintf(stderr,
					"Unknown hash algorithm: '%s'\n",
					optarg);
				show_hash_algs();
				return 2;
			}
			break;
		default:
			usage();
		}
	}
	argv += optind;
	argc -= optind;

	if (argc != 2)
		usage();

	fd = open(argv[0], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open %s: %m\n", argv[0]);
		return 1;
	}

	measurement = calloc(1, sizeof(*measurement) + alg->digest_size);
	measurement->digest_algorithm = alg - &fsverity_hash_algs[0];
	measurement->digest_size = alg->digest_size;
	if (!parse_hex_digest(argv[1], measurement->digest, alg->digest_size)) {
		fprintf(stderr,
			"Invalid EXPECTED_MEASUREMENT hex string.  Expected %u-character hex string for hash algorithm '%s'\n",
			alg->digest_size * 2, alg->name);
		return 2;
	}

	if (ioctl(fd, FS_IOC_SET_VERITY_MEASUREMENT, measurement)) {
		fprintf(stderr, "FS_IOC_SET_VERITY_MEASUREMENT: %m\n");
		return 1;
	}
	close(fd);
	return 0;
}

static const struct {
	const char *name;
	int (*func)(int argc, char *argv[]);
} commands[] = {
	{ "enable", fsverity_enable },
	{ "set_measurement", fsverity_set_measurement },
};

int main(int argc, char *argv[])
{
	size_t i;

	if (argc < 2)
		usage();

	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (!strcmp(argv[1], commands[i].name))
			return commands[i].func(argc - 1, argv + 1);
	}
	usage();
}
