/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * libfsverity API
 *
 * Copyright 2018 Google LLC
 * Copyright (C) 2020 Facebook
 */

#ifndef LIBFSVERITY_H
#define LIBFSVERITY_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#define FS_VERITY_HASH_ALG_SHA256       1
#define FS_VERITY_HASH_ALG_SHA512       2

struct libfsverity_merkle_tree_params {
	uint32_t version;		/* must be 1			*/
	uint32_t hash_algorithm;	/* one of FS_VERITY_HASH_ALG_*	*/
	uint32_t block_size;		/* Merkle tree block size in bytes */
	uint32_t salt_size;		/* salt size in bytes (0 if unsalted) */
	uint64_t file_size;		/* file size in bytes		*/
	const uint8_t *salt;		/* pointer to salt (optional)	*/
	uint64_t reserved[11];		/* must be 0			*/
};

struct libfsverity_digest {
	uint16_t digest_algorithm;	/* one of FS_VERITY_HASH_ALG_* */
	uint16_t digest_size;		/* size of digest in bytes */
	uint8_t digest[];		/* the actual digest */
};

struct libfsverity_signature_params {
	const char *keyfile;		/* path to key file (PEM format) */
	const char *certfile;		/* path to certificate (PEM format) */
	uint64_t reserved[11];		/* must be 0 */
};

/*
 * libfsverity_read_fn_t - callback that incrementally provides a file's data
 * @fd: the user-provided "file descriptor" (opaque to library)
 * @buf: buffer into which to read the next chunk of the file's data
 * @count: number of bytes to read in this chunk
 *
 * Must return 0 on success (all 'count' bytes read), or a negative errno value
 * on failure.
 */
typedef int (*libfsverity_read_fn_t)(void *fd, void *buf, size_t count);

/**
 * libfsverity_compute_digest() - Compute digest of a file
 *          An fsverity digest is the root of the Merkle tree of the file.
 *          Not to be confused with a traditional file digests computed over
 *          the entire file.
 * @fd: context that will be passed to @read_fn
 * @read_fn: a function that will read the data of the file
 * @params: struct libfsverity_merkle_tree_params specifying hash algorithm,
 *	    block size, version, and optional salt parameters.
 *	    reserved parameters must be zero.
 * @digest_ret: Pointer to pointer for computed digest.
 *
 * Returns:
 * * 0 for success, -EINVAL for invalid input arguments, -ENOMEM if failed
 *   to allocate memory, or an error returned by @read_fn.
 * * digest_ret returns a pointer to the digest on success. The digest object
 *   is allocated by libfsverity and must be freed by the caller.
 */
int
libfsverity_compute_digest(void *fd, libfsverity_read_fn_t read_fn,
			   const struct libfsverity_merkle_tree_params *params,
			   struct libfsverity_digest **digest_ret);

/**
 * libfsverity_sign_digest() - Sign previously computed digest of a file
 *          This signature is used by the file system to validate the
 *          signed file measurement against a public key loaded into the
 *          .fs-verity kernel keyring, when CONFIG_FS_VERITY_BUILTIN_SIGNATURES
 *          is enabled. The signature is formatted as PKCS#7 stored in DER
 *          format. See Documentation/filesystems/fsverity.rst in the kernel
 *          source tree for further details.
 * @digest: pointer to previously computed digest
 * @sig_params: struct libfsverity_signature_params providing filenames of
 *          the keyfile and certificate file. Reserved parameters must be zero.
 * @sig_ret: Pointer to pointer for signed digest
 * @sig_size_ret: Pointer to size of signed return digest
 *
 * Return:
 * * 0 for success, -EINVAL for invalid input arguments or if the cryptographic
 *   operations to sign the digest failed, -EBADMSG if the key and/or
 *   certificate file is invalid, or another negative errno value.
 * * sig_ret returns a pointer to the signed digest on success. This object
 *   is allocated by libfsverity and must be freed by the caller.
 * * sig_size_ret returns the size (in bytes) of the signed digest on success.
 */
int
libfsverity_sign_digest(const struct libfsverity_digest *digest,
			const struct libfsverity_signature_params *sig_params,
			uint8_t **sig_ret, size_t *sig_size_ret);

/**
 * libfsverity_find_hash_alg_by_name() - Find hash algorithm by name
 * @name: Pointer to name of hash algorithm
 *
 * Return: The hash algorithm number, or zero if not found.
 */
uint32_t libfsverity_find_hash_alg_by_name(const char *name);

/**
 * libfsverity_get_digest_size() - Get size of digest for a given algorithm
 * @alg_num: Number of hash algorithm
 *
 * Return: size of digest in bytes, or -1 if algorithm is unknown.
 */
int libfsverity_get_digest_size(uint32_t alg_num);

/**
 * libfsverity_get_hash_name() - Get name of hash algorithm by number
 * @alg_num: Number of hash algorithm
 *
 * Return: The name of the hash algorithm, or NULL if algorithm is unknown.
 */
const char *libfsverity_get_hash_name(uint32_t alg_num);

/**
 * libfsverity_set_error_callback() - Set callback to handle error messages
 * @cb: the callback function
 */
void libfsverity_set_error_callback(void (*cb)(const char *msg));

#endif /* LIBFSVERITY_H */