// SPDX-License-Identifier: GPL-2.0+
/*
 * Signature support for 'fsverity setup'
 *
 * Copyright (C) 2018 Google LLC
 *
 * Written by Eric Biggers.
 */

#include <fcntl.h>
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <stdlib.h>
#include <string.h>

#include "fsverity_uapi.h"
#include "fsveritysetup.h"
#include "hash_algs.h"

static void display_openssl_errors(void)
{
	if (ERR_peek_error() == 0)
		return;

	fprintf(stderr, "OpenSSL library errors:\n");
	ERR_print_errors_fp(stderr);
}

static BIO *new_mem_buf(const void *buf, size_t size)
{
	BIO *bio;

	ASSERT(size <= INT_MAX);
	/*
	 * Prior to OpenSSL 1.1.0, BIO_new_mem_buf() took a non-const pointer,
	 * despite still marking the resulting bio as read-only.  So cast away
	 * the const to avoid a compiler warning with older OpenSSL versions.
	 */
	bio = BIO_new_mem_buf((void *)buf, size);
	if (!bio)
		error_msg("out of memory");
	return bio;
}

/* Read a PEM PKCS#8 formatted private key */
static EVP_PKEY *read_private_key(const char *keyfile)
{
	BIO *bio;
	EVP_PKEY *pkey;

	bio = BIO_new_file(keyfile, "r");
	if (!bio) {
		error_msg_errno("can't open '%s' for reading", keyfile);
		return NULL;
	}

	pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (!pkey) {
		error_msg("Failed to parse private key file '%s'.\n"
			  "       Note: it must be in PEM PKCS#8 format.",
			  keyfile);
		display_openssl_errors();
	}
	BIO_free(bio);
	return pkey;
}

/* Read a PEM X.509 formatted certificate */
static X509 *read_certificate(const char *certfile)
{
	BIO *bio;
	X509 *cert;

	bio = BIO_new_file(certfile, "r");
	if (!bio) {
		error_msg_errno("can't open '%s' for reading", certfile);
		return NULL;
	}
	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!cert) {
		error_msg("Failed to parse X.509 certificate file '%s'.\n"
			  "       Note: it must be in PEM format.",
			  certfile);
		display_openssl_errors();
	}
	BIO_free(bio);
	return cert;
}

/*
 * Check that the given data is a valid 'struct fsverity_digest_disk' that
 * matches the given @expected_digest and @hash_alg.
 *
 * Return: NULL if the digests match, else a string describing the difference.
 */
static const char *
compare_fsverity_digest(const void *data, size_t size,
			const u8 *expected_digest,
			const struct fsverity_hash_alg *hash_alg)
{
	const struct fsverity_digest_disk *d = data;

	if (size != sizeof(*d) + hash_alg->digest_size)
		return "unexpected length";

	if (le16_to_cpu(d->digest_algorithm) != hash_alg - fsverity_hash_algs)
		return "unexpected hash algorithm";

	if (le16_to_cpu(d->digest_size) != hash_alg->digest_size)
		return "wrong digest size for hash algorithm";

	if (memcmp(expected_digest, d->digest, hash_alg->digest_size))
		return "wrong digest";

	return NULL;
}

/*
 * Sign the specified @data_to_sign of length @data_size bytes using the private
 * key in @keyfile, the certificate in @certfile, and the hash algorithm
 * @hash_alg.  Returns the DER-formatted PKCS#7 signature, with the signed data
 * included (not detached), in @sig_ret and @sig_size_ret.
 */
static bool sign_data(const void *data_to_sign, size_t data_size,
		      const char *keyfile, const char *certfile,
		      const struct fsverity_hash_alg *hash_alg,
		      void **sig_ret, int *sig_size_ret)
{
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	BIO *bio = NULL;
	PKCS7 *p7 = NULL;
	const EVP_MD *md;
	/*
	 * PKCS#7 signing flags:
	 *
	 * - PKCS7_BINARY	signing binary data, so skip MIME translation
	 *
	 * - PKCS7_NOATTR	omit extra authenticated attributes, such as
	 *			SMIMECapabilities
	 *
	 * - PKCS7_NOCERTS	omit the signer's certificate
	 *
	 * - PKCS7_PARTIAL	PKCS7_sign() creates a handle only, then
	 *			PKCS7_sign_add_signer() can add a signer later.
	 *			This is necessary to change the message digest
	 *			algorithm from the default of SHA-1.  Requires
	 *			OpenSSL 1.0.0 or later.
	 */
	int pkcs7_flags = PKCS7_BINARY | PKCS7_NOATTR | PKCS7_NOCERTS |
			  PKCS7_PARTIAL;
	void *sig;
	int sig_size;
	bool ok = false;

	pkey = read_private_key(keyfile);
	if (!pkey)
		goto out;

	cert = read_certificate(certfile);
	if (!cert)
		goto out;

	OpenSSL_add_all_digests();
	ASSERT(hash_alg->cryptographic);
	md = EVP_get_digestbyname(hash_alg->name);
	if (!md) {
		fprintf(stderr,
			"Warning: '%s' algorithm not found in OpenSSL library.\n"
			"         Falling back to SHA-256 signature.\n",
			hash_alg->name);
		md = EVP_sha256();
	}

	bio = new_mem_buf(data_to_sign, data_size);
	if (!bio)
		goto out;

	p7 = PKCS7_sign(NULL, NULL, NULL, bio, pkcs7_flags);
	if (!p7) {
		error_msg("failed to initialize PKCS#7 signature object");
		display_openssl_errors();
		goto out;
	}

	if (!PKCS7_sign_add_signer(p7, cert, pkey, md, pkcs7_flags)) {
		error_msg("failed to add signer to PKCS#7 signature object");
		display_openssl_errors();
		goto out;
	}

	if (PKCS7_final(p7, bio, pkcs7_flags) != 1) {
		error_msg("failed to finalize PKCS#7 signature");
		display_openssl_errors();
		goto out;
	}

	BIO_free(bio);
	bio = BIO_new(BIO_s_mem());
	if (!bio) {
		error_msg("out of memory");
		goto out;
	}

	if (i2d_PKCS7_bio(bio, p7) != 1) {
		error_msg("failed to DER-encode PKCS#7 signature object");
		display_openssl_errors();
		goto out;
	}

	sig_size = BIO_get_mem_data(bio, &sig);
	*sig_ret = xmemdup(sig, sig_size);
	*sig_size_ret = sig_size;
	ok = true;
out:
	EVP_PKEY_free(pkey);
	X509_free(cert);
	PKCS7_free(p7);
	BIO_free(bio);
	return ok;
}

/*
 * Read a file measurement signature in PKCS#7 DER format from @signature_file,
 * validate that the signed data matches the expected measurement, then return
 * the PKCS#7 DER message in @sig_ret and @sig_size_ret.
 */
static bool read_signature(const char *signature_file,
			   const u8 *expected_measurement,
			   const struct fsverity_hash_alg *hash_alg,
			   void **sig_ret, int *sig_size_ret)
{
	struct filedes file = { .fd = -1 };
	u64 filesize;
	void *sig = NULL;
	BIO *bio = NULL;
	PKCS7 *p7 = NULL;
	bool ok = false;
	const char *reason;

	if (!open_file(&file, signature_file, O_RDONLY, 0))
		goto out;
	if (!get_file_size(&file, &filesize))
		goto out;
	if (filesize <= 0) {
		error_msg("signature file '%s' is empty", signature_file);
		goto out;
	}
	if (filesize > 1000000) {
		error_msg("signature file '%s' is too large", signature_file);
		goto out;
	}
	sig = xmalloc(filesize);
	if (!full_read(&file, sig, filesize))
		goto out;

	bio = new_mem_buf(sig, filesize);
	if (!bio)
		goto out;

	p7 = d2i_PKCS7_bio(bio, NULL);
	if (!p7) {
		error_msg("failed to decode PKCS#7 signature from '%s'",
			  signature_file);
		display_openssl_errors();
		goto out;
	}

	if (OBJ_obj2nid(p7->type) != NID_pkcs7_signed ||
	    OBJ_obj2nid(p7->d.sign->contents->type) != NID_pkcs7_data) {
		reason = "unexpected PKCS#7 content type";
	} else {
		const ASN1_OCTET_STRING *o = p7->d.sign->contents->d.data;

		reason = compare_fsverity_digest(o->data, o->length,
						 expected_measurement,
						 hash_alg);
	}
	if (reason) {
		error_msg("signed file measurement from '%s' is invalid (%s)",
			  signature_file, reason);
		goto out;
	}

	printf("Using existing signed file measurement from '%s'\n",
	       signature_file);
	*sig_ret = sig;
	*sig_size_ret = filesize;
	sig = NULL;
	ok = true;
out:
	filedes_close(&file);
	free(sig);
	BIO_free(bio);
	PKCS7_free(p7);
	return ok;
}

static bool write_signature(const char *signature_file,
			    const void *sig, int sig_size)
{
	struct filedes file;
	bool ok;

	if (!open_file(&file, signature_file, O_WRONLY|O_CREAT|O_TRUNC, 0644))
		return false;
	ok = full_write(&file, sig, sig_size);
	ok &= filedes_close(&file);
	if (ok)
		printf("Wrote signed file measurement to '%s'\n",
		       signature_file);
	return ok;
}

/*
 * Append the signed file measurement to the output file as a PKCS7_SIGNATURE
 * extension item.
 *
 * Return: exit status code (0 on success, nonzero on failure)
 */
int append_signed_measurement(struct filedes *out,
			      const struct fsveritysetup_params *params,
			      const u8 *measurement)
{
	struct fsverity_digest_disk *data_to_sign = NULL;
	void *sig = NULL;
	void *extbuf = NULL;
	void *tmp;
	int sig_size;
	int status;

	if (params->signing_key_file) {
		size_t data_size = sizeof(*data_to_sign) +
				   params->hash_alg->digest_size;

		/* Sign the file measurement using the given key */

		data_to_sign = xzalloc(data_size);
		data_to_sign->digest_algorithm =
			cpu_to_le16(params->hash_alg - fsverity_hash_algs);
		data_to_sign->digest_size =
			cpu_to_le16(params->hash_alg->digest_size);
		memcpy(data_to_sign->digest, measurement,
		       params->hash_alg->digest_size);

		ASSERT(compare_fsverity_digest(data_to_sign, data_size,
					measurement, params->hash_alg) == NULL);

		if (!sign_data(data_to_sign, data_size,
			       params->signing_key_file,
			       params->signing_cert_file ?:
			       params->signing_key_file,
			       params->hash_alg,
			       &sig, &sig_size))
			goto out_err;

		if (params->signature_file &&
		    !write_signature(params->signature_file, sig, sig_size))
			goto out_err;
	} else {
		/* Using a signature that was already created */
		if (!read_signature(params->signature_file, measurement,
				    params->hash_alg, &sig, &sig_size))
			goto out_err;
	}

	tmp = extbuf = xzalloc(FSVERITY_EXTLEN(sig_size));
	fsverity_append_extension(&tmp, FS_VERITY_EXT_PKCS7_SIGNATURE,
				  sig, sig_size);
	ASSERT(tmp == extbuf + FSVERITY_EXTLEN(sig_size));
	if (!full_write(out, extbuf, FSVERITY_EXTLEN(sig_size)))
		goto out_err;
	status = 0;
out:
	free(data_to_sign);
	free(sig);
	free(extbuf);
	return status;

out_err:
	status = 1;
	goto out;
}
