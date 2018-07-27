# Introduction

This is `fsverity`, a userspace utility for fs-verity.  fs-verity is
a Linux kernel feature that does transparent on-demand
integrity/authenticity verification of the contents of read-only
files, using a Merkle tree (hash tree) hidden after the end of the
file.  The mechanism is similar to dm-verity, but implemented at the
file level rather than at the block device level.  The `fsverity`
utility allows you to set up fs-verity protected files.

So far, fs-verity is planned to be supported by the ext4 and f2fs
filesystems.

# Building and installing

The `fsverity` utility uses the OpenSSL library, so you first must
install the needed development files.  For example, on Debian-based
systems, run:

```bash
    sudo apt-get install libssl-dev
```

OpenSSL must be version 1.0.0 or later.

Then, to build and install:

```bash
    make
    sudo make install
```

# Examples

```bash
    mkfs.f2fs -O verity /dev/vdc
    mount /dev/vdc /vdc
    cd /vdc

    # Create a test file
    head -c 1000000 /dev/urandom > file
    md5sum file

    # Append the Merkle tree and other metadata to the file, and
    # (optional) sign the file with the kernel build-time generated key:
    fsverity setup file --signing-key ~/linux/certs/signing_key.pem

    # Enable fs-verity on the file
    fsverity enable file

    # Should show the same hash that 'fsverity setup' printed
    fsverity measure file

    # Contents are now transparently verified and should match the
    # original file contents, i.e. the metadata is hidden.
    md5sum file
```

# Notices

Copyright (C) 2018 Google, Inc.

License GPLv2+.  Permission to link to OpenSSL (libcrypto) is granted.

This is not an official Google product.

Do not fold, spindle, or mutilate.

Send questions, bug reports, and patches to linux-fscrypt@vger.kernel.org.
