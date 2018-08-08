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

This project is provided under the terms of the GNU General Public
License, version 2; or at your option, any later version.  A copy of the
GPLv2 can be found in the file named [COPYING](COPYING).

Permission to link to OpenSSL (libcrypto) is granted.

Send questions and bug reports to linux-fscrypt@vger.kernel.org.

# Submitting patches

Send patches to linux-fscrypt@vger.kernel.org.  Patches should follow
the Linux kernel's coding style.  Additionally, like the Linux kernel
itself, patches require the following "sign-off" procedure:

The sign-off is a simple line at the end of the explanation for the
patch, which certifies that you wrote it or otherwise have the right
to pass it on as an open-source patch.  The rules are pretty simple:
if you can certify the below:

Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

        (a) The contribution was created in whole or in part by me and I
            have the right to submit it under the open source license
            indicated in the file; or

        (b) The contribution is based upon previous work that, to the best
            of my knowledge, is covered under an appropriate open source
            license and I have the right under that license to submit that
            work with modifications, whether created in whole or in part
            by me, under the same open source license (unless I am
            permitted to submit under a different license), as indicated
            in the file; or

        (c) The contribution was provided directly to me by some other
            person who certified (a), (b) or (c) and I have not modified
            it.

        (d) I understand and agree that this project and the contribution
            are public and that a record of the contribution (including all
            personal information I submit with it, including my sign-off) is
            maintained indefinitely and may be redistributed consistent with
            this project or the open source license(s) involved.

then you just add a line saying::

	Signed-off-by: Random J Developer <random@developer.example.org>

using your real name (sorry, no pseudonyms or anonymous contributions.)
