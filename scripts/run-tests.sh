#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test script for fsverity-utils.  Runs 'make check' in lots of configurations,
# runs static analysis, and does a few other tests.
#
# Note: for more test coverage, in addition to running this script, also build
# fsverity-utils into a kvm-xfstests test appliance and run
# 'kvm-xfstests -c ext4,f2fs -g verity'

set -e -u -o pipefail
cd "$(dirname "$0")/.."

log() {
	echo "[$(date)] $*" 1>&2
}

fail() {
	echo "FAIL: $*" 1>&2
	exit 1
}

# Both stdout and stderr go to log file.
# Only stderr goes to terminal.
echo "Starting fsverity-utils tests.  See run-tests.log for full output."
rm -f run-tests.log
exec >> run-tests.log
exec 2> >(tee -ia run-tests.log 1>&2)

MAKE="make -j$(getconf _NPROCESSORS_ONLN)"

log "Build and test with statically linking"
$MAKE
if ldd fsverity | grep libfsverity.so; then
	fail "fsverity binary should be statically linked to libfsverity by default"
fi
./fsverity --version

log "Check that all global symbols are prefixed with \"libfsverity_\""
if nm libfsverity.a | grep ' T ' | grep -v " libfsverity_"; then
	fail "Some global symbols are not prefixed with \"libfsverity_\""
fi

log "Build and test with dynamic linking"
$MAKE USE_SHARED_LIB=1
if ! ldd fsverity | grep libfsverity.so; then
	fail "fsverity binary should be dynamically linked to libfsverity when USE_SHARED_LIB=1"
fi
LD_LIBRARY_PATH="." ./fsverity --version

log "Check that all exported symbols are prefixed with \"libfsverity_\""
if nm libfsverity.so | grep ' T ' | grep -v " libfsverity_"; then
	fail "Some exported symbols are not prefixed with \"libfsverity_\""
fi

log "Build and test with gcc"
$MAKE CC=gcc check

log "Build and test with gcc (-Wall + -Werror)"
$MAKE CC=gcc CFLAGS="-Wall -Werror" check

log "Build and test with gcc (32-bit)"
$MAKE CC=gcc CFLAGS="-m32" LDFLAGS="-m32" check

log "Build and test with clang"
$MAKE CC=clang check

log "Build and test with clang (-Wall + -Werror)"
$MAKE CC=clang CFLAGS="-Wall -Werror" check

log "Build and test with clang + UBSAN"
$MAKE CC=clang CFLAGS="-fsanitize=undefined -fno-sanitize-recover=undefined" \
	LDFLAGS="-fsanitize=undefined" check

log "Build and test with clang + ASAN"
$MAKE CC=clang CFLAGS="-fsanitize=address -fno-sanitize-recover=address" \
	LDFLAGS="-fsanitize=address" check

log "Build and test with clang + unsigned integer overflow sanitizer"
$MAKE CC=clang CFLAGS="-fsanitize=unsigned-integer-overflow -fno-sanitize-recover=unsigned-integer-overflow" \
	LDFLAGS="-fsanitize=unsigned-integer-overflow" check

log "Build and test with valgrind"
$MAKE TEST_WRAPPER_PROG="valgrind --quiet --error-exitcode=100 --leak-check=full --errors-for-leak-kinds=all" \
	check

log "Build and test using BoringSSL instead of OpenSSL"
BSSL=$HOME/src/boringssl
$MAKE LDFLAGS="-L$BSSL/build/crypto" CPPFLAGS="-I$BSSL/include" \
	LDLIBS="-lcrypto -lpthread" check

log "Build and test using -funsigned-char"
$MAKE CFLAGS="-funsigned-char -Wall -Werror" check

log "Build and test using -fsigned-char"
$MAKE CFLAGS="-fsigned-char -Wall -Werror" check

log "Run sparse"
./scripts/run-sparse.sh

log "Run clang static analyzer"
scan-build --status-bugs make all test_programs

log "Run gcc static analyzer"
$MAKE CC=gcc CFLAGS="-fanalyzer -Werror" all test_programs

log "Run shellcheck"
shellcheck scripts/*.sh 1>&2
