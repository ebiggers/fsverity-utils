#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2020 Google LLC

set -e -u -o pipefail
cd "$(dirname "$0")/.."

if [ $# != 1 ]; then
	echo "Usage: $0 VERS" 1>&2
	echo "  e.g. $0 1.0" 1>&2
	exit 2
fi

VERS=$1
PKG=fsverity-utils-$VERS

git checkout -f
git clean -fdx
./scripts/run-tests.sh
git clean -fdx

major=$(echo "$VERS" | cut -d. -f1)
minor=$(echo "$VERS" | cut -d. -f2)
sed -E -i -e "/FSVERITY_UTILS_MAJOR_VERSION/s/[0-9]+/$major/" \
	  -e "/FSVERITY_UTILS_MINOR_VERSION/s/[0-9]+/$minor/" \
	  common/libfsverity.h
git commit -a --signoff --message="v$VERS"
git tag --sign "v$VERS" --message="$PKG"

git archive "v$VERS" --prefix="$PKG/" > "$PKG.tar"
tar xf "$PKG.tar"
( cd "$PKG" && make check )
rm -r "$PKG"

gpg --detach-sign --armor "$PKG.tar"
DESTDIR=/pub/linux/kernel/people/ebiggers/fsverity-utils/v$VERS
kup mkdir "$DESTDIR"
kup put "$PKG.tar" "$PKG.tar.asc" "$DESTDIR/$PKG.tar.gz"
git push
git push --tags
