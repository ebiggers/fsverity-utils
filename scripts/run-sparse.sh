#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2020 Google LLC

set -e -u -o pipefail

find . -name '*.c' | while read -r file; do
	sparse "$file" -gcc-base-dir "$(gcc --print-file-name=)"	\
		-D_FILE_OFFSET_BITS=64 -I. -Wbitwise
done
