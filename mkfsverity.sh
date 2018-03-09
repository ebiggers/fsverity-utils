#!/bin/bash

set -eu

SIZE=36864
KEEP_INPUT=false
PATCHES=()
ELISIONS=()

usage() {
	cat << EOF
Usage: $0 [OPTIONS]

Test formatting a randomly generated file for fs-verity.

Options:
  -s, --size=SIZE
  -k, --keep-input
  -p, --patch=OFFSET,LENGTH [can be repeated]
  -e, --elide=OFFSET,LENGTH [can be repeated]
  -h, --help
EOF
}

if ! options=$(getopt -o s:kp:e:h \
	-l size:,keep-input,patch:,elide:,help -- "$@"); then
	usage 1>&2
	exit 2
fi

eval set -- "$options"

while (( $# > 0 )); do
	case "$1" in
	-s|--size)
		SIZE="$2"
		shift
		;;
	-k|--keep-input)
		KEEP_INPUT=true
		;;
	-p|--patch)
		PATCHES+=("$2")
		shift
		;;
	-e|--elide)
		ELISIONS+=("$2")
		shift
		;;
	-h|--help)
		usage
		exit 0
		;;
	--)
		shift
		break
		;;
	*)
		echo 1>&2 "Invalid option \"$1\""
		usage 1>&2
		exit 2
		;;
	esac
	shift
done

if (( $# != 0 )); then
	usage 1>&2
	exit 2
fi

filename="input-$SIZE.apk"

if ! $KEEP_INPUT; then
    head -c "$SIZE" /dev/urandom > "$filename"
fi

cmd=(./fsveritysetup.py "$filename" "output-$SIZE.apk")
cmd+=("--salt=deadbeef00000000")

for i in "${!PATCHES[@]}"; do
	patch_offset=$(echo "${PATCHES[$i]}" | cut -d, -f1)
	patch_length=$(echo "${PATCHES[$i]}" | cut -d, -f2)
	patch_filename="output-$SIZE-patch_$i"
	head -c "$patch_length" /dev/urandom > "$patch_filename"
	cmd+=("--patch=$patch_offset,$patch_filename")
done

cmd+=("${ELISIONS[@]/#/--elide=}")

echo "${cmd[@]}"
"${cmd[@]}"
