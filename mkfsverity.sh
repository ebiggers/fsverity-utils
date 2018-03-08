#!/bin/sh

set -x

OPTIND=1
patch=0
patch_offset=28672
patch_length=128
elide=0
elide_offset=12288
elid_length=8192
size=36864
keep_input=0
while getopts "poeskf:" opt; do
    case "$opt" in
	p)  patch=1
	    ;;
	o)  patch_offset=$OPTARG
	    ;;
	e)  elide=1
	    ;;
	f)  elide_offset=$OPTARG
	    ;;
	s)  size=$OPTARG
	    ;;
	k)  keep_input=1
	    ;;
    esac
done
shift $((OPTIND-1))
[ "$1" = "--" ] && shift
filename="input-$size.apk"
backup_filename="input-$size-backup.apk"
patch_filename="output-$size-patch"
echo "size=$size, filename='$filename', patch_filename='$patch_filename', patch=$patch, patch_offset=$patch_offset, elide=$elide, unparsed: $@"
num_blks=$(($size / 4096))
blk_aligned_sz=$(($num_blks*4096))
echo "Number of blocks: $num_blks"
if [ $keep_input -eq 0 ]; then
    remainder=$(($size % 4096))
    echo "Remainder: $remainder"
    dd if=/dev/urandom of=$filename bs=4096 count=$num_blks
    dd if=/dev/urandom of=$filename bs=1 count=$remainder seek=$blk_aligned_sz
fi
dd if=/dev/urandom of=$patch_filename bs=1 count=$patch_length
if [ $elide -eq 1 ]; then ELIDE_ARGS=" --elide_offset=${elide_offset} --elide_length=${elide_length}"; fi
if [ $patch -eq 1 ]; then PATCH_ARGS=" --patch_offset=${patch_offset} --patch_file=${patch_filename}"; fi
./fsverity.py $filename "output-$size.apk" --salt=deadbeef00000000 ${PATCH_ARGS} ${ELIDE_ARGS}
