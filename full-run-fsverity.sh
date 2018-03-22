#!/bin/sh

umount /mnt/f2fs
rm -f /root/f2fs.img
dd if=/dev/zero of=/root/f2fs.img seek=$(($1<16384000?128000:$1/128)) bs=512 count=1
/root/f2fs-tools/mkfs/mkfs.f2fs -O verity /root/f2fs.img
mount -o loop /root/f2fs.img /mnt/f2fs
cp /root/output-$1.apk /mnt/f2fs/output-$1.apk
make
./fsverity enable /mnt/f2fs/output-$1.apk
./fsverity set_measurement /mnt/f2fs/output-$1.apk $2
sync
echo 3 > /proc/sys/vm/drop_caches
dd if=/mnt/f2fs/output-$1.apk of=byte0-$1 count=1 bs=1
