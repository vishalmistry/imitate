#!/bin/sh

module="imitate"
device="imitate"
mode="664"

# sync disks
sync

# remove installed module
rmmod ${module}

# install modules with arguments given
/sbin/insmod ./${module}.ko $* || exit 1

# remove stale nodes
rm -f /dev/${device}

major=$(awk "\$2==\"${module}\" {print \$1}" /proc/devices)

mknod /dev/${device}0 c $major 0

group="users"

chgrp ${group} /dev/${device}0
chown ${mode} /dev/${device}0

