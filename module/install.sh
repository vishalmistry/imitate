#!/bin/sh

module="imitate"
device="imitate"
mode="664"
symfile="/proc/kallsyms"

syscall_awk='$0 ~ /sys_call_table$/ { addr = $1; count += 1 } END { if (count == 1) { print "0x" addr } else { print "ERROR" } }'
syscall_addr=$(awk "${syscall_awk}" "${symfile}")

echo "System call table line(s) in '${symfile}':"
grep sys_call_table "${symfile}"

if [ "${syscall_addr}" = "ERROR" ]; then
    echo "Could not obtain address from symbols"
    exit 1
fi

echo
echo -n "System call table address is ${syscall_addr}. Is this correct? (yes/no) [no]: "

while true; do
    read REPLY
    if [ "$REPLY" != "yes" ] && [ "$REPLY" != "no" ] && [ "$REPLY" != "" ]; then
        echo -n "Please answer 'yes' or 'no' [no]: "
    else
        break
    fi
done

if [ "$REPLY" != "yes" ]; then
    echo "Aborting."
    exit 1
fi

# sync disks
sync

# remove installed module
rmmod ${module}

# install modules with arguments given
/sbin/insmod ./${module}.ko sys_call_table_addr=${syscall_addr} $* || exit 1

# remove stale nodes
rm -f /dev/${device}

major=$(awk "\$2==\"${module}\" {print \$1}" /proc/devices)

mknod /dev/${device}0 c $major 0

group="users"

chgrp ${group} /dev/${device}0
chmod ${mode} /dev/${device}0

