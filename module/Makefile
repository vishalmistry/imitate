EXTRA_CFLAGS = -DDEBUG -DSYS_CALL_TABLE_ADDR=0xc02df4c0

obj-m += imitate.o

all:
	./build_type_defs.rb /usr/src/linux-headers-$(shell uname -r)/include/linux/syscalls.h syscall_types.h
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	rm -f *~ *.o *.mod.c *.mod.o .*.cmd
	rm -rf .tmp_versions

install: uninstall imitate.ko
	insmod imitate.ko

uninstall:
	sync
	rmmod imitate

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
