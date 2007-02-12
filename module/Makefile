ARCH = i386
MODULE = imitate
EXTRA_CFLAGS = -DDEBUG -DSYS_CALL_TABLE_ADDR=0xc02dd4c0

obj-m += $(MODULE).o
$(MODULE)-objs += main.o arch/$(ARCH)/syscall_intercept.o

all:
	./build_type_defs.rb /usr/src/linux-headers-$(shell uname -r)/include/linux/syscalls.h syscall_types.h
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	rm -f *~ *.o *.mod.c *.mod.o .*.cmd
	rm -rf .tmp_versions

install: $(MODULE).ko
	./install.sh $(MOD_ARGS)

uninstall:
	sync
	rmmod $(MODULE)

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
