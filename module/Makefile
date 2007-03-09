ARCH = i386
MODULE = imitate
EXTRA_CFLAGS = -DDEBUG=2

SYSCALL_INTERCEPTS = syscall_intercepts/open.o \
                     syscall_intercepts/read.o \
                     syscall_intercepts/close.o \
                     syscall_intercepts/mmap2.o \
                     syscall_intercepts/exit_group.o \
                     syscall_intercepts/clock_gettime.o \
                     syscall_intercepts/getdents64.o \
                     syscall_intercepts/fstat64.o \
                     syscall_intercepts/lstat64.o

obj-m += $(MODULE).o
$(MODULE)-objs += main.o \
                  syscall_log.o \
                  arch/$(ARCH)/syscall_intercept.o \
                  $(SYSCALL_INTERCEPTS)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	rm -f *~ *.o *.mod.c *.mod.o .*.cmd arch/i386/.*.cmd syscall_intercepts/.*.cmd
	rm -rf .tmp_versions

install: $(MODULE).ko
	./install.sh $(MOD_ARGS)

uninstall:
	sync
	rmmod $(MODULE)

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f Module.symvers
