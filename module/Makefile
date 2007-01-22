EXTRA_CFLAGS = -DDEBUG -DSYS_CALL_TABLE_ADDR=0xc02df4c0

obj-m += imitate.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	rm -f *~ *.o *.mod.c *.mod.o .*.cmd
	rm -rf .tmp_versions

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
