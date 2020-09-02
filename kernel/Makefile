TARGET		= mah

MY_CFLAGS += -g # -DDEBUG
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

EXTRA_CFLAGS=-I$(PWD)/include -I$(PWD)/../include

obj-m		+= $(TARGET).o
$(TARGET)-objs := ./src/guest.o ./src/ioctl.o ./src/memory.o ./src/svm.o ./src/vmexit.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean

