# SPDX-License-Identifier: GPL-2.0
# Makefile for io_uring unified interface tests

CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -fno-stack-protector -I../../../../include/uapi -I../../../../include
LDFLAGS = -lrdmacm -libverbs -lbpf -lxdp -lbpf -lelf

TARGETS = unified-rdma-test unified-nvme-test unified-full-stack-test

all: $(TARGETS)

unified-rdma-test: unified-rdma-test.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

unified-nvme-test: unified-nvme-test.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

unified-full-stack-test: unified-full-stack-test.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

install: $(TARGETS)
	mkdir -p $(DESTDIR)/usr/bin
	cp $(TARGETS) $(DESTDIR)/usr/bin/

.PHONY: all clean install