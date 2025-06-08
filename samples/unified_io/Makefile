# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Unified I/O Region sample program
#

CC = gcc
CFLAGS = -Wall -O2 -g
LDFLAGS = -luring -lbpf -lelf -lz

TARGET = unified_io_test
SOURCES = unified_io_test.c

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET) /tmp/unified_bpf.c /tmp/unified_bpf.o

.PHONY: all clean