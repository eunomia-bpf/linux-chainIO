# SPDX-License-Identifier: GPL-2.0
#
# Makefile for NVMe Ring I/O sample program
#

CC = gcc
CFLAGS = -Wall -O2 -g
LDFLAGS = -luring

TARGET = nvme_ring_io_test
SOURCES = nvme_ring_io_test.c

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean