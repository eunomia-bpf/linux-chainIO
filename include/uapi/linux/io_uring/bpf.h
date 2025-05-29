/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR MIT */
/*
 * Header file for the io_uring bpf interface.
 *
 * Copyright (C) 2024 Pavel Begunkov
 */
#ifndef LINUX_IO_URING_BPF_H
#define LINUX_IO_URING_BPF_H

#include <linux/types.h>

enum {
	IOU_BPF_RET_OK,
	IOU_BPF_RET_STOP,

	__IOU_BPF_RET_MAX,
};

struct io_uring_bpf_ctx {
};

#endif
