// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_BPF_H
#define IOU_BPF_H

#include <linux/io_uring/bpf.h>
#include <linux/io_uring_types.h>

struct bpf_prog;

struct io_bpf_ctx {
	struct io_bpf_ctx_kern kern;
	struct io_ring_ctx *ctx;
	struct io_wait_queue *waitq;
	struct bpf_prog *prog;
};

static inline bool io_bpf_enabled(struct io_ring_ctx *ctx)
{
	return IS_ENABLED(CONFIG_BPF) && ctx->bpf_ctx != NULL;
}

#ifdef CONFIG_BPF
int io_register_bpf(struct io_ring_ctx *ctx, void __user *arg,
		    unsigned int nr_args);
int io_unregister_bpf(struct io_ring_ctx *ctx);
int io_run_bpf(struct io_ring_ctx *ctx);

#else
static inline int io_register_bpf(struct io_ring_ctx *ctx, void __user *arg,
				  unsigned int nr_args)
{
	return -EOPNOTSUPP;
}
static inline int io_unregister_bpf(struct io_ring_ctx *ctx)
{
	return -EOPNOTSUPP;
}
static inline int io_run_bpf(struct io_ring_ctx *ctx)
{
}
#endif

#endif
