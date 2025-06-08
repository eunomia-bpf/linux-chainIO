/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IOU_UNIFIED_H
#define IOU_UNIFIED_H

#include <linux/io_uring_types.h>

struct io_kiocb;
struct io_uring_sqe;

int io_register_unified_region(struct io_ring_ctx *ctx,
			       struct io_uring_unified_region_reg __user *arg);
int io_unregister_unified_region(struct io_ring_ctx *ctx);
int io_unified_submit(struct io_ring_ctx *ctx, struct io_unified_desc *desc);
int io_unified_complete(struct io_ring_ctx *ctx, unsigned int nr);
int io_unified_attach_bpf(struct io_ring_ctx *ctx, int prog_fd);

/* IORING_OP_UNIFIED handlers */
int io_unified_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_unified(struct io_kiocb *req, unsigned int issue_flags);

#endif