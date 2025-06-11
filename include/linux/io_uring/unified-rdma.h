/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_IO_URING_UNIFIED_RDMA_H
#define _LINUX_IO_URING_UNIFIED_RDMA_H

#include <linux/types.h>
#include <linux/errno.h>

struct io_unified_rdma_ifq;
struct bpf_prog;

#if IS_ENABLED(CONFIG_IO_URING_UNIFIED)
int io_unified_rdma_setup_xdp(struct io_unified_rdma_ifq *ifq,
			      struct bpf_prog *prog);
void io_unified_rdma_detach_xdp(struct io_unified_rdma_ifq *ifq);
#else
static inline int io_unified_rdma_setup_xdp(struct io_unified_rdma_ifq *ifq,
					    struct bpf_prog *prog)
{
	return -EOPNOTSUPP;
}

static inline void io_unified_rdma_detach_xdp(struct io_unified_rdma_ifq *ifq)
{
}
#endif

#endif /* _LINUX_IO_URING_UNIFIED_RDMA_H */