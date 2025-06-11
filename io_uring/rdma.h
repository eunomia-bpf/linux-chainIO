// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_RDMA_H
#define IOU_RDMA_H

#include <linux/io_uring_types.h>

#if defined(CONFIG_IO_URING_UNIFIED)

int io_rdma_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_rdma_send(struct io_kiocb *req, unsigned int issue_flags);
int io_rdma_recv(struct io_kiocb *req, unsigned int issue_flags);
int io_rdma_write(struct io_kiocb *req, unsigned int issue_flags);
int io_rdma_read(struct io_kiocb *req, unsigned int issue_flags);

#else

static inline int io_rdma_prep(struct io_kiocb *req,
			       const struct io_uring_sqe *sqe)
{
	return -EOPNOTSUPP;
}

static inline int io_rdma_send(struct io_kiocb *req, unsigned int issue_flags)
{
	return -EOPNOTSUPP;
}

static inline int io_rdma_recv(struct io_kiocb *req, unsigned int issue_flags)
{
	return -EOPNOTSUPP;
}

static inline int io_rdma_write(struct io_kiocb *req, unsigned int issue_flags)
{
	return -EOPNOTSUPP;
}

static inline int io_rdma_read(struct io_kiocb *req, unsigned int issue_flags)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_IO_URING_UNIFIED */

#endif /* IOU_RDMA_H */