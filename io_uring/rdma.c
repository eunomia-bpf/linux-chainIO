// SPDX-License-Identifier: GPL-2.0
/*
 * io_uring RDMA operations
 *
 * Copyright (C) 2024 Your Name
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/io_uring.h>

#include "io_uring.h"
#include "unified-rdma.h"
#include "rdma.h"

struct io_rdma {
	struct file *file;
	u64 local_addr;
	u64 remote_addr;
	u32 length;
	u32 rkey;
	u32 lkey;
	u32 imm_data;
};

static void io_rdma_complete(struct io_kiocb *req, int ret)
{
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
}

int io_rdma_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_rdma *rdma;
	struct io_ring_ctx *ctx = req->ctx;
	
	if (!ctx->rdma_ifq)
		return -EOPNOTSUPP;
		
	rdma = io_kiocb_to_cmd(req, struct io_rdma);
	
	/* Validate operation code */
	if (req->opcode < IORING_OP_RDMA_SEND || req->opcode > IORING_OP_RDMA_READ)
		return -EINVAL;
		
	/* Copy RDMA parameters from SQE */
	rdma->local_addr = READ_ONCE(sqe->addr);
	rdma->length = READ_ONCE(sqe->len);
	rdma->remote_addr = READ_ONCE(sqe->addr2);
	rdma->rkey = READ_ONCE(sqe->addr3);
	rdma->imm_data = READ_ONCE(sqe->__pad2[0]);
	rdma->lkey = 0; /* Will be filled by RDMA layer */
	
	/* Validate parameters */
	if (!rdma->local_addr || !rdma->length)
		return -EINVAL;
		
	if ((req->opcode == IORING_OP_RDMA_WRITE || req->opcode == IORING_OP_RDMA_READ) &&
	    (!rdma->remote_addr || !rdma->rkey))
		return -EINVAL;
	
	return 0;
}

int io_rdma_send(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_rdma *rdma = io_kiocb_to_cmd(req, struct io_rdma);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_unified_rdma_ifq *ifq = ctx->rdma_ifq;
	struct io_unified_rdma_wr wr;
	int ret;
	
	if (!ifq || !ifq->connected)
		return -ENOTCONN;
		
	/* Build work request */
	memset(&wr, 0, sizeof(wr));
	wr.user_data = req->cqe.user_data;
	wr.opcode = IO_RDMA_OP_SEND;
	wr.local_addr = rdma->local_addr;
	wr.length = rdma->length;
	wr.imm_data = rdma->imm_data;
	wr.num_sge = 1;
	wr.sge[0].addr = rdma->local_addr;
	wr.sge[0].length = rdma->length;
	wr.sge[0].lkey = rdma->lkey;
	
	/* Submit to RDMA SQ ring */
	ret = io_unified_rdma_submit_wr(ifq, &wr);
	if (ret < 0) {
		io_rdma_complete(req, ret);
		return IOU_OK;
	}
	
	/* For now, complete immediately. Later we'll add async completion */
	io_rdma_complete(req, 0);
	return IOU_OK;
}

int io_rdma_recv(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_rdma *rdma = io_kiocb_to_cmd(req, struct io_rdma);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_unified_rdma_ifq *ifq = ctx->rdma_ifq;
	struct io_unified_rdma_wr wr;
	int ret;
	
	if (!ifq || !ifq->connected)
		return -ENOTCONN;
		
	/* Build work request */
	memset(&wr, 0, sizeof(wr));
	wr.user_data = req->cqe.user_data;
	wr.opcode = IO_RDMA_OP_RECV;
	wr.local_addr = rdma->local_addr;
	wr.length = rdma->length;
	wr.num_sge = 1;
	wr.sge[0].addr = rdma->local_addr;
	wr.sge[0].length = rdma->length;
	wr.sge[0].lkey = rdma->lkey;
	
	/* Submit receive request */
	ret = io_unified_rdma_post_recv(ifq, &wr);
	if (ret < 0) {
		io_rdma_complete(req, ret);
		return IOU_OK;
	}
	
	/* For now, complete immediately. Later we'll add async completion */
	io_rdma_complete(req, 0);
	return IOU_OK;
}

int io_rdma_write(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_rdma *rdma = io_kiocb_to_cmd(req, struct io_rdma);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_unified_rdma_ifq *ifq = ctx->rdma_ifq;
	struct io_unified_rdma_wr wr;
	int ret;
	
	if (!ifq || !ifq->connected)
		return -ENOTCONN;
		
	/* Build work request */
	memset(&wr, 0, sizeof(wr));
	wr.user_data = req->cqe.user_data;
	wr.opcode = IO_RDMA_OP_WRITE;
	wr.local_addr = rdma->local_addr;
	wr.length = rdma->length;
	wr.remote_addr = rdma->remote_addr;
	wr.rkey = rdma->rkey;
	wr.imm_data = rdma->imm_data;
	wr.num_sge = 1;
	wr.sge[0].addr = rdma->local_addr;
	wr.sge[0].length = rdma->length;
	wr.sge[0].lkey = rdma->lkey;
	
	/* Submit RDMA write */
	ret = io_unified_rdma_submit_wr(ifq, &wr);
	if (ret < 0) {
		io_rdma_complete(req, ret);
		return IOU_OK;
	}
	
	io_rdma_complete(req, 0);
	return IOU_OK;
}

int io_rdma_read(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_rdma *rdma = io_kiocb_to_cmd(req, struct io_rdma);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_unified_rdma_ifq *ifq = ctx->rdma_ifq;
	struct io_unified_rdma_wr wr;
	int ret;
	
	if (!ifq || !ifq->connected)
		return -ENOTCONN;
		
	/* Build work request */
	memset(&wr, 0, sizeof(wr));
	wr.user_data = req->cqe.user_data;
	wr.opcode = IO_RDMA_OP_READ;
	wr.local_addr = rdma->local_addr;
	wr.length = rdma->length;
	wr.remote_addr = rdma->remote_addr;
	wr.rkey = rdma->rkey;
	wr.num_sge = 1;
	wr.sge[0].addr = rdma->local_addr;
	wr.sge[0].length = rdma->length;
	wr.sge[0].lkey = rdma->lkey;
	
	/* Submit RDMA read */
	ret = io_unified_rdma_submit_wr(ifq, &wr);
	if (ret < 0) {
		io_rdma_complete(req, ret);
		return IOU_OK;
	}
	
	io_rdma_complete(req, 0);
	return IOU_OK;
}