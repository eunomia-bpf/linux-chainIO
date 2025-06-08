// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/nospec.h>
#include <linux/io_uring.h>
#include <linux/nvme.h>
#include <linux/blk-mq.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <rdma/ib_addr.h>
#include <uapi/linux/io_uring.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <net/xdp.h>

#include "io_uring.h"
#include "memmap.h"
#include "unified.h"
#include "unified-rdma.h"
#include "rsrc.h"

static struct workqueue_struct *io_unified_rdma_wq;

/* RDMA device discovery and management */
static struct ib_device *io_rdma_find_device(const char *dev_name)
{
	struct ib_device *device;
	
	device = ib_find_device_by_name(dev_name);
	if (!device) {
		pr_warn("io_uring: RDMA device '%s' not found\n", dev_name);
		return NULL;
	}
	
	if (!rdma_cap_ib_mad(device, 1) && !rdma_cap_ib_mcast(device, 1) &&
	    !rdma_cap_eth_ah(device, 1)) {
		pr_warn("io_uring: RDMA device '%s' has no usable capabilities\n", dev_name);
		ib_device_put(device);
		return NULL;
	}
	
	return device;
}

/* Memory region management */
int io_unified_rdma_reg_mr(struct io_unified_rdma_region *region,
			   void *addr, size_t length, int access_flags,
			   struct io_unified_rdma_mr *mr)
{
	struct ib_mr *ib_mr;
	int ret;
	
	if (!region || !region->pd || !addr || !length || !mr)
		return -EINVAL;
	
	ib_mr = ib_reg_user_mr(region->pd, (unsigned long)addr, length,
			       (unsigned long)addr, access_flags);
	if (IS_ERR(ib_mr)) {
		ret = PTR_ERR(ib_mr);
		pr_err("io_uring: Failed to register RDMA MR: %d\n", ret);
		return ret;
	}
	
	mr->addr = (u64)(uintptr_t)addr;
	mr->length = length;
	mr->lkey = ib_mr->lkey;
	mr->rkey = ib_mr->rkey;
	mr->access_flags = access_flags;
	
	/* Store IB MR pointer for later cleanup */
	if (region->num_mrs < IO_UNIFIED_RDMA_MAX_ENTRIES) {
		region->mrs[region->num_mrs] = ib_mr;
		region->num_mrs++;
	} else {
		ib_dereg_mr(ib_mr);
		return -ENOSPC;
	}
	
	pr_debug("io_uring: Registered RDMA MR: addr=0x%llx, len=%zu, lkey=0x%x, rkey=0x%x\n",
		 mr->addr, length, mr->lkey, mr->rkey);
	
	return 0;
}

int io_unified_rdma_dereg_mr(struct io_unified_rdma_region *region,
			     struct io_unified_rdma_mr *mr)
{
	struct ib_mr *ib_mr = NULL;
	int i, ret;
	
	if (!region || !mr)
		return -EINVAL;
	
	/* Find the corresponding IB MR */
	for (i = 0; i < region->num_mrs; i++) {
		if (region->mrs[i] && 
		    region->mrs[i]->lkey == mr->lkey &&
		    region->mrs[i]->rkey == mr->rkey) {
			ib_mr = region->mrs[i];
			region->mrs[i] = NULL;
			break;
		}
	}
	
	if (!ib_mr) {
		pr_warn("io_uring: RDMA MR not found for deregistration\n");
		return -ENOENT;
	}
	
	ret = ib_dereg_mr(ib_mr);
	if (ret) {
		pr_err("io_uring: Failed to deregister RDMA MR: %d\n", ret);
		return ret;
	}
	
	memset(mr, 0, sizeof(*mr));
	return 0;
}

/* Queue pair management */
static int io_rdma_create_qp(struct io_unified_rdma_ifq *ifq,
			     struct io_unified_rdma_qp_config *config)
{
	struct ib_qp_init_attr qp_init_attr;
	struct ib_qp_attr qp_attr;
	int qp_attr_mask;
	int ret;
	
	/* Initialize QP attributes */
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.qp_context = ifq;
	qp_init_attr.send_cq = ifq->rdma_region->send_cq;
	qp_init_attr.recv_cq = ifq->rdma_region->recv_cq;
	qp_init_attr.qp_type = config->transport_type;
	qp_init_attr.cap.max_send_wr = config->max_send_wr;
	qp_init_attr.cap.max_recv_wr = config->max_recv_wr;
	qp_init_attr.cap.max_send_sge = config->max_send_sge;
	qp_init_attr.cap.max_recv_sge = config->max_recv_sge;
	qp_init_attr.cap.max_inline_data = config->max_inline_data;
	qp_init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	
	/* Create queue pair */
	ifq->rdma_region->qp = ib_create_qp(ifq->rdma_region->pd, &qp_init_attr);
	if (IS_ERR(ifq->rdma_region->qp)) {
		ret = PTR_ERR(ifq->rdma_region->qp);
		pr_err("io_uring: Failed to create RDMA QP: %d\n", ret);
		return ret;
	}
	
	/* Transition QP to INIT state */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IB_QPS_INIT;
	qp_attr.port_num = 1;
	qp_attr.pkey_index = 0;
	qp_attr.qp_access_flags = IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE |
				  IB_ACCESS_REMOTE_READ;
	
	qp_attr_mask = IB_QP_STATE | IB_QP_PKEY_INDEX | IB_QP_PORT | IB_QP_ACCESS_FLAGS;
	
	ret = ib_modify_qp(ifq->rdma_region->qp, &qp_attr, qp_attr_mask);
	if (ret) {
		pr_err("io_uring: Failed to transition QP to INIT: %d\n", ret);
		ib_destroy_qp(ifq->rdma_region->qp);
		return ret;
	}
	
	pr_info("io_uring: Created RDMA QP %u\n", ifq->rdma_region->qp->qp_num);
	return 0;
}

int io_unified_rdma_connect(struct io_unified_rdma_ifq *ifq,
			   struct io_unified_rdma_qp_config *config)
{
	struct ib_qp_attr qp_attr;
	int qp_attr_mask;
	int ret;
	
	if (!ifq || !ifq->rdma_region->qp || !config)
		return -EINVAL;
	
	/* Transition QP to RTR (Ready to Receive) */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IB_QPS_RTR;
	qp_attr.path_mtu = IB_MTU_4096;
	qp_attr.dest_qp_num = config->dest_qp_num;
	qp_attr.rq_psn = config->rq_psn;
	qp_attr.max_dest_rd_atomic = 1;
	qp_attr.min_rnr_timer = 12;
	
	/* Set address handle attributes */
	qp_attr.ah_attr.type = RDMA_AH_ATTR_TYPE_IB;
	qp_attr.ah_attr.ib.dlid = config->addr.ib.dlid;
	qp_attr.ah_attr.ib.sl = config->addr.ib.sl;
	qp_attr.ah_attr.ib.src_path_bits = config->addr.ib.src_path_bits;
	qp_attr.ah_attr.port_num = 1;
	
	qp_attr_mask = IB_QP_STATE | IB_QP_AV | IB_QP_PATH_MTU | IB_QP_DEST_QPN |
		       IB_QP_RQ_PSN | IB_QP_MAX_DEST_RD_ATOMIC | IB_QP_MIN_RNR_TIMER;
	
	ret = ib_modify_qp(ifq->rdma_region->qp, &qp_attr, qp_attr_mask);
	if (ret) {
		pr_err("io_uring: Failed to transition QP to RTR: %d\n", ret);
		return ret;
	}
	
	/* Transition QP to RTS (Ready to Send) */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IB_QPS_RTS;
	qp_attr.timeout = 14;
	qp_attr.retry_cnt = 7;
	qp_attr.rnr_retry = 7;
	qp_attr.sq_psn = config->sq_psn;
	qp_attr.max_rd_atomic = 1;
	
	qp_attr_mask = IB_QP_STATE | IB_QP_TIMEOUT | IB_QP_RETRY_CNT |
		       IB_QP_RNR_RETRY | IB_QP_SQ_PSN | IB_QP_MAX_QP_RD_ATOMIC;
	
	ret = ib_modify_qp(ifq->rdma_region->qp, &qp_attr, qp_attr_mask);
	if (ret) {
		pr_err("io_uring: Failed to transition QP to RTS: %d\n", ret);
		return ret;
	}
	
	ifq->connected = true;
	pr_info("io_uring: RDMA QP %u connected\n", ifq->rdma_region->qp->qp_num);
	
	return 0;
}

int io_unified_rdma_disconnect(struct io_unified_rdma_ifq *ifq)
{
	struct ib_qp_attr qp_attr;
	int ret;
	
	if (!ifq || !ifq->rdma_region->qp)
		return -EINVAL;
	
	if (!ifq->connected)
		return 0;
	
	/* Transition QP to ERROR state */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IB_QPS_ERR;
	
	ret = ib_modify_qp(ifq->rdma_region->qp, &qp_attr, IB_QP_STATE);
	if (ret) {
		pr_err("io_uring: Failed to transition QP to ERROR: %d\n", ret);
		return ret;
	}
	
	ifq->connected = false;
	pr_info("io_uring: RDMA QP %u disconnected\n", ifq->rdma_region->qp->qp_num);
	
	return 0;
}

/* Work request posting */
int io_unified_rdma_post_send(struct io_unified_rdma_ifq *ifq,
			     struct io_unified_rdma_wr *wr)
{
	struct ib_send_wr send_wr, *bad_wr;
	struct ib_sge sge[IO_UNIFIED_RDMA_MAX_SGE];
	int ret, i;
	
	if (!ifq || !ifq->rdma_region->qp || !wr || !ifq->connected)
		return -EINVAL;
	
	if (wr->num_sge > IO_UNIFIED_RDMA_MAX_SGE)
		return -EINVAL;
	
	/* Prepare scatter-gather list */
	for (i = 0; i < wr->num_sge; i++) {
		sge[i].addr = wr->sge[i].addr;
		sge[i].length = wr->sge[i].length;
		sge[i].lkey = wr->sge[i].lkey;
	}
	
	/* Prepare send work request */
	memset(&send_wr, 0, sizeof(send_wr));
	send_wr.wr_id = wr->user_data;
	send_wr.sg_list = sge;
	send_wr.num_sge = wr->num_sge;
	send_wr.send_flags = (wr->flags & IO_RDMA_WR_SEND_SIGNALED) ? IB_SEND_SIGNALED : 0;
	
	switch (wr->opcode) {
	case IO_RDMA_OP_SEND:
		send_wr.opcode = IB_WR_SEND;
		if (wr->flags & IO_RDMA_WR_SEND_WITH_IMM) {
			send_wr.opcode = IB_WR_SEND_WITH_IMM;
			send_wr.ex.imm_data = cpu_to_be32(wr->imm_data);
		}
		break;
	case IO_RDMA_OP_WRITE:
		send_wr.opcode = IB_WR_RDMA_WRITE;
		send_wr.wr.rdma.remote_addr = wr->remote_addr;
		send_wr.wr.rdma.rkey = wr->rkey;
		if (wr->flags & IO_RDMA_WR_SEND_WITH_IMM) {
			send_wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;
			send_wr.ex.imm_data = cpu_to_be32(wr->imm_data);
		}
		break;
	case IO_RDMA_OP_READ:
		send_wr.opcode = IB_WR_RDMA_READ;
		send_wr.wr.rdma.remote_addr = wr->remote_addr;
		send_wr.wr.rdma.rkey = wr->rkey;
		break;
	case IO_RDMA_OP_ATOMIC_CMP_AND_SWP:
		send_wr.opcode = IB_WR_ATOMIC_CMP_AND_SWP;
		send_wr.wr.atomic.remote_addr = wr->remote_addr;
		send_wr.wr.atomic.rkey = wr->rkey;
		send_wr.wr.atomic.compare_add = wr->compare_add;
		send_wr.wr.atomic.swap = wr->swap;
		break;
	case IO_RDMA_OP_ATOMIC_FETCH_AND_ADD:
		send_wr.opcode = IB_WR_ATOMIC_FETCH_AND_ADD;
		send_wr.wr.atomic.remote_addr = wr->remote_addr;
		send_wr.wr.atomic.rkey = wr->rkey;
		send_wr.wr.atomic.compare_add = wr->compare_add;
		break;
	default:
		return -EINVAL;
	}
	
	/* Post send work request */
	ret = ib_post_send(ifq->rdma_region->qp, &send_wr, &bad_wr);
	if (ret) {
		pr_err("io_uring: Failed to post RDMA send: %d\n", ret);
		atomic64_inc(&ifq->rdma_region->rdma_errors);
		return ret;
	}
	
	switch (wr->opcode) {
	case IO_RDMA_OP_SEND:
		atomic64_inc(&ifq->rdma_region->rdma_sends);
		break;
	case IO_RDMA_OP_WRITE:
		atomic64_inc(&ifq->rdma_region->rdma_writes);
		break;
	case IO_RDMA_OP_READ:
		atomic64_inc(&ifq->rdma_region->rdma_reads);
		break;
	}
	
	return 0;
}

int io_unified_rdma_post_recv(struct io_unified_rdma_ifq *ifq,
			     struct io_unified_rdma_wr *wr)
{
	struct ib_recv_wr recv_wr, *bad_wr;
	struct ib_sge sge[IO_UNIFIED_RDMA_MAX_SGE];
	int ret, i;
	
	if (!ifq || !ifq->rdma_region->qp || !wr)
		return -EINVAL;
	
	if (wr->num_sge > IO_UNIFIED_RDMA_MAX_SGE)
		return -EINVAL;
	
	/* Prepare scatter-gather list */
	for (i = 0; i < wr->num_sge; i++) {
		sge[i].addr = wr->sge[i].addr;
		sge[i].length = wr->sge[i].length;
		sge[i].lkey = wr->sge[i].lkey;
	}
	
	/* Prepare receive work request */
	memset(&recv_wr, 0, sizeof(recv_wr));
	recv_wr.wr_id = wr->user_data;
	recv_wr.sg_list = sge;
	recv_wr.num_sge = wr->num_sge;
	
	/* Post receive work request */
	ret = ib_post_recv(ifq->rdma_region->qp, &recv_wr, &bad_wr);
	if (ret) {
		pr_err("io_uring: Failed to post RDMA recv: %d\n", ret);
		atomic64_inc(&ifq->rdma_region->rdma_errors);
		return ret;
	}
	
	atomic64_inc(&ifq->rdma_region->rdma_recvs);
	return 0;
}

/* Completion queue processing */
static void io_rdma_cq_event_handler(struct ib_cq *cq, void *context)
{
	struct io_unified_rdma_ifq *ifq = context;
	
	/* Schedule work to process completions */
	queue_work(ifq->rdma_wq, &ifq->rdma_work);
}

int io_unified_rdma_poll_cq(struct io_unified_rdma_ifq *ifq)
{
	struct ib_wc wc[16];  /* Poll up to 16 completions at once */
	int num_cqe, i, total = 0;
	
	if (!ifq || !ifq->rdma_region->send_cq)
		return -EINVAL;
	
	do {
		num_cqe = ib_poll_cq(ifq->rdma_region->send_cq, 16, wc);
		if (num_cqe < 0) {
			pr_err("io_uring: Error polling RDMA CQ: %d\n", num_cqe);
			return num_cqe;
		}
		
		for (i = 0; i < num_cqe; i++) {
			struct io_unified_rdma_cqe cqe;
			
			/* Convert IB completion to unified completion */
			memset(&cqe, 0, sizeof(cqe));
			cqe.user_data = wc[i].wr_id;
			cqe.status = wc[i].status;
			cqe.opcode = wc[i].opcode;
			cqe.byte_len = wc[i].byte_len;
			cqe.qp_num = wc[i].qp->qp_num;
			cqe.src_qp = wc[i].src_qp;
			cqe.wc_flags = wc[i].wc_flags;
			cqe.imm_data = be32_to_cpu(wc[i].ex.imm_data);
			cqe.pkey_index = wc[i].pkey_index;
			cqe.slid = wc[i].slid;
			cqe.sl = wc[i].sl;
			cqe.dlid_path_bits = wc[i].dlid_path_bits;
			
			io_unified_rdma_complete_wr(ifq, &cqe);
		}
		
		total += num_cqe;
	} while (num_cqe > 0);
	
	return total;
}

void io_unified_rdma_complete_wr(struct io_unified_rdma_ifq *ifq,
				 struct io_unified_rdma_cqe *cqe)
{
	struct io_unified_ring *cq_ring = ifq->rdma_region->rdma_cq_ring;
	u32 tail, next_tail;
	
	/* Check if CQ has space */
	if ((cq_ring->producer - cq_ring->consumer) >= cq_ring->ring_entries) {
		atomic64_inc(&ifq->rdma_region->rdma_errors);
		pr_warn("io_uring: RDMA CQ ring full, dropping completion\n");
		return;
	}
	
	tail = ifq->rdma_cq_tail_cache;
	next_tail = (tail + 1) & cq_ring->ring_mask;
	
	/* Copy completion entry */
	memcpy(&ifq->rdma_region->rdma_cq_entries[tail], cqe, sizeof(*cqe));
	
	/* Update tail */
	ifq->rdma_cq_tail_cache = next_tail;
	smp_wmb();
	cq_ring->producer = next_tail;
	
	/* Wake up userspace if needed */
	if (cq_ring->flags & IO_UNIFIED_UREF) {
		wake_up_poll(&ifq->base.zcrx_ifq.ctx->cq_wait, EPOLLIN | EPOLLRDNORM);
	}
}

/* RDMA work handler */
static void io_unified_rdma_work_handler(struct work_struct *work)
{
	struct io_unified_rdma_ifq *ifq = container_of(work, struct io_unified_rdma_ifq, rdma_work);
	
	/* Process completions */
	io_unified_rdma_poll_cq(ifq);
	
	/* Re-arm CQ for notifications */
	if (ifq->rdma_region->send_cq) {
		ib_req_notify_cq(ifq->rdma_region->send_cq, IB_CQ_NEXT_COMP);
	}
}

/* Device capability querying */
int io_unified_rdma_query_device(struct io_unified_rdma_ifq *ifq,
				 struct io_unified_rdma_caps *caps)
{
	struct ib_device_attr device_attr;
	int ret;
	
	if (!ifq || !ifq->rdma_region->ib_dev || !caps)
		return -EINVAL;
	
	ret = ib_query_device(ifq->rdma_region->ib_dev, &device_attr);
	if (ret) {
		pr_err("io_uring: Failed to query RDMA device: %d\n", ret);
		return ret;
	}
	
	/* Convert device attributes */
	caps->device_cap_flags = device_attr.device_cap_flags;
	caps->max_qp = device_attr.max_qp;
	caps->max_qp_wr = device_attr.max_qp_wr;
	caps->max_sge = device_attr.max_sge;
	caps->max_cq = device_attr.max_cq;
	caps->max_cqe = device_attr.max_cqe;
	caps->max_mr = device_attr.max_mr;
	caps->max_mr_size = device_attr.max_mr_size;
	caps->max_pd = device_attr.max_pd;
	caps->max_mw = device_attr.max_mw;
	caps->max_fmr = device_attr.max_fmr;
	caps->max_ah = device_attr.max_ah;
	caps->max_srq = device_attr.max_srq;
	caps->max_srq_wr = device_attr.max_srq_wr;
	caps->max_srq_sge = device_attr.max_srq_sge;
	caps->atomic_cap = device_attr.atomic_cap;
	caps->masked_atomic_cap = device_attr.masked_atomic_cap;
	caps->max_mcast_grp = device_attr.max_mcast_grp;
	caps->max_mcast_qp_attach = device_attr.max_mcast_qp_attach;
	caps->max_total_mcast_qp_attach = device_attr.max_total_mcast_qp_attach;
	
	return 0;
}

/* Utility functions */
const char *io_unified_rdma_wc_status_str(int status)
{
	switch (status) {
	case IO_RDMA_WC_SUCCESS:		return "SUCCESS";
	case IO_RDMA_WC_LOC_LEN_ERR:		return "LOC_LEN_ERR";
	case IO_RDMA_WC_LOC_QP_OP_ERR:		return "LOC_QP_OP_ERR";
	case IO_RDMA_WC_LOC_PROT_ERR:		return "LOC_PROT_ERR";
	case IO_RDMA_WC_WR_FLUSH_ERR:		return "WR_FLUSH_ERR";
	case IO_RDMA_WC_BAD_RESP_ERR:		return "BAD_RESP_ERR";
	case IO_RDMA_WC_LOC_ACCESS_ERR:		return "LOC_ACCESS_ERR";
	case IO_RDMA_WC_REM_ACCESS_ERR:		return "REM_ACCESS_ERR";
	case IO_RDMA_WC_RETRY_EXC_ERR:		return "RETRY_EXC_ERR";
	case IO_RDMA_WC_RNR_RETRY_EXC_ERR:	return "RNR_RETRY_EXC_ERR";
	case IO_RDMA_WC_FATAL_ERR:		return "FATAL_ERR";
	case IO_RDMA_WC_RESP_TIMEOUT_ERR:	return "RESP_TIMEOUT_ERR";
	case IO_RDMA_WC_GENERAL_ERR:		return "GENERAL_ERR";
	default:				return "UNKNOWN";
	}
}

bool io_unified_rdma_is_connected(struct io_unified_rdma_ifq *ifq)
{
	return ifq && ifq->connected;
}

/* Region allocation and setup */
static int io_unified_rdma_alloc_region(struct io_ring_ctx *ctx,
					struct io_unified_rdma_ifq *ifq,
					struct io_unified_rdma_reg *reg,
					struct io_uring_region_desc *rd)
{
	struct io_unified_rdma_region *region;
	size_t rdma_size, total_size;
	void *ptr;
	int ret;
	
	/* Allocate RDMA region structure */
	region = kzalloc(sizeof(*region), GFP_KERNEL);
	if (!region)
		return -ENOMEM;
	
	/* Calculate additional RDMA sizes */
	rdma_size = 2 * sizeof(struct io_unified_ring) +		/* RDMA SQ/CQ rings */
		    reg->qp_config.max_send_wr * sizeof(struct io_unified_rdma_wr) +  /* RDMA SQ entries */
		    reg->qp_config.max_recv_wr * sizeof(struct io_unified_rdma_cqe) + /* RDMA CQ entries */
		    reg->num_mrs * sizeof(struct io_unified_rdma_mr);   /* MR descriptors */
	
	total_size = rd->size + rdma_size;
	
	/* First set up base unified region */
	ret = io_unified_alloc_region(ctx, &ifq->base, &reg->base, rd);
	if (ret) {
		kfree(region);
		return ret;
	}
	
	/* Get base region pointer and extend it */
	ptr = io_region_get_ptr(&ctx->zcrx_region);
	
	/* Set up RDMA-specific pointers */
	region->rdma_sq_ring = (struct io_unified_ring *)((char *)ptr + rd->size);
	region->rdma_cq_ring = (struct io_unified_ring *)((char *)ptr + rd->size + sizeof(struct io_unified_ring));
	region->rdma_sq_entries = (struct io_unified_rdma_wr *)((char *)ptr + rd->size + 2 * sizeof(struct io_unified_ring));
	region->rdma_cq_entries = (struct io_unified_rdma_cqe *)((char *)ptr + rd->size + 2 * sizeof(struct io_unified_ring) +
								reg->qp_config.max_send_wr * sizeof(struct io_unified_rdma_wr));
	region->memory_regions = (struct io_unified_rdma_mr *)((char *)ptr + rd->size + 2 * sizeof(struct io_unified_ring) +
							       reg->qp_config.max_send_wr * sizeof(struct io_unified_rdma_wr) +
							       reg->qp_config.max_recv_wr * sizeof(struct io_unified_rdma_cqe));
	
	/* Initialize RDMA rings */
	region->rdma_sq_ring->ring_entries = reg->qp_config.max_send_wr;
	region->rdma_sq_ring->ring_mask = reg->qp_config.max_send_wr - 1;
	region->rdma_cq_ring->ring_entries = reg->qp_config.max_recv_wr;
	region->rdma_cq_ring->ring_mask = reg->qp_config.max_recv_wr - 1;
	
	/* Allocate MR pointer array */
	region->mrs = kcalloc(reg->num_mrs, sizeof(struct ib_mr *), GFP_KERNEL);
	if (!region->mrs) {
		io_unified_free_region(ctx, &ifq->base);
		kfree(region);
		return -ENOMEM;
	}
	
	/* Initialize performance counters */
	atomic64_set(&region->rdma_sends, 0);
	atomic64_set(&region->rdma_recvs, 0);
	atomic64_set(&region->rdma_writes, 0);
	atomic64_set(&region->rdma_reads, 0);
	atomic64_set(&region->rdma_errors, 0);
	
	ifq->rdma_region = region;
	
	/* Set up offsets for userspace */
	reg->rdma_offsets.rdma_sq_ring = rd->size;
	reg->rdma_offsets.rdma_cq_ring = rd->size + sizeof(struct io_unified_ring);
	reg->rdma_offsets.rdma_sq_entries = rd->size + 2 * sizeof(struct io_unified_ring);
	reg->rdma_offsets.rdma_cq_entries = rd->size + 2 * sizeof(struct io_unified_ring) +
					   reg->qp_config.max_send_wr * sizeof(struct io_unified_rdma_wr);
	reg->rdma_offsets.memory_regions = rd->size + 2 * sizeof(struct io_unified_ring) +
					  reg->qp_config.max_send_wr * sizeof(struct io_unified_rdma_wr) +
					  reg->qp_config.max_recv_wr * sizeof(struct io_unified_rdma_cqe);
	
	return 0;
}

static void io_unified_rdma_free_region(struct io_ring_ctx *ctx, struct io_unified_rdma_ifq *ifq)
{
	struct io_unified_rdma_region *region = ifq->rdma_region;
	int i;
	
	if (!region)
		return;
	
	/* Deregister all memory regions */
	for (i = 0; i < region->num_mrs; i++) {
		if (region->mrs[i]) {
			ib_dereg_mr(region->mrs[i]);
			region->mrs[i] = NULL;
		}
	}
	
	/* Clean up RDMA resources */
	if (region->qp) {
		ib_destroy_qp(region->qp);
		region->qp = NULL;
	}
	
	if (region->send_cq) {
		ib_destroy_cq(region->send_cq);
		region->send_cq = NULL;
	}
	
	if (region->recv_cq) {
		ib_destroy_cq(region->recv_cq);
		region->recv_cq = NULL;
	}
	
	if (region->pd) {
		ib_dealloc_pd(region->pd);
		region->pd = NULL;
	}
	
	if (region->ib_dev) {
		ib_device_put(region->ib_dev);
		region->ib_dev = NULL;
	}
	
	if (region->mrs) {
		kfree(region->mrs);
		region->mrs = NULL;
	}
	
	/* Free base region */
	io_unified_free_region(ctx, &ifq->base);
	
	kfree(region);
	ifq->rdma_region = NULL;
}

/* Interface queue management */
static struct io_unified_rdma_ifq *io_unified_rdma_ifq_alloc(struct io_ring_ctx *ctx)
{
	struct io_unified_rdma_ifq *ifq;
	
	ifq = kzalloc(sizeof(*ifq), GFP_KERNEL);
	if (!ifq)
		return NULL;
	
	/* Initialize base unified interface */
	ifq->base.zcrx_ifq.ctx = ctx;
	ifq->base.zcrx_ifq.if_rxq = -1;
	
	/* Initialize RDMA-specific fields */
	INIT_WORK(&ifq->rdma_work, io_unified_rdma_work_handler);
	ifq->rdma_wq = io_unified_rdma_wq;
	ifq->connected = false;
	
	/* Initialize XDP integration */
	io_unified_rdma_rxe_xdp_init(ifq);
	
	return ifq;
}

static void io_unified_rdma_ifq_free(struct io_ring_ctx *ctx, struct io_unified_rdma_ifq *ifq)
{
	if (!ifq)
		return;
	
	/* Disconnect if connected */
	if (ifq->connected) {
		io_unified_rdma_disconnect(ifq);
	}
	
	/* Cancel pending work */
	cancel_work_sync(&ifq->rdma_work);
	
	/* Clean up connection manager */
	if (ifq->cm_id) {
		rdma_destroy_id(ifq->cm_id);
		ifq->cm_id = NULL;
	}
	
	if (ifq->event_channel) {
		rdma_destroy_event_channel(ifq->event_channel);
		ifq->event_channel = NULL;
	}
	
	/* Cleanup XDP integration */
	io_unified_rdma_rxe_xdp_cleanup(ifq);
	
	/* Free RDMA region */
	io_unified_rdma_free_region(ctx, ifq);
	
	/* Free base interface */
	io_unified_ifq_free(ctx, &ifq->base);
	
	kfree(ifq);
}

/* Registration interface */
int io_register_unified_rdma_ifq(struct io_ring_ctx *ctx, struct io_unified_rdma_reg __user *arg)
{
	struct io_unified_rdma_reg reg;
	struct io_uring_region_desc rd;
	struct io_unified_rdma_ifq *ifq;
	char *rdma_dev_name;
	int ret;
	
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	
	if (ctx->unified_rdma_ifq)
		return -EBUSY;
	
	if (copy_from_user(&reg, arg, sizeof(reg)))
		return -EFAULT;
	
	if (copy_from_user(&rd, u64_to_user_ptr(reg.base.region_ptr), sizeof(rd)))
		return -EFAULT;
	
	/* Validate parameters */
	if (!reg.base.sq_entries || !reg.base.cq_entries || !reg.base.buffer_entries)
		return -EINVAL;
	
	if (!reg.qp_config.max_send_wr || !reg.qp_config.max_recv_wr)
		return -EINVAL;
	
	/* Allocate interface queue */
	ifq = io_unified_rdma_ifq_alloc(ctx);
	if (!ifq)
		return -ENOMEM;
	
	/* Copy configuration */
	memcpy(&ifq->qp_config, &reg.qp_config, sizeof(ifq->qp_config));
	
	/* Get RDMA device name */
	rdma_dev_name = strndup_user(u64_to_user_ptr(reg.rdma_dev_name), 64);
	if (IS_ERR(rdma_dev_name)) {
		ret = PTR_ERR(rdma_dev_name);
		goto err_free_ifq;
	}
	
	/* Find RDMA device */
	ifq->rdma_region->ib_dev = io_rdma_find_device(rdma_dev_name);
	kfree(rdma_dev_name);
	
	if (!ifq->rdma_region->ib_dev) {
		ret = -ENODEV;
		goto err_free_ifq;
	}
	
	/* Allocate protection domain */
	ifq->rdma_region->pd = ib_alloc_pd(ifq->rdma_region->ib_dev, 0);
	if (IS_ERR(ifq->rdma_region->pd)) {
		ret = PTR_ERR(ifq->rdma_region->pd);
		pr_err("io_uring: Failed to allocate RDMA PD: %d\n", ret);
		goto err_put_device;
	}
	
	/* Create completion queues */
	ifq->rdma_region->send_cq = ib_create_cq(ifq->rdma_region->ib_dev,
						io_rdma_cq_event_handler,
						NULL, ifq,
						reg.qp_config.max_send_wr, 0);
	if (IS_ERR(ifq->rdma_region->send_cq)) {
		ret = PTR_ERR(ifq->rdma_region->send_cq);
		pr_err("io_uring: Failed to create RDMA send CQ: %d\n", ret);
		goto err_dealloc_pd;
	}
	
	ifq->rdma_region->recv_cq = ib_create_cq(ifq->rdma_region->ib_dev,
						io_rdma_cq_event_handler,
						NULL, ifq,
						reg.qp_config.max_recv_wr, 0);
	if (IS_ERR(ifq->rdma_region->recv_cq)) {
		ret = PTR_ERR(ifq->rdma_region->recv_cq);
		pr_err("io_uring: Failed to create RDMA recv CQ: %d\n", ret);
		goto err_destroy_send_cq;
	}
	
	/* Request CQ notifications */
	ib_req_notify_cq(ifq->rdma_region->send_cq, IB_CQ_NEXT_COMP);
	ib_req_notify_cq(ifq->rdma_region->recv_cq, IB_CQ_NEXT_COMP);
	
	/* Allocate unified region */
	ret = io_unified_rdma_alloc_region(ctx, ifq, &reg, &rd);
	if (ret)
		goto err_destroy_recv_cq;
	
	/* Create queue pair */
	ret = io_rdma_create_qp(ifq, &reg.qp_config);
	if (ret)
		goto err_free_region;
	
	/* Query device capabilities */
	ret = io_unified_rdma_query_device(ifq, &ifq->device_caps);
	if (ret)
		goto err_free_region;
	
	/* Complete registration */
	ctx->unified_rdma_ifq = ifq;
	
	if (copy_to_user(arg, &reg, sizeof(reg)) ||
	    copy_to_user(u64_to_user_ptr(reg.base.region_ptr), &rd, sizeof(rd))) {
		ret = -EFAULT;
		goto err_unregister;
	}
	
	pr_info("io_uring: RDMA unified interface registered successfully\n");
	return 0;
	
err_unregister:
	ctx->unified_rdma_ifq = NULL;
err_free_region:
	io_unified_rdma_free_region(ctx, ifq);
	goto err_free_ifq;
err_destroy_recv_cq:
	ib_destroy_cq(ifq->rdma_region->recv_cq);
err_destroy_send_cq:
	ib_destroy_cq(ifq->rdma_region->send_cq);
err_dealloc_pd:
	ib_dealloc_pd(ifq->rdma_region->pd);
err_put_device:
	ib_device_put(ifq->rdma_region->ib_dev);
err_free_ifq:
	io_unified_rdma_ifq_free(ctx, ifq);
	return ret;
}

void io_unregister_unified_rdma_ifq(struct io_ring_ctx *ctx)
{
	struct io_unified_rdma_ifq *ifq = ctx->unified_rdma_ifq;
	
	lockdep_assert_held(&ctx->uring_lock);
	
	if (!ifq)
		return;
	
	ctx->unified_rdma_ifq = NULL;
	io_unified_rdma_ifq_free(ctx, ifq);
}

void io_shutdown_unified_rdma_ifq(struct io_ring_ctx *ctx)
{
	lockdep_assert_held(&ctx->uring_lock);
	
	if (ctx->unified_rdma_ifq) {
		/* Disconnect and cancel work */
		io_unified_rdma_disconnect(ctx->unified_rdma_ifq);
		cancel_work_sync(&ctx->unified_rdma_ifq->rdma_work);
	}
}

/* Module initialization */
static int __init io_unified_rdma_init(void)
{
	io_unified_rdma_wq = alloc_workqueue("io_unified_rdma", WQ_UNBOUND | WQ_HIGHPRI, 0);
	if (!io_unified_rdma_wq)
		return -ENOMEM;
	
	pr_info("io_uring: unified RDMA interface initialized\n");
	return 0;
}

static void __exit io_unified_rdma_exit(void)
{
	if (io_unified_rdma_wq) {
		destroy_workqueue(io_unified_rdma_wq);
		io_unified_rdma_wq = NULL;
	}
}

/* XDP Integration Functions */

/**
 * io_unified_rdma_setup_xdp - Setup XDP program for unified RDMA interface
 * @ifq: Unified RDMA interface queue
 * @prog: BPF/XDP program to install
 */
int io_unified_rdma_setup_xdp(struct io_unified_rdma_ifq *ifq, struct bpf_prog *prog)
{
	struct bpf_prog *old_prog;
	unsigned long flags;
	
	if (!ifq)
		return -EINVAL;
		
	spin_lock_irqsave(&ifq->xdp_lock, flags);
	
	old_prog = ifq->rxe_xdp_prog;
	
	if (prog) {
		/* Install new XDP program for SoftRoCE */
		bpf_prog_inc(prog);
		ifq->rxe_xdp_prog = prog;
		ifq->xdp_enabled = true;
		
		pr_info("io_uring: XDP program installed for unified RDMA (SoftRoCE)\n");
	} else {
		/* Remove XDP program */
		ifq->rxe_xdp_prog = NULL;
		ifq->xdp_enabled = false;
		
		pr_info("io_uring: XDP program removed from unified RDMA\n");
	}
	
	spin_unlock_irqrestore(&ifq->xdp_lock, flags);
	
	/* Release old program */
	if (old_prog)
		bpf_prog_put(old_prog);
		
	return 0;
}

/**
 * io_unified_rdma_rxe_xdp_init - Initialize SoftRoCE XDP integration
 * @ifq: Unified RDMA interface queue
 */
int io_unified_rdma_rxe_xdp_init(struct io_unified_rdma_ifq *ifq)
{
	if (!ifq)
		return -EINVAL;
		
	spin_lock_init(&ifq->xdp_lock);
	ifq->xdp_enabled = false;
	ifq->rxe_xdp_prog = NULL;
	
	/* Initialize XDP RXQ info */
	memset(&ifq->xdp_rxq, 0, sizeof(ifq->xdp_rxq));
	
	pr_debug("io_uring: SoftRoCE XDP integration initialized\n");
	return 0;
}

/**
 * io_unified_rdma_rxe_xdp_cleanup - Cleanup SoftRoCE XDP integration
 * @ifq: Unified RDMA interface queue
 */
void io_unified_rdma_rxe_xdp_cleanup(struct io_unified_rdma_ifq *ifq)
{
	if (!ifq)
		return;
		
	io_unified_rdma_setup_xdp(ifq, NULL);
	
	pr_debug("io_uring: SoftRoCE XDP integration cleaned up\n");
}

/**
 * io_unified_rdma_xmit_capture - Capture outgoing RDMA packets for XDP processing
 * @ifq: Unified RDMA interface queue
 * @skb: Socket buffer containing RDMA packet
 */
int io_unified_rdma_xmit_capture(struct io_unified_rdma_ifq *ifq, struct sk_buff *skb)
{
	struct bpf_prog *prog;
	struct xdp_buff xdp;
	u32 act;
	int ret = 0;
	
	if (!ifq || !skb)
		return -EINVAL;
		
	rcu_read_lock();
	prog = rcu_dereference(ifq->rxe_xdp_prog);
	
	if (!prog) {
		rcu_read_unlock();
		return 0; /* No XDP program, normal processing */
	}
	
	/* Convert skb to xdp_buff */
	xdp.data = skb->data;
	xdp.data_end = skb->data + skb->len;
	xdp.data_meta = xdp.data;
	xdp.data_hard_start = skb->head;
	xdp.rxq = &ifq->xdp_rxq;
	xdp.frame_sz = skb_end_offset(skb);
	
	/* Run XDP program */
	act = bpf_prog_run_xdp(prog, &xdp);
	
	switch (act) {
	case XDP_PASS:
		/* Allow normal transmission */
		ret = 0;
		break;
	case XDP_DROP:
		/* Drop the packet */
		ret = -EPERM;
		break;
	case XDP_REDIRECT:
		/* Handle redirect action */
		ret = xdp_do_redirect(skb->dev, &xdp, prog);
		if (ret)
			ret = -EPERM;
		break;
	default:
		/* Unknown action, drop */
		ret = -EPERM;
		break;
	}
	
	rcu_read_unlock();
	
	if (ret == 0) {
		/* Update skb if XDP modified the packet */
		skb->len = xdp.data_end - xdp.data;
		skb_set_tail_pointer(skb, skb->len);
	}
	
	return ret;
}

/**
 * io_unified_rdma_recv_capture - Capture incoming RDMA packets for XDP processing  
 * @ifq: Unified RDMA interface queue
 * @skb: Socket buffer containing received RDMA packet
 */
int io_unified_rdma_recv_capture(struct io_unified_rdma_ifq *ifq, struct sk_buff *skb)
{
	struct bpf_prog *prog;
	struct xdp_buff xdp;
	u32 act;
	int ret = 0;
	
	if (!ifq || !skb)
		return -EINVAL;
		
	rcu_read_lock();
	prog = rcu_dereference(ifq->rxe_xdp_prog);
	
	if (!prog) {
		rcu_read_unlock();
		return 0; /* No XDP program, normal processing */
	}
	
	/* Convert skb to xdp_buff */
	xdp.data = skb->data;
	xdp.data_end = skb->data + skb->len;
	xdp.data_meta = xdp.data;
	xdp.data_hard_start = skb->head;
	xdp.rxq = &ifq->xdp_rxq;
	xdp.frame_sz = skb_end_offset(skb);
	
	/* Run XDP program */
	act = bpf_prog_run_xdp(prog, &xdp);
	
	switch (act) {
	case XDP_PASS:
		/* Allow normal reception and processing */
		ret = 0;
		break;
	case XDP_DROP:
		/* Drop the packet */
		ret = -EPERM;
		break;
	case XDP_REDIRECT:
		/* Redirect to unified buffer for zero-copy processing */
		ret = xdp_do_redirect(skb->dev, &xdp, prog);
		if (ret == 0) {
			/* Copy to unified buffer for RDMA/storage processing */
			void *unified_buf = (char *)ifq->base.zcrx_ifq.region.address +
					   (ifq->base.buf_tail_cache % ifq->base.zcrx_ifq.region.info.buffer_entries) * 
					   ifq->base.zcrx_ifq.region.info.buffer_entry_size;
			
			memcpy(unified_buf, xdp.data, xdp.data_end - xdp.data);
			
			/* Update buffer tail for next packet */
			ifq->base.buf_tail_cache++;
		}
		break;
	default:
		/* Unknown action, drop */
		ret = -EPERM;
		break;
	}
	
	rcu_read_unlock();
	
	if (ret == 0) {
		/* Update skb if XDP modified the packet */
		skb->len = xdp.data_end - xdp.data;
		skb_set_tail_pointer(skb, skb->len);
	}
	
	return ret;
}

/**
 * io_unified_rdma_attach_xdp - Attach XDP to network interface
 * @ifq: Unified RDMA interface queue
 */
int io_unified_rdma_attach_xdp(struct io_unified_rdma_ifq *ifq)
{
	/* This would integrate with netdev XDP attachment */
	return 0;
}

/**
 * io_unified_rdma_detach_xdp - Detach XDP from network interface
 * @ifq: Unified RDMA interface queue  
 */
void io_unified_rdma_detach_xdp(struct io_unified_rdma_ifq *ifq)
{
	io_unified_rdma_setup_xdp(ifq, NULL);
}

module_init(io_unified_rdma_init);
module_exit(io_unified_rdma_exit);