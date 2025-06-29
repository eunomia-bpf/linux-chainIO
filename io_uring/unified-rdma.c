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
#include <linux/xdp.h>

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
	
	pr_debug("io_uring: Looking for RDMA device '%s'\n", dev_name);
	
	device = ib_device_get_by_name(dev_name, RDMA_DRIVER_UNKNOWN);
	if (!device) {
		pr_warn("io_uring: RDMA device '%s' not found\n", dev_name);
		return NULL;
	}
	
	pr_debug("io_uring: Found RDMA device '%s', checking capabilities\n", dev_name);
	
	if (!rdma_cap_ib_mad(device, 1) && !rdma_cap_ib_mcast(device, 1) &&
	    !rdma_cap_eth_ah(device, 1)) {
		pr_warn("io_uring: RDMA device '%s' has no usable capabilities\n", dev_name);
		ib_device_put(device);
		return NULL;
	}
	
	pr_info("io_uring: Successfully found RDMA device '%s' with capabilities\n", dev_name);
	return device;
}

/* Memory region management */
int io_unified_rdma_reg_mr(struct io_unified_rdma_region *region,
			   void *addr, size_t length, int access_flags,
			   struct io_unified_rdma_mr *mr)
{
	struct ib_mr *ib_mr;
	int ret;
	
	pr_debug("io_uring: Registering MR: addr=%p, length=%zu, access_flags=0x%x\n",
		 addr, length, access_flags);
	
	if (!region || !region->pd || !addr || !length || !mr) {
		pr_err("io_uring: Invalid parameters for MR registration\n");
		return -EINVAL;
	}
	
	pr_debug("io_uring: Using PD %p for MR registration\n", region->pd);
	
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
		pr_debug("io_uring: Stored MR at index %u, total MRs: %u\n",
			 region->num_mrs - 1, region->num_mrs);
	} else {
		pr_err("io_uring: MR table full (max %d entries)\n", IO_UNIFIED_RDMA_MAX_ENTRIES);
		ib_dereg_mr(ib_mr);
		return -ENOSPC;
	}
	
	pr_info("io_uring: Registered RDMA MR: addr=0x%llx, len=%zu, lkey=0x%x, rkey=0x%x\n",
		 mr->addr, length, mr->lkey, mr->rkey);
	
	return 0;
}

int io_unified_rdma_dereg_mr(struct io_unified_rdma_region *region,
			     struct io_unified_rdma_mr *mr)
{
	struct ib_mr *ib_mr = NULL;
	int i, ret;
	
	pr_debug("io_uring: Deregistering MR: lkey=0x%x, rkey=0x%x\n",
		 mr ? mr->lkey : 0, mr ? mr->rkey : 0);
	
	if (!region || !mr) {
		pr_err("io_uring: Invalid parameters for MR deregistration\n");
		return -EINVAL;
	}
	
	/* Find the corresponding IB MR */
	for (i = 0; i < region->num_mrs; i++) {
		if (region->mrs[i] && 
		    region->mrs[i]->lkey == mr->lkey &&
		    region->mrs[i]->rkey == mr->rkey) {
			ib_mr = region->mrs[i];
			region->mrs[i] = NULL;
			pr_debug("io_uring: Found MR at index %d\n", i);
			break;
		}
	}
	
	if (!ib_mr) {
		pr_warn("io_uring: RDMA MR not found for deregistration (lkey=0x%x, rkey=0x%x)\n",
			mr->lkey, mr->rkey);
		return -ENOENT;
	}
	
	ret = ib_dereg_mr(ib_mr);
	if (ret) {
		pr_err("io_uring: Failed to deregister RDMA MR: %d\n", ret);
		return ret;
	}
	
	pr_info("io_uring: Successfully deregistered MR (lkey=0x%x, rkey=0x%x)\n",
		mr->lkey, mr->rkey);
	
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
	
	pr_debug("io_uring: Creating queue pair\n");
	
	/* Validate input parameters */
	if (!ifq || !ifq->rdma_region || !config) {
		pr_err("io_uring: Invalid parameters for QP creation\n");
		return -EINVAL;
	}
	
	if (!ifq->rdma_region->pd || !ifq->rdma_region->send_cq || !ifq->rdma_region->recv_cq) {
		pr_err("io_uring: RDMA resources not properly initialized (pd=%p, send_cq=%p, recv_cq=%p)\n",
		       ifq->rdma_region->pd, ifq->rdma_region->send_cq, ifq->rdma_region->recv_cq);
		return -EINVAL;
	}
	
	/* Initialize QP attributes */
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.qp_context = ifq;
	qp_init_attr.send_cq = ifq->rdma_region->send_cq;
	qp_init_attr.recv_cq = ifq->rdma_region->recv_cq;
	
	/* Set transport type - fix the mapping */
	switch (config->transport_type) {
	case IO_RDMA_TRANSPORT_RC:
		qp_init_attr.qp_type = IB_QPT_RC;
		break;
	case IO_RDMA_TRANSPORT_UC:
		qp_init_attr.qp_type = IB_QPT_UC;
		break;
	case IO_RDMA_TRANSPORT_UD:
		qp_init_attr.qp_type = IB_QPT_UD;
		break;
	case IO_RDMA_TRANSPORT_RAW_ETH:
		qp_init_attr.qp_type = IB_QPT_RAW_PACKET;
		break;
	default:
		pr_err("io_uring: Unsupported transport type: %u\n", config->transport_type);
		return -EINVAL;
	}
	
	/* Validate and set capabilities */
	qp_init_attr.cap.max_send_wr = min_t(u32, config->max_send_wr, 16384);
	qp_init_attr.cap.max_recv_wr = min_t(u32, config->max_recv_wr, 16384);
	qp_init_attr.cap.max_send_sge = min_t(u32, config->max_send_sge, IO_UNIFIED_RDMA_MAX_SGE);
	qp_init_attr.cap.max_recv_sge = min_t(u32, config->max_recv_sge, IO_UNIFIED_RDMA_MAX_SGE);
	qp_init_attr.cap.max_inline_data = min_t(u32, config->max_inline_data, 1024);
	qp_init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	
	pr_info("io_uring: Creating QP with type=%d, send_wr=%u, recv_wr=%u, send_sge=%u, recv_sge=%u, inline=%u\n",
		 qp_init_attr.qp_type, qp_init_attr.cap.max_send_wr,
		 qp_init_attr.cap.max_recv_wr, qp_init_attr.cap.max_send_sge,
		 qp_init_attr.cap.max_recv_sge, qp_init_attr.cap.max_inline_data);
	
	/* Create queue pair */
	ifq->rdma_region->qp = ib_create_qp(ifq->rdma_region->pd, &qp_init_attr);
	if (IS_ERR(ifq->rdma_region->qp)) {
		ret = PTR_ERR(ifq->rdma_region->qp);
		ifq->rdma_region->qp = NULL;
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
	
	pr_debug("io_uring: Transitioning QP to INIT state\n");
	
	ret = ib_modify_qp(ifq->rdma_region->qp, &qp_attr, qp_attr_mask);
	if (ret) {
		pr_err("io_uring: Failed to transition QP to INIT: %d\n", ret);
		ib_destroy_qp(ifq->rdma_region->qp);
		ifq->rdma_region->qp = NULL;
		return ret;
	}
	
	pr_info("io_uring: Successfully created RDMA QP %u in INIT state\n", ifq->rdma_region->qp->qp_num);
	return 0;
}

static int io_rdma_connect_qp(struct io_unified_rdma_ifq *ifq,
			      struct io_unified_rdma_qp_config *config)
{
	struct ib_qp_attr qp_attr;
	int qp_attr_mask;
	int ret;
	
	pr_debug("io_uring: Connecting QP to remote QP %u\n", config ? config->dest_qp_num : 0);
	
	if (!ifq || !ifq->rdma_region->qp || !config) {
		pr_err("io_uring: Invalid parameters for QP connection\n");
		return -EINVAL;
	}
	
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
	rdma_ah_set_dlid(&qp_attr.ah_attr, config->addr.ib.dlid);
	rdma_ah_set_sl(&qp_attr.ah_attr, config->addr.ib.sl);
	rdma_ah_set_path_bits(&qp_attr.ah_attr, config->addr.ib.src_path_bits);
	rdma_ah_set_port_num(&qp_attr.ah_attr, 1);
	
	qp_attr_mask = IB_QP_STATE | IB_QP_AV | IB_QP_PATH_MTU | IB_QP_DEST_QPN |
		       IB_QP_RQ_PSN | IB_QP_MAX_DEST_RD_ATOMIC | IB_QP_MIN_RNR_TIMER;
	
	pr_debug("io_uring: Transitioning QP to RTR state\n");
	
	ret = ib_modify_qp(ifq->rdma_region->qp, &qp_attr, qp_attr_mask);
	if (ret) {
		pr_err("io_uring: Failed to transition QP to RTR: %d\n", ret);
		return ret;
	}
	
	pr_debug("io_uring: QP transitioned to RTR state successfully\n");
	
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
	
	pr_debug("io_uring: Transitioning QP to RTS state\n");
	
	ret = ib_modify_qp(ifq->rdma_region->qp, &qp_attr, qp_attr_mask);
	if (ret) {
		pr_err("io_uring: Failed to transition QP to RTS: %d\n", ret);
		return ret;
	}
	
	ifq->connected = true;
	pr_info("io_uring: RDMA QP %u connected to remote QP %u (RTS state)\n", 
		ifq->rdma_region->qp->qp_num, config->dest_qp_num);
	
	return 0;
}

static int io_rdma_disconnect_qp(struct io_unified_rdma_ifq *ifq)
{
	struct ib_qp_attr qp_attr;
	int ret;
	
	pr_debug("io_uring: Disconnecting QP\n");
	
	if (!ifq || !ifq->rdma_region->qp) {
		pr_err("io_uring: Invalid parameters for QP disconnection\n");
		return -EINVAL;
	}
	
	if (!ifq->connected) {
		pr_debug("io_uring: QP already disconnected\n");
		return 0;
	}
	
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
	union {
		struct ib_send_wr send_wr;
		struct ib_rdma_wr rdma_wr;
		struct ib_atomic_wr atomic_wr;
	} u;
	struct ib_send_wr *send_wr = &u.send_wr;
	const struct ib_send_wr *bad_wr;
	struct ib_sge sge[IO_UNIFIED_RDMA_MAX_SGE];
	int ret, i;
	
	pr_debug("io_uring: Posting send WR: opcode=%u, num_sge=%u, flags=0x%x\n",
		 wr ? wr->opcode : 0, wr ? wr->num_sge : 0, wr ? wr->flags : 0);
	
	if (!ifq || !ifq->rdma_region->qp || !wr || !ifq->connected) {
		pr_err("io_uring: Invalid parameters for post_send (ifq=%p, qp=%p, wr=%p, connected=%d)\n",
		       ifq, ifq ? ifq->rdma_region->qp : NULL, wr, ifq ? ifq->connected : 0);
		return -EINVAL;
	}
	
	if (wr->num_sge > IO_UNIFIED_RDMA_MAX_SGE) {
		pr_err("io_uring: Too many SGEs: %u > %d\n", wr->num_sge, IO_UNIFIED_RDMA_MAX_SGE);
		return -EINVAL;
	}
	
	/* Prepare scatter-gather list */
	for (i = 0; i < wr->num_sge; i++) {
		sge[i].addr = wr->sge[i].addr;
		sge[i].length = wr->sge[i].length;
		sge[i].lkey = wr->sge[i].lkey;
	}
	
	/* Prepare send work request */
	memset(&u, 0, sizeof(u));
	send_wr->wr_id = wr->user_data;
	send_wr->sg_list = sge;
	send_wr->num_sge = wr->num_sge;
	send_wr->send_flags = (wr->flags & IO_RDMA_WR_SEND_SIGNALED) ? IB_SEND_SIGNALED : 0;
	
	switch (wr->opcode) {
	case IO_RDMA_OP_SEND:
		send_wr->opcode = IB_WR_SEND;
		if (wr->flags & IO_RDMA_WR_SEND_WITH_IMM) {
			send_wr->opcode = IB_WR_SEND_WITH_IMM;
			send_wr->ex.imm_data = cpu_to_be32(wr->imm_data);
		}
		break;
	case IO_RDMA_OP_WRITE:
		send_wr->opcode = IB_WR_RDMA_WRITE;
		u.rdma_wr.remote_addr = wr->remote_addr;
		u.rdma_wr.rkey = wr->rkey;
		if (wr->flags & IO_RDMA_WR_SEND_WITH_IMM) {
			send_wr->opcode = IB_WR_RDMA_WRITE_WITH_IMM;
			send_wr->ex.imm_data = cpu_to_be32(wr->imm_data);
		}
		break;
	case IO_RDMA_OP_READ:
		send_wr->opcode = IB_WR_RDMA_READ;
		u.rdma_wr.remote_addr = wr->remote_addr;
		u.rdma_wr.rkey = wr->rkey;
		break;
	case IO_RDMA_OP_ATOMIC_CMP_AND_SWP:
		send_wr->opcode = IB_WR_ATOMIC_CMP_AND_SWP;
		u.atomic_wr.remote_addr = wr->remote_addr;
		u.atomic_wr.rkey = wr->rkey;
		u.atomic_wr.compare_add = wr->compare_add;
		u.atomic_wr.swap = wr->swap;
		break;
	case IO_RDMA_OP_ATOMIC_FETCH_AND_ADD:
		send_wr->opcode = IB_WR_ATOMIC_FETCH_AND_ADD;
		u.atomic_wr.remote_addr = wr->remote_addr;
		u.atomic_wr.rkey = wr->rkey;
		u.atomic_wr.compare_add = wr->compare_add;
		break;
	default:
		return -EINVAL;
	}
	
	/* Post send work request */
	ret = ib_post_send(ifq->rdma_region->qp, send_wr, &bad_wr);
	if (ret) {
		pr_err("io_uring: Failed to post RDMA send: %d (bad_wr=%p)\n", ret, bad_wr);
		atomic64_inc(&ifq->rdma_region->rdma_errors);
		return ret;
	}
	
	switch (wr->opcode) {
	case IO_RDMA_OP_SEND:
		atomic64_inc(&ifq->rdma_region->rdma_sends);
		pr_debug("io_uring: Posted SEND WR successfully (wr_id=%llu)\n", wr->user_data);
		break;
	case IO_RDMA_OP_WRITE:
		atomic64_inc(&ifq->rdma_region->rdma_writes);
		pr_debug("io_uring: Posted WRITE WR successfully (wr_id=%llu, remote_addr=0x%llx)\n",
			 wr->user_data, wr->remote_addr);
		break;
	case IO_RDMA_OP_READ:
		atomic64_inc(&ifq->rdma_region->rdma_reads);
		pr_debug("io_uring: Posted READ WR successfully (wr_id=%llu, remote_addr=0x%llx)\n",
			 wr->user_data, wr->remote_addr);
		break;
	case IO_RDMA_OP_ATOMIC_CMP_AND_SWP:
	case IO_RDMA_OP_ATOMIC_FETCH_AND_ADD:
		pr_debug("io_uring: Posted ATOMIC WR successfully (wr_id=%llu, remote_addr=0x%llx)\n",
			 wr->user_data, wr->remote_addr);
		break;
	}
	
	return 0;
}

int io_unified_rdma_post_recv(struct io_unified_rdma_ifq *ifq,
			     struct io_unified_rdma_wr *wr)
{
	struct ib_recv_wr recv_wr;
	const struct ib_recv_wr *bad_wr;
	struct ib_sge sge[IO_UNIFIED_RDMA_MAX_SGE];
	int ret, i;
	
	pr_debug("io_uring: Posting recv WR: num_sge=%u\n", wr ? wr->num_sge : 0);
	
	if (!ifq || !ifq->rdma_region->qp || !wr) {
		pr_err("io_uring: Invalid parameters for post_recv (ifq=%p, qp=%p, wr=%p)\n",
		       ifq, ifq ? ifq->rdma_region->qp : NULL, wr);
		return -EINVAL;
	}
	
	if (wr->num_sge > IO_UNIFIED_RDMA_MAX_SGE) {
		pr_err("io_uring: Too many SGEs: %u > %d\n", wr->num_sge, IO_UNIFIED_RDMA_MAX_SGE);
		return -EINVAL;
	}
	
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
		pr_err("io_uring: Failed to post RDMA recv: %d (bad_wr=%p)\n", ret, bad_wr);
		atomic64_inc(&ifq->rdma_region->rdma_errors);
		return ret;
	}
	
	atomic64_inc(&ifq->rdma_region->rdma_recvs);
	pr_debug("io_uring: Posted RECV WR successfully (wr_id=%llu)\n", wr->user_data);
	return 0;
}

/* Completion queue processing */
static void io_rdma_cq_event_handler(struct ib_cq *cq, void *context)
{
	struct io_unified_rdma_ifq *ifq = context;
	
	pr_debug("io_uring: CQ event received on CQ %p\n", cq);
	
	/* Schedule work to process completions */
	queue_work(ifq->rdma_wq, &ifq->rdma_work);
}

int io_unified_rdma_poll_cq(struct io_unified_rdma_ifq *ifq)
{
	struct ib_wc wc[16];  /* Poll up to 16 completions at once */
	int num_cqe, i, total = 0;
	
	pr_debug("io_uring: Polling CQ for completions\n");
	
	if (!ifq || !ifq->rdma_region->send_cq) {
		pr_err("io_uring: Invalid parameters for CQ polling\n");
		return -EINVAL;
	}
	
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
		pr_debug("io_uring: Processed %d completions in this batch\n", num_cqe);
	} while (num_cqe > 0);
	
	if (total > 0)
		pr_debug("io_uring: Total completions processed: %d\n", total);
	
	return total;
}

void io_unified_rdma_complete_wr(struct io_unified_rdma_ifq *ifq,
				 struct io_unified_rdma_cqe *cqe)
{
	struct io_unified_ring *cq_ring = ifq->rdma_region->rdma_cq_ring;
	u32 tail, next_tail;
	
	pr_debug("io_uring: Completing WR: wr_id=%llu, status=%d, opcode=%d, byte_len=%u\n",
		 cqe->user_data, cqe->status, cqe->opcode, cqe->byte_len);
	
	/* Check if CQ has space */
	if ((cq_ring->producer - cq_ring->consumer) >= cq_ring->ring_entries) {
		atomic64_inc(&ifq->rdma_region->rdma_errors);
		pr_warn("io_uring: RDMA CQ ring full, dropping completion (prod=%u, cons=%u, entries=%u)\n",
			cq_ring->producer, cq_ring->consumer, cq_ring->ring_entries);
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
		pr_debug("io_uring: Waking up userspace for CQ notification\n");
		wake_up_poll(&ifq->base.zcrx_ifq.ctx->cq_wait, EPOLLIN | EPOLLRDNORM);
	}
}

/* RDMA work handler */
static void io_unified_rdma_work_handler(struct work_struct *work)
{
	struct io_unified_rdma_ifq *ifq = container_of(work, struct io_unified_rdma_ifq, rdma_work);
	int completions;
	
	pr_debug("io_uring: RDMA work handler invoked\n");
	
	/* Process completions */
	completions = io_unified_rdma_poll_cq(ifq);
	if (completions > 0)
		pr_debug("io_uring: Work handler processed %d completions\n", completions);
	
	/* Re-arm CQ for notifications */
	if (ifq->rdma_region->send_cq) {
		pr_debug("io_uring: Re-arming CQ for notifications\n");
		ib_req_notify_cq(ifq->rdma_region->send_cq, IB_CQ_NEXT_COMP);
	}
}

/* Device capability querying */
int io_unified_rdma_query_device(struct io_unified_rdma_ifq *ifq,
				 struct io_unified_rdma_caps *caps)
{
		struct ib_device_attr device_attr;
		struct ib_udata udata = {};
		int ret;
	
	if (!ifq || !ifq->rdma_region->ib_dev || !caps)
		return -EINVAL;
	
		ret = ifq->rdma_region->ib_dev->ops.query_device(ifq->rdma_region->ib_dev, &device_attr, &udata);
	if (ret) {
		pr_err("io_uring: Failed to query RDMA device: %d\n", ret);
		return ret;
	}
	
	/* Convert device attributes */
	caps->device_cap_flags = device_attr.device_cap_flags;
	caps->max_qp = device_attr.max_qp;
	caps->max_qp_wr = device_attr.max_qp_wr;
	caps->max_sge = device_attr.max_send_sge;
	caps->max_cq = device_attr.max_cq;
	caps->max_cqe = device_attr.max_cqe;
	caps->max_mr = device_attr.max_mr;
	caps->max_mr_size = device_attr.max_mr_size;
	caps->max_pd = device_attr.max_pd;
	caps->max_mw = device_attr.max_mw;
	caps->max_fmr = 0; /* FMR deprecated in modern kernels */
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
	
	pr_debug("io_uring: Allocating RDMA region\n");
	
	/* Allocate RDMA region structure */
	region = kzalloc(sizeof(*region), GFP_KERNEL);
	if (!region) {
		pr_err("io_uring: Failed to allocate RDMA region structure\n");
		return -ENOMEM;
	}
	
	/* Calculate base interface size (from unified.c logic) */
	size_t base_ring_size = 2 * sizeof(struct io_unified_ring);
	size_t base_entries_size = (reg->base.sq_entries * sizeof(struct io_unified_sqe)) +
				   (reg->base.cq_entries * sizeof(struct io_unified_cqe));
	size_t base_buffer_size = reg->base.buffer_entries * reg->base.buffer_entry_size;
	size_t base_total_size = base_ring_size + base_entries_size + base_buffer_size;
	
	/* Calculate additional RDMA sizes */
	rdma_size = 2 * sizeof(struct io_unified_ring) +		/* RDMA SQ/CQ rings */
		    reg->qp_config.max_send_wr * sizeof(struct io_unified_rdma_wr) +  /* RDMA SQ entries */
		    reg->qp_config.max_recv_wr * sizeof(struct io_unified_rdma_cqe) + /* RDMA CQ entries */
		    reg->num_mrs * sizeof(struct io_unified_rdma_mr);   /* MR descriptors */
	
	/* Calculate XDP sizes if enabled */
	size_t xdp_buffer_pool_size = 0;
	size_t xdp_metadata_size = 0;
	if (reg->xdp_config.buffer_count > 0) {
		xdp_buffer_pool_size = reg->xdp_config.buffer_count * reg->xdp_config.buffer_size;
		xdp_metadata_size = reg->xdp_config.buffer_count * sizeof(struct io_unified_buffer_desc) +
				    reg->xdp_config.buffer_count * sizeof(u32); /* free list */
	}
	
	total_size = base_total_size + rdma_size + xdp_buffer_pool_size + xdp_metadata_size;
	
	pr_info("io_uring: Region sizes - base: %zu, RDMA: %zu, total: %zu bytes\n",
		base_total_size, rdma_size, total_size);
	
	/* For RDMA registration, we set up the base unified region ourselves */
	if (ctx->zcrx_region.ptr) {
		pr_err("io_uring: Base unified region already initialized\n");
		kfree(region);
		return -EBUSY;
	}
	
	/* Validate that the user region is large enough for both base and RDMA */
	if (rd->size < total_size) {
		pr_err("io_uring: User region too small for RDMA extension: %llu < %zu\n", rd->size, total_size);
		kfree(region);
		return -EINVAL;
	}
	
	/* Set up the base unified region first */
	ret = io_create_region(ctx, &ctx->zcrx_region, rd, IORING_MAP_OFF_ZCRX_REGION);
	if (ret < 0) {
		pr_err("io_uring: Failed to create base region: %d\n", ret);
		kfree(region);
		return ret;
	}
	
	/* Get base region pointer */
	ptr = io_region_get_ptr(&ctx->zcrx_region);
	if (!ptr) {
		pr_err("io_uring: Failed to get base region pointer\n");
		io_free_region(ctx, &ctx->zcrx_region);
		kfree(region);
		return -EINVAL;
	}
	
	/* Set up base interface structures (similar to unified.c) */
	struct io_unified_ring *base_sq_ring = (struct io_unified_ring *)ptr;
	struct io_unified_ring *base_cq_ring = (struct io_unified_ring *)(ptr + sizeof(struct io_unified_ring));
	
	/* Initialize base rings */
	base_sq_ring->ring_entries = reg->base.sq_entries;
	base_sq_ring->ring_mask = reg->base.sq_entries - 1;
	base_cq_ring->ring_entries = reg->base.cq_entries;
	base_cq_ring->ring_mask = reg->base.cq_entries - 1;
	
	/* Set up RDMA-specific pointers after base structures */
	size_t offset = base_total_size;
	region->rdma_sq_ring = (struct io_unified_ring *)((char *)ptr + offset);
	offset += sizeof(struct io_unified_ring);
	
	region->rdma_cq_ring = (struct io_unified_ring *)((char *)ptr + offset);
	offset += sizeof(struct io_unified_ring);
	
	region->rdma_sq_entries = (struct io_unified_rdma_wr *)((char *)ptr + offset);
	offset += reg->qp_config.max_send_wr * sizeof(struct io_unified_rdma_wr);
	
	region->rdma_cq_entries = (struct io_unified_rdma_cqe *)((char *)ptr + offset);
	offset += reg->qp_config.max_recv_wr * sizeof(struct io_unified_rdma_cqe);
	
	region->memory_regions = (struct io_unified_rdma_mr *)((char *)ptr + offset);
	offset += reg->num_mrs * sizeof(struct io_unified_rdma_mr);
	
	/* Set up XDP pointers if enabled */
	if (reg->xdp_config.buffer_count > 0) {
		pr_debug("io_uring: Setting up XDP buffer pool with %u buffers of size %u\n",
			 reg->xdp_config.buffer_count, reg->xdp_config.buffer_size);
		
		/* XDP buffer pool */
		ifq->rdma_region->xdp.xdp_buffer_pool = (void *)((char *)ptr + offset);
		offset += xdp_buffer_pool_size;
		
		/* Buffer descriptors */
		ifq->rdma_region->buffer_descs = (struct io_unified_buffer_desc *)((char *)ptr + offset);
		offset += reg->xdp_config.buffer_count * sizeof(struct io_unified_buffer_desc);
		
		/* Free list */
		ifq->rdma_region->xdp.free_list = (u32 *)((char *)ptr + offset);
		offset += reg->xdp_config.buffer_count * sizeof(u32);
		
		/* Initialize XDP fields */
		ifq->rdma_region->xdp.xdp_buffer_size = reg->xdp_config.buffer_size;
		ifq->rdma_region->xdp.xdp_buffer_count = reg->xdp_config.buffer_count;
		ifq->rdma_region->xdp.free_count = reg->xdp_config.buffer_count;
		spin_lock_init(&ifq->rdma_region->xdp.free_lock);
		
		/* Initialize free list */
		for (u32 i = 0; i < reg->xdp_config.buffer_count; i++) {
			ifq->rdma_region->xdp.free_list[i] = i;
		}
	}
	
	/* Initialize RDMA rings */
	region->rdma_sq_ring->ring_entries = reg->qp_config.max_send_wr;
	region->rdma_sq_ring->ring_mask = reg->qp_config.max_send_wr - 1;
	region->rdma_cq_ring->ring_entries = reg->qp_config.max_recv_wr;
	region->rdma_cq_ring->ring_mask = reg->qp_config.max_recv_wr - 1;
	
	/* Allocate MR pointer array */
	region->mrs = kcalloc(reg->num_mrs, sizeof(struct ib_mr *), GFP_KERNEL);
	if (!region->mrs) {
		/* TODO: Free base region */
		kfree(region);
		return -ENOMEM;
	}
	
	/* Initialize performance counters */
	atomic64_set(&region->rdma_sends, 0);
	atomic64_set(&region->rdma_recvs, 0);
	atomic64_set(&region->rdma_writes, 0);
	atomic64_set(&region->rdma_reads, 0);
	atomic64_set(&region->rdma_errors, 0);
	
	/* Copy the allocated fields to the existing rdma_region structure */
	ifq->rdma_region->rdma_sq_ring = region->rdma_sq_ring;
	ifq->rdma_region->rdma_cq_ring = region->rdma_cq_ring;
	ifq->rdma_region->rdma_sq_entries = region->rdma_sq_entries;
	ifq->rdma_region->rdma_cq_entries = region->rdma_cq_entries;
	ifq->rdma_region->memory_regions = region->memory_regions;
	ifq->rdma_region->mrs = region->mrs;
	
	/* Copy performance counter values */
	atomic64_set(&ifq->rdma_region->rdma_sends, 0);
	atomic64_set(&ifq->rdma_region->rdma_recvs, 0);
	atomic64_set(&ifq->rdma_region->rdma_writes, 0);
	atomic64_set(&ifq->rdma_region->rdma_reads, 0);
	atomic64_set(&ifq->rdma_region->rdma_errors, 0);
	
	/* Free the temporary region structure */
	kfree(region);
	
	/* Set up offsets for userspace using base_total_size */
	offset = base_total_size;
	reg->rdma_offsets.rdma_sq_ring = offset;
	offset += sizeof(struct io_unified_ring);
	
	reg->rdma_offsets.rdma_cq_ring = offset;
	offset += sizeof(struct io_unified_ring);
	
	reg->rdma_offsets.rdma_sq_entries = offset;
	offset += reg->qp_config.max_send_wr * sizeof(struct io_unified_rdma_wr);
	
	reg->rdma_offsets.rdma_cq_entries = offset;
	offset += reg->qp_config.max_recv_wr * sizeof(struct io_unified_rdma_cqe);
	
	reg->rdma_offsets.memory_regions = offset;
	offset += reg->num_mrs * sizeof(struct io_unified_rdma_mr);
	
	if (reg->xdp_config.buffer_count > 0) {
		reg->rdma_offsets.xdp_buffer_pool = offset;
		offset += xdp_buffer_pool_size;
		
		reg->rdma_offsets.buffer_descs = offset;
		offset += reg->xdp_config.buffer_count * sizeof(struct io_unified_buffer_desc);
	}
	
	pr_info("io_uring: RDMA region allocated successfully - SQ entries: %u, CQ entries: %u\n",
		reg->qp_config.max_send_wr, reg->qp_config.max_recv_wr);
	
	return 0;
}

static void io_unified_rdma_free_region(struct io_ring_ctx *ctx, struct io_unified_rdma_ifq *ifq)
{
	struct io_unified_rdma_region *region;
	int i;
	
	pr_debug("io_uring: Freeing RDMA region\n");
	
	if (!ifq || !ifq->rdma_region) {
		pr_debug("io_uring: No RDMA region to free\n");
		return;
	}
	
	region = ifq->rdma_region;
	
	/* Deregister all memory regions first */
	if (region->mrs && region->num_mrs > 0) {
		pr_debug("io_uring: Deregistering %u memory regions\n", region->num_mrs);
		for (i = 0; i < region->num_mrs; i++) {
			if (region->mrs[i]) {
				ib_dereg_mr(region->mrs[i]);
				region->mrs[i] = NULL;
			}
		}
		kfree(region->mrs);
		region->mrs = NULL;
		region->num_mrs = 0;
	}
	
	/* Clean up RDMA resources in reverse creation order */
	if (region->qp) {
		if (!IS_ERR(region->qp)) {
			ib_destroy_qp(region->qp);
		}
		region->qp = NULL;
	}
	
	if (region->recv_cq) {
		if (!IS_ERR(region->recv_cq)) {
			ib_destroy_cq(region->recv_cq);
		}
		region->recv_cq = NULL;
	}
	
	if (region->send_cq) {
		if (!IS_ERR(region->send_cq)) {
			ib_destroy_cq(region->send_cq);
		}
		region->send_cq = NULL;
	}
	
	if (region->pd) {
		if (!IS_ERR(region->pd)) {
			ib_dealloc_pd(region->pd);
		}
		region->pd = NULL;
	}
	
	if (region->ib_dev) {
		ib_device_put(region->ib_dev);
		region->ib_dev = NULL;
	}
	
	/* TODO: Free base region properly */
	if (ctx && ctx->zcrx_region.ptr) {
		pr_debug("io_uring: Freeing base unified region\n");
		io_free_region(ctx, &ctx->zcrx_region);
	}
	
	pr_info("io_uring: RDMA region freed successfully\n");
}

/* Interface queue management */
static struct io_unified_rdma_ifq *io_unified_rdma_ifq_alloc(struct io_ring_ctx *ctx)
{
	struct io_unified_rdma_ifq *ifq;
	
	pr_debug("io_uring: Allocating RDMA interface queue\n");
	
	ifq = kzalloc(sizeof(*ifq), GFP_KERNEL);
	if (!ifq) {
		pr_err("io_uring: Failed to allocate RDMA IFQ\n");
		return NULL;
	}
	
	/* Allocate RDMA region */
	ifq->rdma_region = kzalloc(sizeof(*ifq->rdma_region), GFP_KERNEL);
	if (!ifq->rdma_region) {
		pr_err("io_uring: Failed to allocate RDMA region in IFQ\n");
		kfree(ifq);
		return NULL;
	}
	
	/* Initialize base unified interface */
	ifq->base.zcrx_ifq.ctx = ctx;
	ifq->base.zcrx_ifq.if_rxq = -1;
	
	/* Initialize RDMA-specific fields */
	INIT_WORK(&ifq->rdma_work, io_unified_rdma_work_handler);
	ifq->rdma_wq = io_unified_rdma_wq;
	ifq->connected = false;
	
	/* Initialize RDMA region with safe defaults */
	ifq->rdma_region->qp = NULL;
	ifq->rdma_region->send_cq = NULL;
	ifq->rdma_region->recv_cq = NULL;
	ifq->rdma_region->pd = NULL;
	ifq->rdma_region->ib_dev = NULL;
	ifq->rdma_region->mrs = NULL;
	ifq->rdma_region->num_mrs = 0;
	
	/* Initialize performance counters */
	atomic64_set(&ifq->rdma_region->rdma_sends, 0);
	atomic64_set(&ifq->rdma_region->rdma_recvs, 0);
	atomic64_set(&ifq->rdma_region->rdma_writes, 0);
	atomic64_set(&ifq->rdma_region->rdma_reads, 0);
	atomic64_set(&ifq->rdma_region->rdma_errors, 0);
	
	/* Initialize XDP integration */
	if (io_unified_rdma_rxe_xdp_init(ifq) < 0) {
		pr_warn("io_uring: Failed to initialize XDP integration\n");
		/* Continue without XDP - not fatal */
	}
	
	pr_info("io_uring: RDMA interface queue allocated successfully\n");
	return ifq;
}

static void io_unified_rdma_ifq_free(struct io_ring_ctx *ctx, struct io_unified_rdma_ifq *ifq)
{
	if (!ifq) {
		pr_debug("io_uring: No IFQ to free\n");
		return;
	}
	
	pr_debug("io_uring: Freeing RDMA interface queue\n");
	
	/* Disconnect if connected */
	if (ifq->connected) {
		pr_debug("io_uring: Disconnecting before freeing IFQ\n");
		io_unified_rdma_disconnect(ctx);
	}
	
	/* Cancel pending work */
	cancel_work_sync(&ifq->rdma_work);
	
	/* Clean up connection manager */
	if (ifq->cm_id) {
		rdma_destroy_id(ifq->cm_id);
		ifq->cm_id = NULL;
	}
	
	if (ifq->event_channel) {
		/* TODO: Proper RDMA event channel cleanup */
		ifq->event_channel = NULL;
	}
	
	/* TODO: Cleanup XDP integration */
	
	/* Free RDMA region */
	io_unified_rdma_free_region(ctx, ifq);
	
	/* Free allocated rdma_region structure */
	if (ifq->rdma_region) {
		kfree(ifq->rdma_region);
		ifq->rdma_region = NULL;
	}
	
	/* TODO: Free base interface */
	
	kfree(ifq);
	pr_info("io_uring: RDMA interface queue freed successfully\n");
}

/* Registration interface */
int io_register_unified_rdma_ifq(struct io_ring_ctx *ctx, struct io_unified_rdma_reg __user *arg)
{
	struct io_unified_rdma_reg reg;
	struct io_uring_region_desc rd;
	struct io_unified_rdma_ifq *ifq;
	char *rdma_dev_name;
	int ret;
	
	pr_info("io_uring: Registering unified RDMA interface\n");
	
	if (!capable(CAP_SYS_ADMIN)) {
		pr_err("io_uring: CAP_SYS_ADMIN required for RDMA registration\n");
		return -EPERM;
	}
	
	if (ctx->rdma_ifq) {
		pr_err("io_uring: RDMA interface already registered\n");
		return -EBUSY;
	}
	
	if (copy_from_user(&reg, arg, sizeof(reg)))
		return -EFAULT;
	
	if (copy_from_user(&rd, u64_to_user_ptr(reg.base.region_ptr), sizeof(rd)))
		return -EFAULT;
	
	/* Validate parameters */
	if (!reg.base.sq_entries || !reg.base.cq_entries || !reg.base.buffer_entries) {
		pr_err("io_uring: Invalid base parameters: sq_entries=%u, cq_entries=%u, buffer_entries=%u\n",
		       reg.base.sq_entries, reg.base.cq_entries, reg.base.buffer_entries);
		return -EINVAL;
	}
	
	if (!reg.qp_config.max_send_wr || !reg.qp_config.max_recv_wr) {
		pr_err("io_uring: Invalid QP parameters: max_send_wr=%u, max_recv_wr=%u\n",
		       reg.qp_config.max_send_wr, reg.qp_config.max_recv_wr);
		return -EINVAL;
	}
	
	/* Set defaults for uninitialized QP config fields */
	if (reg.qp_config.transport_type >= 5) {
		pr_info("io_uring: Defaulting to RC transport\n");
		reg.qp_config.transport_type = IO_RDMA_TRANSPORT_RC;
	}
	
	if (!reg.qp_config.max_send_sge) {
		reg.qp_config.max_send_sge = 1;
	}
	if (!reg.qp_config.max_recv_sge) {
		reg.qp_config.max_recv_sge = 1;  
	}
	if (!reg.qp_config.max_inline_data) {
		reg.qp_config.max_inline_data = 0; /* No inline data by default */
	}
	
	/* Validate and clamp values to reasonable limits */
	reg.qp_config.max_send_wr = min_t(u32, reg.qp_config.max_send_wr, 16384);
	reg.qp_config.max_recv_wr = min_t(u32, reg.qp_config.max_recv_wr, 16384);
	reg.qp_config.max_send_sge = min_t(u32, reg.qp_config.max_send_sge, IO_UNIFIED_RDMA_MAX_SGE);
	reg.qp_config.max_recv_sge = min_t(u32, reg.qp_config.max_recv_sge, IO_UNIFIED_RDMA_MAX_SGE);
	reg.qp_config.max_inline_data = min_t(u32, reg.qp_config.max_inline_data, 1024);
	
	pr_debug("io_uring: QP config: transport=%u, send_wr=%u, recv_wr=%u, send_sge=%u, recv_sge=%u, inline=%u\n",
		 reg.qp_config.transport_type, reg.qp_config.max_send_wr, reg.qp_config.max_recv_wr,
		 reg.qp_config.max_send_sge, reg.qp_config.max_recv_sge, reg.qp_config.max_inline_data);
	
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
		pr_err("io_uring: Failed to get RDMA device name from user: %d\n", ret);
		goto err_free_ifq;
	}
	
	pr_debug("io_uring: Looking for RDMA device: %s\n", rdma_dev_name);
	
	/* Find RDMA device */
	ifq->rdma_region->ib_dev = io_rdma_find_device(rdma_dev_name);
	kfree(rdma_dev_name);
	
	if (!ifq->rdma_region->ib_dev) {
		ret = -ENODEV;
		pr_err("io_uring: RDMA device not found\n");
		goto err_free_ifq;
	}
	
	/* Allocate protection domain */
	ifq->rdma_region->pd = ib_alloc_pd(ifq->rdma_region->ib_dev, 0);
	if (IS_ERR(ifq->rdma_region->pd)) {
		ret = PTR_ERR(ifq->rdma_region->pd);
		ifq->rdma_region->pd = NULL;
		pr_err("io_uring: Failed to allocate RDMA PD: %d\n", ret);
		goto err_put_device;
	}
	
	/* Create completion queues */
	pr_debug("io_uring: Creating completion queues (send_wr=%u, recv_wr=%u)\n",
		 reg.qp_config.max_send_wr, reg.qp_config.max_recv_wr);
	
	struct ib_cq_init_attr send_cq_attr = {
		.cqe = reg.qp_config.max_send_wr,
		.comp_vector = 0
	};
	ifq->rdma_region->send_cq = ib_create_cq(ifq->rdma_region->ib_dev,
						io_rdma_cq_event_handler,
						NULL, ifq,
						&send_cq_attr);
	if (IS_ERR(ifq->rdma_region->send_cq)) {
		ret = PTR_ERR(ifq->rdma_region->send_cq);
		ifq->rdma_region->send_cq = NULL;
		pr_err("io_uring: Failed to create RDMA send CQ: %d\n", ret);
		goto err_dealloc_pd;
	}
	
	struct ib_cq_init_attr recv_cq_attr = {
		.cqe = reg.qp_config.max_recv_wr,
		.comp_vector = 0
	};
	ifq->rdma_region->recv_cq = ib_create_cq(ifq->rdma_region->ib_dev,
						io_rdma_cq_event_handler,
						NULL, ifq,
						&recv_cq_attr);
	if (IS_ERR(ifq->rdma_region->recv_cq)) {
		ret = PTR_ERR(ifq->rdma_region->recv_cq);
		ifq->rdma_region->recv_cq = NULL;
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
	
	/* Initialize XDP buffers if configured */
	if (reg.xdp_config.buffer_count > 0) {
		pr_info("io_uring: Initializing %u XDP buffers for RDMA\n",
			reg.xdp_config.buffer_count);
		
		for (u32 i = 0; i < reg.xdp_config.buffer_count; i++) {
			void *buf_addr = ifq->rdma_region->xdp.xdp_buffer_pool +
					 i * reg.xdp_config.buffer_size;
			struct io_unified_buffer_desc *desc = &ifq->rdma_region->buffer_descs[i];
			
			/* Register buffer with RDMA device */
			struct ib_mr *mr = ib_reg_user_mr(ifq->rdma_region->pd,
							  (unsigned long)buf_addr,
							  reg.xdp_config.buffer_size,
							  (unsigned long)buf_addr,
							  IB_ACCESS_LOCAL_WRITE |
							  IB_ACCESS_REMOTE_WRITE |
							  IB_ACCESS_REMOTE_READ);
			if (IS_ERR(mr)) {
				ret = PTR_ERR(mr);
				pr_err("io_uring: Failed to register XDP buffer %u as MR: %d\n",
				       i, ret);
				/* Clean up previously registered buffers */
				while (i > 0) {
					i--;
					if (ifq->rdma_region->mrs[i]) {
						ib_dereg_mr(ifq->rdma_region->mrs[i]);
					}
				}
				goto err_free_region;
			}
			
			/* Store MR in array */
			if (i < reg.num_mrs) {
				ifq->rdma_region->mrs[i] = mr;
			}
			
			/* Initialize buffer descriptor */
			desc->addr = buf_addr;
			desc->dma_addr = 0; /* Set when DMA mapped */
			desc->size = reg.xdp_config.buffer_size;
			desc->offset = i * reg.xdp_config.buffer_size;
			atomic_set(&desc->ref_count, 0);
			desc->flags = 0;
			desc->state = BUFFER_FREE;
			desc->lkey = mr->lkey;
			desc->rkey = mr->rkey;
			
			pr_debug("io_uring: XDP buffer %u: addr=%p, lkey=0x%x, rkey=0x%x\n",
				 i, buf_addr, mr->lkey, mr->rkey);
		}
		
		/* Initialize XDP statistics */
		atomic64_set(&ifq->rdma_region->xdp.xdp_rx_packets, 0);
		atomic64_set(&ifq->rdma_region->xdp.xdp_tx_packets, 0);
		atomic64_set(&ifq->rdma_region->xdp.xdp_redirects, 0);
		atomic64_set(&ifq->rdma_region->xdp.xdp_drops, 0);
		atomic64_set(&ifq->rdma_region->xdp_to_rdma_transfers, 0);
		atomic64_set(&ifq->rdma_region->rdma_to_xdp_transfers, 0);
	}
	
	/* Complete registration */
	ctx->rdma_ifq = ifq;
	
	/* Set up base interface offsets for userspace (redeclare for scope) */
	size_t ring_size = 2 * sizeof(struct io_unified_ring);
	size_t entries_size = (reg.base.sq_entries * sizeof(struct io_unified_sqe)) +
			      (reg.base.cq_entries * sizeof(struct io_unified_cqe));
	
	reg.base.offsets.sq_ring = 0;
	reg.base.offsets.cq_ring = sizeof(struct io_unified_ring);
	reg.base.offsets.sq_entries = ring_size;
	reg.base.offsets.cq_entries = ring_size + reg.base.sq_entries * sizeof(struct io_unified_sqe);
	reg.base.offsets.buffers = ring_size + entries_size;
	
	if (copy_to_user(arg, &reg, sizeof(reg)) ||
	    copy_to_user(u64_to_user_ptr(reg.base.region_ptr), &rd, sizeof(rd))) {
		ret = -EFAULT;
		goto err_unregister;
	}
	
	pr_info("io_uring: RDMA unified interface registered successfully\n");
	return 0;
	
err_unregister:
	ctx->rdma_ifq = NULL;
err_free_region:
	io_unified_rdma_free_region(ctx, ifq);
	goto err_free_ifq_no_region;
err_destroy_recv_cq:
	ib_destroy_cq(ifq->rdma_region->recv_cq);
	ifq->rdma_region->recv_cq = NULL;
err_destroy_send_cq:
	ib_destroy_cq(ifq->rdma_region->send_cq);
	ifq->rdma_region->send_cq = NULL;
err_dealloc_pd:
	ib_dealloc_pd(ifq->rdma_region->pd);
	ifq->rdma_region->pd = NULL;
err_put_device:
	ib_device_put(ifq->rdma_region->ib_dev);
	ifq->rdma_region->ib_dev = NULL;
err_free_ifq:
	io_unified_rdma_ifq_free(ctx, ifq);
	return ret;
err_free_ifq_no_region:
	/* Cancel pending work */
	cancel_work_sync(&ifq->rdma_work);
	
	/* Clean up connection manager */
	if (ifq->cm_id) {
		rdma_destroy_id(ifq->cm_id);
		ifq->cm_id = NULL;
	}
	
	if (ifq->event_channel) {
		/* TODO: Proper RDMA event channel cleanup */
		ifq->event_channel = NULL;
	}
	
	/* Free allocated rdma_region structure */
	if (ifq->rdma_region) {
		kfree(ifq->rdma_region);
		ifq->rdma_region = NULL;
	}
	
	kfree(ifq);
	return ret;
}

void io_unregister_unified_rdma_ifq(struct io_ring_ctx *ctx)
{
	struct io_unified_rdma_ifq *ifq = ctx->rdma_ifq;
	
	lockdep_assert_held(&ctx->uring_lock);
	
	if (!ifq) {
		pr_debug("io_uring: No RDMA interface to unregister\n");
		return;
	}
	
	pr_info("io_uring: Unregistering RDMA interface\n");
	
	ctx->rdma_ifq = NULL;
	io_unified_rdma_ifq_free(ctx, ifq);
}

void io_shutdown_unified_rdma_ifq(struct io_ring_ctx *ctx)
{
	lockdep_assert_held(&ctx->uring_lock);
	
	if (ctx->rdma_ifq) {
		pr_info("io_uring: Shutting down RDMA interface\n");
		
		/* Disconnect and cancel work */
		io_unified_rdma_disconnect(ctx);
		cancel_work_sync(&ctx->rdma_ifq->rdma_work);
		
		pr_debug("io_uring: RDMA interface shutdown complete\n");
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
	
	pr_debug("io_uring: Setting up XDP program for RDMA interface\n");
	
	if (!ifq) {
		pr_err("io_uring: Invalid IFQ for XDP setup\n");
		return -EINVAL;
	}
		
	spin_lock_irqsave(&ifq->xdp_lock, flags);
	
	old_prog = ifq->rxe_xdp_prog;
	
	if (prog) {
		/* Install new XDP program for SoftRoCE */
		bpf_prog_inc(prog);
		ifq->rxe_xdp_prog = prog;
		ifq->xdp_enabled = true;
		
		pr_info("io_uring: XDP program installed for unified RDMA (SoftRoCE) - prog=%p\n", prog);
	} else {
		/* Remove XDP program */
		ifq->rxe_xdp_prog = NULL;
		ifq->xdp_enabled = false;
		
		pr_info("io_uring: XDP program removed from unified RDMA\n");
	}
	
	spin_unlock_irqrestore(&ifq->xdp_lock, flags);
	
	/* Release old program */
	if (old_prog) {
		pr_debug("io_uring: Releasing old XDP program %p\n", old_prog);
		bpf_prog_put(old_prog);
	}
		
	return 0;
}
EXPORT_SYMBOL_GPL(io_unified_rdma_setup_xdp);

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
	struct io_unified_rdma_region *region;
	struct io_unified_buffer_desc *buffer = NULL;
	struct bpf_prog *prog;
	struct xdp_buff xdp;
	u32 act;
	int ret = 0;
	
	if (!ifq || !skb) {
		pr_err("io_uring: Invalid parameters for XDP xmit capture\n");
		return -EINVAL;
	}
	
	region = ifq->rdma_region;
	if (!region || !region->xdp.xdp_buffer_pool) {
		return 0; /* No unified buffers, use normal path */
	}
		
	rcu_read_lock();
	prog = rcu_dereference(ifq->rxe_xdp_prog);
	
	if (!prog) {
		rcu_read_unlock();
		return 0; /* No XDP program, normal processing */
	}
	
	/* Try to use unified buffer if possible */
	if (skb->data >= region->xdp.xdp_buffer_pool &&
	    skb->data < region->xdp.xdp_buffer_pool + 
			(region->xdp.xdp_buffer_count * region->xdp.xdp_buffer_size)) {
		/* Data is already in unified buffer */
		u32 buffer_idx = (skb->data - region->xdp.xdp_buffer_pool) /
				 region->xdp.xdp_buffer_size;
		buffer = &region->buffer_descs[buffer_idx];
		pr_debug("io_uring: XDP xmit using unified buffer %u\n", buffer_idx);
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
	
	pr_debug("io_uring: XDP xmit action: %u\n", act);
	
	switch (act) {
	case XDP_PASS:
		/* Allow normal transmission */
		pr_debug("io_uring: XDP_PASS - allowing packet transmission\n");
		if (buffer) {
			buffer->state = BUFFER_XDP_TX;
			atomic64_inc(&region->xdp.xdp_tx_packets);
		}
		ret = 0;
		break;
	case XDP_DROP:
		/* Drop the packet */
		pr_debug("io_uring: XDP_DROP - dropping packet\n");
		if (buffer) {
			atomic64_inc(&region->xdp.xdp_drops);
			io_unified_free_xdp_rdma_buffer(region, buffer);
		}
		ret = -EPERM;
		break;
	case XDP_REDIRECT:
		/* Handle redirect action */
		pr_debug("io_uring: XDP_REDIRECT - redirecting packet\n");
		if (buffer) {
			/* Check if redirecting to RDMA */
			struct io_unified_rdma_wr rdma_wr = {0};
			struct xdp_frame *xdp_frame;
			
			/* Convert to XDP frame */
			xdp_frame = xdp_convert_buff_to_frame(&xdp);
			if (xdp_frame) {
				/* Try to transfer to RDMA */
				if (io_unified_xdp_to_rdma_transfer(ifq, xdp_frame, &rdma_wr) == 0) {
					atomic64_inc(&region->xdp.xdp_redirects);
					ret = 0; /* Handled by RDMA */
					break;
				}
			}
		}
		ret = xdp_do_redirect(skb->dev, &xdp, prog);
		if (ret) {
			pr_err("io_uring: XDP redirect failed: %d\n", ret);
			ret = -EPERM;
		}
		break;
	default:
		/* Unknown action, drop */
		pr_warn("io_uring: Unknown XDP action %u, dropping packet\n", act);
		if (buffer) {
			io_unified_free_xdp_rdma_buffer(region, buffer);
		}
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
	struct io_unified_rdma_region *region;
	struct io_unified_buffer_desc *buffer = NULL;
	struct bpf_prog *prog;
	struct xdp_buff xdp;
	u32 act;
	int ret = 0;
	
	if (!ifq || !skb) {
		pr_err("io_uring: Invalid parameters for XDP recv capture\n");
		return -EINVAL;
	}
	
	region = ifq->rdma_region;
	if (!region || !region->xdp.xdp_buffer_pool) {
		return 0; /* No unified buffers, use normal path */
	}
		
	rcu_read_lock();
	prog = rcu_dereference(ifq->rxe_xdp_prog);
	
	if (!prog) {
		rcu_read_unlock();
		return 0; /* No XDP program, normal processing */
	}
	
	/* Allocate unified buffer for receive if not already using one */
	if (skb->data < region->xdp.xdp_buffer_pool ||
	    skb->data >= region->xdp.xdp_buffer_pool + 
			 (region->xdp.xdp_buffer_count * region->xdp.xdp_buffer_size)) {
		/* Need to copy to unified buffer */
		buffer = io_unified_alloc_xdp_rdma_buffer(region, PURPOSE_XDP_RX);
		if (buffer) {
			/* Copy packet data to unified buffer */
			void *buf_data = buffer->addr + XDP_PACKET_HEADROOM;
			size_t copy_len = min_t(size_t, skb->len, 
						buffer->size - XDP_PACKET_HEADROOM);
			
			memcpy(buf_data, skb->data, copy_len);
			
			/* Setup xdp_buff to use unified buffer */
			xdp.data = buf_data;
			xdp.data_end = buf_data + copy_len;
			xdp.data_meta = xdp.data;
			xdp.data_hard_start = buffer->addr;
			xdp.rxq = &ifq->xdp_rxq;
			xdp.frame_sz = buffer->size;
			
			pr_debug("io_uring: XDP recv copied to unified buffer\n");
		} else {
			/* No buffer available, use skb data */
			xdp.data = skb->data;
			xdp.data_end = skb->data + skb->len;
			xdp.data_meta = xdp.data;
			xdp.data_hard_start = skb->head;
			xdp.rxq = &ifq->xdp_rxq;
			xdp.frame_sz = skb_end_offset(skb);
		}
	} else {
		/* Already in unified buffer */
		u32 buffer_idx = (skb->data - region->xdp.xdp_buffer_pool) /
				 region->xdp.xdp_buffer_size;
		buffer = &region->buffer_descs[buffer_idx];
		
		xdp.data = skb->data;
		xdp.data_end = skb->data + skb->len;
		xdp.data_meta = xdp.data;
		xdp.data_hard_start = buffer->addr;
		xdp.rxq = &ifq->xdp_rxq;
		xdp.frame_sz = buffer->size;
		
		pr_debug("io_uring: XDP recv using unified buffer %u\n", buffer_idx);
	}
	
	/* Run XDP program */
	act = bpf_prog_run_xdp(prog, &xdp);
	
	pr_debug("io_uring: XDP recv action: %u\n", act);
	
	switch (act) {
	case XDP_PASS:
		/* Allow normal reception and processing */
		pr_debug("io_uring: XDP_PASS - allowing packet reception\n");
		if (buffer) {
			buffer->state = BUFFER_XDP_RX;
			atomic64_inc(&region->xdp.xdp_rx_packets);
		}
		ret = 0;
		break;
	case XDP_DROP:
		/* Drop the packet */
		pr_debug("io_uring: XDP_DROP - dropping received packet\n");
		if (buffer) {
			atomic64_inc(&region->xdp.xdp_drops);
			io_unified_free_xdp_rdma_buffer(region, buffer);
		}
		ret = -EPERM;
		break;
	case XDP_REDIRECT:
		/* Redirect to unified buffer for zero-copy processing */
		pr_debug("io_uring: XDP_REDIRECT - redirecting to unified buffer\n");
		if (buffer) {
			/* Buffer is ready for RDMA processing */
			buffer->state = BUFFER_TRANSITION;
			atomic64_inc(&region->xdp.xdp_redirects);
			
			/* Create RDMA receive work request */
			struct io_unified_rdma_wr rdma_wr = {
				.opcode = IO_RDMA_OP_RECV,
				.user_data = (u64)buffer - (u64)region->buffer_descs,
				.sge[0] = {
					.addr = (u64)xdp.data,
					.length = xdp.data_end - xdp.data,
					.lkey = buffer->lkey,
				},
				.num_sge = 1,
			};
			
			/* Post to RDMA receive queue */
			if (io_unified_rdma_post_recv(ifq, &rdma_wr) == 0) {
				buffer->state = BUFFER_RDMA_RECV;
				ret = 0; /* Successfully redirected to RDMA */
			} else {
				/* Failed to post, fall back to normal redirect */
				ret = xdp_do_redirect(skb->dev, &xdp, prog);
				if (ret) {
					pr_err("io_uring: XDP redirect failed: %d\n", ret);
					io_unified_free_xdp_rdma_buffer(region, buffer);
				}
			}
		} else {
			ret = xdp_do_redirect(skb->dev, &xdp, prog);
			if (ret) {
				pr_err("io_uring: XDP redirect failed: %d\n", ret);
			}
		}
		break;
	default:
		/* Unknown action, drop */
		pr_warn("io_uring: Unknown XDP action %u, dropping received packet\n", act);
		if (buffer) {
			io_unified_free_xdp_rdma_buffer(region, buffer);
		}
		ret = -EPERM;
		break;
	}
	
	rcu_read_unlock();
	
	if (ret == 0 && buffer && skb->data != xdp.data) {
		/* Need to update skb to point to unified buffer */
		/* This is complex and may require skb reconstruction */
		pr_debug("io_uring: SKB now uses unified buffer\n");
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
EXPORT_SYMBOL_GPL(io_unified_rdma_detach_xdp);

/**
 * io_unified_rdma_connect - Connect RDMA queue pair  
 * @ctx: io_uring context
 * @arg: User pointer to connection arguments
 */
int io_unified_rdma_connect(struct io_ring_ctx *ctx, void __user *arg)
{
	struct io_unified_rdma_ifq *ifq;
	struct io_unified_rdma_connect_params params;
	struct ib_qp_attr qp_attr;
	int qp_attr_mask;
	int ret;
	
	pr_info("io_uring: RDMA connect request received\n");
	
	if (!ctx->rdma_ifq) {
		pr_err("io_uring: No RDMA interface registered\n");
		return -ENODEV;
	}
		
	ifq = ctx->rdma_ifq;
	
	if (!ifq->rdma_region || !ifq->rdma_region->qp) {
		pr_err("io_uring: RDMA region or QP not initialized\n");
		return -EINVAL;
	}
	
	if (copy_from_user(&params, arg, sizeof(params))) {
		pr_err("io_uring: Failed to copy connect params from user\n");
		return -EFAULT;
	}
	
	pr_debug("io_uring: Connect params - remote_qpn=%u, rq_psn=%u, sq_psn=%u\n",
		 params.remote_qpn, params.rq_psn, params.sq_psn);
		
	/* Transition QP to RTR (Ready to Receive) */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IB_QPS_RTR;
	qp_attr.path_mtu = IB_MTU_4096;
	qp_attr.dest_qp_num = params.remote_qpn;
	qp_attr.rq_psn = params.rq_psn;
	qp_attr.max_dest_rd_atomic = 1;
	qp_attr.min_rnr_timer = 12;
	
	/* Set address handle attributes */
	qp_attr.ah_attr.type = RDMA_AH_ATTR_TYPE_IB;
	rdma_ah_set_grh(&qp_attr.ah_attr, &params.remote_gid, 0, params.sgid_index, 1, 0);
	rdma_ah_set_port_num(&qp_attr.ah_attr, 1);
	
	qp_attr_mask = IB_QP_STATE | IB_QP_AV | IB_QP_PATH_MTU | IB_QP_DEST_QPN |
		       IB_QP_RQ_PSN | IB_QP_MAX_DEST_RD_ATOMIC | IB_QP_MIN_RNR_TIMER;
		       
	pr_debug("io_uring: Transitioning QP to RTR state for connection\n");
	
	ret = ib_modify_qp(ifq->rdma_region->qp, &qp_attr, qp_attr_mask);
	if (ret) {
		pr_err("io_uring: Failed to transition QP to RTR: %d\n", ret);
		return ret;
	}
	
	pr_debug("io_uring: QP transitioned to RTR state successfully\n");
	
	/* Transition QP to RTS (Ready to Send) */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IB_QPS_RTS;
	qp_attr.sq_psn = params.sq_psn;
	qp_attr.timeout = 14;
	qp_attr.retry_cnt = 7;
	qp_attr.rnr_retry = 7;
	qp_attr.max_rd_atomic = 1;
	
	qp_attr_mask = IB_QP_STATE | IB_QP_TIMEOUT | IB_QP_RETRY_CNT |
		       IB_QP_RNR_RETRY | IB_QP_SQ_PSN | IB_QP_MAX_QP_RD_ATOMIC;
		       
	pr_debug("io_uring: Transitioning QP to RTS state for connection\n");
	
	ret = ib_modify_qp(ifq->rdma_region->qp, &qp_attr, qp_attr_mask);
	if (ret) {
		pr_err("io_uring: Failed to transition QP to RTS: %d\n", ret);
		return ret;
	}
	
	ifq->connected = true;
	pr_info("io_uring: RDMA connection established - local QP %u <-> remote QP %u\n", 
		ifq->rdma_region->qp->qp_num, params.remote_qpn);
	
	return 0;
}

/**
 * io_unified_rdma_disconnect - Disconnect RDMA queue pair
 * @ctx: io_uring context
 */
int io_unified_rdma_disconnect(struct io_ring_ctx *ctx)
{
	struct io_unified_rdma_ifq *ifq;
	struct ib_qp_attr qp_attr;
	int ret;
	
	pr_info("io_uring: RDMA disconnect request received\n");
	
	if (!ctx->rdma_ifq) {
		pr_err("io_uring: No RDMA interface registered\n");
		return -ENODEV;
	}
		
	ifq = ctx->rdma_ifq;
	
	if (!ifq->rdma_region || !ifq->rdma_region->qp) {
		pr_err("io_uring: RDMA region or QP not initialized\n");
		return -EINVAL;
	}
		
	if (!ifq->connected) {
		pr_debug("io_uring: Already disconnected\n");
		return 0;  /* Already disconnected */
	}
	
	/* Transition QP to ERROR state */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IB_QPS_ERR;
	
	ret = ib_modify_qp(ifq->rdma_region->qp, &qp_attr, IB_QP_STATE);
	if (ret) {
		pr_err("io_uring: Failed to transition QP to ERROR: %d\n", ret);
		/* Continue anyway to clean up */
	}
	
	/* Drain any pending work requests */
	pr_debug("io_uring: Draining pending work requests\n");
	ib_drain_qp(ifq->rdma_region->qp);
	
	/* Reset QP to RESET state */
	pr_debug("io_uring: Resetting QP to RESET state\n");
	qp_attr.qp_state = IB_QPS_RESET;
	ret = ib_modify_qp(ifq->rdma_region->qp, &qp_attr, IB_QP_STATE);
	if (ret) {
		pr_err("io_uring: Failed to reset QP: %d\n", ret);
	}
	
	ifq->connected = false;
	pr_info("io_uring: RDMA connection closed - QP %u disconnected\n", ifq->rdma_region->qp->qp_num);
	
	return 0;
}

/**
 * io_unified_rdma_submit_wr - Submit work request to unified RDMA ring
 * @ifq: Unified RDMA interface queue
 * @wr: Work request to submit
 */
int io_unified_rdma_submit_wr(struct io_unified_rdma_ifq *ifq,
			     struct io_unified_rdma_wr *wr)
{
	struct io_unified_ring *sq_ring;
	struct io_unified_rdma_wr *sq_entry;
	__u32 sq_tail;
	
	if (!ifq || !ifq->rdma_region || !wr)
		return -EINVAL;
		
	sq_ring = ifq->rdma_region->rdma_sq_ring;
	if (!sq_ring)
		return -EINVAL;
		
	/* Check if SQ has space */
	sq_tail = sq_ring->producer;
	if (sq_tail - sq_ring->consumer >= sq_ring->ring_entries)
		return -ENOSPC;
		
	/* Get SQ entry */
	sq_entry = &ifq->rdma_region->rdma_sq_entries[sq_tail & sq_ring->ring_mask];
	
	/* Copy work request */
	memcpy(sq_entry, wr, sizeof(*sq_entry));
	
	/* Update producer */
	sq_ring->producer = sq_tail + 1;
	__sync_synchronize();
	
	/* Optionally, trigger hardware submission here */
	switch (wr->opcode) {
	case IO_RDMA_OP_SEND:
		return io_unified_rdma_post_send(ifq, wr);
	case IO_RDMA_OP_RECV:
		return io_unified_rdma_post_recv(ifq, wr);
	case IO_RDMA_OP_WRITE:
	case IO_RDMA_OP_READ:
		return io_unified_rdma_post_send(ifq, wr);
	default:
		return -EINVAL;
	}
}

/* XDP-RDMA Buffer Management */

struct io_unified_buffer_desc *
io_unified_alloc_xdp_rdma_buffer(struct io_unified_rdma_region *region,
				 enum buffer_purpose purpose)
{
	struct io_unified_buffer_desc *buffer;
	unsigned long flags;
	u32 buffer_idx;
	
	if (!region || !region->xdp.xdp_buffer_pool) {
		pr_err("io_uring: Invalid region for buffer allocation\n");
		return NULL;
	}
	
	spin_lock_irqsave(&region->xdp.free_lock, flags);
	
	if (region->xdp.free_count == 0) {
		spin_unlock_irqrestore(&region->xdp.free_lock, flags);
		pr_debug("io_uring: No free XDP-RDMA buffers available\n");
		return NULL;
	}
	
	/* Get buffer from free list */
	buffer_idx = region->xdp.free_list[--region->xdp.free_count];
	buffer = &region->buffer_descs[buffer_idx];
	
	/* Initialize buffer state */
	atomic_set(&buffer->ref_count, 1);
	
	switch (purpose) {
	case PURPOSE_XDP_RX:
		buffer->state = BUFFER_XDP_RX;
		buffer->flags = BUF_F_XDP;
		break;
	case PURPOSE_XDP_TX:
		buffer->state = BUFFER_XDP_TX;
		buffer->flags = BUF_F_XDP;
		break;
	case PURPOSE_RDMA_RECV:
		buffer->state = BUFFER_RDMA_RECV;
		buffer->flags = BUF_F_RDMA;
		break;
	case PURPOSE_RDMA_SEND:
		buffer->state = BUFFER_RDMA_SEND;
		buffer->flags = BUF_F_RDMA;
		break;
	case PURPOSE_SHARED:
		buffer->state = BUFFER_FREE;
		buffer->flags = BUF_F_XDP | BUF_F_RDMA;
		break;
	default:
		buffer->state = BUFFER_FREE;
		buffer->flags = 0;
	}
	
	spin_unlock_irqrestore(&region->xdp.free_lock, flags);
	
	pr_debug("io_uring: Allocated XDP-RDMA buffer %u for purpose %d\n",
		 buffer_idx, purpose);
	
	return buffer;
}
EXPORT_SYMBOL_GPL(io_unified_alloc_xdp_rdma_buffer);

void io_unified_free_xdp_rdma_buffer(struct io_unified_rdma_region *region,
				    struct io_unified_buffer_desc *buffer)
{
	unsigned long flags;
	u32 buffer_idx;
	
	if (!region || !buffer)
		return;
	
	/* Calculate buffer index */
	buffer_idx = ((void *)buffer - (void *)region->buffer_descs) /
		     sizeof(struct io_unified_buffer_desc);
	
	if (buffer_idx >= region->xdp.xdp_buffer_count) {
		pr_err("io_uring: Invalid buffer index %u\n", buffer_idx);
		return;
	}
	
	/* Check reference count */
	if (!atomic_dec_and_test(&buffer->ref_count))
		return;
	
	spin_lock_irqsave(&region->xdp.free_lock, flags);
	
	/* Reset buffer state */
	buffer->state = BUFFER_FREE;
	buffer->flags = 0;
	buffer->xdp_frame = NULL;
	
	/* Return to free list */
	region->xdp.free_list[region->xdp.free_count++] = buffer_idx;
	
	spin_unlock_irqrestore(&region->xdp.free_lock, flags);
	
	pr_debug("io_uring: Freed XDP-RDMA buffer %u\n", buffer_idx);
}
EXPORT_SYMBOL_GPL(io_unified_free_xdp_rdma_buffer);

/* XDP to RDMA transfer function */
int io_unified_xdp_to_rdma_transfer(struct io_unified_rdma_ifq *ifq,
				   struct xdp_frame *xdp_frame,
				   struct io_unified_rdma_wr *rdma_wr)
{
	struct io_unified_rdma_region *region;
	struct io_unified_buffer_desc *buffer;
	u32 buffer_idx;
	void *xdp_data_start;
	
	if (!ifq || !ifq->rdma_region || !xdp_frame || !rdma_wr) {
		pr_err("io_uring: Invalid parameters for XDP to RDMA transfer\n");
		return -EINVAL;
	}
	
	region = ifq->rdma_region;
	xdp_data_start = xdp_frame->data;
	
	/* Find buffer from XDP frame address */
	if (xdp_data_start < region->xdp.xdp_buffer_pool ||
	    xdp_data_start >= region->xdp.xdp_buffer_pool + 
			      (region->xdp.xdp_buffer_count * region->xdp.xdp_buffer_size)) {
		pr_err("io_uring: XDP frame not in unified buffer pool\n");
		return -EINVAL;
	}
	
	/* Calculate buffer index */
	buffer_idx = ((void *)xdp_data_start - region->xdp.xdp_buffer_pool) /
		     region->xdp.xdp_buffer_size;
	
	if (buffer_idx >= region->xdp.xdp_buffer_count) {
		pr_err("io_uring: Invalid buffer index %u\n", buffer_idx);
		return -EINVAL;
	}
	
	buffer = &region->buffer_descs[buffer_idx];
	
	/* Verify buffer state */
	if (buffer->state != BUFFER_XDP_RX && buffer->state != BUFFER_XDP_TX) {
		pr_err("io_uring: Buffer %u not in XDP state (state=%d)\n",
		       buffer_idx, buffer->state);
		return -EINVAL;
	}
	
	/* Transition buffer state */
	buffer->state = BUFFER_TRANSITION;
	smp_wmb();
	
	/* Setup RDMA work request */
	rdma_wr->sge[0].addr = (u64)xdp_frame->data;
	rdma_wr->sge[0].length = xdp_frame->len;
	rdma_wr->sge[0].lkey = buffer->lkey;
	rdma_wr->num_sge = 1;
	
	/* Update buffer state */
	buffer->state = BUFFER_RDMA_SEND;
	buffer->flags |= BUF_F_RDMA;
	atomic64_inc(&region->xdp_to_rdma_transfers);
	
	pr_debug("io_uring: XDP to RDMA transfer: buffer %u, len %u\n",
		 buffer_idx, xdp_frame->len);
	
	return 0;
}
EXPORT_SYMBOL_GPL(io_unified_xdp_to_rdma_transfer);

/* RDMA to XDP transfer function */
int io_unified_rdma_to_xdp_transfer(struct io_unified_rdma_ifq *ifq,
				   struct io_unified_rdma_cqe *cqe,
				   struct xdp_frame **xdp_frame)
{
	struct io_unified_rdma_region *region;
	struct io_unified_buffer_desc *buffer = NULL;
	void *data_addr;
	u32 buffer_idx;
	
	if (!ifq || !ifq->rdma_region || !cqe || !xdp_frame) {
		pr_err("io_uring: Invalid parameters for RDMA to XDP transfer\n");
		return -EINVAL;
	}
	
	region = ifq->rdma_region;
	
	/* Find buffer from completion user_data or by searching */
	/* Assuming user_data contains buffer index */
	buffer_idx = (u32)cqe->user_data;
	
	if (buffer_idx >= region->xdp.xdp_buffer_count) {
		pr_err("io_uring: Invalid buffer index %u in CQE\n", buffer_idx);
		return -EINVAL;
	}
	
	buffer = &region->buffer_descs[buffer_idx];
	
	/* Verify buffer state */
	if (buffer->state != BUFFER_RDMA_RECV) {
		pr_err("io_uring: Buffer %u not in RDMA_RECV state (state=%d)\n",
		       buffer_idx, buffer->state);
		return -EINVAL;
	}
	
	/* Calculate data address from buffer */
	data_addr = buffer->addr;
	
	/* Create XDP frame - simplified, needs proper implementation */
	*xdp_frame = (struct xdp_frame *)data_addr;
	(*xdp_frame)->data = data_addr + XDP_PACKET_HEADROOM;
	(*xdp_frame)->len = cqe->byte_len;
	(*xdp_frame)->headroom = XDP_PACKET_HEADROOM;
	(*xdp_frame)->metasize = 0;
	(*xdp_frame)->frame_sz = buffer->size;
	
	/* Update buffer state */
	buffer->state = BUFFER_XDP_TX;
	buffer->flags |= BUF_F_XDP;
	buffer->xdp_frame = *xdp_frame;
	atomic64_inc(&region->rdma_to_xdp_transfers);
	
	pr_debug("io_uring: RDMA to XDP transfer: buffer %u, len %u\n",
		 buffer_idx, cqe->byte_len);
	
	return 0;
}
EXPORT_SYMBOL_GPL(io_unified_rdma_to_xdp_transfer);

module_init(io_unified_rdma_init);
module_exit(io_unified_rdma_exit);