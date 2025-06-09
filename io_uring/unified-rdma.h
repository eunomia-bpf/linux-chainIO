// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_UNIFIED_RDMA_H
#define IOU_UNIFIED_RDMA_H

#include <linux/io_uring_types.h>
#include <linux/socket.h>
#include <linux/nvme_ioctl.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/bpf.h>
#include <net/xdp.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <net/page_pool/types.h>
#include <net/net_trackers.h>
#include <../drivers/infiniband/core/cma_priv.h>
#include "zcrx.h"
#include "unified.h"

#define IO_UNIFIED_RDMA_MAX_ENTRIES	32768
#define IO_UNIFIED_RDMA_MAX_WR		4096
#define IO_UNIFIED_RDMA_MAX_SGE		16

/* RDMA transport types supported */
enum io_unified_rdma_transport {
	IO_RDMA_TRANSPORT_RC,		/* Reliable Connection */
	IO_RDMA_TRANSPORT_UC,		/* Unreliable Connection */
	IO_RDMA_TRANSPORT_UD,		/* Unreliable Datagram */
	IO_RDMA_TRANSPORT_RAW_ETH,	/* Raw Ethernet (RoCE) */
	IO_RDMA_TRANSPORT_XDP,		/* XDP-accelerated */
};

/* RDMA operation types */
enum io_unified_rdma_opcode {
	IO_RDMA_OP_SEND,
	IO_RDMA_OP_RECV,
	IO_RDMA_OP_WRITE,
	IO_RDMA_OP_READ,
	IO_RDMA_OP_ATOMIC_CMP_AND_SWP,
	IO_RDMA_OP_ATOMIC_FETCH_AND_ADD,
};

/* RDMA work request for unified interface */
struct io_unified_rdma_wr {
	__u64 user_data;		/* User correlation data */
	__u32 opcode;			/* RDMA operation */
	__u32 flags;			/* Request flags */
	__u64 local_addr;		/* Local buffer address */
	__u32 length;			/* Transfer length */
	__u32 lkey;			/* Local memory key */
	
	/* Remote memory info (for RDMA read/write) */
	__u64 remote_addr;		/* Remote buffer address */
	__u32 rkey;			/* Remote memory key */
	
	/* Immediate data / atomic operands */
	union {
		__u32 imm_data;		/* Immediate data for send */
		__u64 compare_add;	/* For atomic operations */
		__u64 swap;		/* For atomic compare-swap */
	};
	
	/* Scatter-gather list */
	__u32 num_sge;			/* Number of SGEs */
	struct {
		__u64 addr;		/* Buffer address */
		__u32 length;		/* Buffer length */
		__u32 lkey;		/* Local key */
	} sge[IO_UNIFIED_RDMA_MAX_SGE];
};

/* RDMA completion entry */
struct io_unified_rdma_cqe {
	__u64 user_data;		/* Matches wr user_data */
	__u32 status;			/* Completion status */
	__u32 opcode;			/* Completed operation */
	__u32 byte_len;			/* Number of bytes transferred */
	__u32 qp_num;			/* Queue pair number */
	__u32 src_qp;			/* Source QP (for UD) */
	__u32 wc_flags;			/* Completion flags */
	__u32 imm_data;			/* Immediate data received */
	__u16 pkey_index;		/* P_Key index */
	__u16 slid;			/* Source LID */
	__u8 sl;			/* Service Level */
	__u8 dlid_path_bits;		/* DLID path bits */
};

/* RDMA queue pair configuration */
struct io_unified_rdma_qp_config {
	__u32 transport_type;		/* Transport type */
	__u32 max_send_wr;		/* Max send work requests */
	__u32 max_recv_wr;		/* Max receive work requests */
	__u32 max_send_sge;		/* Max send SGEs */
	__u32 max_recv_sge;		/* Max receive SGEs */
	__u32 max_inline_data;		/* Max inline data size */
	
	/* Connection parameters (for RC/UC) */
	__u32 remote_qpn;		/* Remote QP number */
	__u32 rq_psn;			/* Receive queue PSN */
	__u32 sq_psn;			/* Send queue PSN */
	__u32 dest_qp_num;		/* Destination QP */
	
	/* Address parameters */
	union {
		struct {
			__u8 sgid[16];		/* Source GID */
			__u8 dgid[16];		/* Destination GID */
			__u16 dlid;		/* Destination LID */
			__u8 sl;		/* Service Level */
			__u8 src_path_bits;	/* Source path bits */
		} ib;
		struct {
			__u8 smac[6];		/* Source MAC */
			__u8 dmac[6];		/* Destination MAC */
			__u16 vlan_id;		/* VLAN ID */
			__u32 priority;		/* Traffic priority */
		} eth;
	} addr;
};

/* RDMA device capabilities */
struct io_unified_rdma_caps {
	__u64 device_cap_flags;		/* Device capability flags */
	__u32 max_qp;			/* Maximum QPs */
	__u32 max_qp_wr;		/* Max WRs per QP */
	__u32 max_sge;			/* Max SGEs per WR */
	__u32 max_cq;			/* Maximum CQs */
	__u32 max_cqe;			/* Max CQEs per CQ */
	__u32 max_mr;			/* Maximum MRs */
	__u64 max_mr_size;		/* Maximum MR size */
	__u32 max_pd;			/* Maximum PDs */
	__u32 max_mw;			/* Maximum MWs */
	__u32 max_fmr;			/* Maximum FMRs */
	__u32 max_ah;			/* Maximum AHs */
	__u32 max_srq;			/* Maximum SRQs */
	__u32 max_srq_wr;		/* Max WRs per SRQ */
	__u32 max_srq_sge;		/* Max SGEs per SRQ WR */
	__u32 atomic_cap;		/* Atomic capabilities */
	__u32 masked_atomic_cap;	/* Masked atomic capabilities */
	__u32 max_mcast_grp;		/* Max multicast groups */
	__u32 max_mcast_qp_attach;	/* Max QPs per multicast group */
	__u32 max_total_mcast_qp_attach; /* Max total multicast attachments */
};

/* RDMA memory region descriptor */
struct io_unified_rdma_mr {
	__u64 addr;			/* Buffer start address */
	__u64 length;			/* Buffer length */
	__u32 lkey;			/* Local key */
	__u32 rkey;			/* Remote key */
	__u32 access_flags;		/* Access permissions */
	__u32 pd_handle;		/* Protection domain handle */
};

/* RDMA-enhanced unified region */
struct io_unified_rdma_region {
	struct io_unified_region base;	/* Base unified region */
	
	/* RDMA-specific rings */
	struct io_unified_ring *rdma_sq_ring;	/* RDMA SQ ring */
	struct io_unified_ring *rdma_cq_ring;	/* RDMA CQ ring */
	struct io_unified_rdma_wr *rdma_sq_entries;	/* RDMA SQ entries */
	struct io_unified_rdma_cqe *rdma_cq_entries;	/* RDMA CQ entries */
	
	/* RDMA memory management */
	struct io_unified_rdma_mr *memory_regions;	/* Registered MRs */
	u32 num_mrs;			/* Number of MRs */
	
	/* RDMA device handles */
	struct ib_device *ib_dev;	/* IB device */
	struct ib_pd *pd;		/* Protection domain */
	struct ib_cq *send_cq;		/* Send completion queue */
	struct ib_cq *recv_cq;		/* Receive completion queue */
	struct ib_qp *qp;		/* Queue pair */
	struct ib_mr **mrs;		/* Memory region array */
	
	/* XDP integration */
	struct xsk_socket *rdma_xsk;	/* RDMA XDP socket */
	struct xsk_umem *rdma_umem;	/* RDMA UMEM */
	
	/* Performance counters */
	atomic64_t rdma_sends;
	atomic64_t rdma_recvs;
	atomic64_t rdma_writes;
	atomic64_t rdma_reads;
	atomic64_t rdma_errors;
};

/* RDMA-enhanced interface queue */
struct io_unified_rdma_ifq {
	struct io_unified_ifq base;	/* Base unified interface */
	
	/* RDMA-specific fields */
	struct io_unified_rdma_region *rdma_region;
	struct rdma_cm_id *cm_id;	/* Connection manager ID */
	struct rdma_event_channel *event_channel;
	
	/* RDMA configuration */
	struct io_unified_rdma_qp_config qp_config;
	struct io_unified_rdma_caps device_caps;
	
	/* RDMA work management */
	struct workqueue_struct *rdma_wq;
	struct work_struct rdma_work;
	
	/* RDMA ring management */
	u32 rdma_sq_head_cache;
	u32 rdma_cq_tail_cache;
	
	/* Connection state */
	enum rdma_cm_state cm_state;
	bool connected;
	
	/* XDP integration state */
	bool xdp_enabled;
	struct bpf_prog *rxe_xdp_prog;
	struct xdp_rxq_info xdp_rxq;
	spinlock_t xdp_lock;
};

/* Registration structure for RDMA-enhanced interface */
struct io_unified_rdma_reg {
	struct io_unified_reg base;	/* Base registration */
	
	/* RDMA-specific configuration */
	__u64 rdma_dev_name;		/* RDMA device name */
	__u32 rdma_port;		/* RDMA port number */
	__u32 transport_type;		/* Transport type */
	
	/* Queue pair configuration */
	struct io_unified_rdma_qp_config qp_config;
	
	/* XDP integration */
	__u32 xdp_flags;		/* XDP program flags */
	__u64 xdp_prog_path;		/* Path to XDP program */
	
	/* Memory region configuration */
	__u32 num_mrs;			/* Number of memory regions */
	__u32 mr_access_flags;		/* MR access permissions */
	
	/* Output: additional offsets */
	struct {
		__u64 rdma_sq_ring;	/* RDMA SQ ring offset */
		__u64 rdma_cq_ring;	/* RDMA CQ ring offset */
		__u64 rdma_sq_entries;	/* RDMA SQ entries offset */
		__u64 rdma_cq_entries;	/* RDMA CQ entries offset */
		__u64 memory_regions;	/* MR descriptors offset */
	} rdma_offsets;
};

/* IOCTL commands for RDMA-enhanced unified interface */
#define IORING_REGISTER_UNIFIED_RDMA_IFQ	50
#define IORING_UNREGISTER_UNIFIED_RDMA_IFQ	51
#define IORING_UNIFIED_RDMA_CONNECT		52
#define IORING_UNIFIED_RDMA_DISCONNECT		53
#define IORING_UNIFIED_RDMA_QUERY_CAPS		54

/* Function declarations */
#if defined(CONFIG_IO_URING_UNIFIED_RDMA)

/* Registration and management */
int io_register_unified_rdma_ifq(struct io_ring_ctx *ctx,
				 struct io_unified_rdma_reg __user *arg);
void io_unregister_unified_rdma_ifq(struct io_ring_ctx *ctx);
void io_shutdown_unified_rdma_ifq(struct io_ring_ctx *ctx);

/* RDMA operations */
int io_unified_rdma_connect(struct io_ring_ctx *ctx,
			   void __user *arg);
int io_unified_rdma_disconnect(struct io_ring_ctx *ctx);
int io_unified_rdma_post_send(struct io_unified_rdma_ifq *ifq,
			     struct io_unified_rdma_wr *wr);
int io_unified_rdma_post_recv(struct io_unified_rdma_ifq *ifq,
			     struct io_unified_rdma_wr *wr);
int io_unified_rdma_submit_wr(struct io_unified_rdma_ifq *ifq,
			     struct io_unified_rdma_wr *wr);

/* Memory management */
int io_unified_rdma_reg_mr(struct io_unified_rdma_region *region,
			  void *addr, size_t length, int access_flags,
			  struct io_unified_rdma_mr *mr);
int io_unified_rdma_dereg_mr(struct io_unified_rdma_region *region,
			     struct io_unified_rdma_mr *mr);

/* XDP integration */
int io_unified_rdma_setup_xdp(struct io_unified_rdma_ifq *ifq,
			      struct bpf_prog *prog);
int io_unified_rdma_attach_xdp(struct io_unified_rdma_ifq *ifq);
void io_unified_rdma_detach_xdp(struct io_unified_rdma_ifq *ifq);

/* SoftRoCE XDP program functions */
int io_unified_rdma_rxe_xdp_init(struct io_unified_rdma_ifq *ifq);
void io_unified_rdma_rxe_xdp_cleanup(struct io_unified_rdma_ifq *ifq);
int io_unified_rdma_xmit_capture(struct io_unified_rdma_ifq *ifq, 
				 struct sk_buff *skb);
int io_unified_rdma_recv_capture(struct io_unified_rdma_ifq *ifq,
				 struct sk_buff *skb);

/* Completion processing */
int io_unified_rdma_poll_cq(struct io_unified_rdma_ifq *ifq);
void io_unified_rdma_complete_wr(struct io_unified_rdma_ifq *ifq,
				 struct io_unified_rdma_cqe *cqe);

/* Utility functions */
int io_unified_rdma_query_device(struct io_unified_rdma_ifq *ifq,
				 struct io_unified_rdma_caps *caps);
const char *io_unified_rdma_wc_status_str(int status);
bool io_unified_rdma_is_connected(struct io_unified_rdma_ifq *ifq);

#else

static inline int io_register_unified_rdma_ifq(struct io_ring_ctx *ctx,
					       struct io_unified_rdma_reg __user *arg)
{
	return -EOPNOTSUPP;
}

static inline void io_unregister_unified_rdma_ifq(struct io_ring_ctx *ctx)
{
}

static inline void io_shutdown_unified_rdma_ifq(struct io_ring_ctx *ctx)
{
}

static inline int io_unified_rdma_connect(struct io_ring_ctx *ctx,
					 void __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int io_unified_rdma_disconnect(struct io_ring_ctx *ctx)
{
	return -EOPNOTSUPP;
}

static inline int io_unified_rdma_submit_wr(struct io_unified_rdma_ifq *ifq,
					   struct io_unified_rdma_wr *wr)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_IO_URING_UNIFIED_RDMA */

/* Connection parameters for RDMA QP */
struct io_unified_rdma_connect_params {
	__u32 remote_qpn;	/* Remote QP number */
	__u32 rq_psn;		/* Starting receive packet sequence number */
	__u32 sq_psn;		/* Starting send packet sequence number */
	__u32 sgid_index;	/* Source GID index */
	union ib_gid remote_gid;	/* Remote GID */
	__u32 __resv[4];
};

/* Helper macros */
#define IO_RDMA_WR_SEND_WITH_IMM	(1 << 0)
#define IO_RDMA_WR_SEND_WITH_INV	(1 << 1)
#define IO_RDMA_WR_SEND_INLINE		(1 << 2)
#define IO_RDMA_WR_SEND_SIGNALED	(1 << 3)
#define IO_RDMA_WR_SEND_SOLICITED	(1 << 4)

#define IO_RDMA_WC_SUCCESS		0
#define IO_RDMA_WC_LOC_LEN_ERR		1
#define IO_RDMA_WC_LOC_QP_OP_ERR	2
#define IO_RDMA_WC_LOC_EEC_OP_ERR	3
#define IO_RDMA_WC_LOC_PROT_ERR		4
#define IO_RDMA_WC_WR_FLUSH_ERR		5
#define IO_RDMA_WC_MW_BIND_ERR		6
#define IO_RDMA_WC_BAD_RESP_ERR		7
#define IO_RDMA_WC_LOC_ACCESS_ERR	8
#define IO_RDMA_WC_REM_INV_REQ_ERR	9
#define IO_RDMA_WC_REM_ACCESS_ERR	10
#define IO_RDMA_WC_REM_OP_ERR		11
#define IO_RDMA_WC_RETRY_EXC_ERR	12
#define IO_RDMA_WC_RNR_RETRY_EXC_ERR	13
#define IO_RDMA_WC_LOC_RDD_VIOL_ERR	14
#define IO_RDMA_WC_REM_INV_RD_REQ_ERR	15
#define IO_RDMA_WC_REM_ABORT_ERR	16
#define IO_RDMA_WC_INV_EECN_ERR		17
#define IO_RDMA_WC_INV_EEC_STATE_ERR	18
#define IO_RDMA_WC_FATAL_ERR		19
#define IO_RDMA_WC_RESP_TIMEOUT_ERR	20
#define IO_RDMA_WC_GENERAL_ERR		21

#endif /* IOU_UNIFIED_RDMA_H */