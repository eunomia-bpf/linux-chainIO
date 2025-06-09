// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_UNIFIED_H
#define IOU_UNIFIED_H

#include <linux/io_uring_types.h>
#include <linux/socket.h>
#include <linux/nvme_ioctl.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/blk-mq.h>
#include <net/page_pool/types.h>
#include <net/net_trackers.h>
#include "zcrx.h"

#define IO_UNIFIED_MAX_ENTRIES		32768
#define IO_UNIFIED_UREF			0x10000

/* AF_XDP style ring offsets for unified memory layout */
#define IO_UNIFIED_OFFSET_SQ_RING	0
#define IO_UNIFIED_OFFSET_CQ_RING	4096
#define IO_UNIFIED_OFFSET_SQ_ENTRIES	8192
#define IO_UNIFIED_OFFSET_CQ_ENTRIES	(8192 + IO_UNIFIED_MAX_ENTRIES * sizeof(struct io_unified_sqe))
#define IO_UNIFIED_OFFSET_BUFFERS	(IO_UNIFIED_OFFSET_CQ_ENTRIES + IO_UNIFIED_MAX_ENTRIES * sizeof(struct io_unified_cqe))

/* AF_XDP style ring structures */
struct io_unified_ring {
	__u32 producer;
	__u32 consumer;
	__u32 cached_producer;
	__u32 cached_consumer;
	__u32 flags;
	__u32 ring_entries;
	__u64 ring_mask;
	__u64 ring_size;
};

/* AF_XDP style submission queue entry for NVMe commands */
struct io_unified_sqe {
	struct nvme_uring_cmd nvme_cmd;
	__u64 buf_offset;	/* offset into unified buffer area */
	__u64 user_data;	/* for correlation with completion */
	__u32 flags;
	__u32 __pad;
};

/* AF_XDP style completion queue entry */
struct io_unified_cqe {
	__u64 user_data;	/* matches sqe user_data */
	__s32 result;		/* NVMe command result */
	__u32 status;		/* NVMe status code */
	__u64 dma_addr;		/* DMA address for zero-copy */
	__u32 len;		/* data length transferred */
	__u32 flags;
};

/* Unified memory region that combines zcrx and nvme buffers */
struct io_unified_region {
	struct io_zcrx_area zcrx_area;
	
	/* AF_XDP style rings */
	struct io_unified_ring *sq_ring;
	struct io_unified_ring *cq_ring;
	struct io_unified_sqe *sq_entries;
	struct io_unified_cqe *cq_entries;
	
	/* Unified buffer management */
	void *buffer_base;
	size_t buffer_size;
	size_t buffer_entry_size;
	u32 num_buffers;
	
	/* Buffer allocation tracking */
	spinlock_t buf_lock;
	u32 *free_buf_list;
	u32 free_buf_count;
	u32 free_buf_head;
	
	/* Statistics */
	atomic64_t submitted;
	atomic64_t completed;
	atomic64_t errors;
};

/* Unified interface queue that combines zcrx ifq with nvme capabilities */
struct io_unified_ifq {
	struct io_zcrx_ifq zcrx_ifq;
	
	/* NVMe specific fields */
	struct nvme_ctrl *nvme_ctrl;
	struct nvme_ns *nvme_ns;
	
	/* Unified region */
	struct io_unified_region *region;
	
	/* Ring management */
	u32 sq_head_cache;
	u32 cq_tail_cache;
	
	/* Work management */
	struct work_struct completion_work;
	struct workqueue_struct *completion_wq;
};

/* Registration structures */
struct io_unified_reg {
	__u64 region_ptr;		/* pointer to region descriptor */
	__u64 nvme_dev_path;		/* path to nvme device */
	__u32 sq_entries;		/* number of submission queue entries */
	__u32 cq_entries;		/* number of completion queue entries */
	__u32 buffer_entries;		/* number of buffer entries */
	__u32 buffer_entry_size;	/* size of each buffer entry */
	__u32 flags;
	__u32 __resv[3];
	
	/* Output fields */
	struct {
		__u64 sq_ring;		/* offset to SQ ring */
		__u64 cq_ring;		/* offset to CQ ring */
		__u64 sq_entries;	/* offset to SQ entries */
		__u64 cq_entries;	/* offset to CQ entries */
		__u64 buffers;		/* offset to buffer area */
	} offsets;
};

/* IOCTL commands for unified interface */
/* These are already defined in uapi/linux/io_uring.h */

/* Function declarations */
#if defined(CONFIG_IO_URING_UNIFIED)
int io_register_unified_ifq(struct io_ring_ctx *ctx,
			    struct io_unified_reg __user *arg);
void io_unregister_unified_ifq(struct io_ring_ctx *ctx);
void io_shutdown_unified_ifq(struct io_ring_ctx *ctx);

/* Buffer management */
int io_unified_alloc_buffer(struct io_unified_region *region, u32 *buf_id);
void io_unified_free_buffer(struct io_unified_region *region, u32 buf_id);
void *io_unified_get_buffer(struct io_unified_region *region, u32 buf_id);
dma_addr_t io_unified_get_dma_addr(struct io_unified_region *region, u32 buf_id);

/* Ring operations */
bool io_unified_sq_ring_needs_wakeup(struct io_unified_ifq *ifq);
void io_unified_sq_ring_wakeup(struct io_unified_ifq *ifq);
int io_unified_submit_sqe(struct io_unified_ifq *ifq, struct io_unified_sqe *sqe);
int io_unified_complete_cqe(struct io_unified_ifq *ifq, struct io_unified_cqe *cqe);

/* NVMe integration */
int io_unified_nvme_submit(struct io_unified_ifq *ifq, struct io_unified_sqe *sqe);
enum rq_end_io_ret io_unified_nvme_complete(struct request *req, blk_status_t error);

#else
static inline int io_register_unified_ifq(struct io_ring_ctx *ctx,
					  struct io_unified_reg __user *arg)
{
	return -EOPNOTSUPP;
}

static inline void io_unregister_unified_ifq(struct io_ring_ctx *ctx)
{
}

static inline void io_shutdown_unified_ifq(struct io_ring_ctx *ctx)
{
}
#endif

#endif /* IOU_UNIFIED_H */