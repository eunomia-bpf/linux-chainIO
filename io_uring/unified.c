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
#include <uapi/linux/io_uring.h>
#include "../drivers/nvme/host/nvme.h"

#include "io_uring.h"
#include "memmap.h"
#include "unified.h"
#include "rsrc.h"

static struct workqueue_struct *io_unified_wq;

/* Private data structure for request tracking */
struct io_unified_req_data {
	struct io_unified_ifq *ifq;
	__u64 user_data;
};

/* Buffer management functions */
int io_unified_alloc_buffer(struct io_unified_region *region, u32 *buf_id)
{
	unsigned long flags;
	
	spin_lock_irqsave(&region->buf_lock, flags);
	if (region->free_buf_count == 0) {
		spin_unlock_irqrestore(&region->buf_lock, flags);
		return -ENOMEM;
	}
	
	*buf_id = region->free_buf_list[--region->free_buf_count];
	spin_unlock_irqrestore(&region->buf_lock, flags);
	
	return 0;
}

void io_unified_free_buffer(struct io_unified_region *region, u32 buf_id)
{
	unsigned long flags;
	
	if (buf_id >= region->num_buffers)
		return;
	
	spin_lock_irqsave(&region->buf_lock, flags);
	if (region->free_buf_count < region->num_buffers) {
		region->free_buf_list[region->free_buf_count++] = buf_id;
	}
	spin_unlock_irqrestore(&region->buf_lock, flags);
}

void *io_unified_get_buffer(struct io_unified_region *region, u32 buf_id)
{
	if (buf_id >= region->num_buffers)
		return NULL;
		
	return region->buffer_base + (buf_id * region->buffer_entry_size);
}

dma_addr_t io_unified_get_dma_addr(struct io_unified_region *region, u32 buf_id)
{
	struct page *page;
	void *buf_addr;
	
	buf_addr = io_unified_get_buffer(region, buf_id);
	if (!buf_addr)
		return 0;
	
	page = virt_to_page(buf_addr);
	return page_to_phys(page) + offset_in_page(buf_addr);
}

/* Ring operations */
bool io_unified_sq_ring_needs_wakeup(struct io_unified_ifq *ifq)
{
	return (ifq->region->sq_ring->flags & IO_UNIFIED_UREF) != 0;
}

void io_unified_sq_ring_wakeup(struct io_unified_ifq *ifq)
{
	if (io_unified_sq_ring_needs_wakeup(ifq)) {
		wake_up_poll(&ifq->zcrx_ifq.ctx->cq_wait, EPOLLIN | EPOLLRDNORM);
	}
}

static u32 io_unified_sq_ring_entries(struct io_unified_ifq *ifq)
{
	struct io_unified_ring *ring = ifq->region->sq_ring;
	u32 entries;
	
	smp_rmb();
	entries = ring->producer - ifq->sq_head_cache;
	return entries & ring->ring_mask;
}

static u32 io_unified_cq_ring_space(struct io_unified_ifq *ifq)
{
	struct io_unified_ring *ring = ifq->region->cq_ring;
	u32 space;
	
	smp_rmb();
	space = ifq->cq_tail_cache - ring->consumer;
	return (ring->ring_entries - (space & ring->ring_mask)) - 1;
}

int io_unified_submit_sqe(struct io_unified_ifq *ifq, struct io_unified_sqe *sqe)
{
	struct request_queue *q;
	struct nvme_command nvme_cmd;
	struct request *req;
	struct io_unified_req_data *req_data;
	void *data_buf;
	dma_addr_t dma_addr;
	u32 buf_id;
	
	/* Allocate buffer if needed */
	if (sqe->buf_offset != ~0ULL) {
		buf_id = sqe->buf_offset / ifq->region->buffer_entry_size;
		data_buf = io_unified_get_buffer(ifq->region, buf_id);
		dma_addr = io_unified_get_dma_addr(ifq->region, buf_id);
		if (!data_buf) {
			return -EINVAL;
		}
	} else {
		data_buf = NULL;
		dma_addr = 0;
		buf_id = ~0U;
	}
	
	/* Convert to NVMe command */
	memcpy(&nvme_cmd, &sqe->nvme_cmd, sizeof(nvme_cmd));
	nvme_cmd.common.command_id = 0;
	
	/* Get the appropriate queue */
	if (ifq->nvme_ns) {
		q = ifq->nvme_ns->queue;
	} else {
		q = ifq->nvme_ctrl->admin_q;
	}
	
	/* Allocate request */
	req = blk_mq_alloc_request(q, nvme_req_op(&nvme_cmd), BLK_MQ_REQ_NOWAIT);
	if (IS_ERR(req)) {
		if (buf_id != ~0U)
			io_unified_free_buffer(ifq->region, buf_id);
		return PTR_ERR(req);
	}
	
	/* Allocate request data */
	req_data = kmalloc(sizeof(*req_data), GFP_KERNEL);
	if (!req_data) {
		blk_mq_free_request(req);
		if (buf_id != ~0U)
			io_unified_free_buffer(ifq->region, buf_id);
		return -ENOMEM;
	}
	
	req_data->ifq = ifq;
	req_data->user_data = sqe->user_data;
	
	/* Initialize request */
	req->timeout = 30 * HZ; /* 30 second timeout */
	req->cmd_flags |= REQ_FAILFAST_DRIVER;
	
	/* Map data if present */
	if (data_buf && sqe->nvme_cmd.data_len > 0) {
		struct bio *bio;
		struct page *page = virt_to_page(data_buf);
		
		bio = bio_alloc(ifq->nvme_ns ? ifq->nvme_ns->disk->part0 : NULL, 1, 
				nvme_is_write(&nvme_cmd) ? REQ_OP_WRITE : REQ_OP_READ, GFP_KERNEL);
		if (!bio) {
			blk_mq_free_request(req);
			if (buf_id != ~0U)
				io_unified_free_buffer(ifq->region, buf_id);
			return -ENOMEM;
		}
		
		if (!bio_add_page(bio, page, sqe->nvme_cmd.data_len, offset_in_page(data_buf))) {
			bio_put(bio);
			kfree(req_data);
			blk_mq_free_request(req);
			if (buf_id != ~0U)
				io_unified_free_buffer(ifq->region, buf_id);
			return -ENOMEM;
		}
		
		blk_rq_bio_prep(req, bio, 1);
	}
	
	/* Set completion callback */
	req->end_io_data = req_data;
	req->end_io = io_unified_nvme_complete;
	
	/* Submit request */
	blk_execute_rq_nowait(req, false);
	atomic64_inc(&ifq->region->submitted);
	
	return 0;
}

int io_unified_complete_cqe(struct io_unified_ifq *ifq, struct io_unified_cqe *cqe)
{
	struct io_unified_ring *ring = ifq->region->cq_ring;
	u32 tail, next_tail;
	
	if (io_unified_cq_ring_space(ifq) == 0)
		return -ENOSPC;
	
	tail = ifq->cq_tail_cache;
	next_tail = (tail + 1) & ring->ring_mask;
	
	/* Copy completion entry */
	memcpy(&ifq->region->cq_entries[tail], cqe, sizeof(*cqe));
	
	/* Update tail */
	ifq->cq_tail_cache = next_tail;
	smp_wmb();
	ring->producer = next_tail;
	
	atomic64_inc(&ifq->region->completed);
	
	/* Wake up userspace */
	io_unified_sq_ring_wakeup(ifq);
	
	return 0;
}

/* NVMe completion callback */
enum rq_end_io_ret io_unified_nvme_complete(struct request *req, blk_status_t error)
{
	struct io_unified_req_data *req_data = req->end_io_data;
	struct io_unified_ifq *ifq = req_data->ifq;
	struct io_unified_cqe cqe;
	int ret;
	
	/* Fill completion entry */
	memset(&cqe, 0, sizeof(cqe));
	cqe.user_data = req_data->user_data;
	cqe.status = 0; /* Will be filled based on blk_status_t */
	cqe.result = blk_status_to_errno(error);
	
	if (req->bio) {
		cqe.len = req->bio->bi_iter.bi_size;
		cqe.dma_addr = bio_page(req->bio)->dma_addr;
	}
	
	/* Queue completion */
	ret = io_unified_complete_cqe(ifq, &cqe);
	if (ret < 0) {
		atomic64_inc(&ifq->region->errors);
		pr_warn("io_uring: failed to queue completion: %d\n", ret);
	}
	
	/* Free resources */
	if (req->bio) {
		u32 buf_id = cqe.dma_addr / ifq->region->buffer_entry_size;
		io_unified_free_buffer(ifq->region, buf_id);
		bio_put(req->bio);
	}
	
	kfree(req_data);
	blk_mq_free_request(req);
	return RQ_END_IO_NONE;
}

/* NVMe submission worker */
static void io_unified_submission_work(struct work_struct *work)
{
	struct io_unified_ifq *ifq = container_of(work, struct io_unified_ifq, completion_work);
	struct io_unified_sqe *sqe;
	u32 head, entries, i;
	int ret;
	
	entries = io_unified_sq_ring_entries(ifq);
	if (entries == 0)
		return;
	
	head = ifq->sq_head_cache;
	
	for (i = 0; i < entries; i++) {
		sqe = &ifq->region->sq_entries[head & ifq->region->sq_ring->ring_mask];
		
		ret = io_unified_submit_sqe(ifq, sqe);
		if (ret < 0) {
			struct io_unified_cqe cqe;
			memset(&cqe, 0, sizeof(cqe));
			cqe.user_data = sqe->user_data;
			cqe.result = ret;
			cqe.status = NVME_SC_INTERNAL;
			io_unified_complete_cqe(ifq, &cqe);
			atomic64_inc(&ifq->region->errors);
		}
		
		head++;
	}
	
	ifq->sq_head_cache = head;
	smp_wmb();
	ifq->region->sq_ring->consumer = head;
}

int io_unified_nvme_submit(struct io_unified_ifq *ifq, struct io_unified_sqe *sqe)
{
	queue_work(ifq->completion_wq, &ifq->completion_work);
	return 0;
}

/* Region allocation and management */
static int io_unified_alloc_region(struct io_ring_ctx *ctx,
				   struct io_unified_ifq *ifq,
				   struct io_unified_reg *reg,
				   struct io_uring_region_desc *rd)
{
	struct io_unified_region *region;
	size_t total_size, ring_size, entries_size, buffer_size;
	void *ptr;
	int ret, i;
	
	/* Calculate sizes */
	ring_size = 2 * sizeof(struct io_unified_ring);
	entries_size = (reg->sq_entries * sizeof(struct io_unified_sqe)) +
		       (reg->cq_entries * sizeof(struct io_unified_cqe));
	buffer_size = reg->buffer_entries * reg->buffer_entry_size;
	total_size = ring_size + entries_size + buffer_size;
	
	if (total_size > rd->size)
		return -EINVAL;
	
	region = kzalloc(sizeof(*region), GFP_KERNEL);
	if (!region)
		return -ENOMEM;
	
	ret = io_create_region_mmap_safe(ctx, &ctx->zcrx_region, rd,
					 IORING_MAP_OFF_ZCRX_REGION);
	if (ret < 0) {
		kfree(region);
		return ret;
	}
	
	ptr = io_region_get_ptr(&ctx->zcrx_region);
	
	/* Initialize ring pointers */
	region->sq_ring = (struct io_unified_ring *)ptr;
	region->cq_ring = (struct io_unified_ring *)(ptr + sizeof(struct io_unified_ring));
	region->sq_entries = (struct io_unified_sqe *)(ptr + ring_size);
	region->cq_entries = (struct io_unified_cqe *)(ptr + ring_size + 
			     reg->sq_entries * sizeof(struct io_unified_sqe));
	region->buffer_base = ptr + ring_size + entries_size;
	region->buffer_size = buffer_size;
	region->buffer_entry_size = reg->buffer_entry_size;
	region->num_buffers = reg->buffer_entries;
	
	/* Initialize rings */
	region->sq_ring->ring_entries = reg->sq_entries;
	region->sq_ring->ring_mask = reg->sq_entries - 1;
	region->cq_ring->ring_entries = reg->cq_entries;
	region->cq_ring->ring_mask = reg->cq_entries - 1;
	
	/* Initialize buffer management */
	spin_lock_init(&region->buf_lock);
	region->free_buf_list = kmalloc_array(reg->buffer_entries, sizeof(u32), GFP_KERNEL);
	if (!region->free_buf_list) {
		io_free_region(ctx, &ctx->zcrx_region);
		kfree(region);
		return -ENOMEM;
	}
	
	region->free_buf_count = reg->buffer_entries;
	for (i = 0; i < reg->buffer_entries; i++) {
		region->free_buf_list[i] = i;
	}
	
	/* Initialize statistics */
	atomic64_set(&region->submitted, 0);
	atomic64_set(&region->completed, 0);
	atomic64_set(&region->errors, 0);
	
	ifq->region = region;
	
	/* Set up offsets for userspace */
	reg->offsets.sq_ring = 0;
	reg->offsets.cq_ring = sizeof(struct io_unified_ring);
	reg->offsets.sq_entries = ring_size;
	reg->offsets.cq_entries = ring_size + reg->sq_entries * sizeof(struct io_unified_sqe);
	reg->offsets.buffers = ring_size + entries_size;
	
	return 0;
}

static void io_unified_free_region(struct io_ring_ctx *ctx, struct io_unified_ifq *ifq)
{
	if (!ifq->region)
		return;
	
	if (ifq->region->free_buf_list)
		kfree(ifq->region->free_buf_list);
	
	io_free_region(ctx, &ctx->zcrx_region);
	kfree(ifq->region);
	ifq->region = NULL;
}

/* Interface queue management */
static struct io_unified_ifq *io_unified_ifq_alloc(struct io_ring_ctx *ctx)
{
	struct io_unified_ifq *ifq;
	
	ifq = kzalloc(sizeof(*ifq), GFP_KERNEL);
	if (!ifq)
		return NULL;
	
	/* Initialize zcrx portion */
	ifq->zcrx_ifq.ctx = ctx;
	ifq->zcrx_ifq.if_rxq = -1;
	
	/* Initialize work */
	INIT_WORK(&ifq->completion_work, io_unified_submission_work);
	ifq->completion_wq = io_unified_wq;
	
	return ifq;
}

static void io_unified_ifq_free(struct io_ring_ctx *ctx, struct io_unified_ifq *ifq)
{
	if (!ifq)
		return;
	
	/* Cancel pending work */
	cancel_work_sync(&ifq->completion_work);
	
	/* NVMe resources are managed by file descriptors and will be 
	 * cleaned up when userspace closes them */
	
	/* Free region */
	io_unified_free_region(ctx, ifq);
	
	kfree(ifq);
}

/* Registration interface */
int io_register_unified_ifq(struct io_ring_ctx *ctx, struct io_unified_reg __user *arg)
{
	struct io_unified_reg reg;
	struct io_uring_region_desc rd;
	struct io_unified_ifq *ifq;
	char *nvme_path;
	struct file *nvme_file;
	int ret;
	
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	
	if (ctx->unified_ifq)
		return -EBUSY;
	
	if (copy_from_user(&reg, arg, sizeof(reg)))
		return -EFAULT;
	
	if (copy_from_user(&rd, u64_to_user_ptr(reg.region_ptr), sizeof(rd)))
		return -EFAULT;
	
	if (reg.flags || !reg.sq_entries || !reg.cq_entries || !reg.buffer_entries)
		return -EINVAL;
	
	/* Validate and round up to power of 2 */
	if (reg.sq_entries > IO_UNIFIED_MAX_ENTRIES ||
	    reg.cq_entries > IO_UNIFIED_MAX_ENTRIES) {
		if (!(ctx->flags & IORING_SETUP_CLAMP))
			return -EINVAL;
		reg.sq_entries = min(reg.sq_entries, (u32)IO_UNIFIED_MAX_ENTRIES);
		reg.cq_entries = min(reg.cq_entries, (u32)IO_UNIFIED_MAX_ENTRIES);
	}
	
	reg.sq_entries = roundup_pow_of_two(reg.sq_entries);
	reg.cq_entries = roundup_pow_of_two(reg.cq_entries);
	
	/* Allocate interface queue */
	ifq = io_unified_ifq_alloc(ctx);
	if (!ifq)
		return -ENOMEM;
	
	/* Allocate unified region */
	ret = io_unified_alloc_region(ctx, ifq, &reg, &rd);
	if (ret)
		goto err_free_ifq;
	
	/* Open NVMe device */
	nvme_path = strndup_user(u64_to_user_ptr(reg.nvme_dev_path), PATH_MAX);
	if (IS_ERR(nvme_path)) {
		ret = PTR_ERR(nvme_path);
		goto err_free_region;
	}
	
	nvme_file = filp_open(nvme_path, O_RDWR, 0);
	kfree(nvme_path);
	
	if (IS_ERR(nvme_file)) {
		ret = PTR_ERR(nvme_file);
		goto err_free_region;
	}
	
	/* Extract NVMe controller and namespace */
	if (nvme_file->f_op && nvme_file->f_op->unlocked_ioctl) {
		/* This is a simplification - in real implementation,
		   we'd need proper nvme device detection */
		pr_info("io_uring: NVMe device opened successfully\n");
	}
	
	filp_close(nvme_file, NULL);
	
	/* Complete registration */
	ctx->unified_ifq = ifq;
	
	if (copy_to_user(arg, &reg, sizeof(reg)) ||
	    copy_to_user(u64_to_user_ptr(reg.region_ptr), &rd, sizeof(rd))) {
		ret = -EFAULT;
		goto err_unregister;
	}
	
	return 0;
	
err_unregister:
	ctx->unified_ifq = NULL;
err_free_region:
	io_unified_free_region(ctx, ifq);
err_free_ifq:
	io_unified_ifq_free(ctx, ifq);
	return ret;
}

void io_unregister_unified_ifq(struct io_ring_ctx *ctx)
{
	struct io_unified_ifq *ifq = ctx->unified_ifq;
	
	lockdep_assert_held(&ctx->uring_lock);
	
	if (!ifq)
		return;
	
	ctx->unified_ifq = NULL;
	io_unified_ifq_free(ctx, ifq);
}

void io_shutdown_unified_ifq(struct io_ring_ctx *ctx)
{
	lockdep_assert_held(&ctx->uring_lock);
	
	if (ctx->unified_ifq) {
		/* Cancel pending work */
		cancel_work_sync(&ctx->unified_ifq->completion_work);
	}
}

/* Module initialization */
static int __init io_unified_init(void)
{
	io_unified_wq = alloc_workqueue("io_unified", WQ_UNBOUND | WQ_HIGHPRI, 0);
	if (!io_unified_wq)
		return -ENOMEM;
	
	pr_info("io_uring: unified NVMe+zcrx interface initialized\n");
	return 0;
}

static void __exit io_unified_exit(void)
{
	if (io_unified_wq) {
		destroy_workqueue(io_unified_wq);
		io_unified_wq = NULL;
	}
}

module_init(io_unified_init);
module_exit(io_unified_exit);