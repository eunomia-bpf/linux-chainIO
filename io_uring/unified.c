// SPDX-License-Identifier: GPL-2.0
/*
 * io_uring unified I/O region support
 *
 * Combines network (ZCRX), storage (NVMe), and BPF operations
 * in a single shared memory region.
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/io_uring.h>
#include <linux/io_uring_types.h>
#include <linux/nvme.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <net/page_pool/helpers.h>
#include <net/page_pool/memory_provider.h>
#include <net/netdev_rx_queue.h>
#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "memmap.h"
#include "kbuf.h"
#include "rsrc.h"
#include "unified.h"

static const struct memory_provider_ops io_unified_pp_ops;

/* Initialize unified region */
static int io_unified_region_init(struct io_ring_ctx *ctx,
				  struct io_unified_region *unified,
				  struct io_uring_unified_region_reg *reg)
{
	size_t total_size = reg->region_size;
	void *ptr;
	int ret;
	int i;
	
	unified->flags = reg->flags;
	unified->sq_entries = roundup_pow_of_two(reg->sq_entries);
	unified->cq_entries = roundup_pow_of_two(reg->cq_entries);
	
	/* Get mapped region pointer */
	ptr = io_region_get_ptr(&ctx->unified_region);
	if (!ptr)
		return -EINVAL;
	
	/* Setup layout */
	unified->sq_descs = (struct io_unified_desc *)(ptr + reg->offsets.sq_off);
	unified->cq_descs = (struct io_unified_desc *)(ptr + reg->offsets.cq_off);
	unified->data_area = ptr + reg->offsets.data_off;
	unified->data_size = total_size - reg->offsets.data_off;
	
	/* Initialize ring indices */
	unified->sq.producer = 0;
	unified->sq.consumer = 0;
	unified->cq.producer = 0;
	unified->cq.consumer = 0;
	
	/* Setup ZCRX-compatible net_iov area */
	unified->nia.num_niovs = unified->data_size >> PAGE_SHIFT;
	unified->niovs = kvmalloc_array(unified->nia.num_niovs,
					sizeof(struct net_iov),
					GFP_KERNEL | __GFP_ZERO);
	if (!unified->niovs)
		return -ENOMEM;
	
	unified->freelist = kvmalloc_array(unified->nia.num_niovs,
					   sizeof(u32), GFP_KERNEL);
	if (!unified->freelist) {
		ret = -ENOMEM;
		goto err_free_niovs;
	}
	
	unified->user_refs = kvmalloc_array(unified->nia.num_niovs,
					    sizeof(atomic_t), GFP_KERNEL);
	if (!unified->user_refs) {
		ret = -ENOMEM;
		goto err_free_freelist;
	}
	
	/* Initialize net IOVs */
	unified->nia.niovs = unified->niovs;
	for (i = 0; i < unified->nia.num_niovs; i++) {
		struct net_iov *niov = &unified->niovs[i];
		niov->owner = &unified->nia;
		unified->freelist[i] = i;
		atomic_set(&unified->user_refs[i], 0);
	}
	unified->free_count = unified->nia.num_niovs;
	spin_lock_init(&unified->freelist_lock);
	
	/* Setup NVMe if requested */
	if (reg->nvme_fd >= 0) {
		unified->nvme_file = fget(reg->nvme_fd);
		if (!unified->nvme_file) {
			ret = -EBADF;
			goto err_free_refs;
		}
		unified->flags |= IO_UNIFIED_F_NVME;
	}
	
	/* Setup network if requested */
	if (reg->net_ifindex > 0) {
		rtnl_lock();
		unified->dev = netdev_get_by_index(current->nsproxy->net_ns,
						   reg->net_ifindex, NULL,
						   GFP_KERNEL);
		if (!unified->dev) {
			rtnl_unlock();
			ret = -ENODEV;
			goto err_put_nvme;
		}
		unified->if_rxq = reg->net_rxq;
		unified->flags |= IO_UNIFIED_F_NETWORK;
		
		/* Register with page pool */
		/* ... would setup page pool here ... */
		
		rtnl_unlock();
	}
	
	/* Initialize statistics */
	atomic64_set(&unified->nvme_ops, 0);
	atomic64_set(&unified->net_packets, 0);
	atomic64_set(&unified->bpf_ops, 0);
	
	return 0;

err_put_nvme:
	if (unified->nvme_file)
		fput(unified->nvme_file);
err_free_refs:
	kvfree(unified->user_refs);
err_free_freelist:
	kvfree(unified->freelist);
err_free_niovs:
	kvfree(unified->niovs);
	return ret;
}

/* Free unified region resources */
static void io_unified_region_free(struct io_unified_region *unified)
{
	if (!unified)
		return;
	
	if (unified->bpf_prog)
		bpf_prog_put(unified->bpf_prog);
	
	if (unified->dev)
		netdev_put(unified->dev, NULL);
	
	if (unified->nvme_file)
		fput(unified->nvme_file);
	
	kvfree(unified->user_refs);
	kvfree(unified->freelist);
	kvfree(unified->niovs);
}

/* Memory provider operations for page pool integration */
static netmem_ref io_unified_alloc_netmems(struct page_pool *pp, gfp_t gfp)
{
	struct io_unified_region *unified = pp->mp_priv;
	struct net_iov *niov;
	u32 pgid;
	
	spin_lock_bh(&unified->freelist_lock);
	if (unified->free_count == 0) {
		spin_unlock_bh(&unified->freelist_lock);
		return 0;
	}
	
	pgid = unified->freelist[--unified->free_count];
	spin_unlock_bh(&unified->freelist_lock);
	
	niov = &unified->niovs[pgid];
	return net_iov_to_netmem(niov);
}

static bool io_unified_release_netmem(struct page_pool *pp, netmem_ref netmem)
{
	struct io_unified_region *unified = pp->mp_priv;
	struct net_iov *niov;
	u32 pgid;
	
	if (!netmem_is_net_iov(netmem))
		return false;
	
	niov = netmem_to_net_iov(netmem);
	pgid = net_iov_idx(niov);
	
	spin_lock_bh(&unified->freelist_lock);
	unified->freelist[unified->free_count++] = pgid;
	spin_unlock_bh(&unified->freelist_lock);
	
	return true;
}

static int io_unified_pp_init(struct page_pool *pp)
{
	pp->p.order = 0;
	pp->p.flags |= PP_FLAG_DMA_MAP;
	return 0;
}

static void io_unified_pp_destroy(struct page_pool *pp)
{
	/* Cleanup if needed */
}

static const struct memory_provider_ops io_unified_pp_ops = {
	.alloc_netmems = io_unified_alloc_netmems,
	.release_netmem = io_unified_release_netmem,
	.init = io_unified_pp_init,
	.destroy = io_unified_pp_destroy,
};

/* Submit unified operation */
int io_unified_submit(struct io_ring_ctx *ctx, struct io_unified_desc *desc)
{
	struct io_unified_region *unified = ctx->unified;
	u32 sq_tail;
	
	if (!unified)
		return -EINVAL;
	
	spin_lock(&ctx->completion_lock);
	sq_tail = unified->sq.producer;
	
	if (((sq_tail + 1) & (unified->sq_entries - 1)) == unified->sq.consumer) {
		spin_unlock(&ctx->completion_lock);
		return -EBUSY;
	}
	
	/* Copy descriptor */
	memcpy(&unified->sq_descs[sq_tail], desc, sizeof(*desc));
	smp_wmb();
	
	unified->sq.producer = (sq_tail + 1) & (unified->sq_entries - 1);
	
	/* Update statistics */
	if (desc->type & IORING_UNIFIED_OP_NVME)
		atomic64_inc(&unified->nvme_ops);
	if (desc->type & IORING_UNIFIED_OP_NETWORK)
		atomic64_inc(&unified->net_packets);
	if (desc->type & IORING_UNIFIED_OP_BPF)
		atomic64_inc(&unified->bpf_ops);
	
	spin_unlock(&ctx->completion_lock);
	
	/* Trigger appropriate subsystem processing */
	/* ... implementation ... */
	
	return 0;
}

/* Process unified completions */
int io_unified_complete(struct io_ring_ctx *ctx, unsigned int nr)
{
	struct io_unified_region *unified = ctx->unified;
	u32 cq_tail;
	int completed = 0;
	
	if (!unified)
		return 0;
	
	spin_lock(&ctx->completion_lock);
	cq_tail = unified->cq.producer;
	
	while (completed < nr && 
	       ((cq_tail + 1) & (unified->cq_entries - 1)) != unified->cq.consumer) {
		/* Process completion */
		/* ... implementation ... */
		
		cq_tail = (cq_tail + 1) & (unified->cq_entries - 1);
		completed++;
	}
	
	unified->cq.producer = cq_tail;
	spin_unlock(&ctx->completion_lock);
	
	return completed;
}

/* Register unified region */
int io_register_unified_region(struct io_ring_ctx *ctx,
			       struct io_uring_unified_region_reg __user *arg)
{
	struct io_uring_unified_region_reg reg;
	struct io_uring_region_desc rd;
	struct io_unified_region *unified;
	int ret;
	
	if (ctx->unified)
		return -EBUSY;
	
	if (copy_from_user(&reg, arg, sizeof(reg)))
		return -EFAULT;
	
	if (copy_from_user(&rd, u64_to_user_ptr(reg.region_ptr), sizeof(rd)))
		return -EFAULT;
	
	/* Validate parameters */
	if (!reg.sq_entries || !reg.cq_entries || !reg.region_size)
		return -EINVAL;
	
	if (reg.region_size < PAGE_SIZE * 4)  /* Minimum size */
		return -EINVAL;
	
	unified = kzalloc(sizeof(*unified), GFP_KERNEL);
	if (!unified)
		return -ENOMEM;
	
	/* Create memory mapped region */
	ret = io_create_region_mmap_safe(ctx, &ctx->unified_region, &rd,
					 IORING_MAP_OFF_UNIFIED_REGION);
	if (ret < 0) {
		kfree(unified);
		return ret;
	}
	
	/* Calculate offsets */
	reg.offsets.sq_off = PAGE_SIZE;  /* After control area */
	reg.offsets.cq_off = reg.offsets.sq_off + 
			     reg.sq_entries * sizeof(struct io_unified_desc);
	reg.offsets.data_off = PAGE_ALIGN(reg.offsets.cq_off + 
					  reg.cq_entries * sizeof(struct io_unified_desc));
	
	/* Initialize unified region */
	ret = io_unified_region_init(ctx, unified, &reg);
	if (ret < 0) {
		io_free_region(ctx, &ctx->unified_region);
		kfree(unified);
		return ret;
	}
	
	/* Copy back offsets */
	if (copy_to_user(arg, &reg, sizeof(reg))) {
		io_unified_region_free(unified);
		io_free_region(ctx, &ctx->unified_region);
		kfree(unified);
		return -EFAULT;
	}
	
	ctx->unified = unified;
	return 0;
}

/* Unregister unified region */
int io_unregister_unified_region(struct io_ring_ctx *ctx)
{
	struct io_unified_region *unified = ctx->unified;
	
	if (!unified)
		return -EINVAL;
	
	ctx->unified = NULL;
	
	io_unified_region_free(unified);
	io_free_region(ctx, &ctx->unified_region);
	kfree(unified);
	
	return 0;
}

/* Attach BPF program to unified region */
int io_unified_attach_bpf(struct io_ring_ctx *ctx, int prog_fd)
{
	struct io_unified_region *unified = ctx->unified;
	struct bpf_prog *prog;
	
	if (!unified)
		return -EINVAL;
	
	prog = bpf_prog_get(prog_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);
	
	spin_lock(&ctx->completion_lock);
	if (unified->bpf_prog)
		bpf_prog_put(unified->bpf_prog);
	unified->bpf_prog = prog;
	unified->bpf_prog_id = prog->aux->id;
	unified->flags |= IO_UNIFIED_F_BPF;
	spin_unlock(&ctx->completion_lock);
	
	return 0;
}

/* Prepare unified operation */
int io_unified_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_ring_ctx *ctx = req->ctx;
	
	if (!ctx->unified)
		return -EINVAL;
	
	if (sqe->flags & ~IOSQE_FIXED_FILE)
		return -EINVAL;
	
	if (sqe->ioprio || sqe->buf_index || sqe->personality)
		return -EINVAL;
	
	/* Store operation parameters in request */
	req->cqe.res = 0;
	req->flags |= REQ_F_FORCE_ASYNC;  /* Process async for now */
	
	return 0;
}

/* Issue unified operation */
int io_unified(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_unified_region *unified = ctx->unified;
	const struct io_uring_sqe *sqe = req->async_data;
	struct io_unified_desc desc;
	u16 op_type;
	int ret;
	
	if (!unified)
		return -EINVAL;
	
	/* Extract operation type from offset field */
	op_type = sqe->off;
	
	/* Build descriptor from SQE */
	desc.addr = sqe->addr;
	desc.len = sqe->len;
	desc.flags = 0;
	desc.type = op_type;
	
	/* Validate operation type */
	if (!(op_type & (IORING_UNIFIED_OP_NVME | 
			 IORING_UNIFIED_OP_NETWORK | 
			 IORING_UNIFIED_OP_BPF)))
		return -EINVAL;
	
	/* Submit to unified region */
	ret = io_unified_submit(ctx, &desc);
	if (ret < 0) {
		req->cqe.res = ret;
		return IOU_ISSUE_SKIP_COMPLETE;
	}
	
	/* For now, complete immediately with success */
	req->cqe.res = desc.len;
	return IOU_OK;
}