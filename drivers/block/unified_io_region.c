// SPDX-License-Identifier: GPL-2.0
/*
 * Unified I/O Region - Integrating NVMe, ZCRX, and BPF
 * 
 * This module provides a unified memory region that can be operated by:
 * - Network stack (via ZCRX)
 * - File system (via NVMe passthrough)
 * - BPF programs
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/io_uring.h>
#include <linux/io_uring_types.h>
#include <linux/nvme.h>
#include <linux/blkdev.h>
#include <linux/mutex.h>
#include <linux/dma-mapping.h>
#include <linux/hugetlb.h>
#include <linux/vmalloc.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <net/page_pool/types.h>
#include <net/page_pool/helpers.h>
#include <net/busy_poll.h>
#include <net/netdev_rx_queue.h>

#define UNIFIED_IO_NAME "unified_io_region"
#define UNIFIED_IO_CLASS "unified_io_region_class"

/* Unified region flags */
#define UNIFIED_REGION_F_NVME		(1 << 0)
#define UNIFIED_REGION_F_NETWORK	(1 << 1)
#define UNIFIED_REGION_F_BPF		(1 << 2)

/* Memory layout:
 * +-----------------------+ 0x0000
 * | Control Area          |
 * |   - SQ/CQ indices     |
 * |   - Region metadata   |
 * +-----------------------+ 0x1000 (4KB)
 * | Descriptor Area       |
 * |   - SQ descriptors    |
 * |   - CQ descriptors    |
 * |   - Net IOV area      |
 * +-----------------------+
 * | Data Area             |
 * |   - Shared buffers    |
 * |   - Can be used by:   |
 * |     * NVMe commands   |
 * |     * Network packets |
 * |     * BPF operations  |
 * +-----------------------+
 */

struct unified_control {
	/* Ring indices */
	struct {
		u32 producer ____cacheline_aligned_in_smp;
		u32 consumer ____cacheline_aligned_in_smp;
	} sq, cq;
	
	/* Network queue indices */
	struct {
		u32 producer ____cacheline_aligned_in_smp;
		u32 consumer ____cacheline_aligned_in_smp;
	} net_rx, net_tx;
	
	/* Statistics */
	atomic64_t nvme_ops;
	atomic64_t net_packets;
	atomic64_t bpf_ops;
	
	/* Flags and configuration */
	u32 flags;
	u32 region_size;
	u32 data_offset;
	u32 data_size;
};

struct unified_descriptor {
	u64 addr;		/* Address in data area */
	u32 len;		/* Length of data */
	u16 flags;		/* Operation flags */
	u16 type;		/* Operation type */
	union {
		/* NVMe specific */
		struct {
			u16 opcode;
			u16 nsid;
		} nvme;
		/* Network specific */
		struct {
			u16 proto;
			u16 port;
		} net;
		/* BPF specific */
		struct {
			u32 prog_id;
		} bpf;
	};
};

/* Unified I/O region structure */
struct unified_io_region {
	/* Memory management */
	struct io_mapped_region mapped_region;
	void *region_base;
	size_t region_size;
	
	/* Control area */
	struct unified_control *control;
	
	/* Descriptors */
	struct unified_descriptor *sq_descs;
	struct unified_descriptor *cq_descs;
	u32 sq_ring_size;
	u32 cq_ring_size;
	
	/* Data area */
	void *data_area;
	size_t data_size;
	
	/* ZCRX integration */
	struct net_iov_area nia;
	struct net_iov *niovs;
	u32 *freelist;
	atomic_t *user_refs;
	u32 free_count;
	spinlock_t freelist_lock;
	
	/* NVMe integration */
	struct file *nvme_file;
	int nvme_fd;
	
	/* Network integration */
	struct net_device *dev;
	struct netdev_tracker netdev_tracker;
	struct page_pool *pp;
	int if_rxq;
	
	/* io_uring integration */
	struct io_ring_ctx *uring_ctx;
	struct file *uring_file;
	
	/* BPF integration */
	struct bpf_prog *bpf_prog;
	u32 bpf_prog_id;
	
	/* Reference counting and lifecycle */
	struct kref kref;
	struct mutex lock;
	spinlock_t sq_lock;
	spinlock_t cq_lock;
	
	/* Statistics */
	atomic64_t submitted;
	atomic64_t completed;
};

/* BPF context for unified region operations */
struct unified_bpf_ctx {
	struct unified_io_region *region;
	struct unified_descriptor *desc;
	void *data;
	u32 data_len;
};

/* Memory provider operations for page pool (ZCRX style) */
static netmem_ref unified_pp_alloc_netmems(struct page_pool *pp, gfp_t gfp)
{
	struct unified_io_region *region = pp->mp_priv;
	struct net_iov *niov;
	u32 pgid;
	
	spin_lock_bh(&region->freelist_lock);
	if (region->free_count == 0) {
		spin_unlock_bh(&region->freelist_lock);
		return 0;
	}
	
	pgid = region->freelist[--region->free_count];
	spin_unlock_bh(&region->freelist_lock);
	
	niov = &region->niovs[pgid];
	return net_iov_to_netmem(niov);
}

static bool unified_pp_release_netmem(struct page_pool *pp, netmem_ref netmem)
{
	struct unified_io_region *region = pp->mp_priv;
	struct net_iov *niov;
	u32 pgid;
	
	if (!netmem_is_net_iov(netmem))
		return false;
	
	niov = netmem_to_net_iov(netmem);
	pgid = net_iov_idx(niov);
	
	spin_lock_bh(&region->freelist_lock);
	region->freelist[region->free_count++] = pgid;
	spin_unlock_bh(&region->freelist_lock);
	
	return true;
}

static int unified_pp_init(struct page_pool *pp)
{
	struct unified_io_region *region = pp->mp_priv;
	
	/* Initialize page pool integration */
	pp->p.order = 0;
	pp->p.flags |= PP_FLAG_DMA_MAP;
	
	return 0;
}

static void unified_pp_destroy(struct page_pool *pp)
{
	/* Cleanup if needed */
}

static const struct memory_provider_ops unified_pp_ops = {
	.alloc_netmems = unified_pp_alloc_netmems,
	.release_netmem = unified_pp_release_netmem,
	.init = unified_pp_init,
	.destroy = unified_pp_destroy,
};

/* Helper functions */
static inline u32 ring_inc(u32 val, u32 size)
{
	return (val + 1) & (size - 1);
}

static inline bool ring_full(u32 producer, u32 consumer, u32 size)
{
	return ring_inc(producer, size) == consumer;
}

/* Allocate unified region memory */
static int unified_region_alloc(struct unified_io_region *region, size_t size)
{
	unsigned long addr;
	int ret, i;
	void *base;
	size_t offset = 0;
	
	/* Try to allocate huge pages */
	addr = __get_free_pages(GFP_KERNEL | __GFP_COMP | __GFP_NOWARN,
				get_order(size));
	if (!addr) {
		addr = (unsigned long)vmalloc_user(size);
		if (!addr)
			return -ENOMEM;
	}
	
	base = (void *)addr;
	region->region_base = base;
	region->region_size = size;
	
	/* Setup control area */
	region->control = (struct unified_control *)base;
	memset(region->control, 0, sizeof(*region->control));
	offset += PAGE_SIZE;
	
	/* Setup descriptors */
	region->sq_descs = (struct unified_descriptor *)(base + offset);
	offset += region->sq_ring_size * sizeof(struct unified_descriptor);
	
	region->cq_descs = (struct unified_descriptor *)(base + offset);
	offset += region->cq_ring_size * sizeof(struct unified_descriptor);
	
	/* Setup net IOV area */
	region->nia.num_niovs = (size - offset) >> PAGE_SHIFT;
	region->niovs = (struct net_iov *)(base + offset);
	offset += region->nia.num_niovs * sizeof(struct net_iov);
	
	region->freelist = (u32 *)(base + offset);
	offset += region->nia.num_niovs * sizeof(u32);
	
	region->user_refs = (atomic_t *)(base + offset);
	offset += region->nia.num_niovs * sizeof(atomic_t);
	
	/* Data area */
	offset = ALIGN(offset, PAGE_SIZE);
	region->data_area = base + offset;
	region->data_size = size - offset;
	region->control->data_offset = offset;
	region->control->data_size = region->data_size;
	
	/* Initialize net IOVs */
	region->nia.niovs = region->niovs;
	for (i = 0; i < region->nia.num_niovs; i++) {
		struct net_iov *niov = &region->niovs[i];
		niov->owner = &region->nia;
		region->freelist[i] = i;
		atomic_set(&region->user_refs[i], 0);
	}
	region->free_count = region->nia.num_niovs;
	
	/* Setup io_mapped_region */
	region->mapped_region.ptr = base;
	region->mapped_region.nr_pages = size >> PAGE_SHIFT;
	region->mapped_region.pages = kcalloc(region->mapped_region.nr_pages,
					      sizeof(struct page *), GFP_KERNEL);
	if (!region->mapped_region.pages) {
		ret = -ENOMEM;
		goto err_free_mem;
	}
	
	/* Pin pages */
	for (i = 0; i < region->mapped_region.nr_pages; i++) {
		region->mapped_region.pages[i] = virt_to_page(base + i * PAGE_SIZE);
		get_page(region->mapped_region.pages[i]);
	}
	
	return 0;

err_free_mem:
	if (is_vmalloc_addr(base))
		vfree(base);
	else
		free_pages((unsigned long)base, get_order(size));
	return ret;
}

/* Submit operation through unified region */
static int unified_submit_operation(struct unified_io_region *region,
				   struct unified_descriptor *desc)
{
	u32 sq_tail;
	unsigned long flags;
	
	spin_lock_irqsave(&region->sq_lock, flags);
	sq_tail = region->control->sq.producer;
	
	if (ring_full(sq_tail, region->control->sq.consumer, region->sq_ring_size)) {
		spin_unlock_irqrestore(&region->sq_lock, flags);
		return -EBUSY;
	}
	
	/* Copy descriptor */
	memcpy(&region->sq_descs[sq_tail], desc, sizeof(*desc));
	smp_wmb();
	
	region->control->sq.producer = ring_inc(sq_tail, region->sq_ring_size);
	atomic64_inc(&region->submitted);
	
	/* Update statistics based on type */
	if (desc->type & UNIFIED_REGION_F_NVME)
		atomic64_inc(&region->control->nvme_ops);
	if (desc->type & UNIFIED_REGION_F_NETWORK)
		atomic64_inc(&region->control->net_packets);
	if (desc->type & UNIFIED_REGION_F_BPF)
		atomic64_inc(&region->control->bpf_ops);
	
	spin_unlock_irqrestore(&region->sq_lock, flags);
	
	/* Trigger appropriate subsystem */
	if (desc->type & UNIFIED_REGION_F_NVME) {
		/* Submit to NVMe via io_uring */
		/* ... implementation ... */
	}
	if (desc->type & UNIFIED_REGION_F_NETWORK) {
		/* Process network operation */
		/* ... implementation ... */
	}
	if (desc->type & UNIFIED_REGION_F_BPF && region->bpf_prog) {
		/* Run BPF program */
		struct unified_bpf_ctx ctx = {
			.region = region,
			.desc = desc,
			.data = region->data_area + desc->addr,
			.data_len = desc->len,
		};
		bpf_prog_run(region->bpf_prog, &ctx);
	}
	
	return 0;
}

/* Process completions */
static int unified_process_completions(struct unified_io_region *region)
{
	u32 cq_tail;
	unsigned long flags;
	int processed = 0;
	
	spin_lock_irqsave(&region->cq_lock, flags);
	cq_tail = region->control->cq.producer;
	
	/* Process up to 16 completions in batch */
	while (processed < 16 && 
	       !ring_full(cq_tail, region->control->cq.consumer, region->cq_ring_size)) {
		/* Process completion based on source */
		/* ... implementation ... */
		
		cq_tail = ring_inc(cq_tail, region->cq_ring_size);
		processed++;
		atomic64_inc(&region->completed);
	}
	
	region->control->cq.producer = cq_tail;
	spin_unlock_irqrestore(&region->cq_lock, flags);
	
	return processed;
}

/* mmap handler */
static int unified_io_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct unified_io_region *region = file->private_data;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long pfn;
	int ret, i;
	
	if (!region || !region->mapped_region.pages)
		return -EINVAL;
	
	if (size > region->region_size)
		return -EINVAL;
	
	vma->vm_flags |= VM_SHARED | VM_DONTEXPAND | VM_DONTDUMP;
	
	/* Map each page */
	for (i = 0; i < (size >> PAGE_SHIFT); i++) {
		pfn = page_to_pfn(region->mapped_region.pages[i]);
		ret = remap_pfn_range(vma, vma->vm_start + (i << PAGE_SHIFT),
				     pfn, PAGE_SIZE, vma->vm_page_prot);
		if (ret)
			return ret;
	}
	
	return 0;
}

/* ioctl definitions */
#define UNIFIED_IO_SETUP	_IOW('U', 0x80, struct unified_io_setup)
#define UNIFIED_IO_SUBMIT	_IOW('U', 0x81, struct unified_io_submit)
#define UNIFIED_IO_COMPLETE	_IOR('U', 0x82, struct unified_io_complete)
#define UNIFIED_IO_ATTACH_BPF	_IOW('U', 0x83, struct unified_io_bpf)
#define UNIFIED_IO_GET_INFO	_IOR('U', 0x84, struct unified_io_info)

struct unified_io_setup {
	u32 sq_entries;
	u32 cq_entries;
	u32 region_size;
	int nvme_fd;
	int uring_fd;
	int net_ifindex;
	int net_rxq;
	u32 flags;
};

struct unified_io_submit {
	struct unified_descriptor desc;
};

struct unified_io_complete {
	u32 count;
	u32 flags;
};

struct unified_io_bpf {
	u32 prog_fd;
	u32 flags;
};

struct unified_io_info {
	u64 nvme_ops;
	u64 net_packets;
	u64 bpf_ops;
	u64 submitted;
	u64 completed;
	u32 sq_head;
	u32 sq_tail;
	u32 cq_head;
	u32 cq_tail;
};

static long unified_io_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct unified_io_region *region = file->private_data;
	int ret = 0;
	
	if (!region)
		return -EINVAL;
	
	switch (cmd) {
	case UNIFIED_IO_SETUP: {
		struct unified_io_setup setup;
		
		if (copy_from_user(&setup, (void __user *)arg, sizeof(setup)))
			return -EFAULT;
		
		mutex_lock(&region->lock);
		
		if (region->region_base) {
			mutex_unlock(&region->lock);
			return -EBUSY;
		}
		
		/* Setup ring sizes */
		region->sq_ring_size = roundup_pow_of_two(setup.sq_entries);
		region->cq_ring_size = roundup_pow_of_two(setup.cq_entries);
		
		/* Allocate unified region */
		ret = unified_region_alloc(region, setup.region_size);
		if (ret < 0) {
			mutex_unlock(&region->lock);
			return ret;
		}
		
		/* Setup NVMe if requested */
		if (setup.nvme_fd >= 0) {
			region->nvme_fd = setup.nvme_fd;
			region->nvme_file = fget(setup.nvme_fd);
			if (!region->nvme_file) {
				ret = -EBADF;
				goto err_unlock;
			}
			region->control->flags |= UNIFIED_REGION_F_NVME;
		}
		
		/* Setup network if requested */
		if (setup.net_ifindex > 0) {
			rtnl_lock();
			region->dev = netdev_get_by_index(current->nsproxy->net_ns,
							  setup.net_ifindex,
							  &region->netdev_tracker,
							  GFP_KERNEL);
			if (!region->dev) {
				rtnl_unlock();
				ret = -ENODEV;
				goto err_unlock;
			}
			region->if_rxq = setup.net_rxq;
			region->control->flags |= UNIFIED_REGION_F_NETWORK;
			
			/* Setup page pool with our memory provider */
			/* ... implementation ... */
			
			rtnl_unlock();
		}
		
		/* Setup io_uring context if provided */
		if (setup.uring_fd >= 0) {
			region->uring_file = fget(setup.uring_fd);
			if (!region->uring_file) {
				ret = -EBADF;
				goto err_unlock;
			}
			/* Extract io_uring context */
			/* ... implementation ... */
		}
		
		mutex_unlock(&region->lock);
		break;

err_unlock:
		mutex_unlock(&region->lock);
		return ret;
	}
	
	case UNIFIED_IO_SUBMIT: {
		struct unified_io_submit submit;
		
		if (copy_from_user(&submit, (void __user *)arg, sizeof(submit)))
			return -EFAULT;
		
		ret = unified_submit_operation(region, &submit.desc);
		break;
	}
	
	case UNIFIED_IO_COMPLETE: {
		struct unified_io_complete complete;
		
		complete.count = unified_process_completions(region);
		complete.flags = 0;
		
		if (copy_to_user((void __user *)arg, &complete, sizeof(complete)))
			return -EFAULT;
		break;
	}
	
	case UNIFIED_IO_ATTACH_BPF: {
		struct unified_io_bpf bpf_cfg;
		struct bpf_prog *prog;
		
		if (copy_from_user(&bpf_cfg, (void __user *)arg, sizeof(bpf_cfg)))
			return -EFAULT;
		
		prog = bpf_prog_get(bpf_cfg.prog_fd);
		if (IS_ERR(prog))
			return PTR_ERR(prog);
		
		mutex_lock(&region->lock);
		if (region->bpf_prog)
			bpf_prog_put(region->bpf_prog);
		region->bpf_prog = prog;
		region->bpf_prog_id = prog->aux->id;
		region->control->flags |= UNIFIED_REGION_F_BPF;
		mutex_unlock(&region->lock);
		break;
	}
	
	case UNIFIED_IO_GET_INFO: {
		struct unified_io_info info;
		
		mutex_lock(&region->lock);
		info.nvme_ops = atomic64_read(&region->control->nvme_ops);
		info.net_packets = atomic64_read(&region->control->net_packets);
		info.bpf_ops = atomic64_read(&region->control->bpf_ops);
		info.submitted = atomic64_read(&region->submitted);
		info.completed = atomic64_read(&region->completed);
		info.sq_head = region->control->sq.consumer;
		info.sq_tail = region->control->sq.producer;
		info.cq_head = region->control->cq.consumer;
		info.cq_tail = region->control->cq.producer;
		mutex_unlock(&region->lock);
		
		if (copy_to_user((void __user *)arg, &info, sizeof(info)))
			return -EFAULT;
		break;
	}
	
	default:
		return -EINVAL;
	}
	
	return ret;
}

static int unified_io_open(struct inode *inode, struct file *file)
{
	struct unified_io_region *region;
	
	region = kzalloc(sizeof(*region), GFP_KERNEL);
	if (!region)
		return -ENOMEM;
	
	kref_init(&region->kref);
	mutex_init(&region->lock);
	spin_lock_init(&region->sq_lock);
	spin_lock_init(&region->cq_lock);
	spin_lock_init(&region->freelist_lock);
	atomic64_set(&region->submitted, 0);
	atomic64_set(&region->completed, 0);
	region->if_rxq = -1;
	
	file->private_data = region;
	return 0;
}

static void unified_region_release(struct kref *kref)
{
	struct unified_io_region *region = container_of(kref, 
							struct unified_io_region, kref);
	int i;
	
	/* Cleanup BPF */
	if (region->bpf_prog)
		bpf_prog_put(region->bpf_prog);
	
	/* Cleanup network */
	if (region->dev)
		netdev_put(region->dev, &region->netdev_tracker);
	
	/* Cleanup files */
	if (region->nvme_file)
		fput(region->nvme_file);
	if (region->uring_file)
		fput(region->uring_file);
	
	/* Free pages */
	if (region->mapped_region.pages) {
		for (i = 0; i < region->mapped_region.nr_pages; i++) {
			if (region->mapped_region.pages[i])
				put_page(region->mapped_region.pages[i]);
		}
		kfree(region->mapped_region.pages);
	}
	
	/* Free memory */
	if (region->region_base) {
		if (is_vmalloc_addr(region->region_base))
			vfree(region->region_base);
		else
			free_pages((unsigned long)region->region_base,
				   get_order(region->region_size));
	}
	
	kfree(region);
}

static int unified_io_release(struct inode *inode, struct file *file)
{
	struct unified_io_region *region = file->private_data;
	
	if (region)
		kref_put(&region->kref, unified_region_release);
	
	return 0;
}

static const struct file_operations unified_io_fops = {
	.owner = THIS_MODULE,
	.open = unified_io_open,
	.release = unified_io_release,
	.unlocked_ioctl = unified_io_ioctl,
	.compat_ioctl = unified_io_ioctl,
	.mmap = unified_io_mmap,
};

/* Module infrastructure */
struct unified_io_dev {
	struct cdev cdev;
	struct class *class;
	struct device *device;
	dev_t devno;
};

static struct unified_io_dev *unified_io_dev;

static int __init unified_io_init(void)
{
	int ret;
	
	unified_io_dev = kzalloc(sizeof(*unified_io_dev), GFP_KERNEL);
	if (!unified_io_dev)
		return -ENOMEM;
	
	ret = alloc_chrdev_region(&unified_io_dev->devno, 0, 1, UNIFIED_IO_NAME);
	if (ret < 0)
		goto err_free_dev;
	
	cdev_init(&unified_io_dev->cdev, &unified_io_fops);
	unified_io_dev->cdev.owner = THIS_MODULE;
	
	ret = cdev_add(&unified_io_dev->cdev, unified_io_dev->devno, 1);
	if (ret < 0)
		goto err_unregister;
	
	unified_io_dev->class = class_create(UNIFIED_IO_CLASS);
	if (IS_ERR(unified_io_dev->class)) {
		ret = PTR_ERR(unified_io_dev->class);
		goto err_cdev_del;
	}
	
	unified_io_dev->device = device_create(unified_io_dev->class, NULL,
					       unified_io_dev->devno, NULL,
					       UNIFIED_IO_NAME);
	if (IS_ERR(unified_io_dev->device)) {
		ret = PTR_ERR(unified_io_dev->device);
		goto err_class_destroy;
	}
	
	pr_info("Unified I/O Region module loaded\n");
	return 0;

err_class_destroy:
	class_destroy(unified_io_dev->class);
err_cdev_del:
	cdev_del(&unified_io_dev->cdev);
err_unregister:
	unregister_chrdev_region(unified_io_dev->devno, 1);
err_free_dev:
	kfree(unified_io_dev);
	return ret;
}

static void __exit unified_io_exit(void)
{
	device_destroy(unified_io_dev->class, unified_io_dev->devno);
	class_destroy(unified_io_dev->class);
	cdev_del(&unified_io_dev->cdev);
	unregister_chrdev_region(unified_io_dev->devno, 1);
	kfree(unified_io_dev);
	
	pr_info("Unified I/O Region module unloaded\n");
}

module_init(unified_io_init);
module_exit(unified_io_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Unified I/O Region - NVMe, ZCRX, and BPF Integration");
MODULE_AUTHOR("Linux Kernel Developer");