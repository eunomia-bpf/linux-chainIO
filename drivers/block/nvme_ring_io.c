// SPDX-License-Identifier: GPL-2.0
/*
 * NVMe Ring I/O - AF_XDP style ring buffer with io_uring fixed buffer integration
 * for NVMe passthrough commands
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
#include <linux/nvme.h>
#include <linux/blkdev.h>
#include <linux/mutex.h>
#include <linux/dma-mapping.h>
#include <linux/hugetlb.h>
#include <linux/vmalloc.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/io_uring_types.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>

#define NVME_RING_IO_NAME "nvme_ring_io"
#define NVME_RING_IO_CLASS "nvme_ring_io_class"

/* Ring descriptor flags */
#define RING_DESC_F_KERNEL	(1 << 0)
#define RING_DESC_F_USER	(1 << 1)

/* Ring buffer structure - AF_XDP style */
struct nvme_ring {
	/* Producer/Consumer indices */
	struct {
		u32 producer ____cacheline_aligned_in_smp;
		u32 consumer ____cacheline_aligned_in_smp;
	} sq, cq;
	
	/* Ring sizes */
	u32 sq_ring_size;
	u32 cq_ring_size;
	
	/* Descriptors */
	u64 *sq_descs;
	u64 *cq_descs;
	
	/* Data buffer area */
	void *data_area;
	size_t data_size;
	
	/* io_uring integration */
	struct io_uring_ctx *uring_ctx;
	struct file *uring_file;
	
	/* NVMe device */
	struct nvme_ctrl *nvme_ctrl;
	struct file *nvme_file;
	int nvme_fd;
	
	/* Memory management */
	struct page **pages;
	int nr_pages;
	dma_addr_t dma_addr;
	
	/* Synchronization */
	struct mutex lock;
	spinlock_t sq_lock;
	spinlock_t cq_lock;
	
	/* Statistics */
	atomic64_t submitted;
	atomic64_t completed;
};

struct nvme_ring_io_dev {
	struct cdev cdev;
	struct class *class;
	struct device *device;
	dev_t devno;
	struct nvme_ring *ring;
};

static struct nvme_ring_io_dev *nvme_ring_io_dev;

/* Helper functions for ring buffer operations */
static inline u32 ring_inc(u32 val, u32 size)
{
	return (val + 1) & (size - 1);
}

static inline bool ring_full(u32 producer, u32 consumer, u32 size)
{
	return ring_inc(producer, size) == consumer;
}

static inline bool ring_empty(u32 producer, u32 consumer)
{
	return producer == consumer;
}

/* Allocate and setup ring buffer memory */
static int nvme_ring_alloc_memory(struct nvme_ring *ring, size_t total_size)
{
	unsigned long addr;
	int ret;
	int i;
	
	/* Allocate memory using huge pages if possible */
	ring->nr_pages = (total_size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	
	/* Try to allocate huge pages first */
	addr = __get_free_pages(GFP_KERNEL | __GFP_COMP | __GFP_NOWARN,
				get_order(total_size));
	if (!addr) {
		/* Fall back to vmalloc */
		addr = (unsigned long)vmalloc_user(total_size);
		if (!addr)
			return -ENOMEM;
	}
	
	/* Setup ring buffer layout */
	ring->sq.producer = 0;
	ring->sq.consumer = 0;
	ring->cq.producer = 0;
	ring->cq.consumer = 0;
	
	/* Layout: [SQ indices][CQ indices][SQ descs][CQ descs][data area] */
	void *base = (void *)addr;
	size_t offset = 0;
	
	/* Skip indices area (already initialized above) */
	offset += PAGE_SIZE;
	
	/* SQ descriptors */
	ring->sq_descs = (u64 *)(base + offset);
	offset += ring->sq_ring_size * sizeof(u64);
	
	/* CQ descriptors */
	ring->cq_descs = (u64 *)(base + offset);
	offset += ring->cq_ring_size * sizeof(u64);
	
	/* Data area */
	ring->data_area = base + offset;
	ring->data_size = total_size - offset;
	
	/* Pin pages for DMA */
	ring->pages = kcalloc(ring->nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!ring->pages) {
		ret = -ENOMEM;
		goto err_free_mem;
	}
	
	for (i = 0; i < ring->nr_pages; i++) {
		ring->pages[i] = virt_to_page(base + i * PAGE_SIZE);
		get_page(ring->pages[i]);
	}
	
	return 0;

err_free_mem:
	if (is_vmalloc_addr((void *)addr))
		vfree((void *)addr);
	else
		free_pages(addr, get_order(total_size));
	return ret;
}

/* Get io_uring context from file descriptor */
static struct io_uring_ctx *nvme_ring_get_uring_ctx(int fd)
{
	struct file *file;
	struct io_uring_ctx *ctx = NULL;
	
	file = fget(fd);
	if (!file)
		return NULL;
	
	/* Check if this is an io_uring file */
	if (file->f_op && file->f_op->poll) {
		/* In real implementation, we would need to properly extract
		 * the io_uring context from the file. This is a simplified version.
		 */
		ctx = file->private_data;
	}
	
	fput(file);
	return ctx;
}

/* Register ring buffer as io_uring fixed buffer */
static int nvme_ring_register_fixed_buffer(struct nvme_ring *ring, void *base, size_t size)
{
	struct io_uring_rsrc_register reg;
	struct io_uring_rsrc_update2 update;
	struct iovec iov;
	int ret;
	
	if (!ring->uring_ctx)
		return -EINVAL;
	
	iov.iov_base = base;
	iov.iov_len = size;
	
	memset(&reg, 0, sizeof(reg));
	reg.nr = 1;
	reg.data = (unsigned long)&iov;
	
	/* In real implementation, we would call the actual io_uring
	 * registration function. This requires proper kernel API access.
	 */
	pr_info("Registering fixed buffer: base=%p, size=%zu\n", base, size);
	
	return 0;
}

/* Submit NVMe passthrough command via io_uring */
static int nvme_ring_submit_passthrough(struct nvme_ring *ring, u64 desc_addr)
{
	struct io_uring_sqe *sqe;
	struct nvme_uring_cmd *cmd;
	struct nvme_command *nvme_cmd;
	void *data_ptr;
	u32 sq_tail;
	unsigned long flags;
	int ret = 0;
	
	/* Get data from descriptor */
	data_ptr = ring->data_area + (desc_addr - (u64)ring->data_area);
	nvme_cmd = (struct nvme_command *)data_ptr;
	
	/* Get io_uring submission queue entry */
	spin_lock_irqsave(&ring->sq_lock, flags);
	sq_tail = ring->sq.producer;
	
	if (ring_full(sq_tail, ring->sq.consumer, ring->sq_ring_size)) {
		spin_unlock_irqrestore(&ring->sq_lock, flags);
		return -EBUSY;
	}
	
	/* In real implementation, we would get the actual SQE from io_uring */
	/* For now, we simulate the submission */
	
	/* Add to our ring */
	ring->sq_descs[sq_tail] = desc_addr;
	smp_wmb();
	ring->sq.producer = ring_inc(sq_tail, ring->sq_ring_size);
	
	/* Update statistics */
	atomic64_inc(&ring->submitted);
	
	spin_unlock_irqrestore(&ring->sq_lock, flags);
	
	/* In real implementation, we would trigger io_uring submission */
	pr_debug("Submitted NVMe command: opcode=0x%x\n", nvme_cmd->common.opcode);
	
	return ret;
}

/* Process completions from io_uring */
static int nvme_ring_process_completions(struct nvme_ring *ring)
{
	u32 cq_tail;
	unsigned long flags;
	int processed = 0;
	
	spin_lock_irqsave(&ring->cq_lock, flags);
	cq_tail = ring->cq.producer;
	
	/* Process each completion */
	while (processed < 16 && !ring_full(cq_tail, ring->cq.consumer, ring->cq_ring_size)) {
		/* In real implementation, we would:
		 * 1. Check io_uring CQ for completions
		 * 2. Map completions back to our descriptors
		 * 3. Update our completion ring
		 */
		
		/* Simulate completion */
		ring->cq_descs[cq_tail] = 0;  /* Placeholder completion data */
		smp_wmb();
		cq_tail = ring_inc(cq_tail, ring->cq_ring_size);
		processed++;
		atomic64_inc(&ring->completed);
	}
	
	ring->cq.producer = cq_tail;
	spin_unlock_irqrestore(&ring->cq_lock, flags);
	
	return processed;
}

/* mmap handler for userspace access */
static int nvme_ring_io_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct nvme_ring *ring = file->private_data;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long addr;
	unsigned long pfn;
	int ret;
	
	if (!ring || !ring->pages)
		return -EINVAL;
	
	/* Check size */
	if (size > ring->nr_pages * PAGE_SIZE)
		return -EINVAL;
	
	/* Map the ring buffer to userspace */
	vma->vm_flags |= VM_SHARED | VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_ops = NULL;
	
	/* Map each page */
	for (addr = vma->vm_start; addr < vma->vm_end; addr += PAGE_SIZE) {
		unsigned long offset = addr - vma->vm_start;
		unsigned long page_idx = offset >> PAGE_SHIFT;
		
		if (page_idx >= ring->nr_pages)
			return -EINVAL;
		
		pfn = page_to_pfn(ring->pages[page_idx]);
		ret = remap_pfn_range(vma, addr, pfn, PAGE_SIZE, vma->vm_page_prot);
		if (ret)
			return ret;
	}
	
	return 0;
}

/* ioctl handlers */
#define NVME_RING_IO_SETUP	_IOW('N', 0x80, struct nvme_ring_setup)
#define NVME_RING_IO_SUBMIT	_IOW('N', 0x81, struct nvme_ring_submit)
#define NVME_RING_IO_COMPLETE	_IOR('N', 0x82, struct nvme_ring_complete)
#define NVME_RING_IO_GET_INFO	_IOR('N', 0x83, struct nvme_ring_info)

struct nvme_ring_setup {
	u32 sq_entries;
	u32 cq_entries;
	u32 data_size;
	int nvme_fd;
	int uring_fd;
	u32 flags;
	u32 reserved[4];
};

struct nvme_ring_submit {
	u64 desc_addr;
	u32 count;
	u32 flags;
};

struct nvme_ring_complete {
	u32 count;
	u32 flags;
};

struct nvme_ring_info {
	u32 sq_entries;
	u32 cq_entries;
	u64 sq_head;
	u64 sq_tail;
	u64 cq_head;
	u64 cq_tail;
	u64 submitted;
	u64 completed;
};

static long nvme_ring_io_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct nvme_ring *ring = file->private_data;
	int ret = 0;
	
	if (!ring)
		return -EINVAL;
	
	switch (cmd) {
	case NVME_RING_IO_SETUP: {
		struct nvme_ring_setup setup;
		size_t total_size;
		
		if (copy_from_user(&setup, (void __user *)arg, sizeof(setup)))
			return -EFAULT;
		
		mutex_lock(&ring->lock);
		
		/* Check if already initialized */
		if (ring->data_area) {
			mutex_unlock(&ring->lock);
			return -EBUSY;
		}
		
		/* Setup ring sizes (must be power of 2) */
		ring->sq_ring_size = roundup_pow_of_two(setup.sq_entries);
		ring->cq_ring_size = roundup_pow_of_two(setup.cq_entries);
		
		/* Calculate total memory needed */
		total_size = PAGE_SIZE +  /* Indices */
			     ring->sq_ring_size * sizeof(u64) +  /* SQ descs */
			     ring->cq_ring_size * sizeof(u64) +  /* CQ descs */
			     setup.data_size;  /* Data area */
		
		/* Allocate ring buffer memory */
		ret = nvme_ring_alloc_memory(ring, total_size);
		if (ret < 0) {
			mutex_unlock(&ring->lock);
			return ret;
		}
		
		/* Get NVMe file descriptor */
		ring->nvme_fd = setup.nvme_fd;
		ring->nvme_file = fget(setup.nvme_fd);
		if (!ring->nvme_file) {
			/* Cleanup on error */
			if (ring->pages) {
				int i;
				for (i = 0; i < ring->nr_pages; i++) {
					if (ring->pages[i])
						put_page(ring->pages[i]);
				}
				kfree(ring->pages);
				ring->pages = NULL;
			}
			mutex_unlock(&ring->lock);
			return -EBADF;
		}
		
		/* Get io_uring context */
		ring->uring_ctx = nvme_ring_get_uring_ctx(setup.uring_fd);
		if (!ring->uring_ctx) {
			fput(ring->nvme_file);
			ring->nvme_file = NULL;
			/* Cleanup on error */
			if (ring->pages) {
				int i;
				for (i = 0; i < ring->nr_pages; i++) {
					if (ring->pages[i])
						put_page(ring->pages[i]);
				}
				kfree(ring->pages);
				ring->pages = NULL;
			}
			mutex_unlock(&ring->lock);
			return -EBADF;
		}
		
		/* Register as fixed buffer */
		ret = nvme_ring_register_fixed_buffer(ring, ring->data_area, ring->data_size);
		if (ret < 0) {
			fput(ring->nvme_file);
			ring->nvme_file = NULL;
			ring->uring_ctx = NULL;
			/* Cleanup on error */
			if (ring->pages) {
				int i;
				for (i = 0; i < ring->nr_pages; i++) {
					if (ring->pages[i])
						put_page(ring->pages[i]);
				}
				kfree(ring->pages);
				ring->pages = NULL;
			}
			mutex_unlock(&ring->lock);
			return ret;
		}
		
		mutex_unlock(&ring->lock);
		break;
	}
	
	case NVME_RING_IO_SUBMIT: {
		struct nvme_ring_submit submit;
		u32 i;
		
		if (copy_from_user(&submit, (void __user *)arg, sizeof(submit)))
			return -EFAULT;
		
		/* Submit passthrough commands */
		for (i = 0; i < submit.count; i++) {
			ret = nvme_ring_submit_passthrough(ring, submit.desc_addr + i * 64);
			if (ret < 0)
				break;
		}
		break;
	}
	
	case NVME_RING_IO_COMPLETE: {
		struct nvme_ring_complete complete;
		
		complete.count = nvme_ring_process_completions(ring);
		complete.flags = 0;
		
		if (copy_to_user((void __user *)arg, &complete, sizeof(complete)))
			return -EFAULT;
		break;
	}
	
	case NVME_RING_IO_GET_INFO: {
		struct nvme_ring_info info;
		
		mutex_lock(&ring->lock);
		info.sq_entries = ring->sq_ring_size;
		info.cq_entries = ring->cq_ring_size;
		info.sq_head = ring->sq.consumer;
		info.sq_tail = ring->sq.producer;
		info.cq_head = ring->cq.consumer;
		info.cq_tail = ring->cq.producer;
		info.submitted = atomic64_read(&ring->submitted);
		info.completed = atomic64_read(&ring->completed);
		mutex_unlock(&ring->lock);
		
		if (copy_to_user((void __user *)arg, &info, sizeof(info)))
			return -EFAULT;
		break;
	}
	
	default:
		return -EINVAL;
	}
	
	return ret;
}

static int nvme_ring_io_open(struct inode *inode, struct file *file)
{
	struct nvme_ring *ring;
	
	ring = kzalloc(sizeof(*ring), GFP_KERNEL);
	if (!ring)
		return -ENOMEM;
	
	mutex_init(&ring->lock);
	spin_lock_init(&ring->sq_lock);
	spin_lock_init(&ring->cq_lock);
	atomic64_set(&ring->submitted, 0);
	atomic64_set(&ring->completed, 0);
	
	file->private_data = ring;
	
	pr_debug("NVMe Ring I/O device opened\n");
	return 0;
}

static int nvme_ring_io_release(struct inode *inode, struct file *file)
{
	struct nvme_ring *ring = file->private_data;
	int i;
	
	if (!ring)
		return 0;
	
	mutex_lock(&ring->lock);
	
	/* Cleanup */
	if (ring->nvme_file)
		fput(ring->nvme_file);
	if (ring->uring_file)
		fput(ring->uring_file);
	
	/* Free pages */
	if (ring->pages) {
		for (i = 0; i < ring->nr_pages; i++) {
			if (ring->pages[i])
				put_page(ring->pages[i]);
		}
		kfree(ring->pages);
	}
	
	/* Free memory */
	if (ring->data_area) {
		if (is_vmalloc_addr(ring->data_area))
			vfree(ring->data_area);
		else
			free_pages((unsigned long)ring->data_area, 
				   get_order(ring->nr_pages * PAGE_SIZE));
	}
	
	mutex_unlock(&ring->lock);
	kfree(ring);
	
	pr_debug("NVMe Ring I/O device closed\n");
	return 0;
}

static const struct file_operations nvme_ring_io_fops = {
	.owner = THIS_MODULE,
	.open = nvme_ring_io_open,
	.release = nvme_ring_io_release,
	.unlocked_ioctl = nvme_ring_io_ioctl,
	.compat_ioctl = nvme_ring_io_ioctl,
	.mmap = nvme_ring_io_mmap,
};

static int __init nvme_ring_io_init(void)
{
	int ret;
	
	nvme_ring_io_dev = kzalloc(sizeof(*nvme_ring_io_dev), GFP_KERNEL);
	if (!nvme_ring_io_dev)
		return -ENOMEM;
	
	/* Allocate device number */
	ret = alloc_chrdev_region(&nvme_ring_io_dev->devno, 0, 1, NVME_RING_IO_NAME);
	if (ret < 0)
		goto err_free_dev;
	
	/* Initialize character device */
	cdev_init(&nvme_ring_io_dev->cdev, &nvme_ring_io_fops);
	nvme_ring_io_dev->cdev.owner = THIS_MODULE;
	
	ret = cdev_add(&nvme_ring_io_dev->cdev, nvme_ring_io_dev->devno, 1);
	if (ret < 0)
		goto err_unregister;
	
	/* Create device class */
	nvme_ring_io_dev->class = class_create(NVME_RING_IO_CLASS);
	if (IS_ERR(nvme_ring_io_dev->class)) {
		ret = PTR_ERR(nvme_ring_io_dev->class);
		goto err_cdev_del;
	}
	
	/* Create device */
	nvme_ring_io_dev->device = device_create(nvme_ring_io_dev->class, NULL,
						  nvme_ring_io_dev->devno, NULL,
						  NVME_RING_IO_NAME);
	if (IS_ERR(nvme_ring_io_dev->device)) {
		ret = PTR_ERR(nvme_ring_io_dev->device);
		goto err_class_destroy;
	}
	
	pr_info("NVMe Ring I/O module loaded\n");
	return 0;

err_class_destroy:
	class_destroy(nvme_ring_io_dev->class);
err_cdev_del:
	cdev_del(&nvme_ring_io_dev->cdev);
err_unregister:
	unregister_chrdev_region(nvme_ring_io_dev->devno, 1);
err_free_dev:
	kfree(nvme_ring_io_dev);
	return ret;
}

static void __exit nvme_ring_io_exit(void)
{
	device_destroy(nvme_ring_io_dev->class, nvme_ring_io_dev->devno);
	class_destroy(nvme_ring_io_dev->class);
	cdev_del(&nvme_ring_io_dev->cdev);
	unregister_chrdev_region(nvme_ring_io_dev->devno, 1);
	kfree(nvme_ring_io_dev);
	
	pr_info("NVMe Ring I/O module unloaded\n");
}

module_init(nvme_ring_io_init);
module_exit(nvme_ring_io_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("NVMe Ring I/O - AF_XDP style ring with io_uring integration");
MODULE_AUTHOR("Linux Kernel Developer");