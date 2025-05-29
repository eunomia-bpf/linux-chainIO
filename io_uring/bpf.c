// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/filter.h>

#include "bpf.h"
#include "io_uring.h"

static inline struct io_bpf_ctx *io_user_to_bpf_ctx(struct io_uring_bpf_ctx *ctx)
{
	struct io_bpf_ctx_kern *bc = (struct io_bpf_ctx_kern *)ctx;

	return container_of(bc, struct io_bpf_ctx, kern);
}

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_io_uring_queue_sqe(struct io_uring_bpf_ctx *user_ctx,
					void *bpf_sqe, int mem__sz)
{
	struct io_bpf_ctx *bc = io_user_to_bpf_ctx(user_ctx);
	struct io_ring_ctx *ctx = bc->ctx;
	unsigned tail = ctx->rings->sq.tail;
	struct io_uring_sqe *sqe;

	if (mem__sz != sizeof(*sqe))
		return -EINVAL;

	ctx->rings->sq.tail++;
	tail &= (ctx->sq_entries - 1);
	/* double index for 128-byte SQEs, twice as long */
	if (ctx->flags & IORING_SETUP_SQE128)
		tail <<= 1;
	sqe = &ctx->sq_sqes[tail];
	memcpy(sqe, bpf_sqe, sizeof(*sqe));
	return 0;
}

__bpf_kfunc int bpf_io_uring_submit_sqes(struct io_uring_bpf_ctx *user_ctx,
					 unsigned nr)
{
	struct io_bpf_ctx *bc = io_user_to_bpf_ctx(user_ctx);
	struct io_ring_ctx *ctx = bc->ctx;

	return io_submit_sqes(ctx, nr);
}

__bpf_kfunc int bpf_io_uring_get_cqe(struct io_uring_bpf_ctx *user_ctx,
				     struct io_uring_cqe *res__uninit)
{
	struct io_bpf_ctx *bc = io_user_to_bpf_ctx(user_ctx);
	struct io_ring_ctx *ctx = bc->ctx;
	struct io_rings *rings = ctx->rings;
	unsigned int mask = ctx->cq_entries - 1;
	unsigned head = rings->cq.head;
	struct io_uring_cqe *cqe;

	/* TODO CQE32 */
	if (head == rings->cq.tail)
		goto fail;

	cqe = &rings->cqes[head & mask];
	memcpy(res__uninit, cqe, sizeof(*cqe));
	rings->cq.head++;
	return 0;
fail:
	memset(res__uninit, 0, sizeof(*res__uninit));
	return -EINVAL;
}

__bpf_kfunc
struct io_uring_cqe *bpf_io_uring_get_cqe2(struct io_uring_bpf_ctx *user_ctx)
{
	struct io_bpf_ctx *bc = io_user_to_bpf_ctx(user_ctx);
	struct io_ring_ctx *ctx = bc->ctx;
	struct io_rings *rings = ctx->rings;
	unsigned int mask = ctx->cq_entries - 1;
	unsigned head = rings->cq.head;
	struct io_uring_cqe *cqe;

	/* TODO CQE32 */
	if (head == rings->cq.tail)
		return NULL;

	cqe = &rings->cqes[head & mask];
	rings->cq.head++;
	return cqe;
}

__bpf_kfunc
void bpf_io_uring_set_wait_params(struct io_uring_bpf_ctx *user_ctx,
				  unsigned wait_nr)
{
	struct io_bpf_ctx *bc = io_user_to_bpf_ctx(user_ctx);
	struct io_ring_ctx *ctx = bc->ctx;
	struct io_wait_queue *wq = bc->waitq;

	wait_nr = min_t(unsigned, wait_nr, ctx->cq_entries);
	wq->cq_tail = READ_ONCE(ctx->rings->cq.head) + wait_nr;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(io_uring_kfunc_set)
BTF_ID_FLAGS(func, bpf_io_uring_queue_sqe, KF_SLEEPABLE);
BTF_ID_FLAGS(func, bpf_io_uring_submit_sqes, KF_SLEEPABLE);
BTF_ID_FLAGS(func, bpf_io_uring_get_cqe, 0);
BTF_ID_FLAGS(func, bpf_io_uring_get_cqe2, KF_RET_NULL);
BTF_ID_FLAGS(func, bpf_io_uring_set_wait_params, 0);
BTF_KFUNCS_END(io_uring_kfunc_set)

static const struct btf_kfunc_id_set bpf_io_uring_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &io_uring_kfunc_set,
};

static int init_io_uring_bpf(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_IOURING,
					 &bpf_io_uring_kfunc_set);
}
late_initcall(init_io_uring_bpf);


static const struct bpf_func_proto *
io_bpf_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id, prog);
}

static bool io_bpf_is_valid_access(int off, int size,
				   enum bpf_access_type type,
				   const struct bpf_prog *prog,
				   struct bpf_insn_access_aux *info)
{
	return false;
}

const struct bpf_prog_ops bpf_io_uring_prog_ops = {};

const struct bpf_verifier_ops bpf_io_uring_verifier_ops = {
	.get_func_proto			= io_bpf_func_proto,
	.is_valid_access		= io_bpf_is_valid_access,
};

int io_run_bpf(struct io_ring_ctx *ctx)
{
	struct io_bpf_ctx *bc = ctx->bpf_ctx;
	int ret;

	mutex_lock(&ctx->uring_lock);
	ret = bpf_prog_run_pin_on_cpu(bc->prog, bc);
	mutex_unlock(&ctx->uring_lock);
	return ret;
}

int io_unregister_bpf(struct io_ring_ctx *ctx)
{
	struct io_bpf_ctx *bc = ctx->bpf_ctx;

	if (!bc)
		return -ENXIO;
	bpf_prog_put(bc->prog);
	kfree(bc);
	ctx->bpf_ctx = NULL;
	return 0;
}

int io_register_bpf(struct io_ring_ctx *ctx, void __user *arg,
		    unsigned int nr_args)
{
	struct __user io_uring_bpf_reg *bpf_reg_usr = arg;
	struct io_uring_bpf_reg bpf_reg;
	struct io_bpf_ctx *bc;
	struct bpf_prog *prog;

	if (!(ctx->flags & IORING_SETUP_DEFER_TASKRUN))
		return -EOPNOTSUPP;

	if (nr_args != 1)
		return -EINVAL;
	if (copy_from_user(&bpf_reg, bpf_reg_usr, sizeof(bpf_reg)))
		return -EFAULT;
	if (bpf_reg.flags || bpf_reg.resv1 ||
	    bpf_reg.resv2[0] || bpf_reg.resv2[1])
		return -EINVAL;

	if (ctx->bpf_ctx)
		return -ENXIO;

	bc = kzalloc(sizeof(*bc), GFP_KERNEL);
	if (!bc)
		return -ENOMEM;

	prog = bpf_prog_get_type(bpf_reg.prog_fd, BPF_PROG_TYPE_IOURING);
	if (IS_ERR(prog)) {
		kfree(bc);
		return PTR_ERR(prog);
	}

	bc->prog = prog;
	bc->ctx = ctx;
	ctx->bpf_ctx = bc;
	return 0;
}
