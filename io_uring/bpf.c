// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/filter.h>

#include "bpf.h"

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
	ctx->bpf_ctx = bc;
	return 0;
}
