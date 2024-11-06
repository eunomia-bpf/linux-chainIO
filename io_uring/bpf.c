// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>

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
