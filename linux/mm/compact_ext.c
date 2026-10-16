// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) "compact_ext: " fmt

#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/compact_ext.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include <linux/wait.h>

static DEFINE_MUTEX(compact_ext_mutex);

static int bpf_compact_ext_init(struct btf *btf)
{
	static const char * const ctx_types[] = {
		"compact_ext_node_ctx",
		"compact_ext_trigger_ctx",
		"compact_ext_proactive_ctx",
		"compact_ext_frag_ctx",
		"compact_ext_source_ctx",
		"compact_ext_target_ctx",
		"compact_ext_scanner_ctx",
		"compact_ext_folio_ctx",
		"compact_ext_finish_ctx",
		"compact_ext_migration_ctx",
		"compact_ext_result_ctx",
	};
	unsigned int i;
	s32 type_id;

	for (i = 0; i < ARRAY_SIZE(ctx_types); i++) {
		type_id = btf_find_by_name_kind(btf, ctx_types[i],
						BTF_KIND_STRUCT);
		if (type_id < 0) {
			pr_err("struct %s not found in vmlinux BTF\n",
			       ctx_types[i]);
			return -EINVAL;
		}
	}

	return 0;
}

static const struct bpf_func_proto *
bpf_compact_ext_get_func_proto(enum bpf_func_id func_id,
			       const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_get_current_pid_tgid:
		return &bpf_get_current_pid_tgid_proto;
	case BPF_FUNC_tail_call:
		return NULL;
	default:
		return bpf_base_func_proto(func_id);
	}
}

static bool bpf_compact_ext_is_valid_access(int off, int size,
					    enum bpf_access_type type,
					    const struct bpf_prog *prog,
					    struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static int bpf_compact_ext_btf_struct_access(struct bpf_verifier_log *log,
					     const struct bpf_reg_state *reg,
					     int off, int size)
{
	const struct btf_type *t = btf_type_by_id(reg->btf, reg->btf_id);

	bpf_log(log,
		"compact_ext: write to struct %s (off %d, size %d) denied, kernel structs are read-only for policies\n",
		btf_name_by_offset(reg->btf, t->name_off), off, size);
	return -EACCES;
}

static void compact_ext_node_ctx_init(struct compact_ext_node_ctx *ctx,
				      pg_data_t *pgdat)
{
	ctx->pgdat = pgdat;
	ctx->nid = pgdat->node_id;
	ctx->node_start_pfn = pgdat->node_start_pfn;
	ctx->node_spanned_pages = pgdat->node_spanned_pages;
	ctx->node_present_pages = pgdat->node_present_pages;
	ctx->pb_order = pageblock_order;
	ctx->nr_pageblocks = DIV_ROUND_UP(pgdat->node_spanned_pages,
					  pageblock_nr_pages);
}

static int bpf_compact_ext_reg(void *kdata, void *more_data)
{
	struct compact_ext_ops *ops = kdata;
	struct compact_ext_ds_registry *registry;
	struct compact_ext_node_ctx ctx;
	pg_data_t *pgdat = more_data;
	int ret = 0;

	if (!pgdat) {
		pr_err("policies must be attached with a BPF_COMPACT_EXT_OPS link (bpf_map__attach_compact_ext_ops())\n");
		return -EINVAL;
	}

	mutex_lock(&compact_ext_mutex);

	if (rcu_dereference_protected(pgdat->compact_ext_ops,
				      lockdep_is_held(&compact_ext_mutex))) {
		pr_info("node %d already has a policy attached\n",
			pgdat->node_id);
		ret = -EBUSY;
		goto unlock;
	}

	ret = compact_ext_ds_registry_init(pgdat);
	if (ret)
		goto unlock;
	compact_ext_ds_registry_reset(pgdat);

	registry = pgdat->compact_ext_registry;
	registry->init_in_progress = true;
	if (ops->init) {
		compact_ext_node_ctx_init(&ctx, pgdat);
		ret = ops->init(&ctx);
	}
	registry->init_in_progress = false;

	if (ret) {
		pr_info("policy init() failed on node %d: %d\n",
			pgdat->node_id, ret);
		compact_ext_ds_registry_reset(pgdat);
		if (ret > 0 || ret < -MAX_ERRNO)
			ret = -EINVAL;
		goto unlock;
	}

	rcu_assign_pointer(pgdat->compact_ext_ops, ops);

	if (ops->should_proactive_compact) {
		pgdat->proactive_compact_trigger = true;
		wake_up_interruptible(&pgdat->kcompactd_wait);
	}

	pr_info("policy attached to node %d\n", pgdat->node_id);
unlock:
	mutex_unlock(&compact_ext_mutex);
	return ret;
}

static void bpf_compact_ext_unreg(void *kdata, void *more_data)
{
	struct compact_ext_ops *ops = kdata;
	struct compact_ext_node_ctx ctx;
	pg_data_t *pgdat = more_data;

	if (!pgdat)
		return;

	mutex_lock(&compact_ext_mutex);

	if (rcu_dereference_protected(pgdat->compact_ext_ops,
				      lockdep_is_held(&compact_ext_mutex)) != ops)
		goto unlock;

	RCU_INIT_POINTER(pgdat->compact_ext_ops, NULL);
	synchronize_rcu();

	if (ops->exit) {
		compact_ext_node_ctx_init(&ctx, pgdat);
		ops->exit(&ctx);
	}
	compact_ext_ds_registry_reset(pgdat);

	pr_info("policy detached from node %d\n", pgdat->node_id);
unlock:
	mutex_unlock(&compact_ext_mutex);
}

static int bpf_compact_ext_init_member(const struct btf_type *t,
				       const struct btf_member *member,
				       void *kdata, const void *udata)
{
	return 0;
}

static int bpf_compact_ext_check_member(const struct btf_type *t,
					const struct btf_member *member,
					const struct bpf_prog *prog)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct compact_ext_ops, init):
	case offsetof(struct compact_ext_ops, exit):
		return 0;
	default:
		return prog->aux->sleepable ? -EINVAL : 0;
	}
}

static int bpf_compact_ext_validate(void *kdata)
{
	return 0;
}

static const struct bpf_verifier_ops bpf_compact_ext_verifier_ops = {
	.get_func_proto = bpf_compact_ext_get_func_proto,
	.is_valid_access = bpf_compact_ext_is_valid_access,
	.btf_struct_access = bpf_compact_ext_btf_struct_access,
};

struct bpf_struct_ops bpf_compact_ext_ops = {
	.verifier_ops = &bpf_compact_ext_verifier_ops,
	.init = bpf_compact_ext_init,
	.reg = bpf_compact_ext_reg,
	.unreg = bpf_compact_ext_unreg,
	.init_member = bpf_compact_ext_init_member,
	.check_member = bpf_compact_ext_check_member,
	.validate = bpf_compact_ext_validate,
	.name = "compact_ext_ops",
};
