// SPDX-License-Identifier: GPL-2.0

#include "compact_ext_lib.bpf.h"

char LICENSE[] SEC("license") = "GPL";

const volatile __u64 scan_limit = 8192;
const volatile __u64 background_ms = 5000;

__u64 nr_cut;
__u64 nr_background_passes;
__u64 nr_block_ready;

static u64 last_cut_ns;
static int wanted_order;

static __always_inline bool catching_up(void)
{
	return last_cut_ns &&
	       bpf_ktime_get_ns() - last_cut_ns < background_ms * NSEC_PER_MSEC;
}

bool BPF_STRUCT_OPS(bounded_should_proactive_compact,
		    struct compact_ext_proactive_ctx *c)
{
	if (!catching_up())
		return c->default_result;
	COUNT(nr_background_passes);
	return true;
}

enum compact_ext_finish BPF_STRUCT_OPS(bounded_compaction_finished,
				       struct compact_ext_finish_ctx *c)
{
	if (c->trigger == COMPACT_EXT_TRIGGER_DIRECT) {
		if (c->order <= PAGE_ALLOC_COSTLY_ORDER ||
		    c->nr_migrate_scanned + c->nr_free_scanned < scan_limit)
			return COMPACT_EXT_FINISH_DEFAULT;
		if (c->default_result != COMPACT_CONTINUE)
			return COMPACT_EXT_FINISH_DEFAULT;
		last_cut_ns = bpf_ktime_get_ns();
		wanted_order = c->order;
		COUNT(nr_cut);
		return COMPACT_EXT_FINISH_ABORT;
	}

	if (c->trigger != COMPACT_EXT_TRIGGER_PROACTIVE || !catching_up())
		return COMPACT_EXT_FINISH_DEFAULT;
	if (zone_free_blocks(c->zone, wanted_order) > 0) {
		COUNT(nr_block_ready);
		return COMPACT_EXT_FINISH_SUCCESS;
	}
	if (c->default_result == COMPACT_SUCCESS)
		return COMPACT_EXT_FINISH_CONTINUE;
	return COMPACT_EXT_FINISH_DEFAULT;
}

SEC(".struct_ops.link")
struct compact_ext_ops bounded_ops = {
	.should_proactive_compact	= (void *)bounded_should_proactive_compact,
	.compaction_finished		= (void *)bounded_compaction_finished,
};
