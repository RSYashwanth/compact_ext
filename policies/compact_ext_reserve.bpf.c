// SPDX-License-Identifier: GPL-2.0

#include "compact_ext_lib.bpf.h"

char LICENSE[] SEC("license") = "GPL";

const volatile __u32 reserve_blocks = 128;
const volatile __u64 backoff_ms = 5000;

__u64 nr_passes;
__u64 nr_filled;
__u64 nr_backoffs;

static bool zone_short;
static u64 backoff_until_ns;

s64 BPF_STRUCT_OPS(reserve_fragmentation_score, struct compact_ext_frag_ctx *c)
{
	bool is_short;

	if (c->zone_present < (4ULL * reserve_blocks << HPAGE_PMD_ORDER))
		return 0;
	is_short = zone_free_blocks(c->zone, HPAGE_PMD_ORDER) < reserve_blocks;
	if (is_short)
		zone_short = true;
	return is_short ? 100 : 0;
}

bool BPF_STRUCT_OPS(reserve_should_proactive_compact,
		    struct compact_ext_proactive_ctx *c)
{
	bool any_short = zone_short;

	zone_short = false;
	if (!any_short || !c->proactiveness || c->kswapd_running ||
	    bpf_ktime_get_ns() < backoff_until_ns)
		return false;
	COUNT(nr_passes);
	return true;
}

void BPF_STRUCT_OPS(reserve_compaction_completed,
		    struct compact_ext_result_ctx *c)
{
	if (c->trigger != COMPACT_EXT_TRIGGER_PROACTIVE)
		return;
	if (c->result == COMPACT_SUCCESS) {
		COUNT(nr_filled);
		return;
	}
	backoff_until_ns = bpf_ktime_get_ns() + backoff_ms * NSEC_PER_MSEC;
	COUNT(nr_backoffs);
}

SEC(".struct_ops.link")
struct compact_ext_ops reserve_ops = {
	.fragmentation_score		= (void *)reserve_fragmentation_score,
	.should_proactive_compact	= (void *)reserve_should_proactive_compact,
	.compaction_completed		= (void *)reserve_compaction_completed,
};
