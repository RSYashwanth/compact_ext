// SPDX-License-Identifier: GPL-2.0

#include "compact_ext_lib.bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define WINDOW_NS	1000000000ULL

const volatile __u64 pages_per_sec = 25600;

__u64 nr_migrated;
__u64 nr_windows_full;
__u64 nr_stopped;
__u64 nr_refused;

static u64 window_start_ns;
static u64 window_pages;

static __always_inline bool over_budget(void)
{
	u64 now = bpf_ktime_get_ns();

	if (now - window_start_ns >= WINDOW_NS) {
		window_start_ns = now;
		window_pages = 0;
	}
	return window_pages >= pages_per_sec;
}

void BPF_STRUCT_OPS(budget_migration_completed,
		    struct compact_ext_migration_ctx *c)
{
	bool was_over;

	if (!background(c->trigger))
		return;
	was_over = over_budget();
	window_pages += c->nr_succeeded;
	nr_migrated += c->nr_succeeded;
	if (!was_over && window_pages >= pages_per_sec)
		nr_windows_full++;
}

enum compact_ext_run BPF_STRUCT_OPS(budget_should_compact_zone,
				    struct compact_ext_trigger_ctx *c)
{
	if (background(c->trigger) && c->default_result && over_budget()) {
		COUNT(nr_refused);
		return COMPACT_EXT_RUN_NO;
	}
	return c->default_result;
}

bool BPF_STRUCT_OPS(budget_should_proactive_compact,
		    struct compact_ext_proactive_ctx *c)
{
	if (c->default_result && over_budget()) {
		COUNT(nr_refused);
		return false;
	}
	return c->default_result;
}

enum compact_ext_finish BPF_STRUCT_OPS(budget_compaction_finished,
				       struct compact_ext_finish_ctx *c)
{
	if (c->trigger != COMPACT_EXT_TRIGGER_PROACTIVE ||
	    c->default_result != COMPACT_CONTINUE || !over_budget())
		return COMPACT_EXT_FINISH_DEFAULT;
	COUNT(nr_stopped);
	return COMPACT_EXT_FINISH_ABORT;
}

SEC(".struct_ops.link")
struct compact_ext_ops budget_ops = {
	.should_compact_zone		= (void *)budget_should_compact_zone,
	.should_proactive_compact	= (void *)budget_should_proactive_compact,
	.compaction_finished		= (void *)budget_compaction_finished,
	.migration_completed		= (void *)budget_migration_completed,
};
