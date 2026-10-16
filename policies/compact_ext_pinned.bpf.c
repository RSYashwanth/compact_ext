// SPDX-License-Identifier: GPL-2.0

#include "compact_ext_lib.bpf.h"

char LICENSE[] SEC("license") = "GPL";

__u64 nr_sources_skipped;
__u64 nr_targets_taken;

static __always_inline bool pinned_block(int migratetype)
{
	return migratetype == MIGRATE_UNMOVABLE ||
	       migratetype == MIGRATE_RECLAIMABLE;
}

bool BPF_STRUCT_OPS(pinned_select_migration_source,
		    struct compact_ext_source_ctx *c)
{
	if (c->trigger == COMPACT_EXT_TRIGGER_DIRECT &&
	    c->alloc_migratetype == c->pageblock_migratetype)
		return c->default_result;
	if (pinned_block(c->pageblock_migratetype)) {
		COUNT(nr_sources_skipped);
		return false;
	}
	return c->default_result;
}

bool BPF_STRUCT_OPS(pinned_select_migration_target,
		    struct compact_ext_target_ctx *c)
{
	if (pinned_block(c->pageblock_migratetype)) {
		COUNT(nr_targets_taken);
		return true;
	}
	return c->default_result;
}

SEC(".struct_ops.link")
struct compact_ext_ops pinned_ops = {
	.select_migration_source	= (void *)pinned_select_migration_source,
	.select_migration_target	= (void *)pinned_select_migration_target,
};
